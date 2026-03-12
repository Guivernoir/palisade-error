//! Bounded forensic ring buffer.
//!
//! Provides DoS-safe, bounded memory forensic logging.  The buffer is exposed
//! to callers exclusively via [`crate::global_ring_buffer()`]; it cannot be
//! constructed or written to from outside the crate.
//!
//! # Design
//!
//! - Fixed capacity set at construction; no growth, no reallocation.
//! - FIFO eviction: oldest entry is silently dropped when capacity is reached.
//! - Per-entry byte cap prevents one enormous error from dominating.
//! - `Mutex`: exclusive access for simplicity under potential write-heavy loads.
//! - `Arc<str>` for entries: `get_recent()` clones are atomic ref-count bumps.

use crate::AgentError;
use std::borrow::Cow;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

// ── ForensicEntry ─────────────────────────────────────────────────────────────

/// A single immutable forensic log entry with bounded field sizes.
///
/// All string fields use `Arc<str>` so that `clone()` is O(1) (atomic refcount
/// increment, no heap allocation).
#[derive(Debug, Clone)]
pub(crate) struct ForensicEntry {
    /// Unix timestamp (milliseconds) at which the error was logged.
    timestamp: u64,
    /// Obfuscated error code string, e.g. `"E-CFG-103"`.
    code: Arc<str>,
    /// The external / deceptive payload supplied by the caller.
    external: Arc<str>,
    /// The internal diagnostic payload supplied by the caller.
    internal: Arc<str>,
    /// Source identifier; `"[internal]"` for auto-logged errors.
    source_ip: Arc<str>,
    /// Approximate total byte size of this entry.
    size_bytes: usize,
    /// Whether the error was marked as transient.
    retryable: bool,
}

// ── Internal ring buffer ──────────────────────────────────────────────────────

struct RingBuffer {
    entries: Box<[Option<ForensicEntry>]>,
    tail: usize,
    head: usize,
    len: usize,
    total_payload_bytes: AtomicUsize,
}

impl RingBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            entries: std::iter::repeat_with(|| None)
                .take(capacity)
                .collect::<Box<[Option<ForensicEntry>]>>(),
            tail: 0,
            head: 0,
            len: 0,
            total_payload_bytes: AtomicUsize::new(0),
        }
    }

    /// Push an entry; returns the evicted entry if the buffer was full.
    fn push(&mut self, entry: ForensicEntry) -> Option<ForensicEntry> {
        let evicted = self.entries[self.tail].replace(entry);
        self.tail = (self.tail + 1) % self.entries.len();
        if self.len < self.entries.len() {
            self.len += 1;
        } else {
            self.head = (self.head + 1) % self.entries.len();
        }
        if let Some(ref ev) = evicted {
            self.total_payload_bytes
                .fetch_sub(ev.size_bytes, Ordering::Relaxed);
        }
        self.total_payload_bytes.fetch_add(
            self.entries[self.tail.wrapping_sub(1) % self.entries.len()]
                .as_ref()
                .unwrap()
                .size_bytes,
            Ordering::Relaxed,
        );
        evicted
    }

    #[inline]
    fn len(&self) -> usize {
        self.len
    }
    #[inline]
    fn capacity(&self) -> usize {
        self.entries.len()
    }

    fn iter(&self) -> impl DoubleEndedIterator<Item = &ForensicEntry> {
        let head = self.head;
        let len = self.len;
        let cap = self.entries.len();
        (0..len).filter_map(move |i| {
            let idx = (head + i) % cap;
            self.entries[idx].as_ref()
        })
    }

    fn clear(&mut self) {
        for e in self.entries.iter_mut() {
            *e = None;
        }
        self.head = 0;
        self.tail = 0;
        self.len = 0;
        self.total_payload_bytes.store(0, Ordering::Relaxed);
    }
}

// ── RingBufferLogger ──────────────────────────────────────────────────────────

/// Concurrent, bounded forensic log.
///
/// Obtain the global instance via [`crate::global_ring_buffer()`].
/// This type is `pub(crate)` so callers can receive the reference, but its constructor
/// is `pub(crate)` — external code cannot create additional instances.
pub(crate) struct RingBufferLogger {
    buffer: Arc<Mutex<RingBuffer>>,
    max_entries: usize,
    max_entry_bytes: usize,
    eviction_count: Arc<AtomicU64>,
}

impl RingBufferLogger {
    /// Create a new ring buffer logger.
    ///
    /// `pub(crate)` — callers use [`crate::global_ring_buffer()`].
    pub(crate) fn new_internal(max_entries: usize, max_entry_bytes: usize) -> Self {
        let bounded = max_entries.max(1);
        Self {
            buffer: Arc::new(Mutex::new(RingBuffer::new(bounded))),
            max_entries: bounded,
            max_entry_bytes,
            eviction_count: Arc::new(AtomicU64::new(0)),
        }
    }

    // ── Lock helpers ─────────────────────────────────────────────────────────

    #[inline]
    fn lock_buffer(&self) -> MutexGuard<'_, RingBuffer> {
        match self.buffer.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    // ── Internal write path ───────────────────────────────────────────────────

    /// Log an error with a sentinel source identifier `"[internal]"`.
    ///
    /// Called automatically from `AgentError::new()` — not callable externally.
    pub(crate) fn log_internal(&self, err: &AgentError) {
        self.log_with_source(err, "[internal]");
    }

    /// Log an error with an explicit source identifier (e.g. a peer IP address).
    ///
    /// Callers that have access to request context should call this after the
    /// automatic `"[internal]"` entry to add source attribution.
    ///
    /// `pub(crate)` — access via the global handle and `log_with_source` on the
    /// returned reference is the intended pattern.
    pub(crate) fn log_with_source(&self, err: &AgentError, source: &str) {
        let entry = self.make_entry(err, source);
        let mut buf = self.lock_buffer();
        if buf.push(entry).is_some() {
            self.eviction_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    // ── Entry construction ────────────────────────────────────────────────────

    fn make_entry(&self, err: &AgentError, source_ip: &str) -> ForensicEntry {
        let mut remaining = self.max_entry_bytes;
        let mut size = 0usize;

        let code_str = err.code_inner().to_string();
        let ext = err.external_payload();
        let int = err.internal_payload();

        // External field: cap at 512 bytes.
        let ext_cap = remaining.min(512);
        let ext_s = truncate_to_bytes(ext, ext_cap);
        size += ext_s.len();
        remaining = remaining.saturating_sub(ext_s.len());

        // Internal field: cap at 512 bytes.
        let int_cap = remaining.min(512);
        let int_s = truncate_to_bytes(int, int_cap);
        size += int_s.len();
        remaining = remaining.saturating_sub(int_s.len());

        // Source: cap at 128 bytes.
        let src_cap = remaining.min(128);
        let src_s = if src_cap == 0 {
            Cow::Borrowed("[TRUNCATED]")
        } else {
            let s = truncate_to_bytes(source_ip, src_cap);
            size += s.len();
            s
        };

        ForensicEntry {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as u64),
            code: Arc::from(code_str.as_str()),
            external: Arc::from(ext_s.as_ref()),
            internal: Arc::from(int_s.as_ref()),
            source_ip: Arc::from(src_s.as_ref()),
            size_bytes: size,
            retryable: err.is_retryable(),
        }
    }

    // ── Public read API ───────────────────────────────────────────────────────

    /// Execute a closure with the `count` most-recent entries in reverse chronological order.
    pub(crate) fn with_recent<F, R>(&self, count: usize, f: F) -> R
    where
        F: FnOnce(&[ForensicEntry]) -> R,
    {
        let guard = self.lock_buffer();
        let entries: Vec<ForensicEntry> = guard.iter().rev().take(count).cloned().collect();
        drop(guard);
        f(&entries)
    }

    /// Execute a closure with all entries in reverse chronological order.
    pub(crate) fn with_all<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[ForensicEntry]) -> R,
    {
        let guard = self.lock_buffer();
        let entries: Vec<ForensicEntry> = guard.iter().rev().cloned().collect();
        drop(guard);
        f(&entries)
    }

    /// Execute a closure with entries matching a predicate (e.g., filter by source IP).
    pub(crate) fn with_filtered<F, P, R>(&self, predicate: P, f: F) -> R
    where
        P: Fn(&ForensicEntry) -> bool,
        F: FnOnce(&[ForensicEntry]) -> R,
    {
        let guard = self.lock_buffer();
        let entries: Vec<ForensicEntry> = guard.iter().filter(|e| predicate(e)).cloned().collect();
        drop(guard);
        f(&entries)
    }

    /// Current number of entries in the buffer.
    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.lock_buffer().len()
    }

    /// `true` if the buffer contains no entries.
    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Total evictions since creation.  A high and rising value indicates
    /// sustained high-volume attack traffic.
    #[inline]
    pub(crate) fn eviction_count(&self) -> u64 {
        self.eviction_count.load(Ordering::Relaxed)
    }

    /// Buffer capacity set at initialisation.
    #[inline]
    pub(crate) fn capacity(&self) -> usize {
        self.max_entries
    }

    /// `true` if the buffer has reached capacity (next write will evict).
    pub(crate) fn is_full(&self) -> bool {
        self.len() >= self.max_entries
    }

    /// Approximate total payload bytes stored (lower-bound estimate).
    pub(crate) fn payload_bytes(&self) -> usize {
        self.lock_buffer()
            .total_payload_bytes
            .load(Ordering::Relaxed)
    }

    /// Clear all entries.
    pub(crate) fn clear(&self) {
        self.lock_buffer().clear();
    }
}

// ── Truncation helper ─────────────────────────────────────────────────────────

/// Truncate `s` to at most `max_bytes` bytes at a valid UTF-8 boundary.
/// Returns `Cow::Borrowed` when no truncation is needed (zero allocation).
fn truncate_to_bytes<'a>(s: &'a str, max_bytes: usize) -> Cow<'a, str> {
    const INDICATOR: &str = "...[TRUNC]";
    if max_bytes == 0 {
        return Cow::Borrowed("");
    }
    if s.len() <= max_bytes {
        return Cow::Borrowed(s);
    }

    if max_bytes <= INDICATOR.len() {
        return Cow::Borrowed(&INDICATOR[..max_bytes.min(INDICATOR.len())]);
    }
    let max_content = max_bytes - INDICATOR.len();
    let mut idx = max_content;
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    if idx == 0 {
        return Cow::Borrowed(INDICATOR);
    }

    let mut out = String::with_capacity(idx + INDICATOR.len());
    out.push_str(&s[..idx]);
    out.push_str(INDICATOR);
    Cow::Owned(out)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgentError;

    fn make_logger() -> RingBufferLogger {
        RingBufferLogger::new_internal(100, 1_024)
    }

    fn make_err(external: &'static str, internal: &'static str) -> AgentError {
        // Use new() so obfuscation/CT/auto-log all run; we discard the
        // auto-logged entry in the global buffer and re-log to our local one.
        AgentError::new(100, external, internal, "")
    }

    #[test]
    fn evicts_oldest_when_full() {
        let logger = RingBufferLogger::new_internal(3, 1_024);
        for i in 0..5_u32 {
            // We log directly to our local logger — the global buffer also gets
            // an entry from new(), which is expected and inconsequential here.
            logger.log_with_source(&make_err("e", "i"), &format!("src-{}", i));
        }
        assert_eq!(logger.len(), 3);
        assert_eq!(logger.eviction_count(), 2);
    }

    #[test]
    fn filtering_works() {
        let logger = RingBufferLogger::new_internal(20, 1_024);
        for i in 0..6_u32 {
            let ip = if i % 2 == 0 { "1.1.1.1" } else { "2.2.2.2" };
            logger.log_with_source(&make_err("e", "i"), ip);
        }
        logger.with_filtered(
            |e| e.source_ip.as_ref() == "1.1.1.1",
            |from_1| {
                assert_eq!(from_1.len(), 3);
            },
        );
    }

    #[test]
    fn truncate_respects_utf8() {
        let emoji = "🔥".repeat(100);
        let result = truncate_to_bytes(&emoji, 50);
        assert!(std::str::from_utf8(result.as_bytes()).is_ok());
        assert!(result.len() <= 50);
    }

    #[test]
    fn truncate_no_alloc_when_short() {
        let result = truncate_to_bytes("short", 100);
        assert!(matches!(result, Cow::Borrowed(_)));
    }

    #[test]
    fn arc_ptrs_are_shared_across_clones() {
        let logger = make_logger();
        logger.log_internal(&make_err("e", "i"));
        logger.with_recent(1, |e1| {
            logger.with_recent(1, |e2| {
                assert!(Arc::ptr_eq(&e1[0].code, &e2[0].code));
                assert!(Arc::ptr_eq(&e1[0].external, &e2[0].external));
            });
        });
    }

    #[test]
    fn payload_bytes_updates_correctly() {
        let logger = RingBufferLogger::new_internal(3, 1_024);
        logger.log_internal(&make_err("external", "internal"));
        let bytes_after_first = logger.payload_bytes();
        assert!(bytes_after_first > 0);

        logger.log_internal(&make_err("ext2", "int2"));
        assert!(logger.payload_bytes() > bytes_after_first);

        // Fill and evict
        logger.log_internal(&make_err("ext3", "int3"));
        logger.log_internal(&make_err("ext4", "int4"));
        assert_eq!(logger.eviction_count(), 1);
        assert_eq!(logger.len(), 3);
    }

    #[test]
    fn timestamp_is_millis() {
        let logger = make_logger();
        logger.log_internal(&make_err("e", "i"));
        logger.with_recent(1, |recent| {
            let entry = &recent[0];
            let now_millis = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;
            assert!(entry.timestamp <= now_millis);
            assert!(entry.timestamp > now_millis - 1000); // Within last second
        });
    }
}
