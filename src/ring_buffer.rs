// src/ring_buffer.rs
//! Ring buffer for bounded forensic logging with DoS protection.
//!
//! Prevents memory exhaustion attacks by maintaining a fixed-size buffer
//! with FIFO eviction. Ideal for high-volume honeypot deployments where
//! attackers might trigger thousands of errors per second.
//!
//! # Design Principles
//!
//! - **Bounded memory**: Fixed maximum size regardless of attack volume
//! - **FIFO eviction**: Oldest entries dropped first, keeps recent attacks
//! - **Per-entry size caps**: No single error can dominate the buffer
//! - **RwLock-based**: Concurrent readers, exclusive writers
//!
//! # Performance Characteristics
//!
//! - Zero allocations for reads (uses Arc<str> for cheap cloning)
//! - O(1) insertion and eviction
//! - Concurrent read scalability (N readers simultaneously)
//! - Fixed memory footprint (no growth/reallocation)
//!
//! # Example
//!
//! ```rust
//! use palisade_errors::ring_buffer::RingBufferLogger;
//! use palisade_errors::{AgentError, definitions};
//!
//! // Max 1000 entries, 2KB per entry = 2MB total
//! let logger = RingBufferLogger::new(1000, 2048);
//!
//! // Log errors - oldest automatically evicted
//! let err = AgentError::config(definitions::CFG_PARSE_FAILED, "op", "details");
//! logger.log(&err, "192.168.1.100");
//!
//! // Retrieve recent entries for analysis
//! let recent = logger.get_recent(10);
//! for entry in recent {
//!     println!("{:?}", entry);
//! }
//! ```

use crate::AgentError;
use smallvec::SmallVec;
use std::borrow::Cow;
use std::sync::RwLockReadGuard;
use std::sync::RwLockWriteGuard;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// A single forensic log entry with bounded size.
///
/// Uses Arc<str> instead of String to enable cheap cloning (atomic refcount increment)
/// without heap allocations. This is critical for high-frequency logging where
/// get_recent() might be called thousands of times per second.
#[derive(Clone, Debug)]
pub struct ForensicEntry {
    /// Unix timestamp of error creation
    pub timestamp: u64,
    /// Error code (e.g., "E-CFG-100") - shared immutable string
    pub code: Arc<str>,
    /// Operation that failed - shared immutable string
    pub operation: Arc<str>,
    /// Error details - shared immutable string
    pub details: Arc<str>,
    /// Source IP or identifier - shared immutable string
    pub source_ip: Arc<str>,
    /// Additional metadata from the error - exact-size allocation
    pub metadata: Arc<[(Arc<str>, Arc<str>)]>,
    /// Approximate size in bytes
    pub size_bytes: usize,
    /// Whether this error was marked retryable
    pub retryable: bool,
}

/// Fixed-size ring buffer with exact allocation (no growth).
struct RingBuffer {
    /// Fixed-size array of entries (no Vec growth overhead)
    entries: Box<[Option<ForensicEntry>]>,
    /// Write position (tail)
    tail: usize,
    /// Read position (head)
    head: usize,
    /// Current number of entries
    len: usize,
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
        }
    }

    fn push(&mut self, entry: ForensicEntry) -> Option<ForensicEntry> {
        let evicted = self.entries[self.tail].replace(entry);
        self.tail = (self.tail + 1) % self.entries.len();

        if self.len < self.entries.len() {
            self.len += 1;
        } else {
            self.head = (self.head + 1) % self.entries.len();
        }

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

    // Fixed: Return DoubleEndedIterator so rev() works in public methods
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
        for entry in self.entries.iter_mut() {
            *entry = None;
        }
        self.head = 0;
        self.tail = 0;
        self.len = 0;
    }
}

/// Ring buffer logger with bounded memory usage.
///
/// Uses RwLock for concurrent read scalability - multiple threads can
/// call get_recent() simultaneously without contention.
pub struct RingBufferLogger {
    buffer: Arc<RwLock<RingBuffer>>,
    max_entries: usize,
    max_entry_bytes: usize,
    eviction_count: Arc<AtomicU64>,
}

impl RingBufferLogger {
    /// Create a new ring buffer logger.
    ///
    /// # Arguments
    ///
    /// * `max_entries` - Maximum number of entries before FIFO eviction
    /// * `max_entry_bytes` - Maximum bytes per entry (defensive cap)
    ///
    /// # Example
    ///
    /// ```rust
    /// use palisade_errors::ring_buffer::RingBufferLogger;
    ///
    /// // Typical honeypot: 10k entries, 1KB each = 10MB max
    /// let logger = RingBufferLogger::new(10_000, 1024);
    /// ```
    pub fn new(max_entries: usize, max_entry_bytes: usize) -> Self {
        let bounded_entries = max_entries.max(1);
        Self {
            buffer: Arc::new(RwLock::new(RingBuffer::new(bounded_entries))),
            max_entries: bounded_entries,
            max_entry_bytes,
            eviction_count: Arc::new(AtomicU64::new(0)),
        }
    }

    #[inline]
    fn read_buffer(&self) -> RwLockReadGuard<'_, RingBuffer> {
        match self.buffer.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    #[inline]
    fn write_buffer(&self) -> RwLockWriteGuard<'_, RingBuffer> {
        match self.buffer.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Log an error with automatic eviction if buffer is full.
    ///
    /// # Arguments
    ///
    /// * `err` - The error to log
    /// * `source_ip` - Source IP or identifier for tracking
    ///
    /// # Example
    ///
    /// ```rust
    /// # use palisade_errors::ring_buffer::RingBufferLogger;
    /// # use palisade_errors::{AgentError, definitions};
    /// let logger = RingBufferLogger::new(100, 1024);
    /// let err = AgentError::config(definitions::CFG_PARSE_FAILED, "op", "details");
    /// logger.log(&err, "192.168.1.100");
    /// ```
    pub fn log(&self, err: &AgentError, source_ip: &str) {
        let entry = self.create_entry(err, source_ip);

        let mut buffer = self.write_buffer();

        // Evict oldest entry if buffer is full
        if let Some(_evicted) = buffer.push(entry) {
            self.eviction_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Create a bounded forensic entry from an error.
    ///
    /// Uses Cow and Arc to minimize allocations:
    /// - Short strings that don't need truncation: zero allocations
    /// - Truncated strings: single allocation for the truncated content
    /// - Arc cloning: just atomic refcount increments
    fn create_entry(&self, err: &AgentError, source_ip: &str) -> ForensicEntry {
        err.with_internal_log(|log| {
            let mut size = 0usize;
            let mut remaining = self.max_entry_bytes;

            // Truncate operation name (cap at 256 or remaining)
            let op_cap = remaining.min(256);
            let operation = truncate_to_bytes(log.operation(), op_cap);
            let op_len = operation.len();
            size += op_len;
            remaining = remaining.saturating_sub(op_len);

            // Truncate details (cap at 512 or remaining)
            let details_cap = remaining.min(512);
            let details = truncate_to_bytes(log.details(), details_cap);
            let details_len = details.len();
            size += details_len;
            remaining = remaining.saturating_sub(details_len);

            // Add metadata up to remaining space, values capped at 128 bytes each
            let mut metadata_vec: SmallVec<[(Arc<str>, Arc<str>); 8]> = SmallVec::new();
            for (k, v) in log.metadata() {
                if remaining == 0 {
                    break;
                }
                let key_len = k.len();
                if key_len >= remaining {
                    break;
                }
                let value_cap = (remaining - key_len).min(128);
                if value_cap == 0 {
                    break;
                }
                let value = truncate_to_bytes(v.as_str(), value_cap);
                let used = key_len + value.len();
                if used > remaining {
                    break;
                }
                size += used;
                remaining = remaining.saturating_sub(used);
                
                metadata_vec.push((Arc::from(*k), Arc::from(value.as_ref())));
            }

            let metadata: Arc<[(Arc<str>, Arc<str>)]> =
                metadata_vec.into_vec().into_boxed_slice().into();

            // Add source_ip if space permits (cap to 128 bytes)
            let source_ip_str = if remaining == 0 {
                Cow::Borrowed("[TRUNCATED]")
            } else {
                let source_ip = truncate_to_bytes(source_ip, remaining.min(128));
                size += source_ip.len();
                source_ip
            };

            ForensicEntry {
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs()),
                code: Arc::from(log.code().to_string()),
                operation: Arc::from(operation.as_ref()),
                details: Arc::from(details.as_ref()),
                source_ip: Arc::from(source_ip_str.as_ref()),
                metadata,
                size_bytes: size,
                retryable: log.is_retryable(),
            }
        })
    }

    /// Get the N most recent entries in reverse chronological order.
    ///
    /// Uses read lock for concurrent access - multiple threads can call
    /// this simultaneously without blocking each other.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use palisade_errors::ring_buffer::RingBufferLogger;
    /// # let logger = RingBufferLogger::new(100, 1024);
    /// // Get last 10 errors
    /// let recent = logger.get_recent(10);
    /// for entry in recent {
    ///     println!("[{}] {} - {}", entry.timestamp, entry.code, entry.operation);
    /// }
    /// ```
    pub fn get_recent(&self, count: usize) -> Vec<ForensicEntry> {
        let buffer = self.read_buffer();
        buffer
            .iter()
            .rev()
            .take(count)
            .cloned() // Cheap: just Arc refcount increments
            .collect()
    }

    /// Get all entries in reverse chronological order.
    pub fn get_all(&self) -> Vec<ForensicEntry> {
        let buffer = self.read_buffer();
        buffer.iter().rev().cloned().collect()
    }

    /// Get entries matching a predicate (e.g., filter by source IP).
    ///
    /// # Example
    ///
    /// ```rust
    /// # use palisade_errors::ring_buffer::RingBufferLogger;
    /// # let logger = RingBufferLogger::new(100, 1024);
    /// // Get all errors from specific IP
    /// let from_attacker = logger.get_filtered(|entry| {
    ///     entry.source_ip.as_ref() == "192.168.1.100"
    /// });
    /// ```
    pub fn get_filtered<F>(&self, predicate: F) -> Vec<ForensicEntry>
    where
        F: Fn(&ForensicEntry) -> bool,
    {
        let buffer = self.read_buffer();
        buffer.iter().filter(|e| predicate(e)).cloned().collect()
    }

    /// Get current number of entries in buffer.
    #[inline]
    pub fn len(&self) -> usize {
        let buffer = self.read_buffer();
        buffer.len()
    }

    /// Check if buffer is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get total payload bytes (lower-bound estimate).
    pub fn payload_bytes(&self) -> usize {
        let buffer = self.read_buffer();
        buffer.iter().map(|e| e.size_bytes).sum()
    }

    /// Get total number of evictions since creation.
    ///
    /// High eviction rate indicates sustained attack volume.
    #[inline]
    pub fn eviction_count(&self) -> u64 {
        self.eviction_count.load(Ordering::Relaxed)
    }

    /// Clear all entries (useful after archival or testing).
    pub fn clear(&self) {
        let mut buffer = self.write_buffer();
        buffer.clear();
    }

    /// Get buffer capacity.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.max_entries
    }

    /// Check if buffer is at capacity.
    pub fn is_full(&self) -> bool {
        self.len() >= self.max_entries
    }
}

impl Clone for RingBufferLogger {
    fn clone(&self) -> Self {
        Self {
            buffer: Arc::clone(&self.buffer),
            max_entries: self.max_entries,
            max_entry_bytes: self.max_entry_bytes,
            eviction_count: Arc::clone(&self.eviction_count),
        }
    }
}

/// Truncate string to maximum byte length, respecting UTF-8 boundaries.
///
/// Returns Cow to avoid allocation when no truncation is needed (common case).
// Fixed: Added lifetime 'a to signature
fn truncate_to_bytes<'a>(s: &'a str, max_bytes: usize) -> Cow<'a, str> {
    if max_bytes == 0 {
        return Cow::Borrowed("");
    }
    if s.len() <= max_bytes {
        // Common case: no truncation needed, zero allocations
        return Cow::Borrowed(s);
    }

    // Reserve space for truncation indicator
    let indicator = "...[TRUNC]";
    if max_bytes <= indicator.len() {
        return Cow::Borrowed(&indicator[..max_bytes]);
    }
    let max_content = max_bytes - indicator.len();

    // Find last valid UTF-8 boundary
    let mut idx = max_content;
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }

    if idx == 0 {
        return Cow::Borrowed(indicator);
    }

    // Only path that allocates
    let mut out = String::with_capacity(idx + indicator.len());
    out.push_str(&s[..idx]);
    out.push_str(indicator);
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AgentError, definitions};

    #[test]
    fn ring_buffer_evicts_oldest() {
        let logger = RingBufferLogger::new(3, 1024);

        for i in 0..5 {
            let err = AgentError::config(
                definitions::CFG_PARSE_FAILED,
                "op",
                format!("error {}", i),
            );
            logger.log(&err, "192.168.1.1");
        }

        // Should only have last 3
        assert_eq!(logger.len(), 3);
        assert_eq!(logger.eviction_count(), 2);

        let entries = logger.get_all();
        assert!(entries[0].details.contains("error 4"));
        assert!(entries[2].details.contains("error 2"));
    }

    #[test]
    fn ring_buffer_respects_size_limit() {
        let logger = RingBufferLogger::new(100, 128);

        let huge_details = "A".repeat(10000);
        let err =
            AgentError::config(definitions::CFG_PARSE_FAILED, "op", huge_details);
        logger.log(&err, "192.168.1.1");

        let entry = &logger.get_recent(1)[0];
        assert!(entry.size_bytes <= 128);
        assert!(entry.details.contains("TRUNC"));
    }

    #[test]
    fn ring_buffer_filtering() {
        let logger = RingBufferLogger::new(100, 1024);

        for i in 0..10 {
            let err = AgentError::config(
                definitions::CFG_PARSE_FAILED,
                "op",
                format!("error {}", i),
            );
            let ip = if i % 2 == 0 {
                "192.168.1.1"
            } else {
                "192.168.1.2"
            };
            logger.log(&err, ip);
        }

        let from_ip1 =
            logger.get_filtered(|e| e.source_ip.as_ref() == "192.168.1.1");
        assert_eq!(from_ip1.len(), 5);
    }

    #[test]
    fn ring_buffer_clone_shares_state() {
        let logger1 = RingBufferLogger::new(100, 1024);
        let logger2 = logger1.clone();

        let err = AgentError::config(definitions::CFG_PARSE_FAILED, "op", "test");
        logger1.log(&err, "192.168.1.1");

        // Both should see the entry
        assert_eq!(logger1.len(), 1);
        assert_eq!(logger2.len(), 1);
    }

    #[test]
    fn truncate_respects_utf8() {
        let emoji = "🔥".repeat(100);
        let truncated = truncate_to_bytes(&emoji, 50);

        // Should not panic and should be valid UTF-8
        assert!(std::str::from_utf8(truncated.as_bytes()).is_ok());
        assert!(truncated.len() <= 50);
    }

    #[test]
    fn truncate_no_allocation_when_short() {
        let s = "short";
        let truncated = truncate_to_bytes(s, 100);

        // Should be borrowed (zero allocations)
        assert!(matches!(truncated, Cow::Borrowed(_)));
        assert_eq!(truncated.as_ref(), s);
    }

    #[test]
    fn ring_buffer_concurrent_logging() {
        use std::thread;

        let logger = RingBufferLogger::new(128, 256);
        let mut handles = Vec::new();

        for i in 0..8 {
            let logger = logger.clone();
            handles.push(thread::spawn(move || {
                for j in 0..100 {
                    let err = AgentError::config(
                        definitions::CFG_PARSE_FAILED,
                        "op",
                        format!("t{}-{}", i, j),
                    );
                    logger.log(&err, "192.168.1.1");
                }
            }));
        }

        for handle in handles {
            handle.join().expect("thread panicked");
        }

        assert_eq!(logger.len(), 128);
        assert!(logger.eviction_count() > 0);
    }

    #[test]
    fn ring_buffer_concurrent_reads() {
        use std::thread;

        let logger = RingBufferLogger::new(100, 256);

        // Populate buffer
        for i in 0..50 {
            let err = AgentError::config(
                definitions::CFG_PARSE_FAILED,
                "op",
                format!("error {}", i),
            );
            logger.log(&err, "192.168.1.1");
        }

        // Multiple threads reading simultaneously
        let mut handles = Vec::new();
        for _ in 0..8 {
            let logger = logger.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    let entries = logger.get_recent(10);
                    assert!(!entries.is_empty());
                }
            }));
        }

        for handle in handles {
            handle.join().expect("thread panicked");
        }
    }

    #[test]
    fn arc_str_cloning_is_cheap() {
        let logger = RingBufferLogger::new(10, 1024);

        let err = AgentError::config(
            definitions::CFG_PARSE_FAILED,
            "operation",
            "details",
        );
        logger.log(&err, "192.168.1.1");

        let entry1 = logger.get_recent(1)[0].clone();
        let entry2 = logger.get_recent(1)[0].clone();

        // Verify Arc pointers point to same allocation
        assert!(Arc::ptr_eq(&entry1.code, &entry2.code));
        assert!(Arc::ptr_eq(&entry1.operation, &entry2.operation));
        assert!(Arc::ptr_eq(&entry1.details, &entry2.details));
    }
}
