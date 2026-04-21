//! Bounded forensic ring buffer with fully preallocated storage.
//!
//! The hot `AgentError::new()` path writes into this buffer without heap
//! allocation, and the internal read helpers iterate in place without
//! snapshotting.

#![cfg_attr(not(test), allow(dead_code))]

use crate::AgentError;
use crate::fixed::FixedString;
use crate::zeroization::{Zeroize, drop_zeroize};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

const ENTRY_CODE_BYTES: usize = 10;
const ENTRY_EXTERNAL_BYTES: usize = 256;
const ENTRY_INTERNAL_BYTES: usize = 256;
const ENTRY_SOURCE_BYTES: usize = 64;
const ENTRY_TRUNCATION_INDICATOR: &str = "...[TRUNC]";

/// A single immutable forensic log entry with bounded field sizes.
pub(crate) struct ForensicEntry {
    timestamp: u64,
    code: FixedString<ENTRY_CODE_BYTES>,
    external: FixedString<ENTRY_EXTERNAL_BYTES>,
    internal: FixedString<ENTRY_INTERNAL_BYTES>,
    source_ip: FixedString<ENTRY_SOURCE_BYTES>,
    size_bytes: usize,
    retryable: bool,
}

impl ForensicEntry {
    fn matches_source(&self, source: &str) -> bool {
        self.source_ip.as_str() == source
    }
}

impl Zeroize for ForensicEntry {
    fn zeroize(&mut self) {
        self.timestamp.zeroize();
        self.code.zeroize();
        self.external.zeroize();
        self.internal.zeroize();
        self.source_ip.zeroize();
        self.size_bytes.zeroize();
        self.retryable.zeroize();
    }
}

impl Drop for ForensicEntry {
    fn drop(&mut self) {
        drop_zeroize(self);
    }
}

struct RingBuffer<const MAX_ENTRIES: usize> {
    entries: [Option<ForensicEntry>; MAX_ENTRIES],
    tail: usize,
    head: usize,
    len: usize,
    total_payload_bytes: usize,
}

impl<const MAX_ENTRIES: usize> RingBuffer<MAX_ENTRIES> {
    const fn new() -> Self {
        Self {
            entries: [const { None }; MAX_ENTRIES],
            tail: 0,
            head: 0,
            len: 0,
            total_payload_bytes: 0,
        }
    }

    fn push(&mut self, entry: ForensicEntry) -> Option<ForensicEntry> {
        let index = self.tail;
        let entry_size = entry.size_bytes;
        let evicted = self.entries[index].replace(entry);
        if let Some(ref old) = evicted {
            self.total_payload_bytes = self.total_payload_bytes.saturating_sub(old.size_bytes);
        }
        self.total_payload_bytes = self.total_payload_bytes.saturating_add(entry_size);

        self.tail = (self.tail + 1) % MAX_ENTRIES;
        if self.len < MAX_ENTRIES {
            self.len += 1;
        } else {
            self.head = (self.head + 1) % MAX_ENTRIES;
        }

        evicted
    }

    #[inline]
    fn len(&self) -> usize {
        self.len
    }

    fn iter(&self) -> impl DoubleEndedIterator<Item = &ForensicEntry> {
        let head = self.head;
        let len = self.len;
        (0..len).filter_map(move |i| self.entries[(head + i) % MAX_ENTRIES].as_ref())
    }
}

/// Concurrent, bounded forensic log with static capacity.
pub(crate) struct RingBufferLogger<const MAX_ENTRIES: usize, const MAX_ENTRY_BYTES: usize> {
    buffer: Mutex<RingBuffer<MAX_ENTRIES>>,
    eviction_count: AtomicU64,
}

impl<const MAX_ENTRIES: usize, const MAX_ENTRY_BYTES: usize>
    RingBufferLogger<MAX_ENTRIES, MAX_ENTRY_BYTES>
{
    /// Create a new ring buffer logger.
    pub(crate) const fn new_internal() -> Self {
        assert!(MAX_ENTRIES > 0, "ring buffer capacity must be non-zero");
        assert!(
            MAX_ENTRY_BYTES > 0,
            "ring buffer entry size must be non-zero"
        );
        Self {
            buffer: Mutex::new(RingBuffer::new()),
            eviction_count: AtomicU64::new(0),
        }
    }

    #[inline]
    fn lock_buffer(&self) -> MutexGuard<'_, RingBuffer<MAX_ENTRIES>> {
        match self.buffer.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Log an error with the sentinel source identifier `"[internal]"`.
    pub(crate) fn log_internal(&self, err: &AgentError) {
        self.log_with_source(err, "[internal]");
    }

    /// Log an error with an explicit source identifier.
    pub(crate) fn log_with_source(&self, err: &AgentError, source: &str) {
        let entry = self.make_entry(err, source);
        let mut buffer = self.lock_buffer();
        if buffer.push(entry).is_some() {
            self.eviction_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn make_entry(&self, err: &AgentError, source_ip: &str) -> ForensicEntry {
        let mut remaining = MAX_ENTRY_BYTES;

        let mut code = FixedString::<ENTRY_CODE_BYTES>::new();
        write!(&mut code, "{}", err.code_inner()).expect("error code exceeds fixed width");
        let mut size = code.len();
        remaining = remaining.saturating_sub(code.len());

        let mut external = FixedString::<ENTRY_EXTERNAL_BYTES>::new();
        external.set_truncated_to(
            err.external_payload(),
            remaining.min(ENTRY_EXTERNAL_BYTES),
            ENTRY_TRUNCATION_INDICATOR,
        );
        size += external.len();
        remaining = remaining.saturating_sub(external.len());

        let mut internal = FixedString::<ENTRY_INTERNAL_BYTES>::new();
        internal.set_truncated_to(
            err.internal_payload(),
            remaining.min(ENTRY_INTERNAL_BYTES),
            ENTRY_TRUNCATION_INDICATOR,
        );
        size += internal.len();
        remaining = remaining.saturating_sub(internal.len());

        let mut source = FixedString::<ENTRY_SOURCE_BYTES>::new();
        source.set_truncated_to(
            source_ip,
            remaining.min(ENTRY_SOURCE_BYTES),
            ENTRY_TRUNCATION_INDICATOR,
        );
        size += source.len();

        ForensicEntry {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_millis() as u64),
            code,
            external,
            internal,
            source_ip: source,
            size_bytes: size,
            retryable: err.is_retryable(),
        }
    }

    /// Visit the `count` most recent entries in reverse chronological order.
    pub(crate) fn for_each_recent<F>(&self, count: usize, mut f: F)
    where
        F: FnMut(&ForensicEntry),
    {
        let guard = self.lock_buffer();
        for entry in guard.iter().rev().take(count) {
            f(entry);
        }
    }

    /// Visit entries matching a predicate in reverse chronological order.
    pub(crate) fn for_each_filtered<P, F>(&self, predicate: P, mut f: F)
    where
        P: Fn(&ForensicEntry) -> bool,
        F: FnMut(&ForensicEntry),
    {
        let guard = self.lock_buffer();
        for entry in guard.iter().rev() {
            if predicate(entry) {
                f(entry);
            }
        }
    }

    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.lock_buffer().len()
    }

    #[inline]
    pub(crate) fn eviction_count(&self) -> u64 {
        self.eviction_count.load(Ordering::Relaxed)
    }

    pub(crate) fn payload_bytes(&self) -> usize {
        self.lock_buffer().total_payload_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgentError;

    type TestLogger = RingBufferLogger<100, 1_024>;

    fn make_logger() -> TestLogger {
        TestLogger::new_internal()
    }

    fn make_err(external: &'static str, internal: &'static str) -> AgentError {
        AgentError::new(100, external, internal, "")
    }

    #[test]
    fn evicts_oldest_when_full() {
        let logger = RingBufferLogger::<3, 1_024>::new_internal();
        for i in 0..5_u32 {
            let source = if i == 0 {
                "src-0"
            } else if i == 1 {
                "src-1"
            } else if i == 2 {
                "src-2"
            } else if i == 3 {
                "src-3"
            } else {
                "src-4"
            };
            logger.log_with_source(&make_err("e", "i"), source);
        }
        assert_eq!(logger.len(), 3);
        assert_eq!(logger.eviction_count(), 2);
    }

    #[test]
    fn filtering_works() {
        let logger = RingBufferLogger::<20, 1_024>::new_internal();
        for i in 0..6_u32 {
            let ip = if i % 2 == 0 { "1.1.1.1" } else { "2.2.2.2" };
            logger.log_with_source(&make_err("e", "i"), ip);
        }
        let mut from_1 = 0;
        logger.for_each_filtered(
            |entry| entry.matches_source("1.1.1.1"),
            |_| {
                from_1 += 1;
            },
        );
        assert_eq!(from_1, 3);
    }

    #[test]
    fn recent_reads_are_stable() {
        let logger = make_logger();
        logger.log_internal(&make_err("e", "i"));
        let mut first_code = FixedString::<ENTRY_CODE_BYTES>::new();
        let mut first_external = FixedString::<ENTRY_EXTERNAL_BYTES>::new();

        logger.for_each_recent(1, |entry| {
            first_code.set_truncated_to(
                entry.code.as_str(),
                ENTRY_CODE_BYTES,
                ENTRY_TRUNCATION_INDICATOR,
            );
            first_external.set_truncated_to(
                entry.external.as_str(),
                ENTRY_EXTERNAL_BYTES,
                ENTRY_TRUNCATION_INDICATOR,
            );
        });

        logger.for_each_recent(1, |entry| {
            assert_eq!(entry.code.as_str(), first_code.as_str());
            assert_eq!(entry.external.as_str(), first_external.as_str());
        });
    }

    #[test]
    fn payload_bytes_updates_correctly() {
        let logger = RingBufferLogger::<3, 1_024>::new_internal();
        logger.log_internal(&make_err("external", "internal"));
        let bytes_after_first = logger.payload_bytes();
        assert!(bytes_after_first > 0);

        logger.log_internal(&make_err("ext2", "int2"));
        assert!(logger.payload_bytes() > bytes_after_first);

        logger.log_internal(&make_err("ext3", "int3"));
        logger.log_internal(&make_err("ext4", "int4"));
        assert_eq!(logger.eviction_count(), 1);
        assert_eq!(logger.len(), 3);
    }

    #[test]
    fn timestamp_is_millis() {
        let logger = make_logger();
        logger.log_internal(&make_err("e", "i"));
        logger.for_each_recent(1, |entry| {
            let now_millis = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;
            assert!(entry.timestamp <= now_millis);
            assert!(entry.timestamp > now_millis - 1_000);
        });
    }
}
