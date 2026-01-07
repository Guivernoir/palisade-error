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
//! - **Lock-based**: Simple mutex, predictable performance
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
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// A single forensic log entry with bounded size.
#[derive(Clone, Debug)]
pub struct ForensicEntry {
    /// Unix timestamp of error creation
    pub timestamp: u64,
    /// Error code (e.g., "E-CFG-100")
    pub code: String,
    /// Operation that failed
    pub operation: String,
    /// Error details
    pub details: String,
    /// Source IP or identifier
    pub source_ip: String,
    /// Additional metadata from the error
    pub metadata: Vec<(String, String)>,
    /// Approximate size in bytes
    pub size_bytes: usize,
    /// Whether this error was marked retryable
    pub retryable: bool,
}

/// Ring buffer logger with bounded memory usage.
pub struct RingBufferLogger {
    buffer: Arc<Mutex<VecDeque<ForensicEntry>>>,
    max_entries: usize,
    max_entry_bytes: usize,
    eviction_count: Arc<Mutex<u64>>,
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
        Self {
            buffer: Arc::new(Mutex::new(VecDeque::with_capacity(max_entries))),
            max_entries,
            max_entry_bytes,
            eviction_count: Arc::new(Mutex::new(0)),
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
        
        let mut buffer = self.buffer.lock().unwrap();
        
        // Evict oldest entry if buffer is full
        if buffer.len() >= self.max_entries {
            buffer.pop_front();
            let mut count = self.eviction_count.lock().unwrap();
            *count += 1;
        }
        
        buffer.push_back(entry);
    }

    /// Create a bounded forensic entry from an error.
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
            let mut metadata = Vec::new();
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
                metadata.push((k.to_string(), value));
            }

            // Add source_ip if space permits
            let source_ip = if remaining >= source_ip.len() {
                size += source_ip.len();
                remaining = remaining.saturating_sub(source_ip.len());
                source_ip.to_string()
            } else {
                String::from("[TRUNCATED]")
            };

            ForensicEntry {
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                code: log.code().to_string(),
                operation,
                details,
                source_ip,
                metadata,
                size_bytes: size,
                retryable: log.is_retryable(),
            }
        })
    }

    /// Get the N most recent entries in reverse chronological order.
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
        let buffer = self.buffer.lock().unwrap();
        buffer.iter()
            .rev()
            .take(count)
            .cloned()
            .collect()
    }

    /// Get all entries in reverse chronological order.
    pub fn get_all(&self) -> Vec<ForensicEntry> {
        let buffer = self.buffer.lock().unwrap();
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
    ///     entry.source_ip == "192.168.1.100"
    /// });
    /// ```
    pub fn get_filtered<F>(&self, predicate: F) -> Vec<ForensicEntry>
    where
        F: Fn(&ForensicEntry) -> bool,
    {
        let buffer = self.buffer.lock().unwrap();
        buffer.iter()
            .filter(|e| predicate(e))
            .cloned()
            .collect()
    }

    /// Get current number of entries in buffer.
    pub fn len(&self) -> usize {
        let buffer = self.buffer.lock().unwrap();
        buffer.len()
    }

    /// Check if buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get total memory usage estimate in bytes.
    pub fn memory_usage_bytes(&self) -> usize {
        let buffer = self.buffer.lock().unwrap();
        buffer.iter().map(|e| e.size_bytes).sum()
    }

    /// Get total number of evictions since creation.
    ///
    /// High eviction rate indicates sustained attack volume.
    pub fn eviction_count(&self) -> u64 {
        let count = self.eviction_count.lock().unwrap();
        *count
    }

    /// Clear all entries (useful after archival or testing).
    pub fn clear(&self) {
        let mut buffer = self.buffer.lock().unwrap();
        buffer.clear();
    }

    /// Get buffer capacity.
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
fn truncate_to_bytes(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    
    // Reserve space for truncation indicator
    let indicator = "...[TRUNC]";
    let max_content = max_bytes.saturating_sub(indicator.len());
    
    // Find last valid UTF-8 boundary
    let mut idx = max_content;
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    
    if idx == 0 {
        return indicator.to_string();
    }
    
    format!("{}{}", &s[..idx], indicator)
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
                format!("error {}", i)
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
        let err = AgentError::config(
            definitions::CFG_PARSE_FAILED,
            "op",
            huge_details
        );
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
                format!("error {}", i)
            );
            let ip = if i % 2 == 0 { "192.168.1.1" } else { "192.168.1.2" };
            logger.log(&err, ip);
        }
        
        let from_ip1 = logger.get_filtered(|e| e.source_ip == "192.168.1.1");
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
}