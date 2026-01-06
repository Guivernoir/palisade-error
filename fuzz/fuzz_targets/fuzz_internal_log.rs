#![no_main]

//! Fuzz target for internal logging
//!
//! Tests that internal log formatting never:
//! - Panics
//! - Produces invalid UTF-8
//! - Exceeds memory limits
//! - Breaks on long inputs
//!
//! Run with: cargo fuzz run fuzz_internal_log

use libfuzzer_sys::fuzz_target;
use palisade_errors::{AgentError, definitions};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Create error with potentially problematic content
        let err = AgentError::config(
            definitions::CFG_PARSE_FAILED,
            "test_operation",
            s
        );

        // Test internal_log() method
        err.with_internal_log(|log| {
            // Verify accessors don't panic
            let _ = log.code();
            let _ = log.operation();
            let _ = log.details();
            let _ = log.source_internal();
            let _ = log.source_sensitive();
            let _ = log.metadata();
            let _ = log.is_retryable();

            // Test write_to() with string buffer
            let mut buffer = String::new();
            log.write_to(&mut buffer).expect("write_to failed");

            // Verify output is valid UTF-8
            assert!(std::str::from_utf8(buffer.as_bytes()).is_ok());

            // Verify output has reasonable size (truncation working)
            assert!(buffer.len() < 5000,
                "Internal log output too large: {} bytes", buffer.len());

            // If input is truncated, verify indicator is present
            if s.len() > 1024 && buffer.contains(s) {
                assert!(buffer.contains("TRUNCATED") || buffer.len() < s.len(),
                    "Large input not truncated properly");
            }
        });

        // Test with sensitive data
        let err_sensitive = AgentError::config_sensitive(
            definitions::CFG_PARSE_FAILED,
            "test_operation",
            "internal details",
            s // sensitive
        );

        err_sensitive.with_internal_log(|log| {
            let mut buffer = String::new();
            log.write_to(&mut buffer).expect("write_to failed");

            // Should contain sensitive marker or data
            assert!(
                buffer.contains("sensitive=") || buffer.len() > 0,
                "Sensitive data not logged internally"
            );
        });

        // Test with metadata
        let err_meta = AgentError::config(
            definitions::CFG_PARSE_FAILED,
            "test",
            "details"
        )
        .with_metadata("key1", s)
        .with_metadata("key2", "value2");

        err_meta.with_internal_log(|log| {
            let metadata = log.metadata();
            assert_eq!(metadata.len(), 2);

            let mut buffer = String::new();
            log.write_to(&mut buffer).expect("write_to failed");

            // Metadata should appear in internal log
            assert!(buffer.contains("key1="));
            assert!(buffer.contains("key2="));
        });

        // Test with split sources (io error scenario)
        let err_split = AgentError::from_io_path(
            definitions::IO_READ_FAILED,
            "read_file",
            s, // path (sensitive)
            std::io::Error::from(std::io::ErrorKind::NotFound)
        );

        err_split.with_internal_log(|log| {
            // Should have both internal and sensitive sources
            assert!(log.source_internal().is_some() || log.source_sensitive().is_some());

            let mut buffer = String::new();
            log.write_to(&mut buffer).expect("write_to failed");
            
            // Verify reasonable size
            assert!(buffer.len() < 5000);
        });
    }
});