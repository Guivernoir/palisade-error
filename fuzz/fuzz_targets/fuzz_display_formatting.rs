#![no_main]

//! Fuzz target for display formatting
//!
//! Tests that Display and Debug implementations never:
//! - Panic on arbitrary input
//! - Produce invalid UTF-8
//! - Leak sensitive information
//! - Consume unbounded memory
//!
//! Run with: cargo fuzz run fuzz_display_formatting

use libfuzzer_sys::fuzz_target;
use palisade_errors::{AgentError, definitions};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Test with various error types and input sizes
        let inputs = vec![
            s,
            &s[..s.len().min(100)],
            &s[..s.len().min(1000)],
            &s[..s.len().min(10000)],
        ];

        for input in inputs {
            let err = AgentError::config_sensitive(
                definitions::CFG_PARSE_FAILED,
                "fuzz_operation",
                input,
                input // Also test as sensitive data
            );

            // Test Display formatting
            let display_output = format!("{}", err);
            
            // Verify output is valid UTF-8
            assert!(std::str::from_utf8(display_output.as_bytes()).is_ok());
            
            // Verify sensitive data doesn't leak
            assert!(!display_output.contains(input),
                "Sensitive data leaked in Display");
            assert!(!display_output.contains("fuzz_operation"),
                "Operation name leaked in Display");
            
            // Verify output has reasonable size
            assert!(display_output.len() < 500,
                "Display output too large: {} bytes", display_output.len());

            // Test Debug formatting
            let debug_output = format!("{:?}", err);
            
            // Verify output is valid UTF-8
            assert!(std::str::from_utf8(debug_output.as_bytes()).is_ok());
            
            // Verify sensitive data is redacted
            assert!(!debug_output.contains(input) || debug_output.contains("REDACTED"),
                "Sensitive data leaked in Debug without redaction");

            // Test with metadata
            let err_with_metadata = err
                .with_metadata("key1", input)
                .with_metadata("key2", "static_value");

            let display_meta = format!("{}", err_with_metadata);
            assert!(!display_meta.contains(input),
                "Metadata leaked in Display");
            assert!(!display_meta.contains("key1"),
                "Metadata key leaked in Display");
        }
    }
});