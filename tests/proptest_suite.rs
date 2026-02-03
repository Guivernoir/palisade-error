//! Property-based tests for palisade_errors
//!
//! These tests use proptest to generate random inputs and verify invariants hold.

use palisade_errors::{AgentError, definitions, ring_buffer::RingBufferLogger, sanitized};
use proptest::prelude::*;

// ============================================================================
// TRUNCATION PROPERTIES
// ============================================================================

proptest! {
    /// Truncated strings must always be valid UTF-8
    #[test]
    fn truncation_preserves_utf8(s in "\\PC*") {
        let err = AgentError::config(
            definitions::CFG_PARSE_FAILED,
            "operation",
            s
        );
        
        let log = err.internal_log();
        let mut buffer = String::new();
        log.write_to(&mut buffer).unwrap();
        
        // Must be valid UTF-8
        assert!(std::str::from_utf8(buffer.as_bytes()).is_ok());
    }
    
    /// Truncated output must be bounded
    #[test]
    fn truncation_is_bounded(s in "\\PC{0,10000}") {
        let err = AgentError::config(
            definitions::CFG_PARSE_FAILED,
            "operation",
            s
        );
        
        let log = err.internal_log();
        let mut buffer = String::new();
        log.write_to(&mut buffer).unwrap();
        
        // Should be bounded to prevent DoS
        // Max: 1024 per field + indicators + formatting
        assert!(buffer.len() < 10000);
    }
    
    /// Sanitized macro must preserve UTF-8 and bound length
    #[test]
    fn sanitized_macro_properties(s in "\\PC*") {
        let sanitized = sanitized!(s);
        
        // Valid UTF-8
        assert!(std::str::from_utf8(sanitized.as_bytes()).is_ok());
        
        // Bounded length (256 + truncation indicator)
        assert!(sanitized.len() <= 280);
        
        // If original was short, should be preserved (except empty)
        if s.is_empty() {
            assert_eq!(sanitized, "[INVALID_INPUT]");
        } else if s.len() <= 256 {
            assert_eq!(sanitized, s);
        }
    }
}

// ============================================================================
// ERROR CREATION PROPERTIES
// ============================================================================

proptest! {
    /// Errors can be created with arbitrary strings without panicking
    #[test]
    fn error_creation_never_panics(
        operation in "\\PC{0,1000}",
        details in "\\PC{0,1000}",
    ) {
        let _err = AgentError::config(
            definitions::CFG_PARSE_FAILED,
            operation,
            details
        );
    }
    
    /// Error display never contains internal details
    #[test]
    fn external_display_leaks_nothing(
        operation in "\\PC{3,100}",
        details in "\\PC{3,100}",
    ) {
        palisade_errors::obfuscation::clear_session_salt();
        let err = AgentError::config(
            definitions::CFG_PARSE_FAILED,
            operation.clone(),
            details.clone()
        );
        
        let display = format!("{}", err);
        
        // Should not contain operation or details
        assert!(!display.contains(&operation));
        assert!(!display.contains(&details));
        
        // Should contain error code (no salt set)
        assert!(display.contains("E-CFG-100"));
    }
    
    /// Sensitive data never appears in external display
    #[test]
    fn sensitive_never_in_display(
        operation in "\\PC{1,100}",
        details in "\\PC{1,100}",
        sensitive in "\\PC{3,100}",
    ) {
        let err = AgentError::config_sensitive(
            definitions::CFG_PARSE_FAILED,
            operation,
            details,
            sensitive.clone()
        );
        
        let display = format!("{}", err);
        assert!(!display.contains(&sensitive));
    }
}

// ============================================================================
// METADATA PROPERTIES
// ============================================================================

proptest! {
    /// Metadata can be added without panicking
    #[test]
    fn metadata_addition_stable(
        values in prop::collection::vec("\\PC{0,100}", 0..20)
    ) {
        let mut err = AgentError::config(
            definitions::CFG_PARSE_FAILED,
            "operation",
            "details"
        );
        
        for value in values {
            err = err.with_metadata("key", value);
        }
        
        // Should be able to log it
        let log = err.internal_log();
        let mut buffer = String::new();
        log.write_to(&mut buffer).unwrap();
    }
    
    /// Metadata count is preserved
    #[test]
    fn metadata_count_preserved(
        count in 0usize..10,
    ) {
        let mut err = AgentError::config(
            definitions::CFG_PARSE_FAILED,
            "operation",
            "details"
        );
        
        for i in 0..count {
            err = err.with_metadata("key", format!("value_{}", i));
        }
        
        let log = err.internal_log();
        assert_eq!(log.metadata().len(), count);
    }
}

// ============================================================================
// RING BUFFER PROPERTIES
// ============================================================================

proptest! {
    /// Ring buffer never exceeds capacity
    #[test]
    fn ring_buffer_respects_capacity(
        capacity in 1usize..100,
        num_logs in 0usize..200,
    ) {
        let logger = RingBufferLogger::new(capacity, 1024);
        
        for i in 0..num_logs {
            let err = AgentError::config(
                definitions::CFG_PARSE_FAILED,
                "operation",
                format!("error {}", i)
            );
            logger.log(&err, "192.168.1.1");
        }
        
        // Must never exceed capacity
        assert!(logger.len() <= capacity);
        
        // If we logged more than capacity, should be at capacity
        if num_logs >= capacity {
            assert_eq!(logger.len(), capacity);
        } else {
            assert_eq!(logger.len(), num_logs);
        }
    }
    
    /// Ring buffer memory usage is bounded
    #[test]
    fn ring_buffer_memory_bounded(
        capacity in 1usize..100,
        max_entry in 256usize..2048,
        num_logs in 0usize..200,
    ) {
        let logger = RingBufferLogger::new(capacity, max_entry);
        
        for i in 0..num_logs {
            let huge_details = "X".repeat(10000);
            let err = AgentError::config(
                definitions::CFG_PARSE_FAILED,
                "operation",
                huge_details
            );
            logger.log(&err, "192.168.1.1");
        }
        
        // Memory usage must be bounded
        let max_memory = capacity * max_entry;
        assert!(logger.payload_bytes() <= max_memory);
    }
    
    /// Ring buffer queries never panic
    #[test]
    fn ring_buffer_queries_stable(
        capacity in 1usize..50,
        num_logs in 0usize..100,
        recent_count in 0usize..20,
    ) {
        let logger = RingBufferLogger::new(capacity, 1024);
        
        for i in 0..num_logs {
            let err = AgentError::config(
                definitions::CFG_PARSE_FAILED,
                "op",
                format!("error {}", i)
            );
            logger.log(&err, &format!("192.168.1.{}", i % 256));
        }
        
        // All queries should work
        let _ = logger.get_recent(recent_count);
        let _ = logger.get_all();
        let _ = logger.get_filtered(|_| true);
        let _ = logger.len();
        let _ = logger.payload_bytes();
    }
}

// ============================================================================
// DISPLAY AND DEBUG PROPERTIES
// ============================================================================

proptest! {
    /// Display formatting never panics
    #[test]
    fn display_never_panics(
        operation in "\\PC{0,1000}",
        details in "\\PC{0,1000}",
    ) {
        let err = AgentError::config(
            definitions::CFG_PARSE_FAILED,
            operation,
            details
        );
        
        let _ = format!("{}", err);
        let _ = format!("{:?}", err);
    }
    
    /// Display output is always valid UTF-8
    #[test]
    fn display_is_utf8(
        operation in "\\PC{0,1000}",
        details in "\\PC{0,1000}",
    ) {
        let err = AgentError::config(
            definitions::CFG_PARSE_FAILED,
            operation,
            details
        );
        
        let display = format!("{}", err);
        assert!(std::str::from_utf8(display.as_bytes()).is_ok());
        
        let debug = format!("{:?}", err);
        assert!(std::str::from_utf8(debug.as_bytes()).is_ok());
    }
}

// ============================================================================
// CONCURRENT PROPERTIES
// ============================================================================

proptest! {
    /// Multiple errors can be created concurrently
    #[test]
    fn concurrent_error_creation(
        thread_count in 1usize..8,
        errors_per_thread in 1usize..100,
    ) {
        let handles: Vec<_> = (0..thread_count)
            .map(|t| {
                std::thread::spawn(move || {
                    for i in 0..errors_per_thread {
                        let _ = AgentError::config(
                            definitions::CFG_PARSE_FAILED,
                            format!("thread_{}", t),
                            format!("error_{}", i)
                        );
                    }
                })
            })
            .collect();
        
        for handle in handles {
            handle.join().unwrap();
        }
    }
    
    /// Ring buffer handles concurrent writes
    #[test]
    fn concurrent_ring_buffer_writes(
        capacity in 10usize..100,
        thread_count in 1usize..8,
        writes_per_thread in 1usize..50,
    ) {
        let logger = RingBufferLogger::new(capacity, 1024);
        
        let handles: Vec<_> = (0..thread_count)
            .map(|t| {
                let logger = logger.clone();
                std::thread::spawn(move || {
                    for i in 0..writes_per_thread {
                        let err = AgentError::config(
                            definitions::CFG_PARSE_FAILED,
                            format!("thread_{}", t),
                            format!("error_{}", i)
                        );
                        logger.log(&err, &format!("192.168.1.{}", t));
                    }
                })
            })
            .collect();
        
        for handle in handles {
            handle.join().unwrap();
        }
        
        // Verify invariants after concurrent writes
        assert!(logger.len() <= capacity);
    }
}

// ============================================================================
// OBFUSCATION PROPERTIES (always on)
// ============================================================================

proptest! {
    /// Obfuscation preserves namespace
    #[test]
    fn obfuscation_preserves_namespace(salt in 0u32..256) {
        use palisade_errors::obfuscation;
        
        obfuscation::init_session_salt(salt);
        let obfuscated = obfuscation::obfuscate_code(&definitions::CFG_PARSE_FAILED);
        
        // Namespace should be preserved
        assert_eq!(obfuscated.namespace(), definitions::CFG_PARSE_FAILED.namespace());
        
        // Category should be preserved
        assert_eq!(obfuscated.category(), definitions::CFG_PARSE_FAILED.category());
        
        // Code should be in valid range (100-199 for CFG)
        assert!(obfuscated.code() >= 100 && obfuscated.code() < 200);
    }
    
    /// Different salts produce different codes
    #[test]
    fn obfuscation_varies_with_salt(salt1 in 0u32..256, salt2 in 0u32..256) {
        use palisade_errors::obfuscation;
        
        prop_assume!(salt1 != salt2);
        
        obfuscation::init_session_salt(salt1);
        let code1 = obfuscation::obfuscate_code(&definitions::CFG_PARSE_FAILED);
        
        obfuscation::init_session_salt(salt2);
        let code2 = obfuscation::obfuscate_code(&definitions::CFG_PARSE_FAILED);
        
        // Different salts should produce different codes (with high probability)
        // We allow same code due to modulo wrapping
        if (salt1 & 0b111) != (salt2 & 0b111) {
            // If lower 3 bits differ, codes must differ
            assert_ne!(code1.code(), code2.code());
        }
    }
}

// ============================================================================
// UNICODE EDGE CASES
// ============================================================================

proptest! {
    /// Errors handle various Unicode categories correctly
    #[test]
    fn unicode_categories_handled(
        ascii in "[a-zA-Z0-9 ]{0,100}",
        emoji in "[🔥💥🚨😀]{0,50}",
        cyrillic in "[А-Яа-я ]{0,100}",
        chinese in "[\\u{4E00}-\\u{9FFF}]{0,100}",
    ) {
        let mixed = format!("{} {} {} {}", ascii, emoji, cyrillic, chinese);
        
        let err = AgentError::config(
            definitions::CFG_PARSE_FAILED,
            "unicode_test",
            mixed
        );
        
        let log = err.internal_log();
        let mut buffer = String::new();
        log.write_to(&mut buffer).unwrap();
        
        // Must be valid UTF-8
        assert!(std::str::from_utf8(buffer.as_bytes()).is_ok());
    }
}
