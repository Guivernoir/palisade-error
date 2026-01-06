//! Security-focused tests for adversarial scenarios
//!
//! These tests verify that the error handling system is resilient
//! against various attack vectors.

#[cfg(test)]
mod security_tests {
    use palisade_errors::{AgentError, definitions, config_err};
    use std::io;
    use std::time::Duration;

    #[test]
    #[ignore]
    fn attacker_cannot_extract_paths_from_display() {
        let err = AgentError::from_io_path(
            definitions::IO_READ_FAILED,
            "load_config",
            "/etc/shadow",
            io::Error::from(io::ErrorKind::PermissionDenied)
        );
        
        let displayed = format!("{}", err);
        
        // Path should not appear anywhere in external display
        assert!(!displayed.contains("/etc"));
        assert!(!displayed.contains("shadow"));
        assert!(!displayed.contains("/"));
        
        // Debug output should also be safe
        let debug = format!("{:?}", err);
        assert!(!debug.contains("/etc"));
        assert!(!debug.contains("shadow"));
    }

    #[test]
    fn attacker_cannot_extract_operation_names() {
        let err = AgentError::config(
            definitions::CFG_PARSE_FAILED,
            "validate_admin_credentials",
            "validation failed"
        );
        
        let displayed = format!("{}", err);
        
        // Operation name reveals code structure - should not be exposed
        assert!(!displayed.contains("validate"));
        assert!(!displayed.contains("admin"));
        assert!(!displayed.contains("credentials"));
    }

    #[test]
    fn attacker_cannot_extract_validation_logic() {
        let err = AgentError::config(
            definitions::CFG_INVALID_VALUE,
            "check_threshold",
            "Value must be between 0.0 and 1.0"
        );
        
        let displayed = format!("{}", err);
        
        // Validation constraints reveal logic - should not be exposed
        assert!(!displayed.contains("between"));
        assert!(!displayed.contains("0.0"));
        assert!(!displayed.contains("1.0"));
        assert!(!displayed.contains("must be"));
    }

    #[test]
    #[ignore]
    fn timing_normalization_prevents_user_enumeration() {
        use std::time::Instant;
        
        let target = Duration::from_millis(100);
        
        // Fast failure path (user doesn't exist)
        let start1 = Instant::now();
        let err1 = AgentError::config(
            definitions::CFG_VALIDATION_FAILED,
            "auth",
            "invalid"
        ).with_timing_normalization(target);
        let time1 = start1.elapsed();
        drop(err1);
        
        // Simulate slow failure path (password check)
        let start2 = Instant::now();
        std::thread::sleep(Duration::from_millis(50)); // Simulated expensive check
        let err2 = AgentError::config(
            definitions::CFG_VALIDATION_FAILED,
            "auth",
            "invalid"
        ).with_timing_normalization(target);
        let time2 = start2.elapsed();
        drop(err2);
        
        // Both should take at least target duration
        assert!(time1 >= target);
        assert!(time2 >= target);
        
        // Timing difference should be minimal (within 20ms tolerance)
        let diff = if time1 > time2 { 
            time1 - time2 
        } else { 
            time2 - time1 
        };
        assert!(diff < Duration::from_millis(20), 
            "Timing difference too large: {:?}", diff);
    }

    #[test]
    fn error_codes_are_consistent_across_failures() {
        // Attacker shouldn't be able to distinguish between different
        // failure reasons within the same category
        
        let err1 = AgentError::config(
            definitions::CFG_PARSE_FAILED,
            "parse_yaml",
            "syntax error at line 42"
        );
        
        let err2 = AgentError::config(
            definitions::CFG_PARSE_FAILED,
            "parse_json",
            "unexpected token"
        );
        
        // Both should have same external representation
        assert_eq!(
            format!("{}", err1).split('(').last(),
            format!("{}", err2).split('(').last()
        );
    }

    #[test]
    fn massive_input_does_not_cause_dos() {
        // Attacker tries to cause memory exhaustion with huge error messages
        let huge_string = "A".repeat(10_000_000); // 10MB string
        
        let err = config_err!(
            definitions::CFG_PARSE_FAILED,
            "test",
            "Failed: {}",
            &huge_string[..1000] // Truncate before creating error
        );
        
        // Internal logging should truncate this
        let mut buffer = String::new();
        err.with_internal_log(|log| {
            log.write_to(&mut buffer).unwrap();
        });
        
        // Buffer should be much smaller than input
        assert!(buffer.len() < 5000, "Buffer not truncated: {} bytes", buffer.len());
    }

    #[test]
    fn unicode_in_paths_does_not_cause_issues() {
        // Attacker uses unicode in paths to try to break truncation
        let unicode_path = "/etc/файл/🔥/secret.conf";
        
        let err = AgentError::from_io_path(
            definitions::IO_READ_FAILED,
            "read",
            unicode_path,
            io::Error::from(io::ErrorKind::NotFound)
        );
        
        // Should not panic
        let displayed = format!("{}", err);
        
        // Should not leak the path
        assert!(!displayed.contains("файл"));
        assert!(!displayed.contains("🔥"));
        assert!(!displayed.contains("secret"));
    }

    #[test]
    fn metadata_does_not_leak_in_display() {
        let err = AgentError::config(
            definitions::CFG_PARSE_FAILED,
            "test",
            "test"
        )
        .with_metadata("session_id", "secret-session-123")
        .with_metadata("user_id", "admin@example.com");
        
        let displayed = format!("{}", err);
        
        // Metadata should not appear in external display
        assert!(!displayed.contains("session_id"));
        assert!(!displayed.contains("secret-session-123"));
        assert!(!displayed.contains("user_id"));
        assert!(!displayed.contains("admin@example.com"));
    }

    #[test]
    fn retryable_flag_cannot_be_used_for_oracle() {
        // Attacker tries to use retry hints to determine error types
        
        let err1 = AgentError::config(
            definitions::CFG_PARSE_FAILED,
            "test",
            "permanent failure"
        );
        
        let err2 = AgentError::telemetry(
            definitions::TEL_CHANNEL_CLOSED,
            "test",
            "temporary failure"
        ).with_retry();
        
        // Both should display differently but not in a way that reveals internals
        let display1 = format!("{}", err1);
        let display2 = format!("{}", err2);
        
        assert!(display1.contains("[permanent]"));
        assert!(display2.contains("[temporary]"));
        
        // But neither should contain details about what failed
        assert!(!display1.contains("parse"));
        assert!(!display2.contains("channel"));
    }

    #[test]
    fn macro_prevents_variable_operation_names() {
        // This test documents the compile-time protection
        // Uncomment to verify it fails to compile:
        
        // let user_controlled = "malicious_op_name";
        // let err = config_err!(
        //     definitions::CFG_PARSE_FAILED,
        //     user_controlled,  // Should fail: expected string literal
        //     "details"
        // );
    }

    #[test]
    fn error_source_is_zeroized_on_drop() {
        // This is hard to test directly, but we verify the Drop implementation runs
        
        let err = AgentError::from_io_path(
            definitions::IO_READ_FAILED,
            "test",
            "/secret/path",
            io::Error::from(io::ErrorKind::PermissionDenied)
        );
        
        // Get internal log while error exists
        let mut buffer = String::new();
        err.with_internal_log(|log| {
            log.write_to(&mut buffer).unwrap();
        });
        
        // Buffer contains sensitive data
        assert!(buffer.contains("/secret/path"));
        
        // Drop the error explicitly
        drop(err);
        
        // After drop, the sensitive data should be zeroized
        // (we can't directly verify memory, but Drop implementation does this)
    }

    #[test]
    fn error_codes_validate_at_compile_time() {
        // These should compile fine
        let _valid1 = definitions::CFG_PARSE_FAILED;
        let _valid2 = definitions::IO_READ_FAILED;
        
        // These would fail at compile time if uncommented:
        // const INVALID1: ErrorCode = ErrorCode::new("TEST", 0, OperationCategory::Configuration);
        // const INVALID2: ErrorCode = ErrorCode::new("TEST", 1000, OperationCategory::Configuration);
        // const INVALID3: ErrorCode = ErrorCode::new("", 100, OperationCategory::Configuration);
    }
}
