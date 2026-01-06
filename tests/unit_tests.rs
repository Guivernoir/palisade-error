//! Unit tests for error handling core functionality
//!
//! These tests verify the basic behavior of error creation,
//! formatting, and lifecycle management.

#[cfg(test)]
mod unit_tests {
    use palisade_errors::{
        AgentError, ErrorCode, OperationCategory, definitions, 
        config_err, Result
    };
    use std::io;
    use std::time::Duration;

    // ============================================================================
    // ErrorCode Tests
    // ============================================================================

    #[test]
    fn error_code_formatting() {
        let code = definitions::CFG_PARSE_FAILED;
        assert_eq!(code.to_string(), "E-CFG-100");
        assert_eq!(code.namespace(), "CFG");
        assert_eq!(code.code(), 100);
    }

    #[test]
    fn error_code_categories() {
        assert_eq!(
            definitions::CFG_PARSE_FAILED.category(),
            OperationCategory::Configuration
        );
        assert_eq!(
            definitions::TEL_INIT_FAILED.category(),
            OperationCategory::Monitoring
        );
        assert_eq!(
            definitions::IO_READ_FAILED.category(),
            OperationCategory::IO
        );
    }

    #[test]
    #[should_panic(expected = "Error code must be 001-999")]
    fn error_code_rejects_zero() {
        let _ = ErrorCode::new("TEST", 0, OperationCategory::Configuration);
    }

    #[test]
    #[should_panic(expected = "Error code must be 001-999")]
    fn error_code_rejects_1000() {
        let _ = ErrorCode::new("TEST", 1000, OperationCategory::Configuration);
    }

    #[test]
    #[should_panic(expected = "Namespace cannot be empty")]
    fn error_code_rejects_empty_namespace() {
        let _ = ErrorCode::new("", 100, OperationCategory::Configuration);
    }

    // ============================================================================
    // AgentError Construction Tests
    // ============================================================================

    #[test]
    fn basic_error_creation() {
        let err = AgentError::config(
            definitions::CFG_PARSE_FAILED,
            "test_operation",
            "test details"
        );

        assert_eq!(err.code(), definitions::CFG_PARSE_FAILED);
        assert_eq!(err.category(), OperationCategory::Configuration);
        assert!(!err.is_retryable());
    }

    #[test]
    fn error_with_retry_flag() {
        let err = AgentError::telemetry(
            definitions::TEL_CHANNEL_CLOSED,
            "watch",
            "Channel temporarily unavailable"
        ).with_retry();

        assert!(err.is_retryable());
    }

    #[test]
    fn error_with_metadata() {
        let err = AgentError::config(
            definitions::CFG_PARSE_FAILED,
            "parse",
            "Invalid YAML"
        )
        .with_metadata("file", "config.yaml")
        .with_metadata("line", "42");

        // Verify metadata is stored (check internal log)
        err.with_internal_log(|log| {
            assert_eq!(log.metadata().len(), 2);
        });
    }

    #[test]
    fn error_from_io_path() {
        let err = AgentError::from_io_path(
            definitions::IO_READ_FAILED,
            "read_config",
            "/etc/app/config.toml",
            io::Error::from(io::ErrorKind::NotFound)
        );

        // Should have split sources
        err.with_internal_log(|log| {
            assert!(log.source_internal().is_some());
            assert!(log.source_sensitive().is_some());
        });
    }

    // ============================================================================
    // Display and Debug Tests
    // ============================================================================

    #[test]
    fn external_display_format() {
        let err = AgentError::config(
            definitions::CFG_PARSE_FAILED,
            "parse_yaml",
            "Syntax error at line 42"
        );

        let displayed = format!("{}", err);
        
        // Should contain safe info
        assert!(displayed.contains("Configuration"));
        assert!(displayed.contains("operation failed"));
        assert!(displayed.contains("[permanent]"));
        assert!(displayed.contains("E-CFG-100"));

        // Should NOT contain details
        assert!(!displayed.contains("parse_yaml"));
        assert!(!displayed.contains("Syntax error"));
        assert!(!displayed.contains("42"));
    }

    #[test]
    fn external_display_retryable() {
        let err = AgentError::telemetry(
            definitions::TEL_CHANNEL_CLOSED,
            "watch",
            "Channel closed"
        ).with_retry();

        let displayed = format!("{}", err);
        assert!(displayed.contains("[temporary]"));
    }

    #[test]
    fn debug_format_redacts_context() {
        let err = AgentError::config_sensitive(
            definitions::CFG_PARSE_FAILED,
            "validate",
            "Invalid configuration",
            "/secret/path"
        );

        let debug = format!("{:?}", err);
        
        // Should show structure
        assert!(debug.contains("AgentError"));
        assert!(debug.contains("code"));
        
        // Should redact sensitive data
        assert!(debug.contains("<REDACTED>") || debug.contains("REDACTED"));
        assert!(!debug.contains("/secret/path"));
    }

    // ============================================================================
    // Internal Logging Tests
    // ============================================================================

    #[test]
    fn internal_log_contains_full_context() {
        let err = AgentError::config(
            definitions::CFG_PARSE_FAILED,
            "parse_yaml",
            "Syntax error at line 42"
        );

        err.with_internal_log(|log| {
            assert_eq!(log.code(), definitions::CFG_PARSE_FAILED);
            assert_eq!(log.operation(), "parse_yaml");
            assert_eq!(log.details(), "Syntax error at line 42");
            assert!(!log.is_retryable());
        });
    }

    #[test]
    fn internal_log_includes_metadata() {
        let err = AgentError::config(
            definitions::CFG_PARSE_FAILED,
            "parse",
            "Invalid"
        )
        .with_metadata("file", "test.yaml")
        .with_metadata("user_id", "12345");

        err.with_internal_log(|log| {
            let metadata = log.metadata();
            assert_eq!(metadata.len(), 2);
            
            // Check keys exist
            let keys: Vec<&str> = metadata.iter().map(|(k, _)| *k).collect();
            assert!(keys.contains(&"file"));
            assert!(keys.contains(&"user_id"));
        });
    }

    #[test]
    fn internal_log_write_to_buffer() {
        let err = AgentError::config(
            definitions::CFG_PARSE_FAILED,
            "test_op",
            "test details"
        );

        let mut buffer = String::new();
        err.with_internal_log(|log| {
            log.write_to(&mut buffer).unwrap();
        });

        assert!(buffer.contains("E-CFG-100"));
        assert!(buffer.contains("test_op"));
        assert!(buffer.contains("test details"));
    }

    // ============================================================================
    // Timing Tests
    // ============================================================================

    #[test]
    fn error_age_increases_over_time() {
        let err = AgentError::config(
            definitions::CFG_PARSE_FAILED,
            "test",
            "test"
        );

        let age1 = err.age();
        std::thread::sleep(Duration::from_millis(10));
        let age2 = err.age();

        assert!(age2 > age1);
    }

    #[test]
    fn timing_normalization_adds_delay() {
        use std::time::Instant;

        let start = Instant::now();
        let err = AgentError::config(
            definitions::CFG_PARSE_FAILED,
            "test",
            "test"
        );

        // Should delay to reach 50ms
        let _result = err.with_timing_normalization(Duration::from_millis(50));
        
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_millis(50));
        assert!(elapsed < Duration::from_millis(70)); // Allow some tolerance
    }

    #[test]
    fn timing_normalization_no_extra_delay_when_slow() {
        use std::time::Instant;

        let err = AgentError::config(
            definitions::CFG_PARSE_FAILED,
            "test",
            "test"
        );

        // Wait longer than target
        std::thread::sleep(Duration::from_millis(60));

        let start = Instant::now();
        let _result = err.with_timing_normalization(Duration::from_millis(50));
        let elapsed = start.elapsed();

        // Should return immediately (already past target)
        assert!(elapsed < Duration::from_millis(5));
    }

    // ============================================================================
    // Macro Tests
    // ============================================================================

    #[test]
    fn config_err_macro_basic() {
        let err = config_err!(
            definitions::CFG_PARSE_FAILED,
            "test_operation",
            "test details"
        );

        err.with_internal_log(|log| {
            assert_eq!(log.operation(), "test_operation");
            assert_eq!(log.details(), "test details");
        });
    }

    #[test]
    fn config_err_macro_with_format() {
        let line = 42;
        let err = config_err!(
            definitions::CFG_PARSE_FAILED,
            "parse",
            "Error at line {}",
            line
        );

        err.with_internal_log(|log| {
            assert_eq!(log.details(), "Error at line 42");
        });
    }

    // ============================================================================
    // Result Type Tests
    // ============================================================================

    #[test]
    fn result_type_ok() {
        fn test_function() -> Result<i32> {
            Ok(42)
        }

        assert_eq!(test_function().unwrap(), 42);
    }

    #[test]
    fn result_type_err() {
        fn test_function() -> Result<i32> {
            Err(AgentError::config(
                definitions::CFG_PARSE_FAILED,
                "test",
                "failed"
            ))
        }

        assert!(test_function().is_err());
    }

    #[test]
    fn result_type_propagation() {
        fn inner() -> Result<()> {
            Err(AgentError::config(
                definitions::CFG_PARSE_FAILED,
                "inner",
                "inner error"
            ))
        }

        fn outer() -> Result<()> {
            inner()?;
            Ok(())
        }

        let result = outer();
        assert!(result.is_err());
    }

    // ============================================================================
    // Error Source Tests
    // ============================================================================

    #[test]
    fn error_implements_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(
            AgentError::config(
                definitions::CFG_PARSE_FAILED,
                "test",
                "test"
            )
        );

        assert_eq!(err.to_string().contains("Configuration"), true);
    }

    // ============================================================================
    // Category Display Tests
    // ============================================================================

    #[test]
    fn category_display_names() {
        assert_eq!(OperationCategory::Configuration.display_name(), "Configuration");
        assert_eq!(OperationCategory::Deployment.display_name(), "Deployment");
        assert_eq!(OperationCategory::Monitoring.display_name(), "Monitoring");
        assert_eq!(OperationCategory::Analysis.display_name(), "Analysis");
        assert_eq!(OperationCategory::Response.display_name(), "Response");
        assert_eq!(OperationCategory::Audit.display_name(), "Audit");
        assert_eq!(OperationCategory::System.display_name(), "System");
        assert_eq!(OperationCategory::IO.display_name(), "I/O");
    }

    // ============================================================================
    // Error Code Range Tests
    // ============================================================================

    #[test]
    fn error_codes_in_valid_ranges() {
        use palisade_errors::definitions::ranges;

        // CORE range
        assert!(definitions::CORE_INIT_FAILED.code() >= ranges::CORE_START);
        assert!(definitions::CORE_INIT_FAILED.code() <= ranges::CORE_END);

        // CFG range
        assert!(definitions::CFG_PARSE_FAILED.code() >= ranges::CFG_START);
        assert!(definitions::CFG_PARSE_FAILED.code() <= ranges::CFG_END);

        // IO range
        assert!(definitions::IO_READ_FAILED.code() >= ranges::IO_START);
        assert!(definitions::IO_READ_FAILED.code() <= ranges::IO_END);
    }

    // ============================================================================
    // Clone and Copy Tests
    // ============================================================================

    #[test]
    fn error_code_is_copy() {
        let code1 = definitions::CFG_PARSE_FAILED;
        let code2 = code1; // Copy
        assert_eq!(code1, code2);
        assert_eq!(code1.to_string(), code2.to_string());
    }

    #[test]
    fn operation_category_is_copy() {
        let cat1 = OperationCategory::Configuration;
        let cat2 = cat1; // Copy
        assert_eq!(cat1, cat2);
    }

    // ============================================================================
    // Memory Layout Tests
    // ============================================================================

    #[test]
    fn error_size_reasonable() {
        use std::mem::size_of;

        let size = size_of::<AgentError>();
        
        // Should be less than 512 bytes (reasonable for error type)
        assert!(size < 512, "AgentError too large: {} bytes", size);
        
        println!("AgentError size: {} bytes", size);
    }
}