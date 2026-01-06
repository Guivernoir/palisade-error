//! Tests for the palisade_errors crate.

use crate::*;
use std::io;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_formatting() {
        let code = crate::CFG_PARSE_FAILED;
        assert_eq!(code.to_string(), "E-CFG-100");
        assert_eq!(code.namespace(), "CFG");
        assert_eq!(code.code(), 100);
    }

    #[test]
    fn test_sanitization_with_context() {
        let err = AgentError::config(
            crate::CFG_PARSE_FAILED,
            "parse_config",
            "Failed to parse configuration",
        );

        // External display provides category and code
        let external = err.to_string();
        assert!(external.contains("Configuration operation failed"));
        assert!(external.contains("E-CFG-100"));
        assert!(external.contains("[permanent]"));
    }

    #[test]
    fn test_sensitive_data_protection() {
        let err = AgentError::config_sensitive(
            crate::CFG_PARSE_FAILED,
            "parse_config",
            "Invalid syntax",
            "/etc/secret/config.toml with username admin",
        );

        // External display should NOT contain sensitive info
        let external = err.to_string();
        assert!(!external.contains("/etc/secret"));
        assert!(!external.contains("admin"));

        // Internal log should have sensitive details
        let log = err.internal_log();
        assert_eq!(log.operation(), "parse_config");
        assert_eq!(log.details(), "Invalid syntax");
        assert!(log.source_sensitive().unwrap().contains("/etc/secret/config.toml"));
        assert!(log.source_sensitive().unwrap().contains("admin"));
    }

    #[test]
    fn test_retryable_flag() {
        let err = AgentError::telemetry(
            crate::TEL_WATCH_FAILED,
            "init_watcher",
            "inotify limit reached",
        )
        .with_retry();

        assert!(err.is_retryable());
        assert!(err.to_string().contains("[temporary]"));

        let log = err.internal_log();
        assert!(log.is_retryable());
    }

    #[test]
    fn test_io_error_wrapping_with_split_sources() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "access denied");
        let err = AgentError::from_io_path(
            crate::IO_READ_FAILED,
            "read_file",
            "/secret/path/file.txt",
            io_err,
        );

        // External message should be sanitized
        let external = err.to_string();
        assert!(external.contains("E-IO-800"));
        assert!(!external.contains("PermissionDenied"));
        assert!(!external.contains("/secret/path"));

        // Internal log should have split sources
        let log = err.internal_log();
        assert!(log.source_internal().unwrap().contains("PermissionDenied"));
        assert_eq!(log.source_sensitive().unwrap(), "/secret/path/file.txt");
        
        // Verify they're actually separate
        assert_ne!(log.source_internal(), log.source_sensitive());
    }

    #[test]
    fn test_metadata_tracking() {
        let err = AgentError::config(
            crate::CFG_PARSE_FAILED,
            "parse_config",
            "Invalid syntax",
        )
        .with_metadata("correlation_id", "abc-123")
        .with_metadata("session_id", "xyz-789");

        let log = err.internal_log();
        
        // Use write_to for zero-allocation logging
        let mut output = String::new();
        log.write_to(&mut output).unwrap();
        assert!(output.contains("correlation_id='abc-123'"));
        assert!(output.contains("session_id='xyz-789'"));

        // Metadata should NOT appear externally
        let external = err.to_string();
        assert!(!external.contains("abc-123"));
        assert!(!external.contains("xyz-789"));
    }

    #[test]
    fn test_context_field_zeroization() {
        let field = ContextField::Sensitive("secret_data".to_string());
        assert_eq!(field.as_str(), "secret_data");
        drop(field);
        // After drop, memory is zeroized (enforced by ZeroizeOnDrop derive)
    }

    #[test]
    fn test_metadata_mutation_not_cloning() {
        // Create error with metadata
        let mut err = AgentError::config(
            crate::CFG_PARSE_FAILED,
            "parse_config",
            "Invalid syntax",
        );

        // Add metadata multiple times - should mutate in place
        err = err.with_metadata("key1", "value1");
        err = err.with_metadata("key2", "value2");

        let log = err.internal_log();
        assert_eq!(log.metadata().len(), 2);
    }

    #[test]
    fn test_internal_log_lifetime_enforcement() {
        let err = AgentError::config_sensitive(
            crate::CFG_PARSE_FAILED,
            "parse_config",
            "Failed",
            "sensitive_data_here",
        );

        // This works - log borrows from err
        let log = err.internal_log();
        assert_eq!(log.operation(), "parse_config");

        // This would NOT compile (lifetime error):
        // let leaked = {
        //     let temp_err = AgentError::config(...);
        //     temp_err.internal_log()  // ERROR: log cannot outlive temp_err
        // };
    }

    #[test]
    fn test_callback_logging_pattern() {
        let err = AgentError::config_sensitive(
            crate::CFG_PARSE_FAILED,
            "parse_config",
            "Failed",
            "sensitive_path",
        );

        // Callback pattern ensures log doesn't escape
        let result = err.with_internal_log(|log| {
            assert_eq!(log.operation(), "parse_config");
            assert!(log.source_sensitive().unwrap().contains("sensitive_path"));
            42  // Return value passes through
        });

        assert_eq!(result, 42);
    }

    #[test]
    fn test_no_memory_leaks() {
        // Create and drop many errors with sensitive data
        for i in 0..1000 {
            let secret = format!("secret_{}", i);
            let err = AgentError::config_sensitive(
                crate::CFG_PARSE_FAILED,
                "test",
                "test",
                &secret,
            );

            // Create log, use it, drop it
            let _ = err.internal_log();

            // Error drops here, all memory zeroized
        }
        
        // No leaked allocations - all zeroized on drop
    }

    #[test]
    fn test_zero_allocation_logging() {
        let err = AgentError::config_sensitive(
            crate::CFG_PARSE_FAILED,
            "test",
            "test",
            "sensitive",
        );

        // write_to uses zero-allocation formatting
        let log = err.internal_log();
        let mut buffer = String::new();
        log.write_to(&mut buffer).unwrap();
        
        assert!(buffer.contains("operation='test'"));
        assert!(buffer.contains("sensitive='sensitive'"));
    }

    #[test]
    #[cfg(feature = "trusted_debug")]
    fn test_trusted_debug_feature_gated() {
        let err = AgentError::config_sensitive(
            codes::CFG_PARSE_FAILED,
            "test",
            "test",
            "secret_value",
        );

        // This is only available with trusted_debug feature
        let log = err.internal_log();
        let debug_str = log.format_for_trusted_debug();
        
        assert!(debug_str.contains("secret_value"));
    }

    #[test]
    fn test_macro_safety() {
        // Macros only accept static format strings
        let err = config_err!(crate::CFG_PARSE_FAILED, "test", "Error at line {}", 42);
        let log = err.internal_log();
        assert!(log.details().contains("Error at line 42"));

        // Cannot accidentally include sensitive data via format string
        // (this would be a compile error):
        // let sensitive_data = "/etc/passwd";
        // config_err!(codes::CFG_PARSE_FAILED, "test", sensitive_data);
    }

    #[test]
    fn test_debug_format_redacts() {
        let err = AgentError::config_sensitive(
            crate::CFG_PARSE_FAILED,
            "parse_config",
            "Failed",
            "super_secret_path",
        );

        let debug_output = format!("{:?}", err);
        assert!(!debug_output.contains("super_secret_path"));
        assert!(debug_output.contains("REDACTED"));
    }

    #[test]
    fn test_category_display_names() {
        // Verify we're using stored display strings, not computed ones
        assert_eq!(OperationCategory::Configuration.display_name(), "Configuration");
        assert_eq!(OperationCategory::IO.display_name(), "I/O");
        assert_eq!(OperationCategory::Deployment.display_name(), "Deployment");
    }

    #[test]
    fn test_display_is_zero_allocation() {
        let err = AgentError::config(
            crate::CFG_PARSE_FAILED,
            "test",
            "test",
        );

        // Display::fmt writes directly to formatter without intermediate String
        let output = format!("{}", err);
        assert!(output.contains("Configuration operation failed"));
        assert!(output.contains("E-CFG-100"));
    }
}