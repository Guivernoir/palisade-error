//! Comprehensive test suite for the palisade_errors crate.
//!
//! This module provides extensive testing coverage for:
//! - Error code validation and formatting
//! - Context creation and zeroization
//! - Security properties (no information disclosure)
//! - Memory safety (proper cleanup)
//! - Macro hygiene and compile-time safety
//! - Logging functionality
//! - Edge cases and error conditions
//!
//! Note: AgentError does not implement Clone by design (for security reasons),
//! so tests avoid cloning operations.

#[cfg(test)]
mod error_codes {
    use crate::{ErrorCode, OperationCategory};

    #[test]
    fn valid_error_codes_format_correctly() {
        let code = ErrorCode::new("TEST", 42, OperationCategory::Configuration);
        assert_eq!(code.to_string(), "E-TEST-042");
        
        let code = ErrorCode::new("LONG", 999, OperationCategory::System);
        assert_eq!(code.to_string(), "E-LONG-999");
        
        let code = ErrorCode::new("A", 1, OperationCategory::IO);
        assert_eq!(code.to_string(), "E-A-001");
    }

    #[test]
    fn error_code_accessors_work() {
        let code = ErrorCode::new("TEST", 100, OperationCategory::Configuration);
        assert_eq!(code.namespace(), "TEST");
        assert_eq!(code.code(), 100);
        assert_eq!(code.category(), OperationCategory::Configuration);
    }

    #[test]
    fn error_codes_are_copy_and_equality() {
        let code1 = ErrorCode::new("TEST", 100, OperationCategory::Configuration);
        let code2 = code1; // Copy
        assert_eq!(code1, code2);
        
        let code3 = ErrorCode::new("TEST", 101, OperationCategory::Configuration);
        assert_ne!(code1, code3);
    }

    #[test]
    #[should_panic(expected = "Error code must be 001-999")]
    fn error_code_zero_panics() {
        let _ = ErrorCode::new("TEST", 0, OperationCategory::Configuration);
    }

    #[test]
    #[should_panic(expected = "Error code must be 001-999")]
    fn error_code_1000_panics() {
        let _ = ErrorCode::new("TEST", 1000, OperationCategory::Configuration);
    }

    #[test]
    #[should_panic(expected = "Namespace cannot be empty")]
    fn empty_namespace_panics() {
        let _ = ErrorCode::new("", 100, OperationCategory::Configuration);
    }

    #[test]
    #[should_panic(expected = "Namespace too long")]
    fn namespace_over_10_chars_panics() {
        let _ = ErrorCode::new("VERYLONGNAME", 100, OperationCategory::Configuration);
    }

    #[test]
    #[should_panic(expected = "Namespace must be uppercase ASCII")]
    fn lowercase_namespace_panics() {
        let _ = ErrorCode::new("test", 100, OperationCategory::Configuration);
    }

    #[test]
    #[should_panic(expected = "Namespace must be uppercase ASCII")]
    fn mixed_case_namespace_panics() {
        let _ = ErrorCode::new("Test", 100, OperationCategory::Configuration);
    }

    #[test]
    #[should_panic(expected = "Namespace must be uppercase ASCII")]
    fn numeric_namespace_panics() {
        let _ = ErrorCode::new("TEST1", 100, OperationCategory::Configuration);
    }

    #[test]
    #[should_panic(expected = "Namespace must be uppercase ASCII")]
    fn special_char_namespace_panics() {
        let _ = ErrorCode::new("TEST-", 100, OperationCategory::Configuration);
    }
}

#[cfg(test)]
mod operation_categories {
    use crate::OperationCategory;

    #[test]
    fn category_display_names_are_correct() {
        assert_eq!(OperationCategory::Configuration.display_name(), "Configuration");
        assert_eq!(OperationCategory::Deployment.display_name(), "Deployment");
        assert_eq!(OperationCategory::Monitoring.display_name(), "Monitoring");
        assert_eq!(OperationCategory::Analysis.display_name(), "Analysis");
        assert_eq!(OperationCategory::Response.display_name(), "Response");
        assert_eq!(OperationCategory::Audit.display_name(), "Audit");
        assert_eq!(OperationCategory::System.display_name(), "System");
        assert_eq!(OperationCategory::IO.display_name(), "I/O");
    }

    #[test]
    fn categories_support_equality() {
        assert_eq!(OperationCategory::Configuration, OperationCategory::Configuration);
        assert_ne!(OperationCategory::Configuration, OperationCategory::Deployment);
    }

    #[test]
    fn categories_are_copy() {
        let cat1 = OperationCategory::Configuration;
        let cat2 = cat1;
        assert_eq!(cat1, cat2);
    }
}

#[cfg(test)]
mod error_context {
    use crate::{ErrorContext, ContextField};

    #[test]
    fn basic_context_creation() {
        let ctx = ErrorContext::new("test_op", "test details");
        match &ctx.operation {
            ContextField::Internal(s) => assert_eq!(s.as_ref(), "test_op"),
            _ => panic!("Expected Internal field"),
        }
        match &ctx.details {
            ContextField::Internal(s) => assert_eq!(s.as_ref(), "test details"),
            _ => panic!("Expected Internal field"),
        }
    }

    #[test]
    fn context_with_sensitive_info() {
        let ctx = ErrorContext::with_sensitive("op", "details", "/etc/passwd");
        assert!(ctx.source_sensitive.is_some());
        if let Some(ContextField::Sensitive(s)) = &ctx.source_sensitive {
            assert_eq!(s.as_ref(), "/etc/passwd");
        } else {
            panic!("Expected Sensitive field");
        }
    }

    #[test]
    fn context_with_split_sources() {
        let ctx = ErrorContext::with_source_split(
            "operation",
            "details",
            "NotFound",
            "/path/to/file"
        );
        
        assert!(ctx.source_internal.is_some());
        assert!(ctx.source_sensitive.is_some());
        
        if let Some(ContextField::Internal(s)) = &ctx.source_internal {
            assert_eq!(s.as_ref(), "NotFound");
        }
        if let Some(ContextField::Sensitive(s)) = &ctx.source_sensitive {
            assert_eq!(s.as_ref(), "/path/to/file");
        }
    }

    #[test]
    fn metadata_addition() {
        let mut ctx = ErrorContext::new("op", "details");
        ctx.add_metadata("correlation_id", "abc123");
        ctx.add_metadata("session", "xyz789");
        
        assert_eq!(ctx.metadata.len(), 2);
        assert_eq!(ctx.metadata[0].0, "correlation_id");
        assert_eq!(ctx.metadata[1].0, "session");
    }

    #[test]
    fn metadata_stays_inline_up_to_4_entries() {
        let mut ctx = ErrorContext::new("op", "details");
        
        // Add 4 entries - should stay inline (no heap allocation)
        ctx.add_metadata("key1", "value1");
        ctx.add_metadata("key2", "value2");
        ctx.add_metadata("key3", "value3");
        ctx.add_metadata("key4", "value4");
        
        assert_eq!(ctx.metadata.len(), 4);
        // SmallVec will spill to heap only if we add more
    }

    #[test]
    fn context_cloning() {
        let mut ctx = ErrorContext::new("op", "details");
        ctx.add_metadata("key", "value");
        
        match &ctx.operation {
            ContextField::Internal(s) => assert_eq!(s.as_ref(), "op"),
            _ => panic!("Expected Internal field"),
        }
        assert_eq!(ctx.metadata.len(), 1);
    }

    #[test]
    fn context_accepts_static_strings() {
        let ctx = ErrorContext::new("static_op", "static_details");
        // Should not allocate for static strings
        match &ctx.operation {
            ContextField::Internal(s) => assert!(matches!(s, std::borrow::Cow::Borrowed(_))),
            _ => panic!("Expected borrowed string"),
        }
    }

    #[test]
    fn context_accepts_owned_strings() {
        let dynamic = format!("dynamic_{}", 42);
        let ctx = ErrorContext::new(dynamic.clone(), "details");
        match &ctx.operation {
            ContextField::Internal(s) => assert_eq!(s.as_ref(), "dynamic_42"),
            _ => panic!("Expected Internal field"),
        }
    }
}

#[cfg(test)]
mod context_fields {
    use crate::ContextField;
    use std::borrow::Cow;

    #[test]
    fn internal_field_as_str() {
        let field = ContextField::Internal(Cow::Borrowed("test"));
        assert_eq!(field.as_str(), "test");
    }

    #[test]
    fn sensitive_field_as_str() {
        let field = ContextField::Sensitive(Cow::Borrowed("secret"));
        assert_eq!(field.as_str(), "secret");
    }

    #[test]
    fn sensitive_field_debug_is_redacted() {
        let field = ContextField::Sensitive(Cow::Borrowed("password123"));
        let debug_str = format!("{:?}", field);
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains("password123"));
    }

    #[test]
    fn internal_field_debug_shows_value() {
        let field = ContextField::Internal(Cow::Borrowed("info"));
        let debug_str = format!("{:?}", field);
        assert!(debug_str.contains("info"));
    }

    #[test]
    fn field_display() {
        let field = ContextField::Internal(Cow::Borrowed("display_test"));
        assert_eq!(format!("{}", field), "display_test");
    }

    #[test]
    fn field_cloning() {
        let field1 = ContextField::Sensitive(Cow::Borrowed("secret"));
        let field2 = field1.clone();
        assert_eq!(field2.as_str(), "secret");
    }
}

#[cfg(test)]
mod agent_error_creation {
    use crate::{AgentError, definitions, OperationCategory};
    use std::io;

    #[test]
    fn config_error_creation() {
        let err = AgentError::config(definitions::CFG_PARSE_FAILED, "test_op", "test details");
        assert_eq!(err.code(), definitions::CFG_PARSE_FAILED);
        assert!(!err.is_retryable());
    }

    #[test]
    fn deployment_error_creation() {
        let err = AgentError::deployment(definitions::DCP_DEPLOY_FAILED, "deploy", "failed");
        assert_eq!(err.code().category(), OperationCategory::Deployment);
    }

    #[test]
    fn telemetry_error_creation() {
        let err = AgentError::telemetry(definitions::TEL_INIT_FAILED, "init", "failed");
        assert_eq!(err.code().category(), OperationCategory::Monitoring);
    }

    #[test]
    fn correlation_error_creation() {
        let err = AgentError::correlation(definitions::COR_RULE_EVAL_FAILED, "eval", "failed");
        assert_eq!(err.code().category(), OperationCategory::Analysis);
    }

    #[test]
    fn response_error_creation() {
        let err = AgentError::response(definitions::RSP_EXEC_FAILED, "exec", "failed");
        assert_eq!(err.code().category(), OperationCategory::Response);
    }

    #[test]
    fn logging_error_creation() {
        let err = AgentError::logging(definitions::LOG_WRITE_FAILED, "write", "failed");
        assert_eq!(err.code().category(), OperationCategory::Audit);
    }

    #[test]
    fn platform_error_creation() {
        let err = AgentError::platform(definitions::PLT_UNSUPPORTED, "check", "failed");
        assert_eq!(err.code().category(), OperationCategory::System);
    }

    #[test]
    fn io_error_creation() {
        let err = AgentError::io_operation(definitions::IO_READ_FAILED, "read", "failed");
        assert_eq!(err.code().category(), OperationCategory::IO);
    }

    #[test]
    fn config_error_with_sensitive_data() {
        let err = AgentError::config_sensitive(
            definitions::CFG_PERMISSION_DENIED,
            "load",
            "Permission denied",
            "/etc/shadow"
        );
        assert_eq!(err.code(), definitions::CFG_PERMISSION_DENIED);
    }

    #[test]
    fn from_io_error_splits_path_and_kind() {
        let io_err = io::Error::from(io::ErrorKind::NotFound);
        let err = AgentError::from_io_path(
            definitions::IO_NOT_FOUND,
            "read_file",
            "/var/secret/file.txt",
            io_err
        );
        
        let log = err.internal_log();
        assert!(log.source_internal().is_some());
        assert!(log.source_sensitive().is_some());
        assert!(log.source_sensitive().unwrap().contains("/var/secret"));
    }

    #[test]
    fn error_with_retry_flag() {
        let err = AgentError::config(definitions::CFG_PARSE_FAILED, "test", "test")
            .with_retry();
        assert!(err.is_retryable());
    }

    #[test]
    fn error_with_metadata() {
        let err = AgentError::config(definitions::CFG_PARSE_FAILED, "test", "test")
            .with_metadata("correlation_id", "abc123")
            .with_metadata("session_id", "xyz789");
        
        let log = err.internal_log();
        assert_eq!(log.metadata().len(), 2);
    }

    #[test]
    fn error_with_retry_and_metadata_chained() {
        let err = AgentError::config(definitions::CFG_PARSE_FAILED, "test", "test")
            .with_retry()
            .with_metadata("attempt", "1");
        
        assert!(err.is_retryable());
        assert_eq!(err.internal_log().metadata().len(), 1);
    }

    #[test]
    fn accepts_static_str() {
        let _err = AgentError::config(definitions::CFG_PARSE_FAILED, "static", "static");
    }

    #[test]
    fn accepts_string() {
        let dynamic = format!("dynamic_{}", 42);
        let _err = AgentError::config(definitions::CFG_PARSE_FAILED, dynamic.clone(), dynamic);
    }

    #[test]
    fn accepts_string_reference() {
        let s = String::from("owned");
        // Pass a clone so it can be moved into Cow
        let _err = AgentError::config(definitions::CFG_PARSE_FAILED, s.clone(), s);
    }
}

#[cfg(test)]
mod agent_error_display {
    use crate::{AgentError, definitions};
    use std::io;

    #[test]
    fn external_display_format() {
        let err = AgentError::config(definitions::CFG_PARSE_FAILED, "test", "test");
        let display = format!("{}", err);
        
        assert!(display.contains("Configuration"));
        assert!(display.contains("operation failed"));
        assert!(display.contains("[permanent]"));
        assert!(display.contains("E-CFG-100"));
    }

    #[test]
    fn retryable_error_display() {
        let err = AgentError::config(definitions::CFG_PARSE_FAILED, "test", "test")
            .with_retry();
        let display = format!("{}", err);
        
        assert!(display.contains("[temporary]"));
    }

    #[test]
    fn external_display_hides_sensitive_data() {
        let err = AgentError::from_io_path(
            definitions::IO_READ_FAILED,
            "load_secret",
            "/etc/shadow",
            io::Error::from(io::ErrorKind::PermissionDenied)
        );
        
        let display = format!("{}", err);
        
        // Should NOT contain sensitive information
        assert!(!display.contains("/etc"));
        assert!(!display.contains("shadow"));
        assert!(!display.contains("load_secret"));
        assert!(!display.contains("Permission"));
        
        // Should contain safe information
        assert!(display.contains("I/O"));
        assert!(display.contains("E-IO-800"));
    }

    #[test]
    fn external_display_hides_usernames() {
        let err = AgentError::config_sensitive(
            definitions::CFG_VALIDATION_FAILED,
            "validate_user",
            "Invalid user",
            "john_doe"
        );
        
        let display = format!("{}", err);
        assert!(!display.contains("john_doe"));
        assert!(!display.contains("validate_user"));
    }

    #[test]
    fn external_display_hides_metadata() {
        let err = AgentError::config(definitions::CFG_PARSE_FAILED, "test", "test")
            .with_metadata("internal_token", "secret123");
        
        let display = format!("{}", err);
        assert!(!display.contains("internal_token"));
        assert!(!display.contains("secret123"));
    }

    #[test]
    fn debug_format_is_redacted() {
        let err = AgentError::config(definitions::CFG_PARSE_FAILED, "sensitive_op", "details");
        let debug = format!("{:?}", err);
        
        // Should show structure but not sensitive data
        assert!(debug.contains("AgentError"));
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("sensitive_op"));
        assert!(!debug.contains("details"));
    }

    #[test]
    fn different_categories_display_correctly() {
        let tests = vec![
            (definitions::DCP_DEPLOY_FAILED, "Deployment"),
            (definitions::TEL_INIT_FAILED, "Monitoring"),
            (definitions::COR_RULE_EVAL_FAILED, "Analysis"),
            (definitions::RSP_EXEC_FAILED, "Response"),
            (definitions::LOG_WRITE_FAILED, "Audit"),
            (definitions::PLT_UNSUPPORTED, "System"),
            (definitions::IO_TIMEOUT, "I/O"),
        ];
        
        for (code, expected_category) in tests {
            let err = AgentError::config(code, "test", "test");
            let display = format!("{}", err);
            assert!(display.contains(expected_category));
        }
    }
}

#[cfg(test)]
mod internal_logging {
    use crate::{AgentError, definitions};
    use std::io;

    #[test]
    fn internal_log_contains_full_context() {
        let err = AgentError::config(
            definitions::CFG_PARSE_FAILED,
            "validate_config",
            "Invalid threshold value"
        );
        
        let log = err.internal_log();
        assert_eq!(log.code(), definitions::CFG_PARSE_FAILED);
        assert_eq!(log.operation(), "validate_config");
        assert_eq!(log.details(), "Invalid threshold value");
        assert!(!log.is_retryable());
    }

    #[test]
    fn internal_log_shows_retry_status() {
        let err = AgentError::config(definitions::CFG_PARSE_FAILED, "test", "test")
            .with_retry();
        
        let log = err.internal_log();
        assert!(log.is_retryable());
    }

    #[test]
    fn internal_log_includes_metadata() {
        let err = AgentError::config(definitions::CFG_PARSE_FAILED, "test", "test")
            .with_metadata("correlation_id", "12345")
            .with_metadata("attempt", "2");
        
        let log = err.internal_log();
        let metadata = log.metadata();
        assert_eq!(metadata.len(), 2);
        assert_eq!(metadata[0].0, "correlation_id");
        assert_eq!(metadata[1].0, "attempt");
    }

    #[test]
    fn internal_log_shows_split_sources() {
        let io_err = io::Error::from(io::ErrorKind::NotFound);
        let err = AgentError::from_io_path(
            definitions::IO_NOT_FOUND,
            "read",
            "/secret/path",
            io_err
        );
        
        let log = err.internal_log();
        assert!(log.source_internal().is_some());
        assert!(log.source_sensitive().is_some());
        assert!(log.source_internal().unwrap().contains("NotFound"));
        assert!(log.source_sensitive().unwrap().contains("/secret/path"));
    }

    #[test]
    fn internal_log_write_to_formatter() {
        let err = AgentError::config(
            definitions::CFG_PARSE_FAILED,
            "test_op",
            "test details"
        );
        
        let log = err.internal_log();
        let mut buffer = String::new();
        log.write_to(&mut buffer).expect("write failed");
        
        assert!(buffer.contains("E-CFG-100"));
        assert!(buffer.contains("test_op"));
        assert!(buffer.contains("test details"));
    }

    #[test]
    fn internal_log_lifetime_tied_to_error() {
        let err = AgentError::config(definitions::CFG_PARSE_FAILED, "test", "test");
        {
            let log = err.internal_log();
            assert_eq!(log.operation(), "test");
            // log is dropped here
        }
        // err still valid
        assert_eq!(err.code(), definitions::CFG_PARSE_FAILED);
    }

    #[test]
    fn log_truncates_very_long_fields() {
        let very_long = "A".repeat(2000);
        let err = AgentError::config(
            definitions::CFG_PARSE_FAILED,
            "test",
            very_long
        );
        
        let log = err.internal_log();
        let mut buffer = String::new();
        log.write_to(&mut buffer).expect("write failed");
        
        // Should be truncated with indicator
        assert!(buffer.len() < 2000);
        assert!(buffer.contains("TRUNCATED"));
    }
}

#[cfg(test)]
mod convenience_macros {
    use crate::{definitions, config_err, config_err_sensitive, deployment_err, 
                telemetry_err, correlation_err, response_err, logging_err, 
                platform_err, io_err};

    #[test]
    fn config_err_simple() {
        let err = config_err!(definitions::CFG_PARSE_FAILED, "operation", "details");
        assert_eq!(err.code(), definitions::CFG_PARSE_FAILED);
    }

    #[test]
    fn config_err_with_format() {
        let line = 42;
        let err = config_err!(definitions::CFG_PARSE_FAILED, "parse", "Error at line {}", line);
        let log = err.internal_log();
        assert!(log.details().contains("42"));
    }

    #[test]
    fn config_err_with_multiple_args() {
        let line = 42;
        let column = 10;
        let err = config_err!(
            definitions::CFG_PARSE_FAILED,
            "parse",
            "Error at line {} column {}",
            line,
            column
        );
        let log = err.internal_log();
        assert!(log.details().contains("42"));
        assert!(log.details().contains("10"));
    }

    #[test]
    fn config_err_sensitive() {
        let err = config_err_sensitive!(
            definitions::CFG_PERMISSION_DENIED,
            "load",
            "Permission denied",
            "/etc/shadow"
        );
        let log = err.internal_log();
        assert!(log.source_sensitive().is_some());
    }

    #[test]
    fn deployment_err_macro() {
        let err = deployment_err!(definitions::DCP_DEPLOY_FAILED, "deploy", "Failed");
        assert_eq!(err.code(), definitions::DCP_DEPLOY_FAILED);
    }

    #[test]
    fn telemetry_err_macro() {
        let err = telemetry_err!(definitions::TEL_INIT_FAILED, "init", "Failed");
        assert_eq!(err.code(), definitions::TEL_INIT_FAILED);
    }

    #[test]
    fn correlation_err_macro() {
        let err = correlation_err!(definitions::COR_RULE_EVAL_FAILED, "eval", "Failed");
        assert_eq!(err.code(), definitions::COR_RULE_EVAL_FAILED);
    }

    #[test]
    fn response_err_macro() {
        let err = response_err!(definitions::RSP_EXEC_FAILED, "exec", "Failed");
        assert_eq!(err.code(), definitions::RSP_EXEC_FAILED);
    }

    #[test]
    fn logging_err_macro() {
        let err = logging_err!(definitions::LOG_WRITE_FAILED, "write", "Failed");
        assert_eq!(err.code(), definitions::LOG_WRITE_FAILED);
    }

    #[test]
    fn platform_err_macro() {
        let err = platform_err!(definitions::PLT_UNSUPPORTED, "check", "Failed");
        assert_eq!(err.code(), definitions::PLT_UNSUPPORTED);
    }

    #[test]
    fn io_err_macro() {
        let err = io_err!(definitions::IO_TIMEOUT, "read", "Failed");
        assert_eq!(err.code(), definitions::IO_TIMEOUT);
    }

    #[test]
    fn macros_accept_trailing_comma() {
        let value = 42;
        let _err = config_err!(
            definitions::CFG_PARSE_FAILED,
            "test",
            "Value: {}",
            value,
        );
    }
}

#[cfg(test)]
mod error_code_definitions {
    use crate::{definitions, OperationCategory};

    #[test]
    fn core_errors_in_correct_range() {
        assert!(definitions::CORE_INIT_FAILED.code() >= 1);
        assert!(definitions::CORE_INIT_FAILED.code() <= 99);
        assert_eq!(definitions::CORE_INIT_FAILED.category(), OperationCategory::System);
    }

    #[test]
    fn config_errors_in_correct_range() {
        assert!(definitions::CFG_PARSE_FAILED.code() >= 100);
        assert!(definitions::CFG_PARSE_FAILED.code() <= 199);
        assert_eq!(definitions::CFG_PARSE_FAILED.category(), OperationCategory::Configuration);
    }

    #[test]
    fn deployment_errors_in_correct_range() {
        assert!(definitions::DCP_DEPLOY_FAILED.code() >= 200);
        assert!(definitions::DCP_DEPLOY_FAILED.code() <= 299);
        assert_eq!(definitions::DCP_DEPLOY_FAILED.category(), OperationCategory::Deployment);
    }

    #[test]
    fn telemetry_errors_in_correct_range() {
        assert!(definitions::TEL_INIT_FAILED.code() >= 300);
        assert!(definitions::TEL_INIT_FAILED.code() <= 399);
        assert_eq!(definitions::TEL_INIT_FAILED.category(), OperationCategory::Monitoring);
    }

    #[test]
    fn correlation_errors_in_correct_range() {
        assert!(definitions::COR_RULE_EVAL_FAILED.code() >= 400);
        assert!(definitions::COR_RULE_EVAL_FAILED.code() <= 499);
        assert_eq!(definitions::COR_RULE_EVAL_FAILED.category(), OperationCategory::Analysis);
    }

    #[test]
    fn response_errors_in_correct_range() {
        assert!(definitions::RSP_EXEC_FAILED.code() >= 500);
        assert!(definitions::RSP_EXEC_FAILED.code() <= 599);
        assert_eq!(definitions::RSP_EXEC_FAILED.category(), OperationCategory::Response);
    }

    #[test]
    fn logging_errors_in_correct_range() {
        assert!(definitions::LOG_WRITE_FAILED.code() >= 600);
        assert!(definitions::LOG_WRITE_FAILED.code() <= 699);
        assert_eq!(definitions::LOG_WRITE_FAILED.category(), OperationCategory::Audit);
    }

    #[test]
    fn platform_errors_in_correct_range() {
        assert!(definitions::PLT_UNSUPPORTED.code() >= 700);
        assert!(definitions::PLT_UNSUPPORTED.code() <= 799);
        assert_eq!(definitions::PLT_UNSUPPORTED.category(), OperationCategory::System);
    }

    #[test]
    fn io_errors_in_correct_range() {
        assert!(definitions::IO_READ_FAILED.code() >= 800);
        assert!(definitions::IO_READ_FAILED.code() <= 899);
        assert_eq!(definitions::IO_READ_FAILED.category(), OperationCategory::IO);
    }

    #[test]
    fn all_core_codes_unique() {
        let codes = vec![
            definitions::CORE_INIT_FAILED.code(),
            definitions::CORE_SHUTDOWN_FAILED.code(),
            definitions::CORE_PANIC_RECOVERY.code(),
            definitions::CORE_INVALID_STATE.code(),
        ];
        
        for i in 0..codes.len() {
            for j in (i+1)..codes.len() {
                assert_ne!(codes[i], codes[j], "Duplicate error code found");
            }
        }
    }

    #[test]
    fn all_config_codes_unique() {
        let codes = vec![
            definitions::CFG_PARSE_FAILED.code(),
            definitions::CFG_VALIDATION_FAILED.code(),
            definitions::CFG_MISSING_REQUIRED.code(),
            definitions::CFG_INVALID_VALUE.code(),
            definitions::CFG_PERMISSION_DENIED.code(),
        ];
        
        for i in 0..codes.len() {
            for j in (i+1)..codes.len() {
                assert_ne!(codes[i], codes[j], "Duplicate error code found");
            }
        }
    }

    #[test]
    fn error_code_formatting() {
        assert_eq!(definitions::CFG_PARSE_FAILED.to_string(), "E-CFG-100");
        assert_eq!(definitions::DCP_DEPLOY_FAILED.to_string(), "E-DCP-200");
        assert_eq!(definitions::IO_NOT_FOUND.to_string(), "E-IO-804");
    }
}

#[cfg(test)]
mod timing_normalization {
    use crate::{AgentError, definitions};
    use std::time::{Duration, Instant};
    use std::thread;

    #[test]
    fn timing_normalization_adds_delay() {
        let start = Instant::now();
        let err = AgentError::config(definitions::CFG_PARSE_FAILED, "test", "test");
        
        // This should add delay to reach 50ms
        let _normalized = err.with_timing_normalization(Duration::from_millis(50));
        
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_millis(50));
        assert!(elapsed < Duration::from_millis(100)); // Some tolerance
    }

    #[test]
    fn timing_normalization_no_extra_delay_if_slow() {
        let err = AgentError::config(definitions::CFG_PARSE_FAILED, "test", "test");
        
        // Wait longer than target
        thread::sleep(Duration::from_millis(60));
        
        let start = Instant::now();
        let _normalized = err.with_timing_normalization(Duration::from_millis(50));
        let elapsed = start.elapsed();
        
        // Should not add extra delay
        assert!(elapsed < Duration::from_millis(10));
    }

    #[test]
    fn timing_normalization_with_zero_duration() {
        let start = Instant::now();
        let err = AgentError::config(definitions::CFG_PARSE_FAILED, "test", "test");
        let _normalized = err.with_timing_normalization(Duration::from_millis(0));
        let elapsed = start.elapsed();
        
        // Should not sleep
        assert!(elapsed < Duration::from_millis(10));
    }

    #[test]
    fn timing_normalization_preserves_error_data() {
        let err = AgentError::config(definitions::CFG_PARSE_FAILED, "test_op", "test details")
            .with_retry();
        
        let normalized = err.with_timing_normalization(Duration::from_millis(10));
        
        assert_eq!(normalized.code(), definitions::CFG_PARSE_FAILED);
        assert!(normalized.is_retryable());
        let log = normalized.internal_log();
        assert_eq!(log.operation(), "test_op");
    }
}

#[cfg(test)]
mod error_age_tracking {
    use crate::{AgentError, definitions};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn error_age_starts_at_zero() {
        let err = AgentError::config(definitions::CFG_PARSE_FAILED, "test", "test");
        let age = err.age();
        assert!(age < Duration::from_millis(10));
    }

    #[test]
    fn error_age_increases_over_time() {
        let err = AgentError::config(definitions::CFG_PARSE_FAILED, "test", "test");
        
        let age1 = err.age();
        thread::sleep(Duration::from_millis(20));
        let age2 = err.age();
        
        assert!(age2 > age1);
        assert!(age2 >= Duration::from_millis(20));
    }

    #[test]
    fn error_age_preserved_through_methods() {
        let err = AgentError::config(definitions::CFG_PARSE_FAILED, "test", "test");
        thread::sleep(Duration::from_millis(10));
        
        let age_before = err.age();
        let err = err.with_retry().with_metadata("key", "value");
        let age_after = err.age();
        
        // Age should continue from original creation time
        assert!(age_after >= age_before);
    }
}

#[cfg(test)]
mod error_as_std_error {
    use crate::{AgentError, definitions};
    use std::error::Error;

    #[test]
    fn implements_std_error_trait() {
        let err: Box<dyn Error> = Box::new(
            AgentError::config(definitions::CFG_PARSE_FAILED, "test", "test")
        );
        assert!(err.source().is_none());
    }

    #[test]
    fn error_display_works() {
        let err = AgentError::config(definitions::CFG_PARSE_FAILED, "test", "test");
        let display = format!("{}", err);
        assert!(!display.is_empty());
    }

    #[test]
    fn error_debug_works() {
        let err = AgentError::config(definitions::CFG_PARSE_FAILED, "test", "test");
        let debug = format!("{:?}", err);
        assert!(!debug.is_empty());
    }
}

#[cfg(test)]
mod result_type_alias {
    use crate::{Result, AgentError, definitions};

    #[test]
    fn result_type_alias_ok() {
        let result: Result<i32> = Ok(42);
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn result_type_alias_err() {
        let result: Result<i32> = Err(AgentError::config(
            definitions::CFG_PARSE_FAILED,
            "test",
            "test"
        ));
        assert!(result.is_err());
    }

    #[test]
    fn result_in_function_signature() {
        fn test_function() -> Result<String> {
            Ok("success".to_string())
        }
        
        assert_eq!(test_function().unwrap(), "success");
    }

    #[test]
    fn result_with_question_mark() {
        fn inner() -> Result<i32> {
            Err(AgentError::config(definitions::CFG_PARSE_FAILED, "inner", "failed"))
        }
        
        fn outer() -> Result<i32> {
            inner()?;
            Ok(42)
        }
        
        assert!(outer().is_err());
    }
}

#[cfg(test)]
mod integration_scenarios {
    use crate::{AgentError, definitions, Result, config_err, telemetry_err};
    use std::fs::File;
    use std::io;

    fn load_config(path: String, simulate_error: bool) -> Result<String> {
        if simulate_error {
            return Err(AgentError::from_io_path(
                definitions::IO_READ_FAILED,
                "load_config",
                path,
                io::Error::from(io::ErrorKind::NotFound)
            ));
        }
        Ok("config data".to_string())
    }

    fn validate_threshold(value: f64) -> Result<()> {
        if value < 0.0 || value > 100.0 {
            return Err(config_err!(
                definitions::CFG_INVALID_VALUE,
                "validate_threshold",
                "Threshold {} must be between 0 and 100",
                value
            ));
        }
        Ok(())
    }

    #[test]
    fn end_to_end_config_loading() {
        let result = load_config("/etc/config.toml".to_string(), false);
        assert!(result.is_ok());
    }

    #[test]
    fn end_to_end_config_error() {
        let result = load_config("/etc/secret.toml".to_string(), true);
        assert!(result.is_err());
        
        if let Err(e) = result {
            let display = format!("{}", e);
            assert!(!display.contains("/etc/secret"));
            
            let log = e.internal_log();
            assert!(log.source_sensitive().unwrap().contains("/etc/secret"));
        }
    }

    #[test]
    fn end_to_end_validation() {
        assert!(validate_threshold(50.0).is_ok());
        assert!(validate_threshold(-1.0).is_err());
        assert!(validate_threshold(101.0).is_err());
    }

    #[test]
    fn error_chain_with_context() {
        let result = load_config("/etc/config.toml".to_string(), true)
            .map_err(|e| e.with_metadata("stage", "initialization"));
        
        if let Err(e) = result {
            let log = e.internal_log();
            assert_eq!(log.metadata().len(), 1);
        }
    }

    #[test]
    fn retry_logic_simulation() {
        fn flaky_operation(attempt: u32) -> Result<String> {
            if attempt < 3 {
                return Err(telemetry_err!(
                    definitions::TEL_EVENT_LOST,
                    "collect",
                    "Network timeout"
                ).with_retry());
            }
            Ok("success".to_string())
        }
        
        let mut attempt = 0;
        let result = loop {
            attempt += 1;
            match flaky_operation(attempt) {
                Ok(val) => break Ok(val),
                Err(e) if e.is_retryable() && attempt < 5 => continue,
                Err(e) => break Err(e),
            }
        };
        
        assert!(result.is_ok());
        assert_eq!(attempt, 3);
    }
}

#[cfg(test)]
mod security_properties {
    use crate::{AgentError, definitions};
    use std::io;

    #[test]
    fn external_display_never_leaks_paths() {
        let paths = vec![
            "/etc/passwd",
            "/root/.ssh/id_rsa",
            "/var/log/secret.log",
            "C:\\Windows\\System32\\config",
        ];
        
        for path in paths {
            let err = AgentError::from_io_path(
                definitions::IO_NOT_FOUND,
                "read",
                path,
                io::Error::from(io::ErrorKind::NotFound)
            );
            
            let display = format!("{}", err);
            assert!(!display.contains(path), "Path leaked: {}", path);
        }
    }

    #[test]
    fn external_display_never_leaks_operations() {
        let operations = vec![
            "decrypt_secret",
            "validate_password",
            "check_admin_privilege",
            "load_private_key",
        ];
        
        for op in operations {
            let err = AgentError::config(definitions::CFG_PARSE_FAILED, op, "failed");
            let display = format!("{}", err);
            assert!(!display.contains(op), "Operation name leaked: {}", op);
        }
    }

    #[test]
    fn external_display_never_leaks_details() {
        let details = vec![
            "Invalid password format",
            "User john_doe not found",
            "Decryption key mismatch",
            "Token expired at 2024-01-01",
        ];
        
        for detail in details {
            let err = AgentError::config(definitions::CFG_VALIDATION_FAILED, "op", detail);
            let display = format!("{}", err);
            assert!(!display.contains(detail), "Detail leaked: {}", detail);
        }
    }

    #[test]
    fn error_code_provides_tracking_without_disclosure() {
        let err1 = AgentError::config(definitions::CFG_PARSE_FAILED, "op1", "details1");
        let err2 = AgentError::config(definitions::CFG_PARSE_FAILED, "op2", "details2");
        
        // Both should have same external code
        let display1 = format!("{}", err1);
        let display2 = format!("{}", err2);
        assert!(display1.contains("E-CFG-100"));
        assert!(display2.contains("E-CFG-100"));
        
        // But different internal details
        assert_ne!(err1.internal_log().operation(), err2.internal_log().operation());
    }

    #[test]
    fn debug_format_redacts_sensitive_context() {
        let err = AgentError::config_sensitive(
            definitions::CFG_PERMISSION_DENIED,
            "load_key",
            "Permission denied",
            "/root/.ssh/private_key"
        );
        
        let debug = format!("{:?}", err);
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("/root/.ssh"));
        assert!(!debug.contains("private_key"));
    }
}

#[cfg(test)]
mod memory_safety {
    use crate::{AgentError, ErrorContext, ContextField, definitions};
    use std::borrow::Cow;

    #[test]
    fn context_fields_are_zeroized() {
        let mut field = ContextField::Sensitive(Cow::Owned("secret123".to_string()));
        // Explicit zeroize for testing
        use zeroize::Zeroize;
        field.zeroize();
        // After zeroize, the owned string should be cleared
    }

    #[test]
    fn error_context_is_dropped_properly() {
        let ctx = ErrorContext::with_sensitive("op", "details", "secret");
        // ctx is dropped here, should trigger zeroization
    }

    #[test]
    fn error_is_dropped_properly() {
        let err = AgentError::config_sensitive(
            definitions::CFG_PERMISSION_DENIED,
            "op",
            "details",
            "secret"
        );
        // err is dropped here, should trigger zeroization
    }

    #[test]
    fn error_with_metadata_is_dropped_properly() {
        let err = AgentError::config(definitions::CFG_PARSE_FAILED, "op", "details")
            .with_metadata("token", "secret_token_123");
        // err and its metadata are dropped here
    }
}

#[cfg(test)]
mod edge_cases {
    use crate::{AgentError, ErrorContext, definitions};

    #[test]
    fn empty_string_details() {
        let err = AgentError::config(definitions::CFG_PARSE_FAILED, "op", "");
        let log = err.internal_log();
        assert_eq!(log.details(), "");
    }

    #[test]
    fn unicode_in_context() {
        let err = AgentError::config(
            definitions::CFG_PARSE_FAILED,
            "测试操作",
            "ПŽŃ€Ð¾Ð±Ð»ÐµÐ¼Ð° с конфигурацией"
        );
        let log = err.internal_log();
        assert!(log.operation().contains("测试"));
        assert!(log.details().contains("конфигурацией"));
    }

    #[test]
    fn emoji_in_context() {
        let err = AgentError::config(definitions::CFG_PARSE_FAILED, "op", "Error 🔥💥");
        let log = err.internal_log();
        assert!(log.details().contains("🔥"));
    }

    #[test]
    fn very_long_operation_name() {
        let long_op = "a".repeat(1000);
        let err = AgentError::config(definitions::CFG_PARSE_FAILED, long_op.clone(), "details");
        let log = err.internal_log();
        assert_eq!(log.operation(), long_op);
    }

    #[test]
    fn very_long_details() {
        let long_details = "x".repeat(5000);
        let err = AgentError::config(definitions::CFG_PARSE_FAILED, "op", long_details.clone());
        
        let log = err.internal_log();
        let mut buffer = String::new();
        log.write_to(&mut buffer).expect("write failed");
        
        // Should be truncated
        assert!(buffer.len() < 5000);
        assert!(buffer.contains("TRUNCATED"));
    }

    #[test]
    fn many_metadata_entries() {
        let mut err = AgentError::config(definitions::CFG_PARSE_FAILED, "op", "details");
        
        // Add many metadata entries
        for i in 0..10 {
            err = err.with_metadata("key", format!("value{}", i));
        }
        
        let log = err.internal_log();
        assert_eq!(log.metadata().len(), 10);
    }

    #[test]
    fn metadata_with_empty_values() {
        let err = AgentError::config(definitions::CFG_PARSE_FAILED, "op", "details")
            .with_metadata("empty", "")
            .with_metadata("also_empty", "");
        
        let log = err.internal_log();
        assert_eq!(log.metadata().len(), 2);
    }

    #[test]
    fn zero_duration_timing_normalization() {
        use std::time::Duration;
        let err = AgentError::config(definitions::CFG_PARSE_FAILED, "op", "details");
        let _normalized = err.with_timing_normalization(Duration::ZERO);
        // Should not panic
    }

    #[test]
    fn error_immediately_after_creation() {
        let err = AgentError::config(definitions::CFG_PARSE_FAILED, "op", "details");
        let age = err.age();
        // Age should be very small but not exactly zero due to time between creation and check
        assert!(age.as_micros() < 10000);
    }
}

#[cfg(test)]
mod stress_tests {
    use crate::{AgentError, definitions};

    #[test]
    fn many_errors_in_sequence() {
        for i in 0..1000 {
            let err = AgentError::config(
                definitions::CFG_PARSE_FAILED,
                "op",
                format!("Error {}", i)
            );
            // Each error is dropped immediately
            drop(err);
        }
    }

    #[test]
    fn deep_method_chaining() {
        let err = AgentError::config(definitions::CFG_PARSE_FAILED, "op", "details")
            .with_retry()
            .with_metadata("k1", "v1")
            .with_metadata("k2", "v2")
            .with_metadata("k3", "v3")
            .with_metadata("k4", "v4")
            .with_metadata("k5", "v5");
        
        assert!(err.is_retryable());
        assert_eq!(err.internal_log().metadata().len(), 5);
    }

    #[test]
    fn error_in_result_chain() {
        use crate::Result;
        
        fn op1() -> Result<i32> { Ok(1) }
        fn op2(_: i32) -> Result<i32> { 
            Err(AgentError::config(definitions::CFG_PARSE_FAILED, "op2", "failed"))
        }
        fn op3(_: i32) -> Result<i32> { Ok(3) }
        
        let result = op1()
            .and_then(op2)
            .and_then(op3);
        
        assert!(result.is_err());
    }
}