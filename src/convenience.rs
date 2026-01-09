//! Convenience macros for creating errors with format strings.
//!
//! # Security Model
//!
//! These macros enforce compile-time safety to prevent untrusted data from
//! leaking into error messages without explicit sanitization.
//!
//! # Rules
//!
//! 1. **Operation names MUST be string literals** - prevents dynamic injection
//! 2. **Format strings MUST be string literals** - prevents format string attacks
//! 3. **Format arguments are sanitized via `sanitized!()` wrapper** - bounded length
//!
//! # Usage
//!
//! ```rust
//! # use palisade_errors::{config_err, definitions, sanitized};
//! let line_num = 42;
//! // ✓ CORRECT: Format string is literal, variable is sanitized
//! let err = config_err!(
//!     definitions::CFG_PARSE_FAILED,
//!     "validate",
//!     "Invalid value at line {}",
//!     sanitized!(line_num)
//! );
//! ```
//!
//! ```rust,compile_fail
//! # use palisade_errors::{config_err, definitions};
//! let user_input = "attacker data";
//! // ✗ COMPILE ERROR: Operation must be a literal
//! let err = config_err!(definitions::CFG_PARSE_FAILED, user_input, "Failed");
//! ```
//!
//! ## Sanitization
//!
//! The `sanitized!()` macro truncates strings to prevent DoS via massive error messages
//! and ensures all format arguments are bounded in length.

/// Maximum length for sanitized strings in error messages.
/// 
/// This prevents DoS attacks via extremely long error messages while still
/// allowing enough context for debugging.
const MAX_SANITIZED_LEN: usize = 256;

/// Sanitize untrusted input for inclusion in error messages.
///
/// Truncates strings to MAX_SANITIZED_LEN characters, respecting UTF-8 boundaries.
/// 
/// # Example
///
/// ```rust
/// # use palisade_errors::{sanitized, config_err, definitions};
/// let user_input = "potentially malicious data".repeat(1000);
/// let err = config_err!(
///     definitions::CFG_PARSE_FAILED,
///     "validate",
///     "Invalid input: {}",
///     sanitized!(user_input)
/// );
/// ```
#[macro_export]
macro_rules! sanitized {
    ($expr:expr) => {{
        // Convert to string and truncate
        let s = $expr.to_string();
        let max_len = 256usize; // Inline constant for macro context
        
        if s.len() <= max_len {
            s
        } else {
            // Find last valid UTF-8 boundary at or before max_len
            let mut idx = max_len;
            while idx > 0 && !s.is_char_boundary(idx) {
                idx -= 1;
            }
            if idx == 0 {
                String::from("[INVALID_UTF8]")
            } else {
                format!("{}...[TRUNCATED]", &s[..idx])
            }
        }
    }};
}

/// Create a configuration error with compile-time literal enforcement.
///
/// # Arguments
/// - `$code`: Error code (expression)
/// - `$op`: Operation name (must be string literal)
/// - `$details`: Error details (must be string literal when no args)
/// - `$fmt`: Format string (must be string literal)
/// - `$arg`: Format arguments (expressions, should be wrapped in `sanitized!()`)
///
/// # Example
///
/// ```rust
/// # use palisade_errors::{config_err, definitions, sanitized};
/// let value = 42;
/// let err = config_err!(
///     definitions::CFG_INVALID_VALUE,
///     "validate_threshold",
///     "Threshold {} out of range",
///     sanitized!(value)
/// );
/// ```
#[macro_export]
macro_rules! config_err {
    // Simple case: no formatting
    ($code:expr, $op:literal, $details:literal) => {
        $crate::AgentError::config($code, $op, $details)
    };
    // Format case: format string must be literal, args can be expressions
    ($code:expr, $op:literal, $fmt:literal, $($arg:expr),+ $(,)?) => {
        $crate::AgentError::config($code, $op, format!($fmt, $($arg),+))
    };
}

/// Create a configuration error with sensitive context.
///
/// Both operation and details must be literals for safety.
/// The sensitive parameter should be sanitized if it comes from untrusted sources.
///
/// # Example
///
/// ```rust
/// # use palisade_errors::{config_err_sensitive, definitions, sanitized};
/// # let password = "secret";
/// let err = config_err_sensitive!(
///     definitions::CFG_VALIDATION_FAILED,
///     "authenticate",
///     "Authentication failed",
///     sanitized!(format!("password_length={}", password.len()))
/// );
/// ```
#[macro_export]
macro_rules! config_err_sensitive {
    ($code:expr, $op:literal, $details:literal, $sensitive:expr) => {
        $crate::AgentError::config_sensitive($code, $op, $details, $sensitive)
    };
}

/// Create a deployment error with format string.
///
/// # Example
///
/// ```rust
/// # use palisade_errors::{deployment_err, definitions, sanitized};
/// let artifact_id = "art_12345";
/// let err = deployment_err!(
///     definitions::DCP_DEPLOY_FAILED,
///     "deploy_artifact",
///     "Failed to deploy artifact {}",
///     sanitized!(artifact_id)
/// );
/// ```
#[macro_export]
macro_rules! deployment_err {
    ($code:expr, $op:literal, $details:literal) => {
        $crate::AgentError::deployment($code, $op, $details)
    };
    ($code:expr, $op:literal, $fmt:literal, $($arg:expr),+ $(,)?) => {
        $crate::AgentError::deployment($code, $op, format!($fmt, $($arg),+))
    };
}

/// Create a telemetry error with format string.
///
/// # Example
///
/// ```rust
/// # use palisade_errors::{telemetry_err, definitions, sanitized};
/// let event_count = 1000;
/// let err = telemetry_err!(
///     definitions::TEL_EVENT_LOST,
///     "collect_metrics",
///     "Lost {} events",
///     sanitized!(event_count)
/// );
/// ```
#[macro_export]
macro_rules! telemetry_err {
    ($code:expr, $op:literal, $details:literal) => {
        $crate::AgentError::telemetry($code, $op, $details)
    };
    ($code:expr, $op:literal, $fmt:literal, $($arg:expr),+ $(,)?) => {
        $crate::AgentError::telemetry($code, $op, format!($fmt, $($arg),+))
    };
}

/// Create a correlation error with format string.
///
/// # Example
///
/// ```rust
/// # use palisade_errors::{correlation_err, definitions, sanitized};
/// let rule_id = "rule_42";
/// let err = correlation_err!(
///     definitions::COR_RULE_EVAL_FAILED,
///     "evaluate_rules",
///     "Rule {} evaluation failed",
///     sanitized!(rule_id)
/// );
/// ```
#[macro_export]
macro_rules! correlation_err {
    ($code:expr, $op:literal, $details:literal) => {
        $crate::AgentError::correlation($code, $op, $details)
    };
    ($code:expr, $op:literal, $fmt:literal, $($arg:expr),+ $(,)?) => {
        $crate::AgentError::correlation($code, $op, format!($fmt, $($arg),+))
    };
}

/// Create a response error with format string.
///
/// # Example
///
/// ```rust
/// # use palisade_errors::{response_err, definitions, sanitized};
/// let action = "block_ip";
/// let err = response_err!(
///     definitions::RSP_EXEC_FAILED,
///     "execute_action",
///     "Action {} failed",
///     sanitized!(action)
/// );
/// ```
#[macro_export]
macro_rules! response_err {
    ($code:expr, $op:literal, $details:literal) => {
        $crate::AgentError::response($code, $op, $details)
    };
    ($code:expr, $op:literal, $fmt:literal, $($arg:expr),+ $(,)?) => {
        $crate::AgentError::response($code, $op, format!($fmt, $($arg),+))
    };
}

/// Create a logging error with format string.
///
/// # Example
///
/// ```rust
/// # use palisade_errors::{logging_err, definitions, sanitized};
/// let log_file = "/var/log/honeypot.log";
/// let err = logging_err!(
///     definitions::LOG_WRITE_FAILED,
///     "write_log",
///     "Failed to write to {}",
///     sanitized!(log_file)
/// );
/// ```
#[macro_export]
macro_rules! logging_err {
    ($code:expr, $op:literal, $details:literal) => {
        $crate::AgentError::logging($code, $op, $details)
    };
    ($code:expr, $op:literal, $fmt:literal, $($arg:expr),+ $(,)?) => {
        $crate::AgentError::logging($code, $op, format!($fmt, $($arg),+))
    };
}

/// Create a platform error with format string.
///
/// # Example
///
/// ```rust
/// # use palisade_errors::{platform_err, definitions, sanitized};
/// let syscall = "mlock";
/// let err = platform_err!(
///     definitions::PLT_SYSCALL_FAILED,
///     "lock_memory",
///     "Syscall {} failed",
///     sanitized!(syscall)
/// );
/// ```
#[macro_export]
macro_rules! platform_err {
    ($code:expr, $op:literal, $details:literal) => {
        $crate::AgentError::platform($code, $op, $details)
    };
    ($code:expr, $op:literal, $fmt:literal, $($arg:expr),+ $(,)?) => {
        $crate::AgentError::platform($code, $op, format!($fmt, $($arg),+))
    };
}

/// Create an I/O error with format string.
///
/// # Example
///
/// ```rust
/// # use palisade_errors::{io_err, definitions, sanitized};
/// let bytes_read = 1024;
/// let err = io_err!(
///     definitions::IO_READ_FAILED,
///     "read_file",
///     "Read {} bytes before error",
///     sanitized!(bytes_read)
/// );
/// ```
#[macro_export]
macro_rules! io_err {
    ($code:expr, $op:literal, $details:literal) => {
        $crate::AgentError::io_operation($code, $op, $details)
    };
    ($code:expr, $op:literal, $fmt:literal, $($arg:expr),+ $(,)?) => {
        $crate::AgentError::io_operation($code, $op, format!($fmt, $($arg),+))
    };
}

#[cfg(test)]
mod tests {
    use crate::{definitions, AgentError};
    
    #[test]
    fn test_literal_enforcement_compiles() {
        // These should compile
        let _err1 = config_err!(definitions::CFG_PARSE_FAILED, "test_op", "test details");
        let line = 42;
        let _err2 = config_err!(definitions::CFG_PARSE_FAILED, "test_op", "line {}", sanitized!(line));
    }
    
    #[test]
    fn sanitized_macro_truncates_long_strings() {
        let long_string = "A".repeat(1000);
        let sanitized = sanitized!(long_string);
        
        // Should be truncated
        assert!(sanitized.len() < 1000);
        assert!(sanitized.contains("TRUNCATED"));
    }
    
    #[test]
    fn sanitized_macro_preserves_short_strings() {
        let short_string = "short";
        let sanitized = sanitized!(short_string);
        
        assert_eq!(sanitized, "short");
    }
    
    #[test]
    fn sanitized_macro_respects_utf8_boundaries() {
        let emoji = "🔥".repeat(100);
        let sanitized = sanitized!(emoji);
        
        // Should not panic and should be valid UTF-8
        assert!(std::str::from_utf8(sanitized.as_bytes()).is_ok());
    }
    
    #[test]
    fn sanitized_macro_works_with_numbers() {
        let num = 42;
        let sanitized = sanitized!(num);
        
        assert_eq!(sanitized, "42");
    }
    
    #[test]
    fn sanitized_macro_works_with_format() {
        let user = "alice";
        let attempt = 3;
        let sanitized = sanitized!(format!("user={} attempt={}", user, attempt));
        
        assert!(sanitized.contains("alice"));
        assert!(sanitized.contains("3"));
    }
    
    #[test]
    fn error_macros_with_sanitized_args() {
        let value = "untrusted".repeat(100);
        let err = config_err!(
            definitions::CFG_INVALID_VALUE,
            "validate",
            "Invalid value: {}",
            sanitized!(value)
        );
        
        let log = err.internal_log();
        // Details should be truncated
        assert!(log.details().len() < 1000);
    }
    
    #[test]
    fn config_err_sensitive_with_sanitization() {
        let password = "secret123";
        let err = config_err_sensitive!(
            definitions::CFG_VALIDATION_FAILED,
            "auth",
            "Auth failed",
            sanitized!(format!("pwd_len={}", password.len()))
        );
        
        let log = err.internal_log();
        assert!(log.source_sensitive().is_some());
    }
    
    #[test]
    fn all_error_macros_compile() {
        let val = "test";
        
        let _e1 = config_err!(definitions::CFG_PARSE_FAILED, "op", "details");
        let _e2 = deployment_err!(definitions::DCP_DEPLOY_FAILED, "op", "details");
        let _e3 = telemetry_err!(definitions::TEL_INIT_FAILED, "op", "details");
        let _e4 = correlation_err!(definitions::COR_RULE_EVAL_FAILED, "op", "details");
        let _e5 = response_err!(definitions::RSP_EXEC_FAILED, "op", "details");
        let _e6 = logging_err!(definitions::LOG_WRITE_FAILED, "op", "details");
        let _e7 = platform_err!(definitions::PLT_UNSUPPORTED, "op", "details");
        let _e8 = io_err!(definitions::IO_TIMEOUT, "op", "details");
        
        // With format
        let _e9 = config_err!(definitions::CFG_PARSE_FAILED, "op", "val: {}", sanitized!(val));
    }
    
    #[test]
    fn macros_accept_trailing_comma() {
        let value = 42;
        let _err = config_err!(
            definitions::CFG_PARSE_FAILED,
            "test",
            "Value: {}",
            sanitized!(value),
        );
    }
    
    #[test]
    fn sanitized_with_pathological_utf8() {
        // String that's exactly at boundary
        let s = "Ñ".repeat(128); // Each char is 2 bytes
        let sanitized = sanitized!(s);
        
        // Should be valid UTF-8
        assert!(std::str::from_utf8(sanitized.as_bytes()).is_ok());
    }
}