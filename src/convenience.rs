//! Convenience macros for creating errors with format strings.
//!
//! # Safety
//!
//! These macros now enforce that operation names and format strings
//! are compile-time literals, preventing accidental inclusion of
//! untrusted data in error messages.
//!
//! # Usage
//!
//! ```rust
//! # use palisade_errors::{config_err, definitions};
//! let line_num = 42;
//! // ✓ CORRECT: Format string is literal, variable is arg
//! let err = config_err!(definitions::CFG_PARSE_FAILED, "validate", "Invalid value at line {}", line_num);
//! ```
//!
//! ```rust,compile_fail
//! # use palisade_errors::{config_err, definitions};
//! let user_input = "attacker data";
//! // ✗ COMPILE ERROR: Operation must be a literal
//! let err = config_err!(definitions::CFG_PARSE_FAILED, user_input, "Failed");
//! ```
//!
//! ## For Dynamic Content
//!
//! Sanitize before passing as an argument:
//!
//! ```rust
//! # use palisade_errors::{config_err, definitions};
//! # let user_input = "test";
//! let sanitized = &user_input[..user_input.len().min(256)];
//! let err = config_err!(definitions::CFG_PARSE_FAILED, "validate", "Invalid input: {}", sanitized);
//! ```

/// Create a configuration error with compile-time literal enforcement.
///
/// # Arguments
/// - `$code`: Error code (expression)
/// - `$op`: Operation name (must be string literal)
/// - `$details`: Error details (must be string literal when no args)
/// - `$fmt`: Format string (must be string literal)
/// - `$arg`: Format arguments (expressions)
#[macro_export]
macro_rules! config_err {
    // Simple case: no formatting
    ($code:expr, $op:literal, $details:literal) => {
        $crate::AgentError::config($code, $op, $details)
    };
    // Format case: format string must be literal, args can be expressions
    ($code:expr, $op:literal, $fmt:literal, $($arg:expr),+ $(,)?) => {
        $crate::AgentError::config($code, $op, &format!($fmt, $($arg),+))
    };
}

/// Create a configuration error with sensitive context.
/// Both operation and details must be literals for safety.
#[macro_export]
macro_rules! config_err_sensitive {
    ($code:expr, $op:literal, $details:literal, $sensitive:expr) => {
        $crate::AgentError::config_sensitive($code, $op, $details, $sensitive)
    };
}

/// Create a deployment error with format string.
#[macro_export]
macro_rules! deployment_err {
    ($code:expr, $op:literal, $details:literal) => {
        $crate::AgentError::deployment($code, $op, $details)
    };
    ($code:expr, $op:literal, $fmt:literal, $($arg:expr),+ $(,)?) => {
        $crate::AgentError::deployment($code, $op, &format!($fmt, $($arg),+))
    };
}

/// Create a telemetry error with format string.
#[macro_export]
macro_rules! telemetry_err {
    ($code:expr, $op:literal, $details:literal) => {
        $crate::AgentError::telemetry($code, $op, $details)
    };
    ($code:expr, $op:literal, $fmt:literal, $($arg:expr),+ $(,)?) => {
        $crate::AgentError::telemetry($code, $op, &format!($fmt, $($arg),+))
    };
}

/// Create a correlation error with format string.
#[macro_export]
macro_rules! correlation_err {
    ($code:expr, $op:literal, $details:literal) => {
        $crate::AgentError::correlation($code, $op, $details)
    };
    ($code:expr, $op:literal, $fmt:literal, $($arg:expr),+ $(,)?) => {
        $crate::AgentError::correlation($code, $op, &format!($fmt, $($arg),+))
    };
}

/// Create a response error with format string.
#[macro_export]
macro_rules! response_err {
    ($code:expr, $op:literal, $details:literal) => {
        $crate::AgentError::response($code, $op, $details)
    };
    ($code:expr, $op:literal, $fmt:literal, $($arg:expr),+ $(,)?) => {
        $crate::AgentError::response($code, $op, &format!($fmt, $($arg),+))
    };
}

/// Create a logging error with format string.
#[macro_export]
macro_rules! logging_err {
    ($code:expr, $op:literal, $details:literal) => {
        $crate::AgentError::logging($code, $op, $details)
    };
    ($code:expr, $op:literal, $fmt:literal, $($arg:expr),+ $(,)?) => {
        $crate::AgentError::logging($code, $op, &format!($fmt, $($arg),+))
    };
}

/// Create a platform error with format string.
#[macro_export]
macro_rules! platform_err {
    ($code:expr, $op:literal, $details:literal) => {
        $crate::AgentError::platform($code, $op, $details)
    };
    ($code:expr, $op:literal, $fmt:literal, $($arg:expr),+ $(,)?) => {
        $crate::AgentError::platform($code, $op, &format!($fmt, $($arg),+))
    };
}

/// Create an I/O error with format string.
#[macro_export]
macro_rules! io_err {
    ($code:expr, $op:literal, $details:literal) => {
        $crate::AgentError::io_operation($code, $op, $details)
    };
    ($code:expr, $op:literal, $fmt:literal, $($arg:expr),+ $(,)?) => {
        $crate::AgentError::io_operation($code, $op, &format!($fmt, $($arg),+))
    };
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_literal_enforcement_compiles() {
        use crate::{config_err, definitions};
        
        // These should compile
        let _err1 = config_err!(definitions::CFG_PARSE_FAILED, "test_op", "test details");
        let line = 42;
        let _err2 = config_err!(definitions::CFG_PARSE_FAILED, "test_op", "line {}", line);
    }
    
    // Uncomment to verify compile-time enforcement:
    // #[test]
    // fn test_literal_enforcement_fails() {
    //     use crate::{config_err, definitions};
    //     let op = "dynamic";
    //     let _err = config_err!(definitions::CFG_PARSE_FAILED, op, "details");
    //     // ^ Should fail: expected a string literal
    // }
}