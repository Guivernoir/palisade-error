//! Convenience macros for creating errors with format strings.
//!
//! # Usage Convention
//!
//! These macros are designed to be used with literal format
//! strings (not variables). This is a convention enforced by code review, not
//! a compile-time guarantee.
//!
//! ## Correct Usage
//!
//! ```rust
//! # use palisade_errors::{config_err, definitions};
//! let line_num = 42;
//! let err = config_err!(definitions::CFG_PARSE_FAILED, "validate", "Invalid value at line {}", line_num);
//! ```
//!
//! ## Incorrect Usage
//!
//! This compiles but violates intent:
//!
//! ```rust,ignore
//! let user_input = get_untrusted_string();
//! config_err!(definitions::CFG_PARSE_FAILED, "validate", "{}", user_input);  // DON'T
//! ```
//!
//! ## For Untrusted Input
//!
//! Sanitize or truncate before passing to error creation:
//!
//! ```rust
//! # use palisade_errors::{config_err, definitions};
//! # let user_input = "test";
//! let sanitized = &user_input[..user_input.len().min(256)];
//! let err = config_err!(definitions::CFG_PARSE_FAILED, "validate", "Invalid input: {}", sanitized);
//! ```


#[macro_export]
macro_rules! config_err {
    ($code:expr, $op:expr, $fmt:literal $(, $arg:expr)*) => {
        $crate::AgentError::config($code, $op, &format!($fmt $(, $arg)*))
    };
}

/// Create a configuration error with sensitive context.
#[macro_export]
macro_rules! config_err_sensitive {
    ($code:expr, $op:expr, $details:literal, $sensitive:expr) => {
        $crate::AgentError::config_sensitive($code, $op, $details, $sensitive)
    };
}

/// Create a deployment error with format string.
#[macro_export]
macro_rules! deployment_err {
    ($code:expr, $op:expr, $fmt:literal $(, $arg:expr)*) => {
        $crate::AgentError::deployment($code, $op, &format!($fmt $(, $arg)*))
    };
}

/// Create a telemetry error with format string.
#[macro_export]
macro_rules! telemetry_err {
    ($code:expr, $op:expr, $fmt:literal $(, $arg:expr)*) => {
        $crate::AgentError::telemetry($code, $op, &format!($fmt $(, $arg)*))
    };
}

/// Create a correlation error with format string.
#[macro_export]
macro_rules! correlation_err {
    ($code:expr, $op:expr, $fmt:literal $(, $arg:expr)*) => {
        $crate::AgentError::correlation($code, $op, &format!($fmt $(, $arg)*))
    };
}

/// Create a response error with format string.
#[macro_export]
macro_rules! response_err {
    ($code:expr, $op:expr, $fmt:literal $(, $arg:expr)*) => {
        $crate::AgentError::response($code, $op, &format!($fmt $(, $arg)*))
    };
}

/// Create a logging error with format string.
#[macro_export]
macro_rules! logging_err {
    ($code:expr, $op:expr, $fmt:literal $(, $arg:expr)*) => {
        $crate::AgentError::logging($code, $op, &format!($fmt $(, $arg)*))
    };
}

/// Create a platform error with format string.
#[macro_export]
macro_rules! platform_err {
    ($code:expr, $op:expr, $fmt:literal $(, $arg:expr)*) => {
        $crate::AgentError::platform($code, $op, &format!($fmt $(, $arg)*))
    };
}

/// Create an I/O error with format string.
#[macro_export]
macro_rules! io_err {
    ($code:expr, $op:expr, $fmt:literal $(, $arg:expr)*) => {
        $crate::AgentError::io_operation($code, $op, &format!($fmt $(, $arg)*))
    };
}