//! Error code namespace - enables error tracking without information disclosure.
//!
//! When an attacker triggers an error, they see: "Configuration operation failed (E-CFG-100)"
//! Internally, we log full context. Externally, we reveal only category and code.
//!
//! # Namespace Structure
//!
//! - **CORE**: Fundamental system errors (init, shutdown, panic recovery)
//! - **CFG**: Configuration parsing and validation
//! - **DCP**: Deception artifact management
//! - **TEL**: Telemetry collection subsystem
//! - **COR**: Correlation engine
//! - **RSP**: Response execution
//! - **LOG**: Logging subsystem
//! - **PLT**: Platform-specific operations
//! - **IO**: Filesystem and network operations

use crate::OperationCategory;
use std::fmt;

/// An error code with namespace, numeric code, and operation category.
///
/// Error codes follow the format `E-XXX-YYY` where:
/// - `XXX` is the namespace (e.g., CFG, CORE, IO)
/// - `YYY` is the numeric code (001-999)
///
/// # Example
///
/// ```rust
/// use palisade_errors::definitions;
///
/// let code = definitions::CFG_PARSE_FAILED;
/// assert_eq!(code.to_string(), "E-CFG-100");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorCode {
    namespace: &'static str,
    code: u16,
    category: OperationCategory,
}

impl ErrorCode {
    /// Create a new error code with namespace, code, and operation category.
    #[inline]
    pub const fn new(namespace: &'static str, code: u16, category: OperationCategory) -> Self {
        Self { namespace, code, category }
    }

    /// Get the operation category for contextual error messages.
    #[inline]
    pub const fn category(&self) -> OperationCategory {
        self.category
    }

    /// Get namespace for internal tracking.
    #[inline]
    pub const fn namespace(&self) -> &'static str {
        self.namespace
    }

    /// Get numeric code.
    #[inline]
    pub const fn code(&self) -> u16 {
        self.code
    }
}

impl fmt::Display for ErrorCode {
    /// Zero-allocation formatting - writes directly to formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "E-{}-{:03}", self.namespace, self.code)
    }
}