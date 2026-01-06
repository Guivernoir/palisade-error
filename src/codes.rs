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
    ///
    /// # Panics
    ///
    /// Panics at compile time if:
    /// - Code is 0 or >= 1000 (must be 001-999)
    /// - Namespace is empty or > 10 characters
    ///
    /// This validation ensures error codes remain within their allocated ranges
    /// and maintains consistent formatting.
    #[inline]
    pub const fn new(namespace: &'static str, code: u16, category: OperationCategory) -> Self {
        // Validate code range at compile time
        assert!(code > 0 && code < 1000, "Error code must be 001-999");
        
        // Validate namespace at compile time
        assert!(!namespace.is_empty(), "Namespace cannot be empty");
        assert!(namespace.len() <= 10, "Namespace too long (max 10 chars)");
        
        // Validate namespace contains only uppercase ASCII
        let bytes = namespace.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            assert!(
                bytes[i].is_ascii_uppercase(),
                "Namespace must be uppercase ASCII"
            );
            i += 1;
        }
        
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

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn valid_error_code() {
        let code = ErrorCode::new("TEST", 100, OperationCategory::Configuration);
        assert_eq!(code.to_string(), "E-TEST-100");
    }
    
    #[test]
    #[should_panic(expected = "Error code must be 001-999")]
    fn error_code_zero_panics() {
        let _ = ErrorCode::new("TEST", 0, OperationCategory::Configuration);
    }
    
    #[test]
    #[should_panic(expected = "Error code must be 001-999")]
    fn error_code_too_large_panics() {
        let _ = ErrorCode::new("TEST", 1000, OperationCategory::Configuration);
    }
    
    #[test]
    #[should_panic(expected = "Namespace cannot be empty")]
    fn empty_namespace_panics() {
        let _ = ErrorCode::new("", 100, OperationCategory::Configuration);
    }
    
    #[test]
    #[should_panic(expected = "Namespace too long")]
    fn long_namespace_panics() {
        let _ = ErrorCode::new("VERYLONGNAME", 100, OperationCategory::Configuration);
    }
}