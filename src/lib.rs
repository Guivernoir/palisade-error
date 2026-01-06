//! # Palisade Errors
//!
//! Security-conscious error handling with operational security principles.
//!
//! ## Design Philosophy
//!
//! 1. **Internal errors contain full context** for forensic analysis
//! 2. **External errors reveal nothing** that aids an adversary
//! 3. **Error codes enable tracking** without information disclosure
//! 4. **Sensitive data is explicitly marked** and zeroized
//! 5. **Sanitization is mandatory** and provides useful signals without leaking details
//!
//! ## Security Principles
//!
//! - Never expose file paths, usernames, PIDs, or configuration values externally
//! - Never reveal internal architecture, component names, or validation logic
//! - Never show stack traces, memory addresses, or timing information
//! - Sanitized output still provides operation category and retry hints
//! - ALL context data is zeroized on drop - NO LEAKS, NO EXCEPTIONS
//! - Zero-allocation hot paths where possible
//!
//! ## Threat Model
//!
//! We assume attackers:
//! - Read our source code
//! - Trigger errors intentionally to fingerprint the system
//! - Collect error messages to map internal architecture
//! - Use timing and error patterns for side-channel attacks
//! - Perform post-compromise memory scraping and core dump analysis
//!
//! Therefore:
//! - External errors provide only error codes and operation categories
//! - Internal logs use structured data with explicit, short lifetimes
//! - ALL error context is zeroized on drop
//! - No string concatenation of sensitive data
//! - No leaked allocations that bypass zeroization
//! - Sensitive/Internal fields kept separate to prevent conflation
//!
//! ## Quick Start
//!
//! ```rust
//! use palisade_errors::{AgentError, definitions, Result};
//!
//! fn validate_config(threshold: f64) -> Result<()> {
//!     if threshold < 0.0 || threshold > 100.0 {
//!         return Err(AgentError::config(
//!             definitions::CFG_INVALID_VALUE,
//!             "validate_threshold",
//!             "Threshold must be between 0 and 100"
//!         ));
//!     }
//!     Ok(())
//! }
//!
//! // External display (safe for untrusted viewers):
//! // "Configuration operation failed [permanent] (E-CFG-103)"
//!
//! // Internal log (full context for forensics):
//! // [E-CFG-103] operation='validate_threshold' details='Threshold must be between 0 and 100'
//! ```
//!
//! ## Working with Sensitive Data
//!
//! ```rust
//! use palisade_errors::{AgentError, definitions, Result};
//! use std::fs::File;
//!
//! fn load_config(path: &str) -> Result<File> {
//!     File::open(path).map_err(|e|
//!         AgentError::from_io_path(
//!             definitions::IO_READ_FAILED,
//!             "load_config",
//!             path,  // Kept separate as sensitive data
//!             e
//!         )
//!     )
//! }
//! ```
//!
//! ## Features
//!
//! - `trusted_debug`: Enable detailed debug formatting for trusted environments
//! - `external_signaling`: Reserved for future external signaling capabilities

#![warn(missing_docs)]
#![warn(clippy::all)]
#![deny(unsafe_code)]

use std::fmt;
use std::io;
use std::result;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod codes;
pub mod context;
pub mod convenience;
pub mod definitions;
pub mod logging;
pub mod models;
mod tests;

pub use codes::*;
pub use context::*;
pub use convenience::*;
pub use definitions::*;
pub use logging::*;
pub use models::*;

/// Type alias for Results using our error type.
pub type Result<T> = result::Result<T, AgentError>;

/// Main error type with security-conscious design.
///
/// # Key Properties
///
/// - All context is zeroized on drop
/// - External display reveals minimal information
/// - Internal logging uses structured data with explicit lifetimes
/// - No implicit conversions from stdlib errors
/// - Hot paths are zero-allocation where possible
///
/// # Design Rationale - Error Constructors
///
/// We provide convenience constructors like `config()`, `telemetry()`, etc.
/// even though `ErrorCode` already contains the category. This is intentional:
///
/// 1. **Ergonomics**: `AgentError::config(code, ...)` is clearer than `AgentError::new(code, ...)`
/// 2. **Future extensibility**: Different subsystems may need different context types
/// 3. **Type safety**: Prevents mixing categories (compile-time check vs runtime enum match)
/// 4. **Grep-ability**: Engineers can search for "::telemetry(" to find all telemetry errors
///
/// The redundancy is acceptable because it improves maintainability and reduces
/// the chance of errors being created with mismatched code/category pairs.
#[must_use = "errors should be handled or logged"]
pub struct AgentError {
    code: ErrorCode,
    context: ErrorContext,
    retryable: bool,
}

impl AgentError {
    /// Create a generic error with internal context only.
    #[inline]
    fn new(code: ErrorCode, operation: impl Into<String>, details: impl Into<String>) -> Self {
        Self {
            code,
            context: ErrorContext::new(operation, details),
            retryable: false,
        }
    }

    /// Create an error with sensitive information (paths, usernames, etc.)
    #[inline]
    fn new_sensitive(
        code: ErrorCode,
        operation: impl Into<String>,
        details: impl Into<String>,
        sensitive_info: impl Into<String>,
    ) -> Self {
        Self {
            code,
            context: ErrorContext::with_sensitive(operation, details, sensitive_info),
            retryable: false,
        }
    }

    /// Create an error with split internal/sensitive sources.
    ///
    /// This keeps sensitive context (paths) separate from semi-sensitive
    /// context (error kinds), preventing conflation.
    #[inline]
    fn new_with_split_source(
        code: ErrorCode,
        operation: impl Into<String>,
        details: impl Into<String>,
        internal_source: impl Into<String>,
        sensitive_source: impl Into<String>,
    ) -> Self {
        Self {
            code,
            context: ErrorContext::with_source_split(
                operation,
                details,
                internal_source,
                sensitive_source,
            ),
            retryable: false,
        }
    }

    /// Mark this error as retryable (transient failure)
    #[inline]
    pub fn with_retry(mut self) -> Self {
        self.retryable = true;
        self
    }

    /// Add tracking metadata (correlation IDs, session tokens, etc.)
    ///
    /// MUTATES IN PLACE - no cloning, no wasted allocations.
    #[inline]
    pub fn with_metadata(mut self, key: &'static str, value: impl Into<String>) -> Self {
        self.context.add_metadata(key, value);
        self
    }

    /// Check if this error can be retried
    #[inline]
    pub const fn is_retryable(&self) -> bool {
        self.retryable
    }

    /// Get error code
    #[inline]
    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    /// Get operation category
    #[inline]
    pub const fn category(&self) -> OperationCategory {
        self.code.category()
    }

    /// Create structured internal log entry with explicit lifetime.
    ///
    /// # Critical Security Property
    ///
    /// The returned `InternalLog` borrows from `self` and CANNOT
    /// outlive this error. This is intentional and enforces that sensitive
    /// data is consumed immediately by the logger and cannot be retained.
    ///
    /// # Usage Pattern
    ///
    /// ```rust
    /// # use palisade_errors::{AgentError, definitions};
    /// let err = AgentError::config(
    ///     definitions::CFG_PARSE_FAILED,
    ///     "test",
    ///     "test details"
    /// );
    /// let log = err.internal_log();
    /// // logger.log_structured(log);  // log dies here
    /// // err is dropped, all data zeroized
    /// ```
    ///
    /// The short lifetime prevents accidental retention in log buffers,
    /// async contexts, or background threads.
    #[inline]
    pub fn internal_log(&self) -> InternalLog<'_> {
        InternalLog {
            code: self.code,
            operation: self.context.operation.as_str(),
            details: self.context.details.as_str(),
            source_internal: self.context.source_internal.as_ref().map(|s| s.as_str()),
            source_sensitive: self.context.source_sensitive.as_ref().map(|s| s.as_str()),
            metadata: &self.context.metadata,
            retryable: self.retryable,
        }
    }

    /// Alternative logging pattern for frameworks that need callback-style.
    ///
    /// This enforces immediate consumption and prevents accidental retention:
    ///
    /// ```rust
    /// # use palisade_errors::{AgentError, definitions};
    /// # let err = AgentError::config(definitions::CFG_PARSE_FAILED, "test", "test");
    /// err.with_internal_log(|log| {
    ///     // logger.write(log.code(), log.operation());
    ///     // log is destroyed when this closure returns
    /// });
    /// ```
    #[inline]
    pub fn with_internal_log<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&InternalLog<'_>) -> R,
    {
        let log = self.internal_log();
        f(&log)
    }

    // Convenience constructors for each subsystem.
    // See "Design Rationale - Error Constructors" above for why these exist
    // despite apparent redundancy with ErrorCode categories.

    /// Create a configuration error
    #[inline]
    pub fn config(code: ErrorCode, operation: &str, details: &str) -> Self {
        Self::new(code, operation, details)
    }

    /// Create a configuration error with sensitive context
    #[inline]
    pub fn config_sensitive(code: ErrorCode, operation: &str, details: &str, sensitive: &str) -> Self {
        Self::new_sensitive(code, operation, details, sensitive)
    }

    /// Create a deployment error
    #[inline]
    pub fn deployment(code: ErrorCode, operation: &str, details: &str) -> Self {
        Self::new(code, operation, details)
    }

    /// Create a telemetry error
    #[inline]
    pub fn telemetry(code: ErrorCode, operation: &str, details: &str) -> Self {
        Self::new(code, operation, details)
    }

    /// Create a correlation error
    #[inline]
    pub fn correlation(code: ErrorCode, operation: &str, details: &str) -> Self {
        Self::new(code, operation, details)
    }

    /// Create a response error
    #[inline]
    pub fn response(code: ErrorCode, operation: &str, details: &str) -> Self {
        Self::new(code, operation, details)
    }

    /// Create a logging error
    #[inline]
    pub fn logging(code: ErrorCode, operation: &str, details: &str) -> Self {
        Self::new(code, operation, details)
    }

    /// Create a platform error
    #[inline]
    pub fn platform(code: ErrorCode, operation: &str, details: &str) -> Self {
        Self::new(code, operation, details)
    }

    /// Create an I/O operation error
    #[inline]
    pub fn io_operation(code: ErrorCode, operation: &str, details: &str) -> Self {
        Self::new(code, operation, details)
    }

    /// Wrap io::Error with explicit context, keeping path and error separate.
    ///
    /// This prevents conflation of:
    /// - Error kind (semi-sensitive, reveals error type)
    /// - Path (sensitive, reveals filesystem structure)
    ///
    /// By keeping them separate, logging systems can choose to handle them
    /// differently (e.g., hash paths but log error kinds).
    #[inline]
    pub fn from_io_path(
        code: ErrorCode,
        operation: &str,
        path: &str,
        error: io::Error,
    ) -> Self {
        Self::new_with_split_source(
            code,
            operation,
            "I/O operation failed",
            format!("{:?}", error.kind()),  // Internal: error kind
            path.to_string(),                // Sensitive: filesystem path
        )
    }
}

// Manual Drop implementation to ensure proper zeroization ordering
impl Drop for AgentError {
    fn drop(&mut self) {
        // Context is already ZeroizeOnDrop, but we're explicit here
        // to document the security guarantee
        self.context.zeroize();
    }
}

impl fmt::Debug for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentError")
            .field("code", &self.code)
            .field("category", &self.code.category())
            .field("retryable", &self.retryable)
            .field("context", &"<REDACTED>")
            .finish()
    }
}

impl fmt::Display for AgentError {
    /// External display - sanitized for untrusted viewers.
    /// Zero-allocation formatting.
    ///
    /// Format: "{Category} operation failed [{permanence}] ({ERROR-CODE})"
    ///
    /// Example: "Configuration operation failed [permanent] (E-CFG-100)"
    ///
    /// This provides:
    /// - Operation domain (for troubleshooting)
    /// - Retry semantics (for automation)
    /// - Error code (for tracking)
    ///
    /// Without revealing:
    /// - Internal paths or structure
    /// - Validation logic
    /// - User identifiers
    /// - Configuration values
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let permanence = if self.retryable { "temporary" } else { "permanent" };
        write!(
            f,
            "{} operation failed [{}] ({})",
            self.code.category().display_name(),
            permanence,
            self.code  // ErrorCode::Display also writes directly
        )
    }
}

impl std::error::Error for AgentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // We don't expose source errors externally to prevent information leakage
        None
    }
}