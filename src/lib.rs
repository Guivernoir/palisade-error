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
//! 6. **Timing attacks are mitigated** through optional normalization
//!
//! ## Security Principles
//!
//! - Never expose file paths, usernames, PIDs, or configuration values externally
//! - Never reveal internal architecture, component names, or validation logic
//! - Never show stack traces, memory addresses, or timing information
//! - Sanitized output still provides operation category and retry hints
//! - ALL context data is zeroized on drop - NO LEAKS, NO EXCEPTIONS
//! - Zero-allocation hot paths where possible
//! - Timing side-channels can be mitigated with normalization
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
//! - Timing normalization available for sensitive operations
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
//! fn load_config(path: String) -> Result<File> {
//!     File::open(&path).map_err(|e|
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
//! ## Timing Attack Mitigation
//!
//! ```rust
//! use palisade_errors::{AgentError, definitions, Result};
//! use std::time::Duration;
//!
//! fn authenticate(username: &str, password: &str) -> Result<()> {
//!     // Perform authentication...
//!     # Ok(())
//! }
//!
//! // Normalize timing to prevent timing side-channels
//! let result = authenticate("user", "pass");
//! if let Err(e) = result {
//!     // Delay error response to constant time
//!     return Err(e.with_timing_normalization(Duration::from_millis(100)));
//! }
//! # Ok(())
//! ```
//!
//! ## Features
//!
//! - `trusted_debug`: Enable detailed debug formatting for trusted environments (debug builds only)
//! - `external_signaling`: Reserved for future external signaling capabilities

#![warn(missing_docs)]
#![warn(clippy::all)]

use std::fmt;
use std::io;
use std::result;
use std::time::{Duration, Instant};
use smallvec::SmallVec;
use zeroize::Zeroize;
use std::error::Error;
use std::borrow::Cow;

pub mod codes;
pub mod context;
pub mod convenience;
pub mod definitions;
pub mod logging;
pub mod models;
pub mod obfuscation;
pub mod ring_buffer;

pub use codes::*;
pub use context::*;
pub use convenience::*;
pub use definitions::*;
pub use logging::*;
pub use models::*;
pub use obfuscation::*;
pub use ring_buffer::*;

/// Type alias for Results using our error type.
pub type Result<T> = result::Result<T, AgentError>;

// ============================================================================
// Internal Error Context (Legacy, Still Used by AgentError)
// ============================================================================

/// Internal error context storage for `AgentError`.
///
/// This preserves the legacy context model while newer DualContextError APIs evolve.
struct ErrorContext {
    operation: Cow<'static, str>,
    details: Cow<'static, str>,
    source_internal: Option<Cow<'static, str>>,
    source_sensitive: Option<Cow<'static, str>>,
    metadata: SmallVec<[(&'static str, ContextField); 4]>,
}

impl ErrorContext {
    #[inline]
    fn new(operation: impl Into<Cow<'static, str>>, details: impl Into<Cow<'static, str>>) -> Self {
        Self {
            operation: operation.into(),
            details: details.into(),
            source_internal: None,
            source_sensitive: None,
            metadata: SmallVec::new(),
        }
    }

    #[inline]
    fn with_sensitive(
        operation: impl Into<Cow<'static, str>>,
        details: impl Into<Cow<'static, str>>,
        sensitive_info: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            operation: operation.into(),
            details: details.into(),
            source_internal: None,
            source_sensitive: Some(sensitive_info.into()),
            metadata: SmallVec::new(),
        }
    }

    #[inline]
    fn with_source_split(
        operation: impl Into<Cow<'static, str>>,
        details: impl Into<Cow<'static, str>>,
        internal_source: impl Into<Cow<'static, str>>,
        sensitive_source: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            operation: operation.into(),
            details: details.into(),
            source_internal: Some(internal_source.into()),
            source_sensitive: Some(sensitive_source.into()),
            metadata: SmallVec::new(),
        }
    }

    #[inline]
    fn add_metadata(&mut self, key: &'static str, value: impl Into<Cow<'static, str>>) {
        self.metadata.push((key, ContextField::from(value.into())));
    }
}

impl Zeroize for ErrorContext {
    fn zeroize(&mut self) {
        if let Cow::Owned(ref mut s) = self.operation {
            s.zeroize();
        }
        if let Cow::Owned(ref mut s) = self.details {
            s.zeroize();
        }
        if let Some(Cow::Owned(ref mut s)) = self.source_internal {
            s.zeroize();
        }
        if let Some(Cow::Owned(ref mut s)) = self.source_sensitive {
            s.zeroize();
        }
        for (_, value) in &mut self.metadata {
            value.zeroize();
        }
        self.metadata.clear();
    }
}

impl Drop for ErrorContext {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[inline]
const fn io_error_kind_label(kind: io::ErrorKind) -> &'static str {
    match kind {
        io::ErrorKind::NotFound => "NotFound",
        io::ErrorKind::PermissionDenied => "PermissionDenied",
        io::ErrorKind::ConnectionRefused => "ConnectionRefused",
        io::ErrorKind::ConnectionReset => "ConnectionReset",
        io::ErrorKind::HostUnreachable => "HostUnreachable",
        io::ErrorKind::NetworkUnreachable => "NetworkUnreachable",
        io::ErrorKind::ConnectionAborted => "ConnectionAborted",
        io::ErrorKind::NotConnected => "NotConnected",
        io::ErrorKind::AddrInUse => "AddrInUse",
        io::ErrorKind::AddrNotAvailable => "AddrNotAvailable",
        io::ErrorKind::BrokenPipe => "BrokenPipe",
        io::ErrorKind::AlreadyExists => "AlreadyExists",
        io::ErrorKind::WouldBlock => "WouldBlock",
        io::ErrorKind::InvalidInput => "InvalidInput",
        io::ErrorKind::InvalidData => "InvalidData",
        io::ErrorKind::TimedOut => "TimedOut",
        io::ErrorKind::WriteZero => "WriteZero",
        io::ErrorKind::Interrupted => "Interrupted",
        io::ErrorKind::Unsupported => "Unsupported",
        io::ErrorKind::UnexpectedEof => "UnexpectedEof",
        io::ErrorKind::OutOfMemory => "OutOfMemory",
        io::ErrorKind::Other => "Other",
        _ => "Unknown",
    }
}

/// Main error type with security-conscious design.
///
/// # Key Properties
///
/// - All context is zeroized on drop (including source errors)
/// - External display reveals minimal information
/// - Internal logging uses structured data with explicit lifetimes
/// - No implicit conversions from stdlib errors
/// - Hot paths are zero-allocation where possible
/// - Built-in constant-time error generation to reduce timing side-channels
/// - Always-on error code obfuscation to resist fingerprinting
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
    source: Option<Box<dyn Error + Send + Sync>>,
    created_at: Instant,
}

impl AgentError {
    #[inline]
    fn enforce_constant_time(created_at: Instant) {
        const ERROR_GEN_FLOOR_US: u64 = 1;
        let target = Duration::from_micros(ERROR_GEN_FLOOR_US);
        let end = created_at + target;
        while Instant::now() < end {
            std::hint::spin_loop();
        }
    }

    /// Create a generic error with internal context only.
    #[inline]
    fn new(code: ErrorCode, operation: impl Into<Cow<'static, str>>, details: impl Into<Cow<'static, str>>) -> Self {
        let created_at = Instant::now();
        Self {
            code: crate::obfuscation::obfuscate_code(&code),
            context: ErrorContext::new(operation, details),
            retryable: false,
            source: None,
            created_at,
        }
        .with_constant_time(created_at)
    }

    /// Create an error with sensitive information (paths, usernames, etc.)
    #[inline]
    fn new_sensitive(
        code: ErrorCode,
        operation: impl Into<Cow<'static, str>>,
        details: impl Into<Cow<'static, str>>,
        sensitive_info: impl Into<Cow<'static, str>>,
    ) -> Self {
        let created_at = Instant::now();
        Self {
            code: crate::obfuscation::obfuscate_code(&code),
            context: ErrorContext::with_sensitive(operation, details, sensitive_info),
            retryable: false,
            source: None,
            created_at,
        }
        .with_constant_time(created_at)
    }

    /// Create an error with split internal/sensitive sources.
    ///
    /// This keeps sensitive context (paths) separate from semi-sensitive
    /// context (error kinds), preventing conflation.
    #[inline]
    fn new_with_split_source(
        code: ErrorCode,
        operation: impl Into<Cow<'static, str>>,
        details: impl Into<Cow<'static, str>>,
        internal_source: impl Into<Cow<'static, str>>,
        sensitive_source: impl Into<Cow<'static, str>>,
    ) -> Self {
        let created_at = Instant::now();
        Self {
            code: crate::obfuscation::obfuscate_code(&code),
            context: ErrorContext::with_source_split(
                operation,
                details,
                internal_source,
                sensitive_source,
            ),
            retryable: false,
            source: None,
            created_at,
        }
        .with_constant_time(created_at)
    }

    #[inline]
    fn with_constant_time(mut self, created_at: Instant) -> Self {
        Self::enforce_constant_time(created_at);
        self.created_at = created_at;
        self
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
    pub fn with_metadata(mut self, key: &'static str, value: impl Into<Cow<'static, str>>) -> Self {
        self.context.add_metadata(key, value);
        self
    }

    /// Normalize timing to prevent timing side-channel attacks.
    ///
    /// This sleeps until `target_duration` has elapsed since error creation,
    /// ensuring that error responses take a consistent amount of time regardless
    /// of which code path failed.
    ///
    /// # Use Cases
    ///
    /// - Authentication failures (prevent user enumeration)
    /// - Sensitive file operations (prevent path existence probing)
    /// - Cryptographic operations (prevent timing attacks on key material)
    ///
    /// # Example
    ///
    /// ```rust
    /// use palisade_errors::{AgentError, definitions};
    /// use std::time::Duration;
    ///
    /// fn authenticate(user: &str, pass: &str) -> palisade_errors::Result<()> {
    ///     // Fast path: invalid username
    ///     if !user_exists(user) {
    ///         return Err(
    ///             AgentError::config(definitions::CFG_VALIDATION_FAILED, "auth", "Invalid credentials")
    ///                 .with_timing_normalization(Duration::from_millis(100))
    ///         );
    ///     }
    ///     
    ///     // Slow path: password hash check
    ///     if !check_password(user, pass) {
    ///         return Err(
    ///             AgentError::config(definitions::CFG_VALIDATION_FAILED, "auth", "Invalid credentials")
    ///                 .with_timing_normalization(Duration::from_millis(100))
    ///         );
    ///     }
    ///     
    ///     Ok(())
    /// }
    /// # fn user_exists(_: &str) -> bool { true }
    /// # fn check_password(_: &str, _: &str) -> bool { true }
    /// ```
    ///
    /// Both error paths now take at least 100ms, preventing attackers from
    /// distinguishing between "user doesn't exist" and "wrong password".
    ///
    /// # Performance Note
    ///
    /// This adds a sleep to the error path, which is acceptable since errors
    /// are not the hot path. The slight performance cost is worth the security
    /// benefit for sensitive operations.
    ///
    /// # Limitations
    /// 
    /// - **Not async-safe**: Blocks the thread. Use in sync contexts only.
    /// - **Coarse precision**: OS scheduling affects accuracy (1-15ms jitter).
    /// - **Partial protection**: Only normalizes error return timing, not upstream operations.
    /// - **Observable side-channels**: Network timing, cache behavior, DB queries remain.
    /// 
    /// This provides defense-in-depth against timing attacks but is not a complete solution.
    #[inline]
    pub fn with_timing_normalization(self, target_duration: Duration) -> Self {
        let elapsed = self.created_at.elapsed();
        if elapsed < target_duration {
            std::thread::sleep(target_duration - elapsed);
        }
        self
    }

    /// Check if this error can be retried
    #[inline]
    pub const fn is_retryable(&self) -> bool {
        self.retryable
    }

    /// Get error code
    #[inline]
    pub const fn code(&self) -> &ErrorCode {
        &self.code
    }

    /// Get operation category
    #[inline]
    pub const fn category(&self) -> OperationCategory {
        self.code.category()
    }

    /// Get the time elapsed since this error was created.
    ///
    /// Useful for metrics and debugging, but should NOT be exposed externally
    /// as it could leak timing information.
    #[inline]
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
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
            code: &self.code,
            operation: self.context.operation.as_ref(),
            details: self.context.details.as_ref(),
            source_internal: self
                .context
                .source_internal
                .as_ref()
                .map(|s: &Cow<'static, str>| s.as_ref()),
            source_sensitive: self
                .context
                .source_sensitive
                .as_ref()
                .map(|s: &Cow<'static, str>| s.as_ref()),
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
    pub fn config(
        code: ErrorCode, 
        operation: impl Into<Cow<'static, str>>, 
        details: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self::new(code, operation, details)
    }

    /// Create a configuration error with sensitive context
    #[inline]
    pub fn config_sensitive(
        code: ErrorCode, 
        operation: impl Into<Cow<'static, str>>, 
        details: impl Into<Cow<'static, str>>, 
        sensitive: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self::new_sensitive(code, operation, details, sensitive)
    }

    /// Create a deployment error
    #[inline]
    pub fn deployment(
        code: ErrorCode, 
        operation: impl Into<Cow<'static, str>>, 
        details: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self::new(code, operation, details)
    }

    /// Create a telemetry error
    #[inline]
    pub fn telemetry(
        code: ErrorCode, 
        operation: impl Into<Cow<'static, str>>, 
        details: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self::new(code, operation, details)
    }

    /// Create a correlation error
    #[inline]
    pub fn correlation(
        code: ErrorCode, 
        operation: impl Into<Cow<'static, str>>, 
        details: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self::new(code, operation, details)
    }

    /// Create a response error
    #[inline]
    pub fn response(
        code: ErrorCode, 
        operation: impl Into<Cow<'static, str>>, 
        details: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self::new(code, operation, details)
    }

    /// Create a logging error
    #[inline]
    pub fn logging(
        code: ErrorCode, 
        operation: impl Into<Cow<'static, str>>, 
        details: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self::new(code, operation, details)
    }

    /// Create a platform error
    #[inline]
    pub fn platform(
        code: ErrorCode, 
        operation: impl Into<Cow<'static, str>>, 
        details: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self::new(code, operation, details)
    }

    /// Create an I/O operation error
    #[inline]
    pub fn io_operation(
        code: ErrorCode, 
        operation: impl Into<Cow<'static, str>>, 
        details: impl Into<Cow<'static, str>>,
    ) -> Self {
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
        operation: impl Into<Cow<'static, str>>,
        path: impl Into<Cow<'static, str>>,
        error: io::Error,
    ) -> Self {
        Self::new_with_split_source(
            code,
            operation,
            "I/O operation failed",
            io_error_kind_label(error.kind()), // Internal: error kind
            path.into(),                // Sensitive: filesystem path
        )
    }

    /// Async-safe timing normalization for non-blocking contexts.
    ///
    /// Unlike `with_timing_normalization`, this uses async sleep primitives
    /// and won't block the executor thread. Essential for Tokio/async-std runtimes.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// async fn authenticate(user: &str, pass: &str) -> Result<Session> {
    ///     let result = check_credentials(user, pass).await;
    ///     
    ///     if let Err(e) = result {
    ///         // Normalize timing without blocking executor
    ///         return Err(
    ///             e.with_timing_normalization_async(Duration::from_millis(100)).await
    ///         );
    ///     }
    ///     
    ///     result
    /// }
    /// ```
    ///
    /// # Runtime Support
    ///
    /// - Requires either `tokio` or `async-std` feature
    /// - Tokio takes precedence if both are enabled
    /// - Will not compile without at least one async runtime feature
    #[cfg(any(feature = "tokio", feature = "async_std"))]
    #[inline]
    pub async fn with_timing_normalization_async(self, target_duration: Duration) -> Self {
        // FIXED: Calculate target absolute time to avoid race conditions
        let target_time = self.created_at + target_duration;
        let now = Instant::now();
        
        if now < target_time {
            let sleep_duration = target_time - now;
            
            #[cfg(feature = "tokio")]
            tokio::time::sleep(sleep_duration).await;
            
            #[cfg(all(feature = "async_std", not(feature = "tokio")))]
            async_std::task::sleep(sleep_duration).await;
        }
        self
    }

    // Obfuscation is always applied at construction time.
}

// Manual Drop implementation to ensure proper zeroization ordering
impl Drop for AgentError {
    /// Panic-safe drop with explicit zeroization order.
    ///
    /// Marked #[inline(never)] to prevent optimization that could skip zeroization.
    #[inline(never)]
    fn drop(&mut self) {
        // Use catch_unwind to ensure we attempt cleanup even if something panics
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // Drop the source error first (may contain sensitive data)
            // By setting to None, we ensure the boxed error is dropped
            self.source = None;
            
            // Context zeroizes itself via ZeroizeOnDrop
            // but we're explicit here for documentation
            self.context.zeroize();
        }));
    }
}

impl fmt::Debug for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentError")
            .field("code", &self.code)
            .field("category", &self.code.category())
            .field("retryable", &self.retryable)
            .field("age", &self.created_at.elapsed())
            .field("context", &"<REDACTED>")
            .field("source", &self.source.as_ref().map(|_| "<PRESENT>"))
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
    /// - Timing information
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
        self.source.as_ref().map(|e| e.as_ref() as &(dyn std::error::Error + 'static))
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn timing_normalization_adds_delay() {
        let start = Instant::now();
        let err = AgentError::config(
            definitions::CFG_PARSE_FAILED,
            "test",
            "test"
        );
        
        // This should add delay to reach 50ms
        let _normalized = err.with_timing_normalization(Duration::from_millis(50));
        
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_millis(50));
        assert!(elapsed < Duration::from_millis(100)); // Some tolerance
    }

    #[test]
    fn timing_normalization_no_delay_if_already_slow() {
        let err = AgentError::config(
            definitions::CFG_PARSE_FAILED,
            "test",
            "test"
        );
        
        // Wait longer than target
        thread::sleep(Duration::from_millis(60));
        
        let start = Instant::now();
        let _normalized = err.with_timing_normalization(Duration::from_millis(50));
        let elapsed = start.elapsed();
        
        // Should not add extra delay
        assert!(elapsed < Duration::from_millis(10));
    }

    #[test]
    fn external_display_reveals_no_details() {
        crate::obfuscation::clear_session_salt();
        let err = AgentError::from_io_path(
            definitions::IO_READ_FAILED,
            "load_config",
            "/etc/shadow",
            io::Error::from(io::ErrorKind::PermissionDenied)
        );
        
        let displayed = format!("{}", err);
        
        // Should not contain sensitive information
        assert!(!displayed.contains("/etc"));
        assert!(!displayed.contains("shadow"));
        assert!(!displayed.contains("load_config"));
        assert!(!displayed.contains("Permission"));
        
        // Should contain safe information
        assert!(displayed.contains("I/O"));
        assert!(displayed.contains("E-IO-800"));
    }

    #[test]
    fn internal_log_contains_details() {
        let err = AgentError::config(
            definitions::CFG_PARSE_FAILED,
            "test_operation",
            "test details"
        );
        
        let log = err.internal_log();
        assert_eq!(log.operation(), "test_operation");
        assert_eq!(log.details(), "test details");
    }

    #[test]
    fn error_age_increases() {
        let err = AgentError::config(
            definitions::CFG_PARSE_FAILED,
            "test",
            "test"
        );
        
        let age1 = err.age();
        thread::sleep(Duration::from_millis(10));
        let age2 = err.age();
        
        assert!(age2 > age1);
    }
}
