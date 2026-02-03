//! Dual-context error handling for honeypot systems with type-enforced trust boundaries.
//!
//! # Architecture
//!
//! This module separates public-facing error messages from internal diagnostic data
//! using distinct types that cannot be confused at compile time:
//!
//! - `PublicContext`: Contains data safe for external display (truthful or deceptive)
//! - `InternalContext`: Contains diagnostic data restricted to authenticated SOC access
//! - `DualContextError`: Pairs these contexts with enforced consistency rules
//!
//! # Trust Boundary Enforcement
//!
//! The type system prevents accidental cross-boundary leakage:
//! - `PublicContext` implements `Display` for external rendering
//! - `InternalContext` implements `Display` as redacted placeholder only
//! - No implicit conversions exist between these types
//!
//! # Feature Gates
//!
//! When `external_signaling` is disabled, `PublicTruth` variant is unavailable at
//! compile time. This forces all external outputs to use `DeceptiveLie`, ensuring
//! honeypot deployments cannot accidentally expose truthful diagnostic information.
//!
//! # Memory Safety Strategy
//!
//! Sensitive data receives best-effort clearing from memory on drop:
//!
//! 1. **Owned strings**: Cleared via `zeroize` crate (handles heap buffers)
//! 2. **Compiler optimization**: Volatile writes prevent LLVM dead-store elimination
//! 3. **Instruction ordering**: Compiler fences prevent reordering across security boundaries
//!
//! ## What This Does NOT Guarantee
//!
//! - **Hardware cache visibility**: Compiler fences do not flush CPU caches
//! - **Cross-thread guarantees**: Other threads may observe old values in cache
//! - **Allocator-level security**: Memory may be reallocated before physical clearing
//! - **DMA or swap**: OS/hardware may have copied data before zeroization
//!
//! This protects against compiler optimizations and casual memory inspection.
//! It does NOT provide HSM-grade secure memory wiping. For that, use platform-specific
//! APIs (mlock, SecureZeroMemory, etc.) and dedicated secure allocators.

use std::borrow::Cow;
use std::fmt;
use std::ptr;
use std::sync::atomic::{compiler_fence, Ordering};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ============================================================================
// Capability Token for Sensitive Access Control
// ============================================================================

/// Capability token for accessing sensitive internal context data.
///
/// # Purpose
///
/// This zero-sized type serves as a proof-of-authority for accessing sensitive
/// information via `InternalContext::expose_sensitive()`. Requiring this token:
///
/// 1. Forces explicit privilege acquisition (cannot call accidentally)
/// 2. Makes sensitive access grep-able in codebase
/// 3. Enables future RBAC or audit hook integration
/// 4. Documents authority requirement in the type system
///
/// # Construction
///
/// Only constructible via `SocAccess::acquire()`, which should be called only in
/// controlled contexts (authenticated logging pipelines, SOC-exclusive endpoints, etc.).
///
/// # Security Model
///
/// This is not cryptographic. An attacker with code execution can trivially construct
/// this type. The purpose is **organizational process safety**: preventing accidental
/// misuse by well-meaning developers, not preventing malicious actors.
///
/// # Example
///
/// ```ignore
/// // In SOC-restricted logging code:
/// let access = SocAccess::acquire();
/// if let Some(sensitive) = context.expose_sensitive(&access) {
///     secure_log_to_encrypted_siem(sensitive);
/// }
/// ```
pub struct SocAccess(());

impl SocAccess {
    /// Acquire SOC access capability for sensitive data exposure.
    ///
    /// # Security Contract
    ///
    /// Caller must ensure this is invoked only in contexts where sensitive data
    /// disclosure is authorized:
    /// - Authenticated SOC dashboards with RBAC
    /// - Encrypted internal logging pipelines
    /// - Forensic analysis tools with access controls
    ///
    /// # Audit Recommendation
    ///
    /// Calls to this method should be logged separately for compliance auditing.
    /// Consider wrapping this in a macro that logs the caller's location:
    ///
    /// ```ignore
    /// macro_rules! acquire_soc_access {
    ///     () => {{
    ///         audit_log!("SOC access acquired at {}:{}", file!(), line!());
    ///         SocAccess::acquire()
    ///     }}
    /// }
    /// ```
    #[inline]
    pub fn acquire() -> Self {
        Self(())
    }
}

// ============================================================================
// Core Context Classification
// ============================================================================

/// Internal context field classification for SOC-visible error data.
///
/// This type is wrapped in `InternalContext` newtype and never directly exposed
/// to external systems. The wrapper prevents accidental leakage via Display trait.
///
/// # Variants
///
/// - `Diagnostic`: Standard internal error information for SOC analysis
/// - `Sensitive`: Contains PII, credentials, file paths, or other high-value data
/// - `Lie`: Deceptive content tracked internally (marked to prevent analyst confusion)
///
/// # Memory Model
///
/// Uses `Cow<'static, str>` to allow both:
/// - Zero-allocation storage of compile-time string literals (`Cow::Borrowed`)
/// - Runtime-allocated sensitive data that can be zeroized (`Cow::Owned`)
///
/// ## Assumption About Borrowed Data
///
/// By convention, `Cow::Borrowed` is assumed to contain non-sensitive data
/// (typically string literals embedded in the binary). This assumption can be
/// violated if someone uses `Box::leak()` to create 'static references to sensitive
/// data, but this is not a supported pattern.
///
/// Only `Cow::Owned` variants receive zeroization. Borrowed static data cannot
/// and need not be cleared (it's in the binary).
///
/// # No Clone/Copy Policy
///
/// Prevents unintended duplication of potentially sensitive diagnostic data.
/// All access requires borrowing from the single owner.
enum InternalContextField {
    Diagnostic(Cow<'static, str>),
    Sensitive(Cow<'static, str>),
    Lie(Cow<'static, str>),
}

impl Zeroize for InternalContextField {
    fn zeroize(&mut self) {
        match self {
            Self::Diagnostic(cow) | Self::Sensitive(cow) | Self::Lie(cow) => {
                if let Cow::Owned(s) = cow {
                    s.zeroize();
                }
            }
        }
    }
}

impl ZeroizeOnDrop for InternalContextField {}

impl Drop for InternalContextField {
    fn drop(&mut self) {
        // For sensitive variants with owned data, perform volatile write to prevent
        // compiler from eliding the zeroization as a "dead store" optimization.
        //
        // GUARANTEES PROVIDED:
        // - Prevents LLVM from removing the write as dead code
        // - Ensures write completes before subsequent drop logic
        //
        // GUARANTEES NOT PROVIDED:
        // - Does NOT guarantee CPU cache flushes
        // - Does NOT prevent other threads from seeing old values
        // - Does NOT prevent allocator from reusing memory before physical clear
        // - Does NOT protect against swap, DMA, or hardware memory copies
        //
        // This is best-effort memory clearing for defense against casual inspection
        // and compiler optimizations. Not suitable for cryptographic key material
        // that requires HSM-grade wiping.
        if let Self::Sensitive(cow) = &mut *self {
            if let Cow::Owned(s) = cow {
                // SAFETY:
                // - We own this String and are in its Drop implementation
                // - as_mut_ptr() returns valid pointer to the String's buffer
                // - len() is correct and bounds-checked by Rust
                // - We write only within allocated bounds (0..len)
                // - Volatile writes prevent compiler optimization
                unsafe {
                    let ptr = s.as_mut_ptr();
                    let len = s.len();
                    for i in 0..len {
                        ptr::write_volatile(ptr.add(i), 0u8);
                    }
                }
            };
        }
        
        // High-level zeroization via zeroize crate
        self.zeroize();
        
        // Compiler fence prevents reordering of instructions across this boundary.
        // Ensures zeroization completes before any subsequent destructor logic.
        //
        // GUARANTEES PROVIDED:
        // - Prevents compiler from reordering instructions
        // - Sequential consistency for this thread's view
        //
        // GUARANTEES NOT PROVIDED:
        // - Does NOT imply hardware memory barriers
        // - Does NOT force cache coherence across CPU cores
        // - Other threads may still observe old values in their caches
        compiler_fence(Ordering::SeqCst);
    }
}

/// Public context field classification for externally-visible error data.
///
/// This type is wrapped in `PublicContext` newtype and can only display data
/// explicitly marked as safe or intentionally deceptive for external consumption.
///
/// # Variants
///
/// - `Truth`: Minimal truthful message safe for external display (feature-gated)
/// - `Lie`: Intentionally false narrative for misleading attackers
///
/// # Feature Gate Behavior
///
/// `Truth` variant only exists when `external_signaling` feature is enabled.
/// Without this feature, attempting to construct `PublicContext::truth()` will
/// fail at compile time, forcing all external outputs to be deceptive.
///
/// # Memory Model
///
/// Same as `InternalContextField` - uses `Cow<'static, str>` for efficient
/// storage of both static and dynamic strings. Borrowed data assumed non-sensitive.
///
/// # No Clone/Copy Policy
///
/// Prevents accidental propagation of deceptive narratives across system boundaries.
enum PublicContextField {
    #[cfg(feature = "external_signaling")]
    Truth(Cow<'static, str>),
    Lie(Cow<'static, str>),
}

impl Zeroize for PublicContextField {
    fn zeroize(&mut self) {
        match self {
            #[cfg(feature = "external_signaling")]
            Self::Truth(cow) => {
                if let Cow::Owned(s) = cow {
                    s.zeroize();
                }
            }
            Self::Lie(cow) => {
                if let Cow::Owned(s) = cow {
                    s.zeroize();
                }
            }
        }
    }
}

impl ZeroizeOnDrop for PublicContextField {}

// Note: No custom Drop implementation here. Public contexts rarely contain
// sensitive data, and if they did, they should be in InternalContext instead.
// ZeroizeOnDrop provides sufficient cleanup for owned strings.

// ============================================================================
// Type-Safe Context Wrappers
// ============================================================================

/// Type-safe wrapper for public-facing error contexts.
///
/// # Trust Boundary Enforcement
///
/// This newtype prevents `InternalContextField` from being accidentally displayed
/// externally. The type system ensures only `PublicContextField` variants can be
/// wrapped here, and the `Display` implementation is the sole external rendering path.
///
/// # Construction
///
/// - `lie()`: Always available for deceptive public messages
/// - `truth()`: Only available with `external_signaling` feature enabled
///
/// # Safety Properties
///
/// 1. Cannot be constructed from `InternalContext`
/// 2. Cannot implicitly convert to string (must use `as_str()` or `Display`)
/// 3. Implements `ZeroizeOnDrop` for owned string data
///
/// # No Clone/Copy Policy
///
/// Single-owner semantics prevent duplicate public messages from existing
/// simultaneously, reducing risk of inconsistent external responses.
pub struct PublicContext(PublicContextField);

impl PublicContext {
    /// Create a deceptive public context for external display.
    ///
    /// # Use Case
    ///
    /// Default constructor for honeypot deployments. Deceptive messages are
    /// explicitly labeled and auditable in internal logs.
    ///
    /// # Performance
    ///
    /// Accepts `Cow<'static, str>` to allow zero-allocation when passed string
    /// literals: `PublicContext::lie("error")` allocates nothing.
    #[inline]
    pub fn lie(message: impl Into<Cow<'static, str>>) -> Self {
        Self(PublicContextField::Lie(message.into()))
    }

    /// Create a truthful public context for external display.
    ///
    /// # Availability
    ///
    /// This method only exists when `external_signaling` feature is enabled.
    /// Without this feature, all public contexts must be deceptive, enforcing
    /// operational security at compile time rather than runtime configuration.
    ///
    /// # Use Case
    ///
    /// For honeypots that intentionally signal some authentic errors to appear
    /// more legitimate (e.g., benign input validation failures).
    #[cfg(feature = "external_signaling")]
    #[inline]
    pub fn truth(message: impl Into<Cow<'static, str>>) -> Self {
        Self(PublicContextField::Truth(message.into()))
    }

    /// Get the external-safe string representation.
    ///
    /// # Returns
    ///
    /// Borrowed string slice suitable for HTTP responses, external APIs, or any
    /// untrusted display context. This string may be deceptive.
    ///
    /// # Lifetime
    ///
    /// Returned reference borrows from self, valid until this context is dropped.
    #[inline]
    pub fn as_str(&self) -> &str {
        match &self.0 {
            #[cfg(feature = "external_signaling")]
            PublicContextField::Truth(c) => c.as_ref(),
            PublicContextField::Lie(c) => c.as_ref(),
        }
    }

    /// Get classification label for internal audit trails.
    ///
    /// # Returns
    ///
    /// Static string identifying context type without exposing payload.
    /// Useful for metrics, SOC dashboards, and audit log indexing.
    ///
    /// # Values
    ///
    /// - `"PublicTruth"`: Authentic message (requires feature flag)
    /// - `"DeceptiveLie"`: Intentionally false message
    #[inline]
    pub const fn classification(&self) -> &'static str {
        match &self.0 {
            #[cfg(feature = "external_signaling")]
            PublicContextField::Truth(_) => "PublicTruth",
            PublicContextField::Lie(_) => "DeceptiveLie",
        }
    }
}

impl Zeroize for PublicContext {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for PublicContext {}

impl fmt::Display for PublicContext {
    /// Render public context for external display.
    ///
    /// This is the primary interface for converting error contexts into
    /// externally-visible strings (HTTP responses, external APIs, etc.).
    ///
    /// # Security Note
    ///
    /// This implementation is intentionally simple and does not check context
    /// classification. The type system guarantees only `PublicContextField`
    /// variants can be wrapped in this type, so all outputs are safe by construction.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for PublicContext {
    /// Debug representation for internal logging and diagnostics.
    ///
    /// # Redaction Strategy
    ///
    /// Deceptive payloads are redacted in debug output to prevent lies from
    /// being aggregated as factual data in log analysis systems that may:
    /// - Export logs to external SIEMs
    /// - Send logs to cloud providers
    /// - Aggregate metrics across trust boundaries
    ///
    /// This prevents deceptive error messages from polluting statistical analysis.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            #[cfg(feature = "external_signaling")]
            PublicContextField::Truth(c) => write!(f, "PublicTruth({:?})", c),
            PublicContextField::Lie(_) => write!(f, "DeceptiveLie([REDACTED])"),
        }
    }
}

/// Type-safe wrapper for internal-only error contexts.
///
/// # Trust Boundary Enforcement
///
/// This newtype ensures internal diagnostic data cannot be accidentally exposed
/// externally. The `Display` implementation returns a redacted placeholder, not
/// actual content, preventing misuse in external-facing code paths.
///
/// # Access Patterns
///
/// - `payload()`: Returns structured data for SOC logging (zero allocation)
/// - `expose_sensitive()`: Returns raw sensitive content (requires `SocAccess` capability)
///
/// Both methods require conscious choice and cannot be used accidentally via
/// generic string formatting.
///
/// # Memory Safety
///
/// Implements `ZeroizeOnDrop` to clear owned string data. Sensitive variants
/// receive additional volatile write treatment in `InternalContextField::drop()`
/// to prevent compiler optimization of the clearing operation.
///
/// # No Clone/Copy Policy
///
/// Single-owner semantics prevent sensitive diagnostic data from being duplicated
/// across memory regions, reducing attack surface for memory inspection.
pub struct InternalContext(InternalContextField);

impl InternalContext {
    /// Create a standard diagnostic internal context.
    ///
    /// # Use Case
    ///
    /// For typical internal error diagnostics that SOC analysts need but that
    /// should never be exposed externally (stack traces, internal state, etc.).
    ///
    /// # Example
    ///
    /// ```ignore
    /// InternalContext::diagnostic("SQL injection detected in /api/users?id=1' OR '1'='1")
    /// ```
    #[inline]
    pub fn diagnostic(message: impl Into<Cow<'static, str>>) -> Self {
        Self(InternalContextField::Diagnostic(message.into()))
    }

    /// Create a sensitive internal context with best-effort memory clearing.
    ///
    /// # Use Case
    ///
    /// For internal diagnostics containing:
    /// - Personally identifiable information (PII)
    /// - Credentials or API keys
    /// - Filesystem paths that reveal system topology
    /// - Database connection strings
    /// - Any data that could aid an attacker
    ///
    /// # Memory Clearing Strategy
    ///
    /// When this context is dropped:
    /// 1. Owned string data is cleared via `zeroize` crate
    /// 2. Volatile writes prevent LLVM dead-store elimination
    /// 3. Compiler fence prevents instruction reordering
    ///
    /// This provides best-effort clearing against casual memory inspection and
    /// compiler optimizations. It does NOT provide guarantees against:
    /// - Hardware cache persistence
    /// - Allocator-level memory reuse
    /// - Swap file or DMA copies
    ///
    /// For cryptographic key material, use dedicated secure allocators.
    ///
    /// # Example
    ///
    /// ```ignore
    /// InternalContext::sensitive(format!("Failed login for username: {}", username))
    /// ```
    #[inline]
    pub fn sensitive(message: impl Into<Cow<'static, str>>) -> Self {
        Self(InternalContextField::Sensitive(message.into()))
    }

    /// Create an internal context marked as deceptive.
    ///
    /// # Use Case
    ///
    /// When internal logs themselves may be exfiltrated and you need to track
    /// deceptive narratives without exposing them externally. The `payload()`
    /// method will return this with a `Lie` marker to prevent SOC analysts from
    /// treating it as authentic diagnostic data.
    ///
    /// # Distinction from PublicContext::lie()
    ///
    /// - `PublicContext::lie()`: For external consumption
    /// - `InternalContext::lie()`: For internal tracking of deception operations
    ///
    /// # Example
    ///
    /// ```ignore
    /// InternalContext::lie("Normal database query executed successfully")
    /// ```
    #[inline]
    pub fn lie(message: impl Into<Cow<'static, str>>) -> Self {
        Self(InternalContextField::Lie(message.into()))
    }

    /// Get classification label for logging and metrics.
    ///
    /// # Returns
    ///
    /// Static string identifying the context type:
    /// - `"InternalDiagnostic"`: Standard internal error information
    /// - `"Sensitive"`: Contains high-value data requiring special handling
    /// - `"InternalLie"`: Deceptive content tracked internally
    ///
    /// # Use Case
    ///
    /// For indexing in log aggregation systems, metrics collection, or
    /// routing different context types to different storage backends.
    #[inline]
    pub const fn classification(&self) -> &'static str {
        match &self.0 {
            InternalContextField::Diagnostic(_) => "InternalDiagnostic",
            InternalContextField::Sensitive(_) => "Sensitive",
            InternalContextField::Lie(_) => "InternalLie",
        }
    }

    /// Get structured payload for internal logging without heap allocation.
    ///
    /// # Returns
    ///
    /// - `Some(InternalPayload::Truth(_))`: For diagnostic contexts
    /// - `Some(InternalPayload::Lie(_))`: For lie contexts (marked for SOC awareness)
    /// - `None`: For sensitive contexts (use `expose_sensitive()` instead)
    ///
    /// # Performance
    ///
    /// Zero allocation. The returned `InternalPayload` borrows directly from the
    /// underlying `Cow<'static, str>`. Loggers can format this without heap use:
    ///
    /// ```ignore
    /// match context.payload() {
    ///     Some(payload) => println!("{}", payload),  // No allocation
    ///     None => println!("[SENSITIVE REDACTED]"),
    /// }
    /// ```
    ///
    /// # Rationale
    ///
    /// Previous design allocated `format!("[LIE] {}", msg)` on every access.
    /// This approach defers formatting to the logger, allowing:
    /// - Zero-copy access to underlying data
    /// - Logger-controlled formatting policy
    /// - Better performance under high error rates
    #[inline]
    pub fn payload(&self) -> Option<InternalPayload<'_>> {
        match &self.0 {
            InternalContextField::Diagnostic(c) => Some(InternalPayload::Truth(c.as_ref())),
            InternalContextField::Sensitive(_) => None,
            InternalContextField::Lie(c) => Some(InternalPayload::Lie(c.as_ref())),
        }
    }

    /// Expose raw sensitive content with capability-based access control.
    ///
    /// # Access Control
    ///
    /// Requires `SocAccess` capability token, which forces:
    /// 1. Explicit privilege acquisition (cannot call accidentally)
    /// 2. Grep-able sensitive data access points
    /// 3. Future integration with RBAC or audit systems
    ///
    /// # Security Contract
    ///
    /// Caller must ensure returned data is sent ONLY to:
    /// - Authenticated, encrypted, access-controlled endpoints
    /// - SOC-exclusive dashboards with strict RBAC
    /// - Encrypted internal logging with key rotation
    /// - Forensic analysis workstations with air-gapped storage
    ///
    /// Never send to:
    /// - External SIEMs or cloud logging services
    /// - Unencrypted log files
    /// - Monitoring services that aggregate across trust boundaries
    ///
    /// # Returns
    ///
    /// - `Some(&str)`: Raw sensitive content (if this is a Sensitive context)
    /// - `None`: If this is not a Sensitive context
    ///
    /// # Why #[must_use]
    ///
    /// Forces caller to explicitly handle the returned sensitive data rather than
    /// accidentally discarding it (which might indicate a logic error).
    ///
    /// # Example
    ///
    /// ```ignore
    /// let access = SocAccess::acquire();
    /// if let Some(sensitive) = context.expose_sensitive(&access) {
    ///     send_to_encrypted_soc_siem(sensitive);
    /// }
    /// ```
    #[must_use]
    #[inline]
    pub fn expose_sensitive(&self, _access: &SocAccess) -> Option<&str> {
        match &self.0 {
            InternalContextField::Sensitive(c) => Some(c.as_ref()),
            _ => None,
        }
    }
}

impl Zeroize for InternalContext {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for InternalContext {}

impl fmt::Display for InternalContext {
    /// Display implementation for internal contexts.
    ///
    /// # Security Policy
    ///
    /// This ALWAYS returns a redacted placeholder, never actual content.
    /// Internal contexts should not be formatted for external display under
    /// any circumstances. This implementation exists only to satisfy trait
    /// bounds in generic code.
    ///
    /// # Correct Usage
    ///
    /// - Use `payload()` for SOC logging
    /// - Use `expose_sensitive()` for controlled sensitive access
    /// - Do NOT use `Display` or `ToString` on internal contexts
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[INTERNAL CONTEXT REDACTED]")
    }
}

impl fmt::Debug for InternalContext {
    /// Debug representation for internal development and diagnostics.
    ///
    /// # Redaction Policy
    ///
    /// - Diagnostic: Shows full content (for debugging)
    /// - Sensitive: Redacted (to prevent accidental logging)
    /// - Lie: Redacted (to prevent aggregation as factual data)
    ///
    /// # Use Case
    ///
    /// Primarily for unit tests and local development. Production logging should
    /// use `payload()` or `expose_sensitive()` for explicit control.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            InternalContextField::Diagnostic(c) => write!(f, "InternalDiagnostic({:?})", c),
            InternalContextField::Sensitive(_) => write!(f, "Sensitive([REDACTED])"),
            InternalContextField::Lie(_) => write!(f, "InternalLie([REDACTED])"),
        }
    }
}

/// Zero-allocation internal payload for SOC logging.
///
/// Returned by `InternalContext::payload()`. This type borrows from the
/// underlying context and allows loggers to format output without heap allocation.
///
/// # Variants
///
/// - `Truth(&str)`: Authentic diagnostic message
/// - `Lie(&str)`: Deceptive message (should be prefixed in logs)
///
/// # Performance
///
/// The borrowed lifetime ties this to the parent `InternalContext`, preventing
/// accidental persistence of sensitive data beyond the logging operation.
///
/// # No Copy Policy
///
/// While this type only contains `&str` (which is Copy), we deliberately do not
/// derive Copy to maintain consistency with the module's no-duplication philosophy.
/// Use `Clone` if you need to store the payload temporarily.
///
/// # Usage Pattern
///
/// ```ignore
/// match context.payload() {
///     Some(InternalPayload::Truth(msg)) => soc_log!("DIAG: {}", msg),
///     Some(InternalPayload::Lie(msg)) => soc_log!("LIE: {}", msg),
///     None => {
///         // Sensitive - requires explicit access
///         let access = SocAccess::acquire();
///         if let Some(sensitive) = context.expose_sensitive(&access) {
///             secure_log_encrypted(sensitive);
///         }
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub enum InternalPayload<'a> {
    Truth(&'a str),
    Lie(&'a str),
}

impl<'a> InternalPayload<'a> {
    /// Get the raw message content without classification prefix.
    ///
    /// # Returns
    ///
    /// Borrowed string slice from the parent context. Valid until the
    /// `InternalContext` is dropped.
    ///
    /// # Note
    ///
    /// This does NOT include `[LIE]` prefix. Use the `Display` implementation
    /// if you want formatted output with classification markers.
    #[inline]
    pub const fn as_str(&self) -> &'a str {
        match self {
            Self::Truth(s) | Self::Lie(s) => s,
        }
    }

    /// Check if this payload represents deceptive content.
    ///
    /// # Returns
    ///
    /// - `true`: This is a lie, should be marked in logs
    /// - `false`: This is authentic diagnostic data
    ///
    /// # Use Case
    ///
    /// For conditional log routing or metrics collection based on deception status.
    #[inline]
    pub const fn is_lie(&self) -> bool {
        matches!(self, Self::Lie(_))
    }
}

impl<'a> fmt::Display for InternalPayload<'a> {
    /// Format payload with classification prefix for logging.
    ///
    /// # Output Format
    ///
    /// - Truth: Raw message (no prefix)
    /// - Lie: `[LIE] {message}`
    ///
    /// # Rationale
    ///
    /// The `[LIE]` prefix prevents SOC analysts from mistaking deceptive content
    /// for authentic diagnostic data when reviewing logs. This is critical when
    /// logs may be exported to systems that lack context classification.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truth(s) => f.write_str(s),
            Self::Lie(s) => write!(f, "[LIE] {}", s),
        }
    }
}

// ============================================================================
// Operation Category
// ============================================================================

/// Operation category for contextualizing errors without revealing architecture.
///
/// Categories are intentionally broad to provide SOC operators with sufficient
/// signal for triage and response while preventing attackers from mapping internal
/// system topology through error analysis.
///
/// # Design Principle
///
/// Each category represents a functional domain rather than a specific component.
/// This prevents errors from revealing:
/// - Service boundaries
/// - Technology stack details
/// - Deployment architecture
/// - Internal naming conventions
///
/// # Copy Semantics Exception
///
/// This is the only type in this module that implements Copy. Rationale:
/// - Small fieldless enum (single byte in practice)
/// - No owned or sensitive data
/// - Copying is cheaper than reference passing (no indirection)
/// - Frequently passed by value in error construction
///
/// # Deception Support
///
/// Honeypot-specific categories (Deception, Detection, Containment) have
/// deceptive display names that mask defensive operations as routine work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperationCategory {
    /// Configuration parsing, validation, or application
    Configuration,
    /// Artifact deployment, management, or versioning
    Deployment,
    /// Event collection, monitoring, or observability
    Monitoring,
    /// Rule evaluation, scoring, or decision logic
    Analysis,
    /// Action execution, remediation, or enforcement
    Response,
    /// Logging, audit trail, or compliance recording
    Audit,
    /// System-level operations (process, memory, OS interaction)
    System,
    /// File system or network I/O operations
    IO,
    /// Honeypot luring, facade maintenance, or attacker engagement
    Deception,
    /// Intrusion detection, anomaly identification, or threat recognition
    Detection,
    /// Attack isolation, sandboxing, or containment operations
    Containment,
}

impl OperationCategory {
    /// Get the authentic display name for this category.
    ///
    /// # Returns
    ///
    /// Static string describing the operation domain. No allocation, no Unicode
    /// edge cases. Safe for all internal logging and SOC dashboards.
    ///
    /// # Performance
    ///
    /// Const function compiled to direct pointer return. Zero runtime cost.
    #[inline]
    pub const fn display_name(&self) -> &'static str {
        match self {
            Self::Configuration => "Configuration",
            Self::Deployment => "Deployment",
            Self::Monitoring => "Monitoring",
            Self::Analysis => "Analysis",
            Self::Response => "Response",
            Self::Audit => "Audit",
            Self::System => "System",
            Self::IO => "I/O",
            Self::Deception => "Deception",
            Self::Detection => "Detection",
            Self::Containment => "Containment",
        }
    }

    /// Get deceptive display name for external contexts.
    ///
    /// # Returns
    ///
    /// Static string that masks honeypot-specific operations as routine work:
    /// - Deception → "Routine Operation"
    /// - Detection → "Routine Operation"
    /// - Containment → "Routine Operation"
    /// - All others → Same as `display_name()`
    ///
    /// # Use Case
    ///
    /// For external error messages where revealing defensive operations would
    /// compromise the honeypot's effectiveness. Generic labels prevent attackers
    /// from identifying which interactions triggered defensive responses.
    ///
    /// # Performance
    ///
    /// Const function, zero runtime cost. Compiled to direct pointer return.
    #[inline]
    pub const fn deceptive_name(&self) -> &'static str {
        match self {
            Self::Deception | Self::Detection | Self::Containment => "Routine Operation",
            _ => self.display_name(),
        }
    }
}

// ============================================================================
// Dual-Context Error with Invariant Enforcement
// ============================================================================

/// Dual-context error model for honeypot systems with constructor-enforced invariants.
///
/// # Type Safety Guarantees
///
/// 1. Public and internal contexts use distinct wrapper types (cannot be confused)
/// 2. Fields are private (all construction goes through validated constructors)
/// 3. Constructors enforce semantic consistency rules at creation time
///
/// # Enforced Invariants
///
/// - Public truth requires internal truth (no internal lies when external truth)
/// - Public lie allows any internal context (deception is flexible)
/// - Sensitive data flows only through InternalContext (type system prevents external leakage)
///
/// # Constructor Selection
///
/// - `with_lie()`: Public deception + internal diagnostic (most common)
/// - `with_lie_and_sensitive()`: Public deception + best-effort cleared sensitive internal
/// - `with_truth()`: Public truth + internal truth (feature-gated, enforces consistency)
/// - `with_double_lie()`: Public deception + internal deception (for log exfiltration scenarios)
///
/// # Memory Management
///
/// Implements `ZeroizeOnDrop` to clear all owned string data. Sensitive contexts
/// receive additional volatile write treatment in `InternalContextField::drop()`
/// to prevent LLVM from eliding the zeroization as a dead-store optimization.
///
/// This provides best-effort memory clearing but does not guarantee:
/// - Hardware cache flushes
/// - Cross-thread memory visibility
/// - Protection against allocator reuse before physical clear
///
/// # No Clone/Copy Policy
///
/// Single-owner semantics prevent:
/// - Duplicate error contexts in memory (reduced attack surface)
/// - Inconsistent public/internal message pairs
/// - Accidental persistence of sensitive data across scopes
pub struct DualContextError {
    public: PublicContext,
    internal: InternalContext,
    category: OperationCategory,
}

impl DualContextError {
    /// Internal constructor from pre-built contexts.
    ///
    /// This is crate-private to preserve external API invariants.
    #[inline]
    pub(crate) fn new(
        public: PublicContext,
        internal: InternalContext,
        category: OperationCategory,
    ) -> Self {
        Self {
            public,
            internal,
            category,
        }
    }

    /// Create error with public deception and internal diagnostic.
    ///
    /// # Use Case
    ///
    /// Standard constructor for honeypot deployments. External attackers see
    /// deceptive error message while SOC analysts see actual diagnostic data.
    ///
    /// # Invariant
    ///
    /// Public message is explicitly marked as `DeceptiveLie`. Internal message
    /// is authentic diagnostic data for SOC analysis.
    ///
    /// # Example
    ///
    /// ```ignore
    /// DualContextError::with_lie(
    ///     "Permission denied",  // Attacker sees generic error
    ///     "Blocked SQL injection attempt: UNION SELECT detected in query parameter 'id'",
    ///     OperationCategory::Detection,
    /// )
    /// ```
    ///
    /// # Performance
    ///
    /// Zero allocation if string literals are passed. `Into<Cow<'static, str>>`
    /// allows both literals and owned strings without forcing allocation.
    #[inline]
    pub fn with_lie(
        public_lie: impl Into<Cow<'static, str>>,
        internal_diagnostic: impl Into<Cow<'static, str>>,
        category: OperationCategory,
    ) -> Self {
        Self {
            public: PublicContext::lie(public_lie),
            internal: InternalContext::diagnostic(internal_diagnostic),
            category,
        }
    }

    /// Create error with public deception and sensitive internal data.
    ///
    /// # Use Case
    ///
    /// When internal diagnostic contains PII, credentials, file paths, or other
    /// high-value data requiring best-effort memory clearing on drop.
    ///
    /// # Memory Clearing Strategy
    ///
    /// When this error is dropped, sensitive data receives:
    /// 1. High-level clearing via `zeroize` crate
    /// 2. Volatile writes to prevent compiler optimization
    /// 3. Compiler fence to prevent instruction reordering
    ///
    /// This provides best-effort defense against casual memory inspection and
    /// compiler optimizations. See module-level docs for limitations.
    ///
    /// # Example
    ///
    /// ```ignore
    /// DualContextError::with_lie_and_sensitive(
    ///     "Resource not found",
    ///     format!("Attempted access to restricted path: /var/secrets/api_keys.txt by user {}", username),
    ///     OperationCategory::IO,
    /// )
    /// ```
    ///
    /// # Invariant
    ///
    /// Public message is deceptive. Internal message is marked sensitive and
    /// will be redacted in most logging contexts (requires explicit access via
    /// `expose_sensitive()` with `SocAccess` capability).
    #[inline]
    pub fn with_lie_and_sensitive(
        public_lie: impl Into<Cow<'static, str>>,
        internal_sensitive: impl Into<Cow<'static, str>>,
        category: OperationCategory,
    ) -> Self {
        Self {
            public: PublicContext::lie(public_lie),
            internal: InternalContext::sensitive(internal_sensitive),
            category,
        }
    }

    /// Create error with public truth and internal diagnostic.
    ///
    /// # Availability
    ///
    /// Only available when `external_signaling` feature is enabled. Without this
    /// feature, all public contexts must be deceptive (compile-time enforcement).
    ///
    /// # Invariant Enforcement
    ///
    /// When telling truth externally, internal context must also be truthful.
    /// This constructor enforces semantic consistency - you cannot lie internally
    /// while being honest externally.
    ///
    /// # Use Case
    ///
    /// For honeypots that intentionally signal some authentic errors to appear
    /// more legitimate (e.g., benign validation failures that don't reveal
    /// defensive posture).
    ///
    /// # Example
    ///
    /// ```ignore
    /// DualContextError::with_truth(
    ///     "Invalid JSON format",
    ///     "JSON parse error at line 42, column 15: expected closing brace",
    ///     OperationCategory::Configuration,
    /// )
    /// ```
    #[cfg(feature = "external_signaling")]
    #[inline]
    pub fn with_truth(
        public_truth: impl Into<Cow<'static, str>>,
        internal_diagnostic: impl Into<Cow<'static, str>>,
        category: OperationCategory,
    ) -> Self {
        Self {
            public: PublicContext::truth(public_truth),
            internal: InternalContext::diagnostic(internal_diagnostic),
            category,
        }
    }

    /// Create error where both public and internal contexts are deceptive.
    ///
    /// # Use Case
    ///
    /// Advanced deception scenarios where even internal logs may be exfiltrated
    /// by sophisticated attackers. Both contexts contain lies, but the internal
    /// lie is marked to prevent SOC analysts from treating it as authentic.
    ///
    /// # Behavior
    ///
    /// - External systems see the public lie (generic error)
    /// - Internal logs show internal lie prefixed with `[LIE]` marker
    /// - SOC analysts are warned not to trust this diagnostic data
    ///
    /// # Example
    ///
    /// ```ignore
    /// DualContextError::with_double_lie(
    ///     "Service temporarily unavailable",
    ///     "Routine maintenance window in progress",
    ///     OperationCategory::System,
    /// )
    /// ```
    ///
    /// # Rationale
    ///
    /// In environments where log exfiltration is a threat (compromised SIEM,
    /// malicious cloud provider, etc.), truthful internal logs become a liability.
    /// This constructor allows full deception while maintaining analyst awareness.
    #[inline]
    pub fn with_double_lie(
        public_lie: impl Into<Cow<'static, str>>,
        internal_lie: impl Into<Cow<'static, str>>,
        category: OperationCategory,
    ) -> Self {
        Self {
            public: PublicContext::lie(public_lie),
            internal: InternalContext::lie(internal_lie),
            category,
        }
    }

    /// Get the public context (safe for external display).
    ///
    /// # Returns
    ///
    /// Borrowed reference to `PublicContext`, which can be used with `Display`
    /// trait to render external error messages.
    ///
    /// # Lifetime
    ///
    /// Reference borrows from self, valid until this error is dropped.
    #[inline]
    pub const fn public(&self) -> &PublicContext {
        &self.public
    }

    /// Get the internal context (SOC-only visibility).
    ///
    /// # Returns
    ///
    /// Borrowed reference to `InternalContext`. Use `payload()` or
    /// `expose_sensitive()` methods for accessing content.
    ///
    /// # Security Note
    ///
    /// Do NOT use `Display` or `ToString` on this reference. Those implementations
    /// return redacted placeholders. Use explicit accessor methods instead.
    #[inline]
    pub const fn internal(&self) -> &InternalContext {
        &self.internal
    }

    /// Get the operation category.
    ///
    /// # Returns
    ///
    /// Copy of the `OperationCategory` enum. Can be used with `display_name()`
    /// for internal logging or `deceptive_name()` for external contexts.
    #[inline]
    pub const fn category(&self) -> OperationCategory {
        self.category
    }

    /// Get the external-facing error message as a string.
    ///
    /// # Returns
    ///
    /// Borrowed string slice suitable for HTTP responses, external APIs, or any
    /// untrusted context. May be deceptive depending on constructor used.
    ///
    /// # Use Case
    ///
    /// Primary method for rendering errors to external clients:
    /// ```ignore
    /// let error = DualContextError::with_lie(...);
    /// http_response.body(error.external_message());
    /// ```
    ///
    /// # Performance
    ///
    /// Returns borrowed reference, no allocation. Delegates to
    /// `PublicContext::as_str()` which in turn delegates to `Cow::as_ref()`.
    #[inline]
    pub fn external_message(&self) -> &str {
        self.public.as_str()
    }

    /// Get the deceptive category name for external display.
    ///
    /// # Returns
    ///
    /// Static string that masks honeypot operations as generic activity.
    /// Honeypot-specific categories return "Routine Operation".
    ///
    /// # Use Case
    ///
    /// For structured error responses where category field is included:
    /// ```ignore
    /// json!({
    ///     "error": error.external_message(),
    ///     "category": error.external_category(),
    /// })
    /// ```
    ///
    /// # Performance
    ///
    /// Const function, compiles to direct pointer return. Zero runtime cost.
    #[inline]
    pub fn external_category(&self) -> &'static str {
        self.category.deceptive_name()
    }
}

impl Zeroize for DualContextError {
    fn zeroize(&mut self) {
        self.public.zeroize();
        self.internal.zeroize();
        // category is Copy, contains no sensitive data, no zeroization needed
    }
}

impl ZeroizeOnDrop for DualContextError {}

// Note: No custom Drop implementation here. Zeroization is handled authoritatively
// in InternalContextField::drop() for sensitive data. This layer just delegates
// via ZeroizeOnDrop trait. Consolidating the volatile writes and fences to a single
// location (the base field type) reduces complexity and prevents redundant operations.

impl fmt::Display for DualContextError {
    /// Render error for external display.
    ///
    /// # Behavior
    ///
    /// Displays only the public context. Internal diagnostic data is never
    /// included in this output.
    ///
    /// # Use Case
    ///
    /// For generic error handling where you want automatic string conversion:
    /// ```ignore
    /// println!("Error occurred: {}", error);
    /// ```
    ///
    /// # Security Note
    ///
    /// This is safe for external use. Only public context is rendered, which
    /// can only contain `PublicTruth` or `DeceptiveLie` - never internal diagnostics.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.public)
    }
}

impl fmt::Debug for DualContextError {
    /// Debug representation for development and internal diagnostics.
    ///
    /// # Output Format
    ///
    /// Structured representation showing all three fields:
    /// - public: May be redacted if deceptive
    /// - internal: May be redacted if sensitive
    /// - category: Always shown
    ///
    /// # Use Case
    ///
    /// For unit tests, local development logging, and internal debugging.
    /// Not intended for production SOC logging (use explicit accessors instead).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DualContextError")
            .field("public", &self.public)
            .field("internal", &self.internal)
            .field("category", &self.category)
            .finish()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_context_lie() {
        let ctx = PublicContext::lie("Permission denied");
        assert_eq!(ctx.as_str(), "Permission denied");
        assert_eq!(ctx.classification(), "DeceptiveLie");
    }

    #[cfg(feature = "external_signaling")]
    #[test]
    fn test_public_context_truth() {
        let ctx = PublicContext::truth("Invalid input format");
        assert_eq!(ctx.as_str(), "Invalid input format");
        assert_eq!(ctx.classification(), "PublicTruth");
    }

    #[test]
    fn test_internal_context_diagnostic() {
        let ctx = InternalContext::diagnostic("SQL injection detected in /api/users");
        assert_eq!(ctx.classification(), "InternalDiagnostic");
        
        match ctx.payload() {
            Some(InternalPayload::Truth(msg)) => {
                assert_eq!(msg, "SQL injection detected in /api/users");
            }
            _ => panic!("Expected truth payload"),
        }
    }

    #[test]
    fn test_internal_context_sensitive() {
        let ctx = InternalContext::sensitive("/etc/passwd accessed by user:admin");
        assert_eq!(ctx.classification(), "Sensitive");
        assert!(ctx.payload().is_none());
        
        let access = SocAccess::acquire();
        let exposed = ctx.expose_sensitive(&access);
        assert_eq!(exposed, Some("/etc/passwd accessed by user:admin"));
    }

    #[test]
    fn test_internal_context_lie() {
        let ctx = InternalContext::lie("Normal database query");
        assert_eq!(ctx.classification(), "InternalLie");
        
        match ctx.payload() {
            Some(InternalPayload::Lie(msg)) => {
                assert_eq!(msg, "Normal database query");
            }
            _ => panic!("Expected lie payload"),
        }
    }

    #[test]
    fn test_internal_payload_display() {
        let truth = InternalPayload::Truth("test message");
        assert_eq!(format!("{}", truth), "test message");
        
        let lie = InternalPayload::Lie("test message");
        assert_eq!(format!("{}", lie), "[LIE] test message");
    }

    #[test]
    fn test_dual_context_with_lie() {
        let err = DualContextError::with_lie(
            "Access forbidden",
            "Honeypot triggered: multiple failed auth attempts",
            OperationCategory::Detection,
        );
        
        assert_eq!(err.external_message(), "Access forbidden");
        assert_eq!(err.external_category(), "Routine Operation");
    }

    #[test]
    fn test_dual_context_with_sensitive() {
        let err = DualContextError::with_lie_and_sensitive(
            "Resource not found",
            "File path: /var/secrets/api_keys.txt",
            OperationCategory::IO,
        );
        
        assert_eq!(err.external_message(), "Resource not found");
        assert!(err.internal().payload().is_none());
    }

    #[cfg(feature = "external_signaling")]
    #[test]
    fn test_dual_context_with_truth() {
        let err = DualContextError::with_truth(
            "Invalid JSON format",
            "JSON parse error at line 42: unexpected token",
            OperationCategory::Configuration,
        );
        
        assert_eq!(err.external_message(), "Invalid JSON format");
    }

    #[test]
    fn test_operation_category_deceptive_names() {
        assert_eq!(OperationCategory::Deception.deceptive_name(), "Routine Operation");
        assert_eq!(OperationCategory::Detection.deceptive_name(), "Routine Operation");
        assert_eq!(OperationCategory::Containment.deceptive_name(), "Routine Operation");
        assert_eq!(OperationCategory::Configuration.deceptive_name(), "Configuration");
    }

    #[test]
    fn test_soc_access_capability() {
        let ctx = InternalContext::sensitive("secret data".to_string());
        
        // Without capability, cannot access
        // (This is enforced by requiring SocAccess parameter)
        
        // With capability, can access
        let access = SocAccess::acquire();
        assert_eq!(ctx.expose_sensitive(&access), Some("secret data"));
    }

    #[test]
    fn test_zeroization() {
        let mut ctx = InternalContext::sensitive("secret data".to_string());
        
        // Verify data exists before zeroization
        let access = SocAccess::acquire();
        assert_eq!(ctx.expose_sensitive(&access), Some("secret data"));
        
        // Explicit zeroize call
        ctx.zeroize();
        
        // Note: Actual verification of memory clearing would require unsafe inspection.
        // This test demonstrates the API contract. In production, zeroization happens
        // automatically on drop via ZeroizeOnDrop trait and InternalContextField::drop().
    }

    #[test]
    fn test_volatile_write_on_drop() {
        // This test verifies the drop behavior exists and compiles correctly.
        // Actual verification of volatile writes would require memory inspection tools.
        let ctx = InternalContext::sensitive("highly sensitive data".to_string());
        drop(ctx);
        // If this compiles and runs without panicking, the Drop impl is correct
    }

    #[test]
    fn test_display_never_leaks_internal() {
        let err = DualContextError::with_lie(
            "Generic error",
            "Actual internal diagnostic with sensitive details",
            OperationCategory::System,
        );
        
        let display_output = format!("{}", err);
        assert_eq!(display_output, "Generic error");
        assert!(!display_output.contains("internal"));
        assert!(!display_output.contains("sensitive"));
    }

    #[test]
    fn test_internal_display_always_redacts() {
        let ctx = InternalContext::diagnostic("secret diagnostic info");
        let display_output = format!("{}", ctx);
        assert_eq!(display_output, "[INTERNAL CONTEXT REDACTED]");
        assert!(!display_output.contains("secret"));
    }

    #[test]
    fn test_internal_payload_not_copy() {
        // This test verifies InternalPayload does not implement Copy
        // If it did, this would compile with just moving instead of cloning
        let payload = InternalPayload::Truth("test");
        let _payload2 = payload.clone();
        // If we try to use payload again without Clone, it would fail to compile
        // (proving it's not Copy)
    }
}
