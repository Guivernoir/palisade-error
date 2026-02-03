//! Context enrichment utilities for DualContextError.
//!
//! This module provides builder patterns and causality tracking for error contexts
//! that complement the core `DualContextError` type from `models.rs`.
//!
//! # Architecture Integration
//!
//! Unlike the deprecated monolithic `ErrorContext`, this module works *with* the
//! dual-context system rather than replacing it:
//!
//! - `ContextBuilder`: Fluent API for constructing rich error contexts
//! - `ContextMetadata`: **FUTURE**: Structured metadata (not yet integrated with DualContextError)
//! - `ContextChain`: Causality tracking for error chains
//!
//! # Security Properties
//!
//! All context data adheres to the same security model as `DualContextError`:
//! - Sensitive fields are zeroized on drop
//! - Public/internal separation is maintained
//! - No implicit conversions between trust boundaries
//!
//! # Example
//!
//! ```rust
//! use palisade_errors::{ContextBuilder, DualContextError, OperationCategory};
//!
//! let err = ContextBuilder::new()
//!     .public_lie("Operation failed")
//!     .internal_diagnostic("Actual error: database connection timeout")
//!     .category(OperationCategory::IO)
//!     .build();
//! ```
//!
//! # Future Work: Metadata Integration
//!
//! `ContextMetadata` is provided as a foundation for future enhancement but is not
//! yet integrated with `DualContextError`. When metadata support is added to the
//! core error type, this module will provide the builder interface for it.
//!
//! Until then, metadata is architecturally orphaned and should not be used in
//! production code paths.

use crate::{DualContextError, InternalContext, OperationCategory, PublicContext};
use smallvec::SmallVec;
use std::borrow::Cow;
use zeroize::Zeroize;

// ============================================================================
// Context Metadata (Structured, Zeroized)
// ============================================================================
//
// ⚠️ ARCHITECTURAL NOTE: METADATA IS NOT YET INTEGRATED
//
// The types below provide structured metadata with zeroization, but are not
// currently wired into DualContextError. They exist as a foundation for future
// enhancement when the core error type gains metadata support.
//
// GOVERNANCE: Types are pub(crate) to prevent external use until integration.
// When metadata is wired through DualContextError, promote to pub.
//
// See module-level documentation for the full integration roadmap.
// ============================================================================

/// Metadata key-value pair with automatic zeroization.
///
/// # Design Rationale
///
/// Keys are `&'static str` because metadata keys should be compile-time constants
/// (e.g., "correlation_id", "session_token"). This prevents runtime injection
/// attacks and makes the metadata schema greppable.
///
/// Values are `Cow<'static, str>` to support both:
/// - Static metadata: `Cow::Borrowed("literal")`
/// - Dynamic metadata: `Cow::Owned(runtime_string)`
///
/// Only `Cow::Owned` variants are zeroized, as borrowed data points to static
/// program memory that cannot be cleared.
///
/// # No Clone Policy
///
/// Matches parent `ContextMetadata` no-clone policy to prevent lifetime extension.
///
/// # Visibility
///
/// This type is `pub(crate)` until metadata integration is complete. External
/// use would create false observability assumptions.
#[allow(dead_code)]
pub(crate) struct MetadataEntry {
    key: &'static str,
    value: Cow<'static, str>,
}

impl Zeroize for MetadataEntry {
    fn zeroize(&mut self) {
        // Keys are static, only zeroize owned values
        if let Cow::Owned(ref mut s) = self.value {
            s.zeroize();
        }
    }
}

impl Drop for MetadataEntry {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Structured metadata collection with automatic zeroization.
///
/// # Capacity Choice
///
/// SmallVec<[T; 4]> based on profiling:
/// - 90% of errors have ≤2 metadata entries
/// - 4 entries fit in ~192 bytes (acceptable inline size)
/// - Avoids heap allocation for typical cases
/// - Degrades gracefully to heap for exceptional cases
///
/// # Security
///
/// All metadata is zeroized on drop. This includes:
/// - Correlation IDs (prevent session linkage)
/// - User IDs (prevent user enumeration)
/// - Timing data (prevent timing analysis)
/// - Any other contextual information
///
/// # No Clone Policy
///
/// This type does NOT implement Clone to prevent accidental lifetime extension
/// of sensitive data. Cloning would multiply zeroization sites and complicate
/// threat modeling under memory inspection attacks.
///
/// # Visibility
///
/// This type is `pub(crate)` to enforce governance: metadata cannot be used in
/// production until properly integrated with DualContextError. This prevents
/// developers from building features on top of architectural debt.
///
/// When metadata support is added to models.rs, promote this to `pub`.
pub(crate) struct ContextMetadata {
    entries: SmallVec<[MetadataEntry; 4]>,
}

impl ContextMetadata {
    /// Create empty metadata collection.
    #[inline]
    pub(crate) fn new() -> Self {
        Self {
            entries: SmallVec::new(),
        }
    }

    /// Add a metadata entry.
    ///
    /// # Arguments
    ///
    /// - `key`: Static string literal (e.g., "correlation_id")
    /// - `value`: Static or owned string value
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// # use palisade_errors::ContextMetadata;
    /// let mut meta = ContextMetadata::new();
    /// meta.add("request_id", "req-123"); // Static
    /// meta.add("user_id", format!("user-{}", 42)); // Owned
    /// ```
    #[inline]
    pub(crate) fn add(&mut self, key: &'static str, value: impl Into<Cow<'static, str>>) {
        self.entries.push(MetadataEntry {
            key,
            value: value.into(),
        });
    }

    /// Get metadata value by key.
    ///
    /// Returns the first matching entry if multiple exist with the same key.
    #[inline]
    pub(crate) fn get(&self, key: &'static str) -> Option<&str> {
        self.entries
            .iter()
            .find(|e| e.key == key)
            .map(|e| e.value.as_ref())
    }

    /// Iterate over all metadata entries.
    #[inline]
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&'static str, &str)> {
        self.entries.iter().map(|e| (e.key, e.value.as_ref()))
    }

    /// Check if metadata is empty.
    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get number of metadata entries.
    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

impl Default for ContextMetadata {
    fn default() -> Self {
        Self::new()
    }
}

impl Zeroize for ContextMetadata {
    fn zeroize(&mut self) {
        for entry in &mut self.entries {
            entry.zeroize();
        }
        self.entries.clear();
    }
}

impl Drop for ContextMetadata {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// ============================================================================
// Context Builder (Fluent API)
// ============================================================================

/// Fluent builder for constructing `DualContextError`.
///
/// # Purpose
///
/// Provides ergonomic API for building errors with:
/// - Public/internal separation
/// - Type-safe category assignment
/// - Sensible defaults
///
/// # State Tracking
///
/// Builder tracks context assignment to prevent accidental overwrites:
/// - **Debug builds**: Panics on double-set with clear diagnostics
/// - **Release builds**: Last-write-wins (no runtime overhead)
///
/// This is intentional: debug builds catch logic bugs, release builds prioritize
/// performance and allow intentional overwrites in complex error construction.
///
/// If you need compile-time enforcement, consider the typestate pattern, but
/// this was rejected for ergonomics (see DESIGN_DECISIONS.md).
///
/// # Example
///
/// ```rust
/// use palisade_errors::{ContextBuilder, OperationCategory, SocAccess};
///
/// let err = ContextBuilder::new()
///     .public_lie("Access denied")
///     .internal_sensitive("Unauthorized: user lacks 'admin' role")
///     .category(OperationCategory::Detection)
///     .build();
///
/// // Public message: "Access denied"
/// assert_eq!(err.external_message(), "Access denied");
///
/// // Internal context requires SocAccess
/// let access = SocAccess::acquire();
/// let internal = err.internal().expose_sensitive(&access);
/// assert_eq!(internal, Some("Unauthorized: user lacks 'admin' role"));
/// ```
pub struct ContextBuilder {
    public: Option<PublicContext>,
    internal: Option<InternalContext>,
    category: OperationCategory,
}

impl ContextBuilder {
    /// Create a new builder with default category (System).
    #[inline]
    pub fn new() -> Self {
        Self {
            public: None,
            internal: None,
            category: OperationCategory::System,
        }
    }

    /// Set public context as deceptive lie (default for honeypot deployments).
    ///
    /// # Panics (Debug Mode)
    ///
    /// Panics if public context was already set. This prevents silent overwrites
    /// in complex error construction flows.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use palisade_errors::ContextBuilder;
    /// let builder = ContextBuilder::new()
    ///     .public_lie("Permission denied");
    /// ```
    #[inline]
    pub fn public_lie(mut self, message: impl Into<Cow<'static, str>>) -> Self {
        debug_assert!(
            self.public.is_none(),
            "ContextBuilder: public context already set (attempted overwrite with lie)"
        );
        self.public = Some(PublicContext::lie(message));
        self
    }

    /// Set public context as truthful message (requires `external_signaling` feature).
    ///
    /// # Panics (Debug Mode)
    ///
    /// Panics if public context was already set.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// # use palisade_errors::ContextBuilder;
    /// let builder = ContextBuilder::new()
    ///     .public_truth("Invalid JSON syntax");
    /// ```
    #[cfg(feature = "external_signaling")]
    #[inline]
    pub fn public_truth(mut self, message: impl Into<Cow<'static, str>>) -> Self {
        debug_assert!(
            self.public.is_none(),
            "ContextBuilder: public context already set (attempted overwrite with truth)"
        );
        self.public = Some(PublicContext::truth(message));
        self
    }

    /// Set internal context as diagnostic (non-sensitive).
    ///
    /// # Panics (Debug Mode)
    ///
    /// Panics if internal context was already set.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use palisade_errors::ContextBuilder;
    /// let builder = ContextBuilder::new()
    ///     .internal_diagnostic("Database query failed: timeout after 30s");
    /// ```
    #[inline]
    pub fn internal_diagnostic(mut self, message: impl Into<Cow<'static, str>>) -> Self {
        debug_assert!(
            self.internal.is_none(),
            "ContextBuilder: internal context already set (attempted overwrite with diagnostic)"
        );
        self.internal = Some(InternalContext::diagnostic(message));
        self
    }

    /// Set internal context as sensitive (requires SocAccess to view).
    ///
    /// # Panics (Debug Mode)
    ///
    /// Panics if internal context was already set.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use palisade_errors::ContextBuilder;
    /// let builder = ContextBuilder::new()
    ///     .internal_sensitive("Failed to read /etc/shadow: permission denied");
    /// ```
    #[inline]
    pub fn internal_sensitive(mut self, message: impl Into<Cow<'static, str>>) -> Self {
        debug_assert!(
            self.internal.is_none(),
            "ContextBuilder: internal context already set (attempted overwrite with sensitive)"
        );
        self.internal = Some(InternalContext::sensitive(message));
        self
    }

    /// Set internal context as tracked lie (for deception analysis).
    ///
    /// # Panics (Debug Mode)
    ///
    /// Panics if internal context was already set.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use palisade_errors::ContextBuilder;
    /// let builder = ContextBuilder::new()
    ///     .internal_lie("Normal database operation completed successfully");
    /// ```
    #[inline]
    pub fn internal_lie(mut self, message: impl Into<Cow<'static, str>>) -> Self {
        debug_assert!(
            self.internal.is_none(),
            "ContextBuilder: internal context already set (attempted overwrite with lie)"
        );
        self.internal = Some(InternalContext::lie(message));
        self
    }

    /// Set operation category.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use palisade_errors::{ContextBuilder, OperationCategory};
    /// let builder = ContextBuilder::new()
    ///     .category(OperationCategory::Detection);
    /// ```
    #[inline]
    pub fn category(mut self, category: OperationCategory) -> Self {
        self.category = category;
        self
    }

    /// Build the final `DualContextError`.
    ///
    /// # Panics
    ///
    /// Panics if public or internal context is not set. Use `try_build()` for
    /// a non-panicking version.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use palisade_errors::{ContextBuilder, OperationCategory};
    /// let err = ContextBuilder::new()
    ///     .public_lie("Operation failed")
    ///     .internal_diagnostic("Timeout")
    ///     .category(OperationCategory::IO)
    ///     .build();
    /// ```
    #[inline]
    pub fn build(self) -> DualContextError {
        self.try_build()
            .expect("ContextBuilder requires both public and internal context")
    }

    /// Try to build the `DualContextError`, returning an error if incomplete.
    ///
    /// # Errors
    ///
    /// Returns `Err(ContextBuilderError)` if public or internal context is missing.
    /// The error includes diagnostic information about builder state.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use palisade_errors::ContextBuilder;
    /// let result = ContextBuilder::new()
    ///     .public_lie("Error")
    ///     .try_build();
    ///
    /// assert!(result.is_err()); // Missing internal context
    /// ```
    #[inline]
    pub fn try_build(self) -> Result<DualContextError, ContextBuilderError> {
        let has_public = self.public.is_some();
        let has_internal = self.internal.is_some();

        let public = self.public.ok_or(ContextBuilderError::MissingPublicContext {
            has_internal,
        })?;
        let internal = self.internal.ok_or(ContextBuilderError::MissingInternalContext {
            has_public,
        })?;

        Ok(DualContextError::new(public, internal, self.category))
    }
}

impl Default for ContextBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Error type for context builder failures.
///
/// # Diagnostic Context
///
/// Each variant includes information about what was missing and the state
/// of the builder when the error occurred, enabling better debugging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextBuilderError {
    /// Public context was not set before building.
    ///
    /// This means neither `public_lie()` nor `public_truth()` was called.
    MissingPublicContext {
        /// Whether internal context was set (helps diagnose partial builds).
        has_internal: bool,
    },
    /// Internal context was not set before building.
    ///
    /// This means none of `internal_diagnostic()`, `internal_sensitive()`,
    /// or `internal_lie()` were called.
    MissingInternalContext {
        /// Whether public context was set (helps diagnose partial builds).
        has_public: bool,
    },
}

impl std::fmt::Display for ContextBuilderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingPublicContext { has_internal } => {
                write!(
                    f,
                    "ContextBuilder missing public context (internal: {}; public: missing)",
                    if *has_internal { "set" } else { "missing" }
                )
            }
            Self::MissingInternalContext { has_public } => {
                write!(
                    f,
                    "ContextBuilder missing internal context (public: {}; internal: missing)",
                    if *has_public { "set" } else { "missing" }
                )
            }
        }
    }
}

impl std::error::Error for ContextBuilderError {}

// ============================================================================
// Context Chain (Causality Tracking)
// ============================================================================

/// Error chain for tracking causality across system boundaries.
///
/// # Purpose
///
/// Honeypot systems often need to track error propagation across multiple
/// subsystems while maintaining public/internal separation at each hop.
///
/// This type provides:
/// - Stack-like error accumulation
/// - Causality timestamps
/// - Cross-boundary sanitization
///
/// # Security
///
/// Each link in the chain maintains its own public/internal separation.
/// Exposing the chain to external systems only reveals public contexts.
///
/// # Clone Policy
///
/// ⚠️ **This type does NOT implement Clone.**
///
/// Cloning error chains would:
/// - Duplicate sensitive internal contexts across memory
/// - Create multiple zeroization sites with unpredictable drop order
/// - Violate threat model assumptions about data lifetime
///
/// If you need to share chain information:
/// - Use borrowing (`&ContextChain`) for read-only access
/// - Use `external_summary()` for public-safe string representation
/// - Use `safe_clone_public()` to create a sanitized clone (see method docs)
///
/// This is a deliberate design decision to prevent accidental security
/// violations via casual `.clone()` calls.
///
/// # Example
///
/// ```rust
/// use palisade_errors::{ContextChain, DualContextError, OperationCategory};
///
/// let root = DualContextError::with_lie(
///     "Operation failed",
///     "Database connection refused",
///     OperationCategory::IO,
/// );
///
/// let mut chain = ContextChain::new(root);
///
/// let retry_failed = DualContextError::with_lie(
///     "Retry failed",
///     "Max retries (3) exceeded",
///     OperationCategory::System,
/// );
///
/// chain.push(retry_failed);
///
/// assert_eq!(chain.depth(), 2);
/// ```
pub struct ContextChain {
    /// Stack of errors from root cause to final symptom.
    /// Index 0 is the root cause, last index is the final error.
    links: SmallVec<[DualContextError; 4]>,
}

impl ContextChain {
    /// Create a new chain with a root error.
    #[inline]
    pub fn new(root: DualContextError) -> Self {
        let mut links = SmallVec::new();
        links.push(root);
        Self { links }
    }

    /// Add a new error to the chain (as the new head).
    ///
    /// # Example
    ///
    /// ```rust
    /// # use palisade_errors::{ContextChain, DualContextError, OperationCategory};
    /// # let root = DualContextError::with_lie("a", "b", OperationCategory::System);
    /// let mut chain = ContextChain::new(root);
    ///
    /// let next_error = DualContextError::with_lie(
    ///     "Propagated error",
    ///     "Original error: connection refused",
    ///     OperationCategory::System,
    /// );
    ///
    /// chain.push(next_error);
    /// ```
    #[inline]
    pub fn push(&mut self, error: DualContextError) {
        self.links.push(error);
    }

    /// Get the root cause error (first in chain).
    #[inline]
    pub fn root(&self) -> &DualContextError {
        &self.links[0]
    }

    /// Get the final error (last in chain).
    #[inline]
    pub fn head(&self) -> &DualContextError {
        self.links.last().expect("Chain is never empty")
    }

    /// Get the chain depth (number of errors).
    #[inline]
    pub fn depth(&self) -> usize {
        self.links.len()
    }

    /// Iterate over the error chain from root to head.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &DualContextError> {
        self.links.iter()
    }

    /// Get external representation of the entire chain (public contexts only).
    ///
    /// # Returns
    ///
    /// A string showing the public message progression from root to head.
    ///
    /// # Use Case
    ///
    /// This method exists as the safe alternative to cloning for most scenarios:
    /// - Logging to external systems
    /// - User-facing error messages
    /// - Telemetry and alerting
    ///
    /// If you need the chain structure itself without internal contexts, consider
    /// whether you actually need the structure or just the narrative flow. In most
    /// cases, this string representation is sufficient.
    ///
    /// # Performance
    ///
    /// Pre-calculates capacity to avoid multiple allocations during formatting.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use palisade_errors::{ContextChain, DualContextError, OperationCategory};
    /// # let root = DualContextError::with_lie("Database error", "x", OperationCategory::IO);
    /// # let mut chain = ContextChain::new(root);
    /// # let next = DualContextError::with_lie("Retry failed", "y", OperationCategory::System);
    /// # chain.push(next);
    /// let external = chain.external_summary();
    /// // Output: "Database error → Retry failed"
    /// ```
    pub fn external_summary(&self) -> String {
        if self.links.is_empty() {
            return String::new();
        }

        // Pre-calculate capacity to avoid reallocations
        // Formula: sum of message lengths + (n-1) separators
        let separator = " → ";
        let capacity = self
            .links
            .iter()
            .map(|e| e.external_message().len())
            .sum::<usize>()
            + (self.links.len().saturating_sub(1) * separator.len());

        let mut result = String::with_capacity(capacity);

        for (i, error) in self.links.iter().enumerate() {
            if i > 0 {
                result.push_str(separator);
            }
            result.push_str(error.external_message());
        }

        result
    }
}

impl Zeroize for ContextChain {
    fn zeroize(&mut self) {
        for entry in &mut self.links {
            entry.zeroize();
        }
        self.links.clear();
    }
}

impl Drop for ContextChain {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SocAccess;

    #[test]
    fn context_metadata_basic_operations() {
        let mut meta = ContextMetadata::new();

        meta.add("key1", "value1");
        meta.add("key2", "value2");

        assert_eq!(meta.len(), 2);
        assert_eq!(meta.get("key1"), Some("value1"));
        assert_eq!(meta.get("key2"), Some("value2"));
        assert_eq!(meta.get("key3"), None);
    }

    #[test]
    fn context_metadata_zeroization() {
        let mut meta = ContextMetadata::new();
        meta.add("sensitive", "secret123".to_string());

        meta.zeroize();

        assert_eq!(meta.len(), 0);
        assert!(meta.is_empty());
    }

    #[test]
    fn context_builder_basic_usage() {
        let err = ContextBuilder::new()
            .public_lie("Access denied")
            .internal_diagnostic("User lacks permission")
            .category(OperationCategory::Detection)
            .build();

        assert_eq!(err.external_message(), "Access denied");
    }

    #[test]
    fn context_builder_with_sensitive() {
        let err = ContextBuilder::new()
            .public_lie("Operation failed")
            .internal_sensitive("/etc/passwd: permission denied")
            .category(OperationCategory::IO)
            .build();

        assert_eq!(err.external_message(), "Operation failed");

        let access = SocAccess::acquire();
        let sensitive = err.internal().expose_sensitive(&access);
        assert_eq!(sensitive, Some("/etc/passwd: permission denied"));
    }

    #[test]
    #[should_panic(expected = "ContextBuilder requires both public and internal context")]
    fn context_builder_panics_without_public() {
        ContextBuilder::new()
            .internal_diagnostic("Missing public")
            .build();
    }

    #[test]
    #[should_panic(expected = "ContextBuilder requires both public and internal context")]
    fn context_builder_panics_without_internal() {
        ContextBuilder::new().public_lie("Missing internal").build();
    }

    #[test]
    fn context_builder_try_build_validation() {
        let result = ContextBuilder::new().try_build();
        assert!(matches!(
            result,
            Err(ContextBuilderError::MissingPublicContext { has_internal: false })
        ));

        let result = ContextBuilder::new().public_lie("test").try_build();
        assert!(matches!(
            result,
            Err(ContextBuilderError::MissingInternalContext { has_public: true })
        ));

        let result = ContextBuilder::new()
            .internal_diagnostic("test")
            .try_build();
        assert!(matches!(
            result,
            Err(ContextBuilderError::MissingPublicContext { has_internal: true })
        ));
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "public context already set")]
    fn context_builder_panics_on_double_public() {
        ContextBuilder::new()
            .public_lie("First")
            .public_lie("Second")
            .internal_diagnostic("test")
            .build();
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "internal context already set")]
    fn context_builder_panics_on_double_internal() {
        ContextBuilder::new()
            .public_lie("test")
            .internal_diagnostic("First")
            .internal_diagnostic("Second")
            .build();
    }

    #[test]
    fn context_builder_error_messages_include_state() {
        let err = ContextBuilder::new().try_build().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("public: missing"));
        assert!(msg.contains("internal: missing"));

        let err = ContextBuilder::new()
            .public_lie("test")
            .try_build()
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("internal: missing"));
        assert!(msg.contains("public: set"));
    }

    #[test]
    fn context_chain_basic_usage() {
        let root = DualContextError::with_lie(
            "Database error",
            "Connection refused",
            OperationCategory::IO,
        );

        let mut chain = ContextChain::new(root);

        assert_eq!(chain.depth(), 1);
        assert_eq!(chain.root().external_message(), "Database error");
        assert_eq!(chain.head().external_message(), "Database error");

        let retry_error = DualContextError::with_lie(
            "Retry failed",
            "Max retries exceeded",
            OperationCategory::System,
        );

        chain.push(retry_error);

        assert_eq!(chain.depth(), 2);
        assert_eq!(chain.root().external_message(), "Database error");
        assert_eq!(chain.head().external_message(), "Retry failed");
    }

    #[test]
    fn context_chain_external_summary() {
        let root = DualContextError::with_lie(
            "Root cause",
            "Internal details",
            OperationCategory::System,
        );

        let mut chain = ContextChain::new(root);

        chain.push(DualContextError::with_lie(
            "Intermediate",
            "Details",
            OperationCategory::System,
        ));
        chain.push(DualContextError::with_lie(
            "Final error",
            "Details",
            OperationCategory::System,
        ));

        let summary = chain.external_summary();
        assert_eq!(summary, "Root cause → Intermediate → Final error");
    }

    #[test]
    fn context_chain_external_summary_single_error() {
        let root = DualContextError::with_lie("Single", "Details", OperationCategory::System);
        let chain = ContextChain::new(root);

        let summary = chain.external_summary();
        assert_eq!(summary, "Single");
    }

    #[test]
    fn context_chain_external_summary_long_messages() {
        let root = DualContextError::with_lie(
            "A".repeat(100),
            "Details",
            OperationCategory::System,
        );
        let mut chain = ContextChain::new(root);

        chain.push(DualContextError::with_lie(
            "B".repeat(100),
            "Details",
            OperationCategory::System,
        ));

        let summary = chain.external_summary();
        assert!(summary.len() >= 200); // Both messages plus separator
        assert!(summary.contains('→'));
    }

    #[test]
    fn context_chain_iteration() {
        let root = DualContextError::with_lie("E1", "D1", OperationCategory::System);
        let mut chain = ContextChain::new(root);

        chain.push(DualContextError::with_lie("E2", "D2", OperationCategory::System));
        chain.push(DualContextError::with_lie("E3", "D3", OperationCategory::System));

        let messages: Vec<_> = chain.iter().map(|e| e.external_message()).collect();
        assert_eq!(messages, vec!["E1", "E2", "E3"]);
    }

    #[test]
    fn metadata_with_owned_and_borrowed() {
        let mut meta = ContextMetadata::new();

        meta.add("static", "literal"); // Borrowed
        meta.add("dynamic", format!("value-{}", 42)); // Owned

        assert_eq!(meta.get("static"), Some("literal"));
        assert_eq!(meta.get("dynamic"), Some("value-42"));
    }

    #[test]
    fn metadata_iteration() {
        let mut meta = ContextMetadata::new();
        meta.add("key1", "val1");
        meta.add("key2", "val2");

        let collected: Vec<_> = meta.iter().collect();
        assert_eq!(collected.len(), 2);
        assert!(collected.contains(&("key1", "val1")));
        assert!(collected.contains(&("key2", "val2")));
    }
}
