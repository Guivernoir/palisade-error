//! Internal error context that is FULLY ZEROIZED on drop.
//!
//! All fields are protected, not just those marked "sensitive".
//! This prevents post-compromise memory scraping from recovering:
//! - Operation names (reveal code paths)
//! - Details (reveal validation logic)
//! - Source errors (reveal internal structure)
//! - Metadata (reveal correlation IDs, session tokens)
//!
//! Fields are kept separate by sensitivity to avoid conflation:
//! - `source_internal`: Non-sensitive error details (e.g., "NotFound")
//! - `source_sensitive`: Sensitive context (e.g., "/etc/passwd")
//!
//! # Security
//!
//! Every field is zeroized because attackers don't discriminate.
//! If it's in memory, it's a target.

use crate::ContextField;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Error context with full zeroization on drop.
///
/// All fields are zeroized when the error is dropped, preventing
/// memory scraping attacks.
#[derive(Clone)]
pub struct ErrorContext {
    /// Operation name (zeroized)
    pub operation: ContextField,
    /// Error details (zeroized)
    pub details: ContextField,
    /// Internal source information (zeroized)
    pub source_internal: Option<ContextField>,
    /// Sensitive source information (zeroized)
    pub source_sensitive: Option<ContextField>,
    /// Additional metadata (zeroized)
    pub metadata: Vec<(&'static str, ContextField)>,
}

impl Zeroize for ErrorContext {
    fn zeroize(&mut self) {
        self.operation.zeroize();
        self.details.zeroize();
        self.source_internal.zeroize();
        self.source_sensitive.zeroize();
        // Zeroize each ContextField in metadata, skip the &'static str keys
        for (_key, value) in &mut self.metadata {
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

impl ErrorContext {
    pub fn new(operation: impl Into<String>, details: impl Into<String>) -> Self {
        Self {
            operation: ContextField::Internal(operation.into()),
            details: ContextField::Internal(details.into()),
            source_internal: None,
            source_sensitive: None,
            metadata: Vec::new(),
        }
    }

    pub fn with_sensitive(
        operation: impl Into<String>,
        details: impl Into<String>,
        sensitive_info: impl Into<String>,
    ) -> Self {
        Self {
            operation: ContextField::Internal(operation.into()),
            details: ContextField::Internal(details.into()),
            source_internal: None,
            source_sensitive: Some(ContextField::Sensitive(sensitive_info.into())),
            metadata: Vec::new(),
        }
    }

    pub fn with_source_split(
        operation: impl Into<String>,
        details: impl Into<String>,
        internal_source: impl Into<String>,
        sensitive_source: impl Into<String>,
    ) -> Self {
        Self {
            operation: ContextField::Internal(operation.into()),
            details: ContextField::Internal(details.into()),
            source_internal: Some(ContextField::Internal(internal_source.into())),
            source_sensitive: Some(ContextField::Sensitive(sensitive_source.into())),
            metadata: Vec::new(),
        }
    }

    /// Add metadata in-place (no cloning, no allocation waste)
    #[inline]
    pub fn add_metadata(&mut self, key: &'static str, value: impl Into<String>) {
        self.metadata.push((key, ContextField::Internal(value.into())));
    }
}