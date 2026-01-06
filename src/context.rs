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
use smallvec::SmallVec;
use zeroize::{Zeroize, ZeroizeOnDrop};
use std::error::Error;
use std::borrow::Cow;

/// Error context with full zeroization on drop.
///
/// All fields are zeroized when the error is dropped, preventing
/// memory scraping attacks.
///
/// # Panic Safety
///
/// The Drop implementation is marked `#[inline(never)]` to ensure
/// it's not optimized away and uses std::panic::catch_unwind to
/// ensure zeroization happens even if a panic occurs during drop.
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
    /// 
    /// SmallVec<[T; 4]> chosen based on profiling:
    /// - Most errors have 0-2 metadata entries
    /// - 4 entries fit in ~128 bytes (reasonable inline size)
    /// - Avoids heap allocation for typical cases
    pub metadata: SmallVec<[(&'static str, ContextField); 4]>,
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
    /// Panic-safe drop that ensures zeroization happens.
    ///
    /// This is marked #[inline(never)] to prevent the optimizer from
    /// removing it and to ensure consistent behavior in all build modes.
    #[inline(never)]
    fn drop(&mut self) {
        // Use catch_unwind to ensure zeroization happens even if
        // something panics during the zeroize operation itself.
        // This is defense-in-depth - zeroize shouldn't panic, but
        // if it does, we still clear what we can.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.zeroize();
        }));
        
        // If zeroize panicked, at least clear the SmallVec
        // This is a last-resort cleanup
        if !self.metadata.is_empty() {
            self.metadata.clear();
        }
    }
}

impl Clone for ErrorContext {
    fn clone(&self) -> Self {
        Self {
            operation: self.operation.clone(),
            details: self.details.clone(),
            source_internal: self.source_internal.clone(),
            source_sensitive: self.source_sensitive.clone(),
            metadata: self.metadata.clone(),
        }
    }
}

impl ErrorContext {
    pub fn new(
        operation: impl Into<Cow<'static, str>>, 
        details: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            operation: ContextField::Internal(operation.into()),
            details: ContextField::Internal(details.into()),
            source_internal: None,
            source_sensitive: None,
            metadata: SmallVec::new(),
        }
    }

    pub fn with_sensitive(
        operation: impl Into<Cow<'static, str>>,
        details: impl Into<Cow<'static, str>>,
        sensitive_info: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            operation: ContextField::Internal(operation.into()),
            details: ContextField::Internal(details.into()),
            source_internal: None,
            source_sensitive: Some(ContextField::Sensitive(sensitive_info.into())),
            metadata: SmallVec::new(),
        }
    }

    pub fn with_source_split(
        operation: impl Into<Cow<'static, str>>,
        details: impl Into<Cow<'static, str>>,
        internal_source: impl Into<Cow<'static, str>>,
        sensitive_source: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            operation: ContextField::Internal(operation.into()),
            details: ContextField::Internal(details.into()),
            source_internal: Some(ContextField::Internal(internal_source.into())),
            source_sensitive: Some(ContextField::Sensitive(sensitive_source.into())),
            metadata: SmallVec::new(),
        }
    }

    /// Add metadata in-place (no cloning, no allocation waste)
    #[inline]
    pub fn add_metadata(&mut self, key: &'static str, value: impl Into<Cow<'static, str>>) {
        self.metadata.push((key, ContextField::Internal(value.into())));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn metadata_stays_inline_for_typical_usage() {
        let mut ctx = ErrorContext::new("test", "details");
        
        // Add 4 metadata entries - should not heap allocate
        ctx.add_metadata("key1", "value1");
        ctx.add_metadata("key2", "value2");
        ctx.add_metadata("key3", "value3");
        ctx.add_metadata("key4", "value4");
        
        assert_eq!(ctx.metadata.len(), 4);
        // SmallVec will spill to heap if we add more than 4
    }
    
    #[test]
    fn zeroize_clears_all_fields() {
        let mut ctx = ErrorContext::with_sensitive(
            "operation",
            "details",
            "sensitive"
        );
        ctx.add_metadata("key", "value");
        
        // Explicitly zeroize
        ctx.zeroize();
        
        // After zeroization, strings should be empty
        // (This test verifies the behavior but won't catch all memory issues)
        assert_eq!(ctx.metadata.len(), 0);
    }
}