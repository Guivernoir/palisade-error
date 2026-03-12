//! Context enrichment utilities.
//!
//! All items are `pub(crate)`.  This module is not wired into the primary
//! `AgentError` path; it is retained as a foundation for future `DualContextError`
//! integration.
//!
//! # Current status
//!
//! `ContextBuilder` and `ContextChain` are operational internally but do not
//! feed into the public API.  Until they are wired through `AgentError`, they
//! should not be used in production code paths.

use crate::models::{InternalContext, OperationCategory, PublicContext};
use crate::zeroization::{Zeroize, drop_zeroize};
use std::borrow::Cow;

// ── Metadata ──────────────────────────────────────────────────────────────────

/// Maximum number of metadata key-value pairs per context.
/// Prevents unbounded growth under adversarial conditions.
const MAX_METADATA_PAIRS: usize = 16;

/// A key-value metadata pair with zeroize-on-drop for owned values.
struct MetadataPair {
    key: &'static str,
    value: Cow<'static, str>,
}

impl Zeroize for MetadataPair {
    fn zeroize(&mut self) {
        if let Cow::Owned(ref mut s) = self.value {
            s.zeroize();
        }
    }
}

impl Drop for MetadataPair {
    fn drop(&mut self) {
        drop_zeroize(self);
    }
}

// ── ContextBuilder ────────────────────────────────────────────────────────────

/// Fluent builder for dual-context errors.
///
/// `pub(crate)` — not accessible externally.
pub(crate) struct ContextBuilder {
    public: Option<PublicContext>,
    internal: Option<InternalContext>,
    category: OperationCategory,
    metadata: Vec<MetadataPair>,
}

impl ContextBuilder {
    pub(crate) fn new() -> Self {
        Self {
            public: None,
            internal: None,
            category: OperationCategory::System,
            metadata: Vec::new(),
        }
    }

    pub(crate) fn public_lie(mut self, msg: impl Into<Cow<'static, str>>) -> Self {
        self.public = Some(PublicContext::lie(msg));
        self
    }

    pub(crate) fn internal_diagnostic(mut self, msg: impl Into<Cow<'static, str>>) -> Self {
        self.internal = Some(InternalContext::diagnostic(msg));
        self
    }

    pub(crate) fn internal_sensitive(mut self, msg: impl Into<Cow<'static, str>>) -> Self {
        self.internal = Some(InternalContext::sensitive(msg));
        self
    }

    pub(crate) fn category(mut self, cat: OperationCategory) -> Self {
        self.category = cat;
        self
    }

    /// Add a metadata key-value pair (up to `MAX_METADATA_PAIRS`).
    /// Pairs beyond the limit are silently dropped to prevent DoS.
    pub(crate) fn with_meta(
        mut self,
        key: &'static str,
        value: impl Into<Cow<'static, str>>,
    ) -> Self {
        if self.metadata.len() < MAX_METADATA_PAIRS {
            self.metadata.push(MetadataPair {
                key,
                value: value.into(),
            });
        }
        self
    }

    /// Build and return the contexts.
    pub(crate) fn build(
        self,
    ) -> (
        Option<PublicContext>,
        Option<InternalContext>,
        OperationCategory,
    ) {
        (self.public, self.internal, self.category)
    }
}

// ── ContextChain ──────────────────────────────────────────────────────────────

/// Causality chain for tracking error propagation across subsystem boundaries.
///
/// Not yet integrated with `AgentError`; preserved for future use.
pub(crate) struct ContextChain {
    entries: Vec<ChainEntry>,
}

struct ChainEntry {
    subsystem: &'static str,
    message: Cow<'static, str>,
}

impl Zeroize for ChainEntry {
    fn zeroize(&mut self) {
        if let Cow::Owned(ref mut s) = self.message {
            s.zeroize();
        }
    }
}

impl Drop for ChainEntry {
    fn drop(&mut self) {
        drop_zeroize(self);
    }
}

impl ContextChain {
    pub(crate) fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub(crate) fn push(
        mut self,
        subsystem: &'static str,
        msg: impl Into<Cow<'static, str>>,
    ) -> Self {
        self.entries.push(ChainEntry {
            subsystem,
            message: msg.into(),
        });
        self
    }

    /// Iterate over (subsystem, message) pairs in causal order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&'static str, &str)> {
        self.entries
            .iter()
            .map(|e| (e.subsystem, e.message.as_ref()))
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_constructs_lie_context() {
        let (pub_ctx, int_ctx, _) = ContextBuilder::new()
            .public_lie("nothing to see here")
            .internal_diagnostic("actual failure: db timeout")
            .category(OperationCategory::IO)
            .build();

        assert!(pub_ctx.is_some());
        assert_eq!(pub_ctx.unwrap().as_str(), "nothing to see here");
        assert!(int_ctx.is_some());
    }

    #[test]
    fn builder_caps_metadata() {
        let mut builder = ContextBuilder::new();
        for i in 0..(MAX_METADATA_PAIRS + 10) {
            builder = builder.with_meta("key", format!("value-{}", i));
        }
        assert!(builder.metadata.len() <= MAX_METADATA_PAIRS);
    }

    #[test]
    fn chain_records_causality() {
        let chain = ContextChain::new()
            .push("io", "file not found")
            .push("cfg", "config load failed");
        assert_eq!(chain.len(), 2);
        let entries: Vec<_> = chain.iter().collect();
        assert_eq!(entries[0].0, "io");
        assert_eq!(entries[1].0, "cfg");
    }

    #[test]
    fn sensitive_internal_requires_soc_access() {
        use crate::models::SocAccess;
        let (_, int_ctx, _) = ContextBuilder::new()
            .internal_sensitive("super secret path")
            .build();
        let ctx = int_ctx.unwrap();
        // Without token, payload is None.
        assert_eq!(ctx.as_str(), None);
        // With token, payload is Some.
        let token = SocAccess::acquire();
        assert_eq!(ctx.expose_sensitive(&token), Some("super secret path"));
    }
}
