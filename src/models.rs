//! Shared model types — all `pub(crate)`.
//!
//! Nothing from this module is re-exported by `lib.rs`.  External crates
//! interact with error data only through the redacted `Display` on `AgentError`
//! or by reading an encrypted log file with the session key.

use crate::zeroization::{Zeroize, drop_zeroize};
use std::borrow::Cow;
use std::fmt;

// ── SocAccess capability token ────────────────────────────────────────────────

/// Capability token required to call [`crate::logging::InternalLog::expose_sensitive`].
///
/// This is an **organisational control**, not a cryptographic one.  Its purpose
/// is preventing accidental access to sensitive fields by well-intentioned
/// developers — not resisting adversaries with code-execution capability.
///
/// `pub(crate)` — no external code can name or construct this type.
pub(crate) struct SocAccess(());

impl SocAccess {
    /// Acquire a SOC-access capability.
    ///
    /// Only call from authenticated, encrypted internal logging pipelines or
    /// forensic analysis tools with appropriate access controls.
    #[inline]
    pub(crate) fn acquire() -> Self {
        Self(())
    }
}

// ── OperationCategory ─────────────────────────────────────────────────────────

/// Broad operation domain for contextualising errors.
///
/// `pub(crate)` — external callers receive category information as `&'static str`
/// via the redacted `Display` output on `AgentError`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum OperationCategory {
    Configuration,
    Deployment,
    Monitoring,
    Analysis,
    Response,
    Audit,
    System,
    IO,
    Deception,
    Detection,
    Containment,
}

impl OperationCategory {
    /// Authentic name for internal / SOC logs.
    #[inline]
    pub(crate) const fn display_name(&self) -> &'static str {
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

    /// Deceptive label for external-facing output.
    ///
    /// Honeypot categories are masked as `"Routine Operation"` to prevent
    /// adversaries from identifying defensive subsystems.
    #[inline]
    pub(crate) const fn deceptive_name(&self) -> &'static str {
        match self {
            Self::Deception | Self::Detection | Self::Containment => "Routine Operation",
            _ => self.display_name(),
        }
    }
}

// ── Internal context types (used by ContextBuilder / DualContextError) ────────

enum InternalContextField {
    Diagnostic(Cow<'static, str>),
    Sensitive(Cow<'static, str>),
    Lie(Cow<'static, str>),
}

impl Zeroize for InternalContextField {
    fn zeroize(&mut self) {
        match self {
            Self::Diagnostic(c) | Self::Sensitive(c) | Self::Lie(c) => {
                if let Cow::Owned(s) = c {
                    s.zeroize();
                }
            }
        }
    }
}

impl Drop for InternalContextField {
    fn drop(&mut self) {
        drop_zeroize(self);
    }
}

enum PublicContextField {
    #[cfg(feature = "external_signaling")]
    Truth(Cow<'static, str>),
    Lie(Cow<'static, str>),
}

impl Zeroize for PublicContextField {
    fn zeroize(&mut self) {
        match self {
            #[cfg(feature = "external_signaling")]
            Self::Truth(c) => {
                if let Cow::Owned(s) = c {
                    s.zeroize();
                }
            }
            Self::Lie(c) => {
                if let Cow::Owned(s) = c {
                    s.zeroize();
                }
            }
        }
    }
}

impl Drop for PublicContextField {
    fn drop(&mut self) {
        drop_zeroize(self);
    }
}

// ── PublicContext ─────────────────────────────────────────────────────────────

pub(crate) struct PublicContext(PublicContextField);

impl PublicContext {
    pub(crate) fn lie(message: impl Into<Cow<'static, str>>) -> Self {
        Self(PublicContextField::Lie(message.into()))
    }

    #[cfg(feature = "external_signaling")]
    pub(crate) fn truth(message: impl Into<Cow<'static, str>>) -> Self {
        Self(PublicContextField::Truth(message.into()))
    }

    pub(crate) fn as_str(&self) -> &str {
        match &self.0 {
            #[cfg(feature = "external_signaling")]
            PublicContextField::Truth(c) => c.as_ref(),
            PublicContextField::Lie(c) => c.as_ref(),
        }
    }

    pub(crate) const fn classification(&self) -> &'static str {
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

impl fmt::Display for PublicContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── InternalContext ───────────────────────────────────────────────────────────

pub(crate) struct InternalContext(InternalContextField);

impl InternalContext {
    pub(crate) fn diagnostic(message: impl Into<Cow<'static, str>>) -> Self {
        Self(InternalContextField::Diagnostic(message.into()))
    }

    pub(crate) fn sensitive(message: impl Into<Cow<'static, str>>) -> Self {
        Self(InternalContextField::Sensitive(message.into()))
    }

    pub(crate) fn lie(message: impl Into<Cow<'static, str>>) -> Self {
        Self(InternalContextField::Lie(message.into()))
    }

    pub(crate) fn as_str(&self) -> Option<&str> {
        match &self.0 {
            InternalContextField::Diagnostic(c) | InternalContextField::Lie(c) => Some(c.as_ref()),
            InternalContextField::Sensitive(_) => None,
        }
    }

    pub(crate) fn expose_sensitive<'a>(&'a self, _: &SocAccess) -> Option<&'a str> {
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

/// Display outputs a redacted placeholder — internal content must never be
/// visible via the `Display` trait.
impl fmt::Display for InternalContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<INTERNAL_CONTEXT_REDACTED>")
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deceptive_names_mask_honeypot_categories() {
        assert_eq!(
            OperationCategory::Deception.deceptive_name(),
            "Routine Operation"
        );
        assert_eq!(
            OperationCategory::Detection.deceptive_name(),
            "Routine Operation"
        );
        assert_eq!(
            OperationCategory::Containment.deceptive_name(),
            "Routine Operation"
        );
        assert_eq!(OperationCategory::IO.deceptive_name(), "I/O");
    }

    #[test]
    fn soc_access_is_crate_local_only() {
        // SocAccess is pub(crate) — this test simply verifies it can be acquired.
        let _token = SocAccess::acquire();
    }

    #[test]
    fn sensitive_redacted_without_token() {
        let ctx = InternalContext::sensitive("super secret");
        assert_eq!(ctx.as_str(), None, "sensitive leaked without token");
        let tok = SocAccess::acquire();
        assert_eq!(ctx.expose_sensitive(&tok), Some("super secret"));
    }

    #[test]
    fn public_context_lie_displays() {
        let ctx = PublicContext::lie("nothing to see here");
        assert_eq!(format!("{}", ctx), "nothing to see here");
        assert_eq!(ctx.classification(), "DeceptiveLie");
    }
}
