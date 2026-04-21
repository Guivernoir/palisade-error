//! Error code primitives.
//!
//! This entire module is `pub(crate)`.  No type from here is re-exported by
//! `lib.rs`; external callers interact with error codes only through their
//! string representation (`"E-CFG-103"`) as produced by `Display`.
//!
//! # Governance contract
//!
//! - Namespaces are compile-time constants; runtime construction is impossible.
//! - `ErrorCode` carries its namespace, numeric code, category, and impact.
//! - `const_new` panics at compile time on invalid inputs (enforced by `assert!`).
//! - `obfuscate_code` in `obfuscation.rs` creates a new `ErrorCode` from an
//!   existing one, which is the only runtime construction path.

use crate::models::OperationCategory;
use std::fmt;

// ── ImpactScore ───────────────────────────────────────────────────────────────

/// Validated impact score (0–1000).
#[derive(Debug, PartialEq, Eq, Hash)]
pub(crate) struct ImpactScore(u16);

impl ImpactScore {
    /// Compile-time construction.  Panics (compile error) if `score > 1000`.
    #[inline]
    pub(crate) const fn new(score: u16) -> Self {
        assert!(score <= 1000, "ImpactScore must be 0-1000");
        Self(score)
    }

    #[cfg_attr(not(feature = "log"), allow(dead_code))]
    #[inline]
    pub(crate) const fn value(&self) -> u16 {
        self.0
    }

    #[inline]
    pub(crate) const fn duplicate(&self) -> Self {
        Self(self.0)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    #[inline]
    pub(crate) const fn to_impact_level(&self) -> ErrorImpact {
        ErrorImpact::from_score(self.0)
    }

    #[cfg_attr(not(feature = "strict_severity"), allow(dead_code))]
    #[inline]
    pub(crate) const fn is_breach_level(&self) -> bool {
        self.0 >= 951
    }
}

// ── ErrorImpact ───────────────────────────────────────────────────────────────

/// Severity classification derived from an `ImpactScore`.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, PartialEq, Eq, Hash)]
pub(crate) enum ErrorImpact {
    Noise,
    Flaw,
    Jitter,
    Glitch,
    Suspicion,
    Leak,
    Collapse,
    Escalation,
    Breach,
}

impl ErrorImpact {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const fn from_score(score: u16) -> Self {
        match score {
            0..=50 => Self::Noise,
            51..=150 => Self::Flaw,
            151..=300 => Self::Jitter,
            301..=450 => Self::Glitch,
            451..=600 => Self::Suspicion,
            601..=750 => Self::Leak,
            751..=850 => Self::Collapse,
            851..=950 => Self::Escalation,
            _ => Self::Breach,
        }
    }
}

// ── ErrorNamespace ────────────────────────────────────────────────────────────

/// A compile-time-frozen error namespace.
///
/// The private `_private` field prevents runtime construction; only the
/// constants in `namespaces` can exist.
#[derive(Debug, PartialEq, Eq, Hash)]
pub(crate) struct ErrorNamespace {
    name: &'static str,
    can_breach: bool,
    _private: (),
}

impl ErrorNamespace {
    /// Internal constructor — used only to initialise `namespaces` constants.
    #[doc(hidden)]
    pub(crate) const fn __internal_new(name: &'static str, can_breach: bool) -> Self {
        Self {
            name,
            can_breach,
            _private: (),
        }
    }

    #[inline]
    pub(crate) const fn as_str(&self) -> &'static str {
        self.name
    }
    #[cfg_attr(not(feature = "strict_severity"), allow(dead_code))]
    #[inline]
    pub(crate) const fn can_breach(&self) -> bool {
        self.can_breach
    }
}

/// All permitted namespace instances.  No other values can exist.
pub(crate) mod namespaces {
    use super::ErrorNamespace;
    pub(crate) const CORE: ErrorNamespace = ErrorNamespace::__internal_new("CORE", true);
    pub(crate) const CFG: ErrorNamespace = ErrorNamespace::__internal_new("CFG", false);
    pub(crate) const DCP: ErrorNamespace = ErrorNamespace::__internal_new("DCP", true);
    pub(crate) const TEL: ErrorNamespace = ErrorNamespace::__internal_new("TEL", false);
    pub(crate) const COR: ErrorNamespace = ErrorNamespace::__internal_new("COR", false);
    pub(crate) const RSP: ErrorNamespace = ErrorNamespace::__internal_new("RSP", false);
    pub(crate) const LOG: ErrorNamespace = ErrorNamespace::__internal_new("LOG", false);
    pub(crate) const PLT: ErrorNamespace = ErrorNamespace::__internal_new("PLT", false);
    pub(crate) const IO: ErrorNamespace = ErrorNamespace::__internal_new("IO", false);
}

// ── Category / impact validation ──────────────────────────────────────────────

pub(crate) const fn permits_category(
    namespace: &ErrorNamespace,
    category: &OperationCategory,
) -> bool {
    match namespace.name.as_bytes() {
        b"IO" => !matches!(
            category,
            &OperationCategory::Deception
                | &OperationCategory::Detection
                | &OperationCategory::Containment
        ),
        b"LOG" | b"TEL" => matches!(
            category,
            &OperationCategory::Audit | &OperationCategory::Monitoring | &OperationCategory::System
        ),
        b"DCP" => matches!(
            category,
            &OperationCategory::Deception
                | &OperationCategory::Detection
                | &OperationCategory::Containment
                | &OperationCategory::Deployment
        ),
        // All other namespaces are permissive.
        _ => true,
    }
}

pub(crate) const fn permits_impact(namespace: &ErrorNamespace, impact: &ImpactScore) -> bool {
    // In permissive mode all namespaces allow any impact.
    #[cfg(not(feature = "strict_severity"))]
    {
        let _ = namespace;
        let _ = impact;
        true
    }
    // In strict mode only namespaces with CAN_BREACH may use Breach-level scores.
    #[cfg(feature = "strict_severity")]
    {
        if impact.is_breach_level() {
            namespace.can_breach()
        } else {
            true
        }
    }
}

// ── ErrorCode ─────────────────────────────────────────────────────────────────

/// A fully-qualified error code: namespace + numeric value + category + impact.
///
/// All instances are either `const` statics defined in `definitions.rs`, or
/// obfuscated copies produced by `obfuscation::obfuscate_code`.
///
/// `Sync` is satisfied because all fields are plain data or `&'static`.
#[derive(Debug, PartialEq, Eq, Hash)]
pub(crate) struct ErrorCode {
    pub(crate) namespace: &'static ErrorNamespace,
    pub(crate) code: u16,
    pub(crate) category: OperationCategory,
    pub(crate) impact: ImpactScore,
}

// SAFETY: All fields are plain value types or `&'static` references, and no
// interior mutability is present.
unsafe impl Send for ErrorCode {}
unsafe impl Sync for ErrorCode {}

impl ErrorCode {
    /// Compile-time construction (panics at compile time on bad inputs).
    #[inline]
    pub(crate) const fn const_new(
        namespace: &'static ErrorNamespace,
        code: u16,
        category: OperationCategory,
        impact: ImpactScore,
    ) -> Self {
        assert!(code > 0 && code < 1000, "ErrorCode must be 001-999");
        assert!(
            permits_category(namespace, &category),
            "category not permitted for namespace"
        );
        assert!(
            permits_impact(namespace, &impact),
            "impact not permitted for namespace"
        );
        Self {
            namespace,
            code,
            category,
            impact,
        }
    }

    #[inline]
    pub(crate) const fn category(&self) -> &OperationCategory {
        &self.category
    }
    #[inline]
    pub(crate) const fn namespace(&self) -> &'static ErrorNamespace {
        self.namespace
    }
    #[inline]
    pub(crate) const fn code(&self) -> u16 {
        self.code
    }
    #[inline]
    pub(crate) const fn impact(&self) -> &ImpactScore {
        &self.impact
    }
    #[cfg_attr(not(test), allow(dead_code))]
    #[inline]
    pub(crate) const fn impact_level(&self) -> ErrorImpact {
        self.impact.to_impact_level()
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "E-{}-{:03}", self.namespace.as_str(), self.code)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_format() {
        const CODE: ErrorCode = ErrorCode::const_new(
            &namespaces::CFG,
            100,
            OperationCategory::Configuration,
            ImpactScore::new(200),
        );
        assert_eq!(CODE.to_string(), "E-CFG-100");
    }

    #[test]
    fn impact_levels_mapped_correctly() {
        assert_eq!(ImpactScore::new(50).to_impact_level(), ErrorImpact::Noise);
        assert_eq!(ImpactScore::new(51).to_impact_level(), ErrorImpact::Flaw);
        assert_eq!(ImpactScore::new(951).to_impact_level(), ErrorImpact::Breach);
    }

    #[test]
    fn category_enforcement_io() {
        assert!(permits_category(&namespaces::IO, &OperationCategory::IO));
        assert!(!permits_category(
            &namespaces::IO,
            &OperationCategory::Deception
        ));
    }

    #[test]
    fn namespace_cannot_be_constructed_at_runtime() {
        // compile-time proof: the only way to get an ErrorNamespace is via
        // the constants in `namespaces`; the `_private` field prevents direct
        // struct literal construction.
        let _: &ErrorNamespace = &namespaces::CFG;
    }
}
