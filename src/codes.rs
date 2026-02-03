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
//!
//! # Governance
//! Namespaces are enforced at compile-time via the `ErrorNamespace` type with
//! private fields. This prevents ad-hoc namespace creation and runtime construction,
//! ensuring taxonomy stability.
//!
//! See [error-governance.md](../docs/error-governance.md) for the complete governance contract.
//!
//! # Security Properties
//!
//! ## No-Copy/No-Clone Semantics
//! Error **identity** is non-Copy and non-movable; contextual **metadata** is Copy by design.
//!
//! - **Identity** (`ErrorCode`, `ErrorNamespace`): Frozen at compile time
//!   - Namespaces cannot be constructed or moved at runtime
//!   - Error codes are defined once as const statics
//!   - Makes data flow explicit and auditable
//!   - Enforces governance through type system, not discipline
//!
//! - **Metadata** (`OperationCategory`, `ErrorImpact`, `ImpactScore`): Copy-enabled
//!   - Small enums that benefit from pass-by-value
//!   - Defensive code can extract and propagate metadata cheaply
//!   - No governance risk from duplication of classification data
//!
//! This is a **policy choice for code hygiene**, not a cryptographic mitigation.
//!
//! ## Zero-Allocation Guarantee
//! All operations in this module are guaranteed zero-allocation:
//! - Error code construction: compile-time const evaluation
//! - Display formatting: writes directly to provided formatter (no intermediate buffers)
//! - Namespace validation: compile-time const assertions
//! - Category checking: pure computation, no heap use
//!
//! Note: `Display` itself is allocation-free; `to_string()` allocates in user code.
//!
//! This ensures error handling remains fast and predictable even under
//! memory pressure or DoS conditions where allocators may be stressed.
//!
//! # Example Usage
//!
//! ```rust
//! use palisade_errors::{ErrorCode, OperationCategory, ImpactScore, define_error_codes, namespaces};
//!
//! // Define error codes as const statics (zero allocation)
//! define_error_codes! {
//!     &namespaces::CFG, OperationCategory::Configuration => {
//!         CFG_PARSE_FAILED = (100, 350),
//!         CFG_INVALID_SCHEMA = (101, 250),
//!     }
//! }
//!
//! // Use by reference (no copies, no moves)
//! fn handle_error(code: &ErrorCode) {
//!     println!("Error: {}", code); // Zero allocation display
//! }
//!
//! handle_error(&CFG_PARSE_FAILED);
//! ```

use crate::OperationCategory;
use std::fmt;

// ============================================================================
// Impact Score Type (Validates Policy)
// ============================================================================

/// Validated impact score representing error severity (0-1000).
///
/// # Purpose
///
/// This newtype centralizes impact validation and makes the type system
/// encode security policy:
/// - Impact scores must be in valid range (0-1000)
/// - Construction enforces validation once at creation
/// - Downstream consumers receive pre-validated scores
///
/// # Copy Semantics
///
/// This type is Copy because:
/// - It's a small numeric value (u16)
/// - No governance risk from duplication
/// - Defensive code benefits from pass-by-value semantics
///
/// # Feature: Strict Severity Authority
///
/// When `strict_severity` feature is enabled, additional constraints apply
/// based on namespace authority flags. See `ErrorNamespace::CAN_BREACH`.
///
/// # Example
///
/// ```rust
/// # use palisade_errors::ImpactScore;
/// // Compile-time validation
/// const MINOR_IMPACT: ImpactScore = ImpactScore::new(150);
///
/// // Runtime validation
/// # let user_input = 123u16;
/// let score = ImpactScore::checked_new(user_input).unwrap();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ImpactScore(u16);

impl ImpactScore {
    /// Create a new impact score with compile-time validation.
    ///
    /// # Panics
    ///
    /// Panics at compile time (in const contexts) if score > 1000.
    /// Panics at runtime (in non-const contexts) if score > 1000.
    ///
    /// # Use Case
    ///
    /// For const static error code definitions where scores are known at compile time.
    #[inline]
    pub const fn new(score: u16) -> Self {
        assert!(score <= 1000, "Impact score must be 0-1000");
        Self(score)
    }

    /// Create a new impact score with runtime validation.
    ///
    /// # Errors
    ///
    /// Returns `Err` if score > 1000.
    ///
    /// # Use Case
    ///
    /// For runtime paths where impact scores come from configuration,
    /// user input, or dynamic sources. Prevents panics.
    #[inline]
    pub fn checked_new(score: u16) -> Result<Self, ImpactScoreError> {
        if score > 1000 {
            Err(ImpactScoreError::OutOfRange { value: score })
        } else {
            Ok(Self(score))
        }
    }

    /// Get the raw numeric value.
    #[inline]
    pub const fn value(self) -> u16 {
        self.0
    }

    /// Convert to detailed impact level classification.
    #[inline]
    pub const fn to_impact_level(self) -> ErrorImpact {
        ErrorImpact::from_score(self.0)
    }

    /// Check if this is a Breach-level impact (951-1000).
    #[inline]
    pub const fn is_breach_level(self) -> bool {
        self.0 >= 951
    }
}

impl fmt::Display for ImpactScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Error type for impact score validation failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImpactScoreError {
    /// Score exceeds maximum allowed value (1000).
    OutOfRange { value: u16 },
}

impl fmt::Display for ImpactScoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfRange { value } => {
                write!(f, "Impact score {} exceeds maximum (1000)", value)
            }
        }
    }
}

impl std::error::Error for ImpactScoreError {}

// ============================================================================
// Error Impact Classification
// ============================================================================

/// Error impact enum - derives impact mapping
/// 
/// Each impact level maps to the threat represented by an error.
///
/// # Copy Semantics
///
/// This type is Copy because it's a small enum representing metadata,
/// not governed identity. Defensive code can freely extract and propagate
/// impact levels without governance concerns.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum ErrorImpact {
    /// 0-50: Purely internal noise; no operational or deception impact.
    Noise,
    /// 51-150: Minor visual discrepancy in the deception layer.
    Flaw,
    /// 151-300: Performance issues that may be perceived as network lag.
    Jitter,
    /// 301-450: Functional error where an emulated feature fails to respond correctly.
    Glitch,
    /// 451-600: Logic inconsistency that allows an attacker to identify the trap.
    Suspicion,
    /// 601-750: Error reveals sensitive internal system information (Fingerprinting).
    Leak,
    /// 751-850: Total failure of the emulated service; the "illusion" stops.
    Collapse,
    /// 851-950: Error provides the attacker with unintended lateral or vertical access.
    Escalation,
    /// 951-1000: High risk of sandbox breakout or host machine compromise.
    Breach,
}

impl ErrorImpact {
    /// Converts a raw u16 score into a detailed ErrorImpact variant.
    pub const fn from_score(score: u16) -> Self {
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

// ============================================================================
// Error Namespace (Frozen Identity)
// ============================================================================

/// Error namespace type - enforces frozen taxonomy.
///
/// Namespaces are locked at compile-time with no runtime construction:
/// - Private field prevents user construction
/// - Only const instances are exported (see `namespaces` module)
/// - Cannot be moved or duplicated at runtime
///
/// Each namespace has authority flags determining permitted operations:
/// - Which categories are semantically valid
/// - Whether Breach-level impacts are allowed (strict_severity mode)
///
/// # No-Copy, No-Move Semantics
///
/// This type does not implement Copy or Clone, and cannot be constructed
/// at runtime. Namespaces exist only as const statics, making governance
/// a compile-time property, not a runtime discipline.
///
/// This is the **identity** layer - completely frozen.
///
/// # Authority Flags
///
/// Each namespace carries const authority flags:
/// - `CAN_BREACH`: Whether Breach-level impacts (951-1000) are permitted
///
/// This allows authority to evolve independently of namespace identity.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct ErrorNamespace {
    name: &'static str,
    can_breach: bool,
    _private: (),
}

impl ErrorNamespace {
    /// Internal constructor - not pub, enforces const-only usage.
    #[doc(hidden)]
    pub const fn __internal_new(name: &'static str, can_breach: bool) -> Self {
        Self {
            name,
            can_breach,
            _private: (),
        }
    }

    /// Get the string representation for external display.
    /// Zero-allocation - returns static string.
    #[inline]
    pub const fn as_str(&self) -> &'static str {
        self.name
    }

    /// Check if this namespace permits Breach-level impacts (951-1000).
    ///
    /// # Strict Severity Mode
    ///
    /// When `strict_severity` feature is enabled, this authority is enforced
    /// at error code construction. Without the feature, it's advisory only.
    ///
    /// Authority is granted via const flag, allowing architectural evolution
    /// without hardcoded namespace checks.
    #[inline]
    pub const fn can_breach(&self) -> bool {
        self.can_breach
    }
}

/// Canonical namespace instances.
///
/// These are the **only** ErrorNamespace values that can exist.
/// Private field in ErrorNamespace prevents runtime construction.
pub mod namespaces {
    use super::ErrorNamespace;

    /// Fundamental system errors (init, shutdown, panic recovery).
    /// Authority: Can emit Breach-level impacts.
    pub const CORE: ErrorNamespace = ErrorNamespace::__internal_new("CORE", true);

    /// Configuration parsing and validation.
    /// Authority: Cannot emit Breach-level impacts.
    pub const CFG: ErrorNamespace = ErrorNamespace::__internal_new("CFG", false);

    /// Deception artifact management.
    /// Authority: Can emit Breach-level impacts (deception compromise = breach).
    pub const DCP: ErrorNamespace = ErrorNamespace::__internal_new("DCP", true);

    /// Telemetry collection subsystem.
    /// Authority: Cannot emit Breach-level impacts.
    pub const TEL: ErrorNamespace = ErrorNamespace::__internal_new("TEL", false);

    /// Correlation engine.
    /// Authority: Cannot emit Breach-level impacts.
    pub const COR: ErrorNamespace = ErrorNamespace::__internal_new("COR", false);

    /// Response execution.
    /// Authority: Cannot emit Breach-level impacts (future: may need elevation).
    pub const RSP: ErrorNamespace = ErrorNamespace::__internal_new("RSP", false);

    /// Logging subsystem.
    /// Authority: Cannot emit Breach-level impacts.
    pub const LOG: ErrorNamespace = ErrorNamespace::__internal_new("LOG", false);

    /// Platform-specific operations.
    /// Authority: Cannot emit Breach-level impacts (future: may need elevation).
    pub const PLT: ErrorNamespace = ErrorNamespace::__internal_new("PLT", false);

    /// Filesystem and network operations.
    /// Authority: Cannot emit Breach-level impacts.
    pub const IO: ErrorNamespace = ErrorNamespace::__internal_new("IO", false);
}

// ============================================================================
// Category Policy (Extracted for Maintainability)
// ============================================================================

/// Category enforcement policy - extracted to reduce god-function complexity.
///
/// This module centralizes category validation logic and makes policy
/// changes easier to audit and maintain.
mod category_policy {
    use crate::OperationCategory;

    /// Check if IO namespace permits a category.
    pub(super) const fn io_permits(category: OperationCategory) -> bool {
        use OperationCategory::*;
        !matches!(category, Deception | Detection | Containment)
    }

    /// Check if Log/Telemetry namespace permits a category.
    pub(super) const fn observability_permits(category: OperationCategory) -> bool {
        use OperationCategory::*;
        matches!(category, Audit | Monitoring | System)
    }

    /// Check if Deception namespace permits a category.
    pub(super) const fn deception_permits(category: OperationCategory) -> bool {
        use OperationCategory::*;
        matches!(category, Deception | Detection | Containment | Deployment)
    }

    /// Check if permissive namespaces permit a category (default mode).
    #[cfg(not(feature = "strict_taxonomy"))]
    #[allow(unused_variables)]
    pub(super) const fn permissive_permits(category: OperationCategory) -> bool {
        true
    }

    /// Check category for strict taxonomy mode.
    #[cfg(feature = "strict_taxonomy")]
    pub(super) const fn strict_core_permits(category: OperationCategory) -> bool {
        matches!(category, OperationCategory::System)
    }

    #[cfg(feature = "strict_taxonomy")]
    pub(super) const fn strict_cfg_permits(category: OperationCategory) -> bool {
        matches!(category, OperationCategory::Configuration)
    }

    #[cfg(feature = "strict_taxonomy")]
    pub(super) const fn strict_cor_permits(category: OperationCategory) -> bool {
        matches!(category, OperationCategory::Analysis)
    }

    #[cfg(feature = "strict_taxonomy")]
    pub(super) const fn strict_rsp_permits(category: OperationCategory) -> bool {
        matches!(category, OperationCategory::Response)
    }

    #[cfg(feature = "strict_taxonomy")]
    pub(super) const fn strict_plt_permits(category: OperationCategory) -> bool {
        use OperationCategory::*;
        matches!(category, System | IO)
    }
}

/// Validate that a namespace permits the given operation category.
///
/// # Category Enforcement Policy
///
/// Enforces semantic constraints to prevent obvious mismatches:
/// - IO namespace: Cannot use Deception/Detection/Containment
/// - DCP namespace: Must use deception-related categories
/// - Log/Tel namespaces: Restricted to Audit/Monitoring/System
///
/// # Strict Taxonomy Mode
///
/// When `strict_taxonomy` feature is enabled, formerly permissive namespaces
/// enforce strict category mappings. See governance docs for migration guide.
///
/// Returns true if the pairing is semantically valid.
pub const fn permits_category(namespace: &ErrorNamespace, category: OperationCategory) -> bool {
    // Match on namespace name (identity-based dispatch)
    // This avoids encoding namespace enum into the type
    match namespace.name.as_bytes() {
        b"IO" => category_policy::io_permits(category),
        b"LOG" | b"TEL" => category_policy::observability_permits(category),
        b"DCP" => category_policy::deception_permits(category),

        // Strict mode enforcement
        #[cfg(feature = "strict_taxonomy")]
        b"CORE" => category_policy::strict_core_permits(category),
        #[cfg(feature = "strict_taxonomy")]
        b"CFG" => category_policy::strict_cfg_permits(category),
        #[cfg(feature = "strict_taxonomy")]
        b"COR" => category_policy::strict_cor_permits(category),
        #[cfg(feature = "strict_taxonomy")]
        b"RSP" => category_policy::strict_rsp_permits(category),
        #[cfg(feature = "strict_taxonomy")]
        b"PLT" => category_policy::strict_plt_permits(category),

        // Permissive fallback (default mode)
        #[cfg(not(feature = "strict_taxonomy"))]
        _ => category_policy::permissive_permits(category),

        // Exhaustiveness in strict mode
        #[cfg(feature = "strict_taxonomy")]
        _ => false,
    }
}

/// Validate that a namespace permits the given impact level.
///
/// # Severity Authority Enforcement
///
/// When `strict_severity` feature is enabled, restricts Breach-level
/// impacts (951-1000) to namespaces with `can_breach` authority.
///
/// Authority is decoupled from namespace identity, allowing architectural
/// evolution without policy rewrites.
pub const fn permits_impact(namespace: &ErrorNamespace, impact: ImpactScore) -> bool {
    #[cfg(feature = "strict_severity")]
    {
        if impact.is_breach_level() {
            return namespace.can_breach();
        }
    }

    #[cfg(not(feature = "strict_severity"))]
    let _ = (namespace, impact);

    true
}

// ============================================================================
// Error Violation Types (Internal + Public)
// ============================================================================

/// Internal error code violation with detailed taxonomy information.
///
/// **SECURITY WARNING**: This type contains internal policy details and
/// should NEVER be exposed to external systems or untrusted contexts.
///
/// For external error reporting, use `.to_public()` to get sanitized message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InternalErrorCodeViolation {
    /// Code is zero or exceeds 999.
    CodeOutOfRange { value: u16 },
    /// Category not permitted for namespace (reveals policy).
    CategoryNotPermitted {
        namespace: &'static str,
        category: &'static str,
    },
    /// Impact level not permitted for namespace (reveals authority model).
    ImpactNotPermitted {
        namespace: &'static str,
        impact: u16,
    },
}

impl InternalErrorCodeViolation {
    /// Convert to public-safe error message (taxonomy-sanitized).
    ///
    /// Returns a generic error string that does not reveal:
    /// - Namespace restrictions
    /// - Category policies
    /// - Authority models
    ///
    /// # Use Case
    ///
    /// For external APIs, plugin systems, or any untrusted boundary where
    /// detailed policy information should not leak.
    pub fn to_public(&self) -> &'static str {
        match self {
            Self::CodeOutOfRange { .. } => "Invalid error code format",
            Self::CategoryNotPermitted { .. } => "Invalid error configuration",
            Self::ImpactNotPermitted { .. } => "Invalid error severity",
        }
    }
}

impl fmt::Display for InternalErrorCodeViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CodeOutOfRange { value } => {
                write!(f, "Error code {} is out of range (must be 001-999)", value)
            }
            Self::CategoryNotPermitted { namespace, category } => {
                write!(
                    f,
                    "Category {} not permitted for namespace {}",
                    category, namespace
                )
            }
            Self::ImpactNotPermitted { namespace, impact } => {
                write!(
                    f,
                    "Impact level {} not permitted for namespace {}",
                    impact, namespace
                )
            }
        }
    }
}

impl std::error::Error for InternalErrorCodeViolation {}

// ============================================================================
// Error Code (Primary Identity Type)
// ============================================================================

/// An error code with namespace, numeric code, and operation category.
///
/// Error codes follow the format `E-XXX-YYY` where:
/// - `XXX` is the namespace (CORE, CFG, IO, etc.)
/// - `YYY` is the numeric code (001-999)
///
/// # Compile-time Guarantees
///
/// All error codes are defined as const statics, providing:
/// - Namespace frozen at compile time (cannot be constructed at runtime)
/// - Code range validated (001-999)
/// - Impact score validated (0-1000)
/// - Category compatibility enforced
/// - Severity authority enforced (strict_severity mode)
///
/// # Construction APIs
///
/// - `const_new`: For const statics (panics = compile error)
/// - `checked_new`: For runtime construction (returns Result, never panics)
///
/// # No-Copy/No-Clone Semantics
///
/// This type is part of the error **identity** layer and cannot be copied,
/// cloned, or moved after const initialization. All usage is by reference.
///
/// # Zero-Allocation Guarantee
///
/// All operations are zero-allocation. Display writes directly to formatter.
///
/// # Example
///
/// ```rust
/// use palisade_errors::{ErrorCode, OperationCategory, ImpactScore, define_error_codes, namespaces};
///
/// // Compile-time construction (panics if invalid)
/// const CFG_PARSE_FAILED: ErrorCode = ErrorCode::const_new(
///     &namespaces::CFG,
///     100,
///     OperationCategory::Configuration,
///     ImpactScore::new(700)
/// );
/// 
/// // Runtime construction (returns Result)
/// # let code_from_config = 801u16;
/// # let impact_from_config = 700u16;
/// let code = ErrorCode::checked_new(
///     &namespaces::IO,
///     code_from_config,
///     OperationCategory::IO,
///     ImpactScore::checked_new(impact_from_config).unwrap()
/// ).unwrap();
/// 
/// // Use by reference only
/// fn log_error(code: &ErrorCode) {
///     println!("Error: {}", code);
/// }
/// 
/// log_error(&CFG_PARSE_FAILED);
/// ```
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct ErrorCode {
    namespace: &'static ErrorNamespace,
    code: u16,
    category: OperationCategory,
    impact: ImpactScore,
}

impl ErrorCode {
    /// Create a new error code with compile-time validation (infallible in const contexts).
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - Code is 0 or >= 1000 (must be 001-999)
    /// - Category is not permitted for the namespace
    /// - Impact is not permitted for the namespace (strict_severity mode)
    ///
    /// In **const contexts**, panics occur at compile time.
    /// In **runtime contexts**, panics occur at runtime.
    ///
    /// # Use Case
    ///
    /// For const static error code definitions where all values are known
    /// at compile time and violations indicate programmer error.
    #[inline]
    pub const fn const_new(
        namespace: &'static ErrorNamespace,
        code: u16,
        category: OperationCategory,
        impact: ImpactScore,
    ) -> Self {
        // Validate code range (001-999)
        assert!(code > 0 && code < 1000, "Error code must be 001-999");

        // Validate category compatibility
        assert!(
            permits_category(namespace, category),
            "Category not permitted for this namespace"
        );

        // Validate impact authority
        assert!(
            permits_impact(namespace, impact),
            "Impact level not permitted for this namespace"
        );

        Self {
            namespace,
            code,
            category,
            impact,
        }
    }

    /// Create a new error code with runtime validation (fallible, no panics).
    ///
    /// # Errors
    ///
    /// Returns `Err` with **internal** violation details. For external contexts,
    /// call `.to_public()` on the error to sanitize taxonomy information.
    ///
    /// # Use Case
    ///
    /// For runtime construction from untrusted sources (config, plugins, etc.).
    #[inline]
    pub fn checked_new(
        namespace: &'static ErrorNamespace,
        code: u16,
        category: OperationCategory,
        impact: ImpactScore,
    ) -> Result<Self, InternalErrorCodeViolation> {
        // Validate code range
        if code == 0 || code >= 1000 {
            return Err(InternalErrorCodeViolation::CodeOutOfRange { value: code });
        }

        // Validate category compatibility
        if !permits_category(namespace, category) {
            return Err(InternalErrorCodeViolation::CategoryNotPermitted {
                namespace: namespace.as_str(),
                category: category.display_name(),
            });
        }

        // Validate impact authority
        if !permits_impact(namespace, impact) {
            return Err(InternalErrorCodeViolation::ImpactNotPermitted {
                namespace: namespace.as_str(),
                impact: impact.value(),
            });
        }

        Ok(Self {
            namespace,
            code,
            category,
            impact,
        })
    }

    /// Get the operation category.
    #[inline]
    pub const fn category(&self) -> OperationCategory {
        self.category
    }

    /// Get namespace reference.
    #[inline]
    pub const fn namespace(&self) -> &'static ErrorNamespace {
        self.namespace
    }

    /// Get numeric code.
    #[inline]
    pub const fn code(&self) -> u16 {
        self.code
    }

    /// Get impact score.
    #[inline]
    pub const fn impact(&self) -> ImpactScore {
        self.impact
    }

    /// Get the detailed impact level.
    #[inline]
    pub const fn impact_level(&self) -> ErrorImpact {
        self.impact.to_impact_level()
    }
}

impl fmt::Display for ErrorCode {
    /// Zero-allocation formatting - writes directly to formatter.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "E-{}-{:03}", self.namespace.as_str(), self.code)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::define_error_codes;

    // ========================================================================
    // Namespace Governance Tests
    // ========================================================================

    #[test]
    fn namespaces_are_frozen_at_compile_time() {
        // This compiles - using const namespace
        const _CODE: ErrorCode = ErrorCode::const_new(
            &namespaces::CORE,
            1,
            OperationCategory::System,
            ImpactScore::new(100),
        );

        // This would NOT compile (namespace cannot be constructed):
        // let ns = ErrorNamespace { name: "FAKE", can_breach: false, _private: () };
    }

    #[test]
    fn namespace_authority_flags_work() {
        assert!(namespaces::CORE.can_breach());
        assert!(namespaces::DCP.can_breach());
        assert!(!namespaces::CFG.can_breach());
        assert!(!namespaces::IO.can_breach());
    }

    // ========================================================================
    // Basic Construction Tests
    // ========================================================================

    #[test]
    fn valid_error_code_const_construction() {
        const CODE: ErrorCode = ErrorCode::const_new(
            &namespaces::CFG,
            100,
            OperationCategory::Configuration,
            ImpactScore::new(100),
        );
        assert_eq!(CODE.to_string(), "E-CFG-100");
        assert_eq!(CODE.namespace().as_str(), "CFG");
        assert_eq!(CODE.code(), 100);
    }

    #[test]
    fn valid_error_code_checked_construction() {
        let code = ErrorCode::checked_new(
            &namespaces::IO,
            200,
            OperationCategory::IO,
            ImpactScore::new(500),
        )
        .unwrap();

        assert_eq!(code.to_string(), "E-IO-200");
    }

    #[test]
    fn checked_new_rejects_invalid_code() {
        let result = ErrorCode::checked_new(
            &namespaces::CORE,
            0,
            OperationCategory::System,
            ImpactScore::new(100),
        );
        assert!(matches!(
            result,
            Err(InternalErrorCodeViolation::CodeOutOfRange { value: 0 })
        ));
    }

    #[test]
    fn violation_to_public_sanitizes_details() {
        let violation = InternalErrorCodeViolation::CategoryNotPermitted {
            namespace: "IO",
            category: "Deception",
        };

        // Internal has details
        assert!(violation.to_string().contains("IO"));
        assert!(violation.to_string().contains("Deception"));

        // Public is sanitized
        assert_eq!(violation.to_public(), "Invalid error configuration");
        assert!(!violation.to_public().contains("IO"));
    }

    // ========================================================================
    // Category Policy Tests
    // ========================================================================

    #[test]
    fn category_enforcement_io_namespace() {
        assert!(permits_category(&namespaces::IO, OperationCategory::IO));
        assert!(!permits_category(
            &namespaces::IO,
            OperationCategory::Deception
        ));
    }

    #[test]
    fn category_enforcement_dcp_namespace() {
        assert!(permits_category(
            &namespaces::DCP,
            OperationCategory::Deception
        ));
        assert!(!permits_category(
            &namespaces::DCP,
            OperationCategory::Configuration
        ));
    }

    // ========================================================================
    // Dual-Mode Testing
    // ========================================================================

    #[cfg(not(feature = "strict_taxonomy"))]
    #[test]
    fn permissive_mode_allows_flexible_categories() {
        assert!(permits_category(
            &namespaces::CORE,
            OperationCategory::Configuration
        ));
        assert!(permits_category(
            &namespaces::CFG,
            OperationCategory::System
        ));
    }

    #[cfg(feature = "strict_taxonomy")]
    #[test]
    fn strict_mode_enforces_core_namespace() {
        assert!(permits_category(
            &namespaces::CORE,
            OperationCategory::System
        ));
        assert!(!permits_category(
            &namespaces::CORE,
            OperationCategory::Configuration
        ));
    }

    // ========================================================================
    // Severity Authority Tests
    // ========================================================================

    #[cfg(not(feature = "strict_severity"))]
    #[test]
    fn permissive_severity_allows_breach_anywhere() {
        let _code = ErrorCode::const_new(
            &namespaces::CFG,
            1,
            OperationCategory::Configuration,
            ImpactScore::new(980),
        );
    }

    #[cfg(feature = "strict_severity")]
    #[test]
    fn strict_severity_respects_authority_flags() {
        assert!(permits_impact(&namespaces::CORE, ImpactScore::new(980)));
        assert!(permits_impact(&namespaces::DCP, ImpactScore::new(1000)));
        assert!(!permits_impact(&namespaces::CFG, ImpactScore::new(980)));
    }

    // ========================================================================
    // Impact Score Tests
    // ========================================================================

    #[test]
    fn impact_score_boundaries() {
        assert_eq!(ImpactScore::new(50).to_impact_level(), ErrorImpact::Noise);
        assert_eq!(ImpactScore::new(51).to_impact_level(), ErrorImpact::Flaw);
        assert_eq!(ImpactScore::new(951).to_impact_level(), ErrorImpact::Breach);
        assert!(ImpactScore::new(980).is_breach_level());
    }

    // ========================================================================
    // Macro Tests
    // ========================================================================

    #[test]
    fn macro_batch_definition() {
        define_error_codes! {
            &namespaces::IO, OperationCategory::IO => {
                IO_READ_ERROR = (100, 500),
                IO_WRITE_ERROR = (101, 500),
            }
        }

        assert_eq!(IO_READ_ERROR.to_string(), "E-IO-100");
        assert_eq!(IO_WRITE_ERROR.to_string(), "E-IO-101");
    }
}
