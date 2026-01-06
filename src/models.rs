//! Context field with sensitivity classification.
//!
//! This determines both protection level and visibility:
//! - Public: Safe for external display (error codes, retry hints) - RESERVED FOR FUTURE USE
//! - Internal: Authenticated logs only (operation names, generic details)
//! - Sensitive: Contains PII/secrets (file paths, usernames, credentials)
//!
//! All variants are zeroized on drop to prevent memory scraping attacks.
//!
//! # Note on Public Variant
//!
//! `Public` is currently reserved for future external signaling capabilities.
//! When implemented, it will allow selective field exposure in sanitized outputs
//! while maintaining the security invariant that only explicitly-public data
//! can appear in `Display` formatting.

use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Context field with sensitivity classification.
///
/// Determines protection level and visibility for error context data.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub enum ContextField {
    /// Safe to display externally (RESERVED - not yet used)
    #[cfg(feature = "external_signaling")]
    Public(String),
    /// Internal logging only
    Internal(String),
    /// Contains sensitive data (paths, usernames, secrets)
    Sensitive(String),
}

impl ContextField {
    /// Get the string slice from this field.
    #[inline]
    pub(crate) fn as_str(&self) -> &str {
        match self {
            #[cfg(feature = "external_signaling")]
            Self::Public(s) => s,
            Self::Internal(s) => s,
            Self::Sensitive(s) => s,
        }
    }

    /// Check if this field contains sensitive data.
    #[inline]
    pub(crate) fn is_sensitive(&self) -> bool {
        matches!(self, Self::Sensitive(_))
    }
}

impl fmt::Debug for ContextField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "external_signaling")]
            Self::Public(s) => write!(f, "Public({:?})", s),
            Self::Internal(s) => write!(f, "Internal({:?})", s),
            Self::Sensitive(_) => write!(f, "Sensitive([REDACTED])"),
        }
    }
}

/// Operation category for providing useful context without leaking details.
///
/// These categories are intentionally broad and give legitimate operators
/// enough signal to understand the failure domain without helping attackers
/// map internal architecture.
///
/// # Categories
///
/// - `Configuration`: Configuration parsing or validation
/// - `Deployment`: Artifact deployment or management
/// - `Monitoring`: Event collection or monitoring
/// - `Analysis`: Rule evaluation or scoring
/// - `Response`: Action execution
/// - `Audit`: Logging or audit trail
/// - `System`: System-level operations
/// - `IO`: File or network I/O
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationCategory {
    /// Configuration parsing or validation
    Configuration,
    /// Artifact deployment or management
    Deployment,
    /// Event collection or monitoring
    Monitoring,
    /// Rule evaluation or scoring
    Analysis,
    /// Action execution
    Response,
    /// Logging or audit trail
    Audit,
    /// System-level operations
    System,
    /// File or network I/O
    IO,
}

impl OperationCategory {
    /// Get the display name for this category.
    ///
    /// Pre-computed display strings - no allocation, no Unicode edge cases.
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
        }
    }
}