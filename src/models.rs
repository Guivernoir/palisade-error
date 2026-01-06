//! Context field with sensitivity classification.
//!
//! This determines both protection level and visibility:
//! - Public: Safe for external display
//! - Internal: Authenticated logs only
//! - Sensitive: Contains PII/secrets
//!
//! # Optimization
//! Uses `Cow<'static, str>` to allow zero-allocation storage of string literals
//! while still supporting dynamic strings when necessary.

use std::borrow::Cow;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Context field with sensitivity classification.
#[derive(Clone)]
pub enum ContextField {
    /// Safe to display externally (RESERVED)
    #[cfg(feature = "external_signaling")]
    Public(Cow<'static, str>),
    /// Internal logging only
    Internal(Cow<'static, str>),
    /// Contains sensitive data (paths, usernames, secrets)
    Sensitive(Cow<'static, str>),
}

// Manual Zeroize implementation is required because we cannot
// zeroize a static string slice (Cow::Borrowed). We only zeroize owned data.
impl Zeroize for ContextField {
    fn zeroize(&mut self) {
        match self {
            #[cfg(feature = "external_signaling")]
            Self::Public(cow) => {
                if let Cow::Owned(s) = cow { s.zeroize(); }
            }
            Self::Internal(cow) => {
                if let Cow::Owned(s) = cow { s.zeroize(); }
            }
            Self::Sensitive(cow) => {
                if let Cow::Owned(s) = cow { s.zeroize(); }
            }
        }
    }
}

impl ZeroizeOnDrop for ContextField {}

impl ContextField {
    /// Get the string slice from this field.
    #[inline]
    pub fn as_str(&self) -> &str {
        match self {
            #[cfg(feature = "external_signaling")]
            Self::Public(c) => c.as_ref(),
            Self::Internal(c) => c.as_ref(),
            Self::Sensitive(c) => c.as_ref(),
        }
    }
}

impl fmt::Debug for ContextField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "external_signaling")]
            Self::Public(c) => write!(f, "Public({:?})", c),
            Self::Internal(c) => write!(f, "Internal({:?})", c),
            Self::Sensitive(_) => write!(f, "Sensitive([REDACTED])"),
        }
    }
}

impl fmt::Display for ContextField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
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