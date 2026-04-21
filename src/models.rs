//! Shared model types used by the crate-private error tables.

/// Broad operation domain for contextualizing errors.
///
/// `pub(crate)` only: external callers see category information only through
/// redacted `AgentError` formatting.
#[derive(Debug, PartialEq, Eq, Hash)]
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
    #[inline]
    pub(crate) const fn duplicate(&self) -> Self {
        match self {
            Self::Configuration => Self::Configuration,
            Self::Deployment => Self::Deployment,
            Self::Monitoring => Self::Monitoring,
            Self::Analysis => Self::Analysis,
            Self::Response => Self::Response,
            Self::Audit => Self::Audit,
            Self::System => Self::System,
            Self::IO => Self::IO,
            Self::Deception => Self::Deception,
            Self::Detection => Self::Detection,
            Self::Containment => Self::Containment,
        }
    }

    /// Authentic name for internal formatting.
    #[cfg_attr(not(feature = "trusted_debug"), allow(dead_code))]
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
    #[cfg_attr(not(any(feature = "log", test)), allow(dead_code))]
    #[inline]
    pub(crate) const fn deceptive_name(&self) -> &'static str {
        match self {
            Self::Deception | Self::Detection | Self::Containment => "Routine Operation",
            _ => self.display_name(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::OperationCategory;

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
    fn duplicate_preserves_category() {
        let category = OperationCategory::Audit;
        let duplicated = category.duplicate();
        assert_eq!(duplicated.display_name(), "Audit");
    }
}
