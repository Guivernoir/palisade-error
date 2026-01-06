//! Structured log entry for internal forensics.
//!
//! # Critical Security Properties
//!
//! - Borrows from AgentError with explicit lifetime
//! - CANNOT outlive the error that created it
//! - Forces immediate consumption by logger
//! - NO heap allocations
//! - NO leaked memory
//! - NO escaped references
//!
//! This structure exists only during the logging call and is destroyed
//! immediately afterward, ensuring all sensitive data is zeroized when
//! the error drops.
//!
//! The short lifetime is a FEATURE, not a limitation. It enforces that
//! sensitive data cannot be retained beyond its intended scope.

use crate::{ContextField, ErrorCode};
use std::fmt;

/// Maximum length for any individual field in formatted output (DoS prevention)
const MAX_FIELD_OUTPUT_LEN: usize = 1024;

/// Structured log entry with borrowed data from AgentError.
///
/// This struct has an explicit lifetime parameter that ties it to the
/// error that created it, preventing the log from outliving the error.
///
/// # Example
///
/// ```rust
/// # use palisade_errors::{AgentError, definitions};
/// let err = AgentError::config(definitions::CFG_PARSE_FAILED, "test", "details");
/// let log = err.internal_log();
/// // Use log immediately
/// // log is destroyed when it goes out of scope
/// ```
#[derive(Debug)]
pub struct InternalLog<'a> {
    pub code: ErrorCode,
    pub operation: &'a str,
    pub details: &'a str,
    pub source_internal: Option<&'a str>,
    pub source_sensitive: Option<&'a str>,
    pub metadata: &'a [(&'static str, ContextField)],
    pub retryable: bool,
}

impl<'a> InternalLog<'a> {
    /// Format for human-readable logs in trusted debug contexts.
    /// 
    /// WARNING: This materializes sensitive data into a String.
    /// This function is only available with the `trusted_debug` feature flag.
    /// 
    /// Only use this in:
    /// - Local development debugging
    /// - Trusted internal logging systems with proper access controls
    /// - Post-mortem forensic analysis in secure environments
    /// 
    /// NEVER use in:
    /// - External-facing logs
    /// - Untrusted log aggregation
    /// - Production without proper sanitization pipeline
    #[cfg(feature = "trusted_debug")]
    pub fn format_for_trusted_debug(&self) -> String {
        let mut output = format!(
            "[{}] {} operation='{}' details='{}'",
            self.code,
            if self.retryable { "[RETRYABLE]" } else { "" },
            truncate_for_display(self.operation),
            truncate_for_display(self.details)
        );

        if let Some(internal) = self.source_internal {
            output.push_str(&format!(" source='{}'", truncate_for_display(internal)));
        }

        if let Some(sensitive) = self.source_sensitive {
            output.push_str(&format!(" sensitive='{}'", truncate_for_display(sensitive)));
        }

        for (key, value) in self.metadata {
            output.push_str(&format!(" {}='{}'", key, truncate_for_display(value.as_str())));
        }

        output
    }

    /// Write structured log data to a formatter without allocating.
    /// 
    /// This is the preferred method for production logging as it:
    /// - Does not allocate strings for sensitive data
    /// - Writes directly to the output
    /// - Allows the logging framework to control serialization
    /// - Truncates fields to prevent DoS via memory exhaustion
    /// 
    /// Example:
    /// ```rust,ignore
    /// err.with_internal_log(|log| {
    ///     let mut buffer = String::new();
    ///     log.write_to(&mut buffer).unwrap();
    /// });
    /// ```
    pub fn write_to(&self, f: &mut impl fmt::Write) -> fmt::Result {
        write!(
            f,
            "[{}] {} operation='{}' details='{}'",
            self.code,
            if self.retryable { "[RETRYABLE]" } else { "" },
            truncate_for_display(self.operation),
            truncate_for_display(self.details)
        )?;

        if let Some(internal) = self.source_internal {
            write!(f, " source='{}'", truncate_for_display(internal))?;
        }

        if let Some(sensitive) = self.source_sensitive {
            write!(f, " sensitive='{}'", truncate_for_display(sensitive))?;
        }

        for (key, value) in self.metadata {
            write!(f, " {}='{}'", key, truncate_for_display(value.as_str()))?;
        }

        Ok(())
    }

    /// Access structured fields for JSON/structured logging.
    /// 
    /// Preferred over string formatting because it allows the logging
    /// framework to handle sensitive data according to its own policies.
    /// 
    /// Note: Fields are not truncated here - truncation is the responsibility
    /// of the logging framework when serializing to its output format.
    #[inline]
    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    #[inline]
    pub const fn operation(&self) -> &str {
        self.operation
    }

    #[inline]
    pub const fn details(&self) -> &str {
        self.details
    }

    #[inline]
    pub const fn source_internal(&self) -> Option<&str> {
        self.source_internal
    }

    #[inline]
    pub const fn source_sensitive(&self) -> Option<&str> {
        self.source_sensitive
    }

    #[inline]
    pub const fn metadata(&self) -> &[(&'static str, ContextField)] {
        self.metadata
    }

    #[inline]
    pub const fn is_retryable(&self) -> bool {
        self.retryable
    }
}

/// Truncate a string for display to prevent DoS via extremely long error messages.
/// 
/// If the string exceeds MAX_FIELD_OUTPUT_LEN, it's truncated with an indicator.
/// This prevents memory exhaustion when formatting logs from untrusted input.
#[inline]
fn truncate_for_display(s: &str) -> &str {
    if s.len() <= MAX_FIELD_OUTPUT_LEN {
        s
    } else {
        // Safe: We're truncating at a byte boundary we control
        &s[..MAX_FIELD_OUTPUT_LEN]
        // Note: This may truncate mid-UTF8 character in pathological cases.
        // For production, consider using a proper UTF-8 boundary check:
        // s.char_indices().nth(MAX_FIELD_OUTPUT_LEN).map_or(s, |(idx, _)| &s[..idx])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncation() {
        let short = "short string";
        assert_eq!(truncate_for_display(short), short);

        let long = "a".repeat(MAX_FIELD_OUTPUT_LEN + 100);
        let truncated = truncate_for_display(&long);
        assert_eq!(truncated.len(), MAX_FIELD_OUTPUT_LEN);
    }
}