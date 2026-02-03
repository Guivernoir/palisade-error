//! Structured log entry for internal forensics.
//!
//! # Critical Security Properties
//!
//! - Borrows from AgentError with explicit lifetime
//! - CANNOT outlive the error that created it
//! - Forces immediate consumption by logger
//! - NO heap allocations in accessors
//! - NO leaked memory
//! - NO escaped references
//!
//! This structure exists only during the logging call and is destroyed
//! immediately afterward, ensuring all sensitive data is zeroized when
//! the error drops.
//!
//! The short lifetime is a FEATURE, not a limitation. It enforces that
//! sensitive data cannot be retained beyond its intended scope.

use crate::ErrorCode;
use std::borrow::Cow;
use std::fmt;
use zeroize::Zeroize;

/// Maximum length for any individual field in formatted output (DoS prevention)
const MAX_FIELD_OUTPUT_LEN: usize = 1024;

/// Truncation indicator appended to truncated strings
const TRUNCATION_INDICATOR: &str = "...[TRUNCATED]";

/// Metadata value wrapper with zeroization for owned data.
///
/// Borrowed values are assumed static and are not zeroized.
#[derive(Debug)]
pub struct ContextField {
    value: Cow<'static, str>,
}

impl ContextField {
    #[inline]
    pub fn as_str(&self) -> &str {
        self.value.as_ref()
    }
}

impl From<&'static str> for ContextField {
    fn from(value: &'static str) -> Self {
        Self {
            value: Cow::Borrowed(value),
        }
    }
}

impl From<String> for ContextField {
    fn from(value: String) -> Self {
        Self {
            value: Cow::Owned(value),
        }
    }
}

impl From<Cow<'static, str>> for ContextField {
    fn from(value: Cow<'static, str>) -> Self {
        Self { value }
    }
}

impl Zeroize for ContextField {
    fn zeroize(&mut self) {
        if let Cow::Owned(ref mut s) = self.value {
            s.zeroize();
        }
    }
}

impl Drop for ContextField {
    fn drop(&mut self) {
        self.zeroize();
    }
}

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
    pub code: &'a ErrorCode,
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
    /// This function is only available with BOTH the `trusted_debug` feature flag
    /// AND debug assertions enabled. This prevents accidental use in production.
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
    #[cfg(all(feature = "trusted_debug", debug_assertions))]
    pub fn format_for_trusted_debug(&self) -> String {
        let mut output = format!(
            "[{}] {} operation='{}' details='{}'",
            self.code,
            if self.retryable { "[RETRYABLE]" } else { "" },
            truncate_with_indicator(self.operation),
            truncate_with_indicator(self.details)
        );

        if let Some(internal) = self.source_internal {
            output.push_str(&format!(
                " source='{}'",
                truncate_with_indicator(internal)
            ));
        }

        if let Some(sensitive) = self.source_sensitive {
            output.push_str(&format!(
                " sensitive='{}'",
                truncate_with_indicator(sensitive)
            ));
        }

        for (key, value) in self.metadata {
            output.push_str(&format!(
                " {}='{}'",
                key,
                truncate_with_indicator(value.as_str())
            ));
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
            truncate_with_indicator(self.operation),
            truncate_with_indicator(self.details)
        )?;

        if let Some(internal) = self.source_internal {
            write!(f, " source='{}'", truncate_with_indicator(internal))?;
        }

        if let Some(sensitive) = self.source_sensitive {
            write!(f, " sensitive='{}'", truncate_with_indicator(sensitive))?;
        }

        for (key, value) in self.metadata {
            write!(
                f,
                " {}='{}'",
                key,
                truncate_with_indicator(value.as_str())
            )?;
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
    pub const fn code(&self) -> &ErrorCode {
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

    /// Get metadata fields - zero-cost accessor.
    ///
    /// PERFORMANCE FIX: Removed enforce_metadata_floor() that was causing
    /// 15ms delays. Timing obfuscation should be done once during error
    /// construction, not on every field access.
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
/// If the string exceeds MAX_FIELD_OUTPUT_LEN, it's truncated with an indicator
/// to make the truncation visible to operators.
///
/// Returns a Cow<str> to avoid allocation when no truncation is needed.
fn truncate_with_indicator(s: &str) -> Cow<'_, str> {
    if s.len() <= MAX_FIELD_OUTPUT_LEN {
        return Cow::Borrowed(s);
    }

    // Reserve space for the truncation indicator
    let max_content_len = MAX_FIELD_OUTPUT_LEN.saturating_sub(TRUNCATION_INDICATOR.len());

    // Find the last valid UTF-8 character boundary at or before the limit
    let mut idx = max_content_len;
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }

    // If we couldn't find a boundary (pathological case), just use the indicator
    if idx == 0 {
        return Cow::Borrowed(TRUNCATION_INDICATOR);
    }

    // Allocate a new string with the truncated content + indicator
    let mut result = String::with_capacity(idx + TRUNCATION_INDICATOR.len());
    result.push_str(&s[..idx]);
    result.push_str(TRUNCATION_INDICATOR);
    Cow::Owned(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_ascii() {
        let s = "a".repeat(MAX_FIELD_OUTPUT_LEN + 10);
        let truncated = truncate_with_indicator(&s);

        // Should be truncated
        assert!(truncated.len() <= MAX_FIELD_OUTPUT_LEN);

        // Should contain truncation indicator
        assert!(truncated.ends_with(TRUNCATION_INDICATOR));
    }

    #[test]
    fn no_truncate_when_under_limit() {
        let s = "short string";
        let truncated = truncate_with_indicator(s);

        // Should be borrowed (no allocation)
        assert!(matches!(truncated, Cow::Borrowed(_)));
        assert_eq!(truncated, s);
    }

    #[test]
    fn truncate_utf8_boundary() {
        // Russian text: каждый символ занимает 2 байта
        let s = "й".repeat(MAX_FIELD_OUTPUT_LEN); // Each 'й' is 2 bytes
        let truncated = truncate_with_indicator(&s);

        // Should not panic, should be valid UTF-8
        let _ = truncated.to_string();

        // Length should be at most MAX_FIELD_OUTPUT_LEN
        assert!(truncated.len() <= MAX_FIELD_OUTPUT_LEN);

        // Should end with truncation indicator
        assert!(truncated.ends_with(TRUNCATION_INDICATOR));
    }

    #[test]
    fn truncate_emoji() {
        let s = "🔥".repeat(MAX_FIELD_OUTPUT_LEN); // Each emoji is 4 bytes
        let truncated = truncate_with_indicator(&s);

        // Must remain valid UTF-8
        assert!(std::str::from_utf8(truncated.as_bytes()).is_ok());

        // Should contain truncation indicator
        assert!(truncated.ends_with(TRUNCATION_INDICATOR));
    }

    #[test]
    fn exactly_at_limit() {
        let s = "a".repeat(MAX_FIELD_OUTPUT_LEN);
        let truncated = truncate_with_indicator(&s);

        // Should NOT be truncated (exactly at limit)
        assert!(matches!(truncated, Cow::Borrowed(_)));
        assert_eq!(truncated.len(), MAX_FIELD_OUTPUT_LEN);
        assert!(!truncated.ends_with(TRUNCATION_INDICATOR));
    }

    #[test]
    fn one_over_limit() {
        let s = "a".repeat(MAX_FIELD_OUTPUT_LEN + 1);
        let truncated = truncate_with_indicator(&s);

        // Should be truncated
        assert!(matches!(truncated, Cow::Owned(_)));
        assert!(truncated.len() <= MAX_FIELD_OUTPUT_LEN);
        assert!(truncated.ends_with(TRUNCATION_INDICATOR));
    }

    #[test]
    fn context_field_zeroizes_owned() {
        let mut field = ContextField::from(String::from("sensitive"));

        // Verify it's owned
        assert!(matches!(field.value, Cow::Owned(_)));

        // Zeroize manually (normally done in Drop)
        field.zeroize();

        // Value should be empty after zeroization
        assert_eq!(field.as_str(), "");
    }

    #[test]
    fn context_field_doesnt_zeroize_borrowed() {
        let mut field = ContextField::from("static");

        // Verify it's borrowed
        assert!(matches!(field.value, Cow::Borrowed(_)));

        // Zeroize should be no-op for borrowed
        field.zeroize();

        // Value should still be intact (static string)
        assert_eq!(field.as_str(), "static");
    }
}