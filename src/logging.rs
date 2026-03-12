//! Structured internal log view.
//!
//! `InternalLog` is `pub(crate)` only.  External callers interact with error
//! data exclusively through the redacted `Display` on `AgentError` or by
//! reading an encrypted log file produced by `AgentError::log()`.
//!
//! # Trust boundary
//!
//! | Field      | Accessor             | Requires            |
//! |------------|----------------------|---------------------|
//! | external   | `external()`         | nothing (lie/decoy) |
//! | internal   | `internal()`         | trusted log context |
//! | sensitive  | `expose_sensitive()` | `SocAccess` token   |
//!
//! # Zero-allocation guarantee
//!
//! All accessors return `&str` slices into the parent `AgentError`.
//! `write_to()` writes directly to a `fmt::Write` sink — no intermediate heap.

use crate::codes::ErrorCode;
use crate::models::SocAccess;
use crate::zeroization::{Zeroize, drop_zeroize};
use std::borrow::Cow;
use std::fmt;

// ── Field length caps ─────────────────────────────────────────────────────────

const MAX_FIELD_OUTPUT_LEN: usize = 1_024;
const TRUNCATION_INDICATOR: &str = "...[TRUNCATED]";

// ── ContextField ──────────────────────────────────────────────────────────────

/// Metadata value wrapper with zeroize-on-drop for owned data.
#[derive(Debug)]
pub(crate) struct ContextField {
    pub(crate) value: Cow<'static, str>,
}

impl ContextField {
    #[inline]
    pub(crate) fn as_str(&self) -> &str {
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
        drop_zeroize(self);
    }
}

// ── InternalLog ───────────────────────────────────────────────────────────────

/// Structured view of an `AgentError` for crate-internal logging purposes.
///
/// # Lifetime
///
/// `'a` is tied to the originating `AgentError`.  The log cannot outlive the
/// error — compiler-enforced, not merely conventional.
///
/// # Security note
///
/// `Display` and `Debug` are intentionally absent.  Callers must use explicit
/// accessor methods to select which fields to emit, preventing accidental
/// bulk-logging of sensitive content.
///
/// `pub(crate)` — not accessible from outside this crate.
pub(crate) struct InternalLog<'a> {
    pub(crate) code: &'a ErrorCode,
    pub(crate) external: &'a str,
    pub(crate) internal: &'a str,
    pub(crate) sensitive: Option<&'a str>,
    pub(crate) retryable: bool,
}

impl<'a> InternalLog<'a> {
    #[inline]
    pub(crate) fn new(
        code: &'a ErrorCode,
        external: &'a str,
        internal: &'a str,
        sensitive: Option<&'a str>,
        retryable: bool,
    ) -> Self {
        Self {
            code,
            external,
            internal,
            sensitive,
            retryable,
        }
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    /// Obfuscated error code string, e.g. `"E-CFG-103"`.
    #[inline]
    pub(crate) fn code_display(&self) -> String {
        self.code.to_string()
    }

    /// Deceptive category label (mirrors external-facing output).
    #[inline]
    pub(crate) fn category_name(&self) -> &'static str {
        self.code.category().deceptive_name()
    }

    /// The external / deceptive payload — the lie presented to adversaries.
    #[inline]
    pub(crate) fn external(&self) -> &str {
        self.external
    }

    /// The internal diagnostic payload.  **Never** forward to external systems.
    #[inline]
    pub(crate) fn internal(&self) -> &str {
        self.internal
    }

    /// Access the sensitive payload.  Requires a `SocAccess` capability token.
    #[inline]
    pub(crate) fn expose_sensitive(&self, _token: &SocAccess) -> Option<&str> {
        self.sensitive
    }

    /// Whether the originating error is transient.
    #[inline]
    pub(crate) const fn is_retryable(&self) -> bool {
        self.retryable
    }

    // ── Formatted output ──────────────────────────────────────────────────────

    /// Write non-sensitive fields to any `fmt::Write` sink.
    ///
    /// Writes `code`, `category`, `retryable`, `external`, and `internal`.
    /// The `sensitive` field is **never** written; callers must use
    /// `expose_sensitive` explicitly.  Each field is truncated to
    /// `MAX_FIELD_OUTPUT_LEN` bytes to prevent DoS via enormous payloads.
    pub(crate) fn write_to(&self, f: &mut impl fmt::Write) -> fmt::Result {
        write!(
            f,
            "[{}]{} category='{}' external='",
            self.code,
            if self.retryable { "[RETRYABLE]" } else { "" },
            self.code.category().deceptive_name(),
        )?;
        write_truncated(f, self.external)?;
        f.write_str("' internal='")?;
        write_truncated(f, self.internal)?;
        f.write_str("' sensitive=<REQUIRES_SOC_ACCESS>")
    }
}

// ── Truncation helpers ────────────────────────────────────────────────────────

fn truncate_with_indicator(s: &str) -> Cow<'_, str> {
    if s.len() <= MAX_FIELD_OUTPUT_LEN {
        return Cow::Borrowed(s);
    }
    let max_content = MAX_FIELD_OUTPUT_LEN.saturating_sub(TRUNCATION_INDICATOR.len());
    let mut idx = max_content;
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    if idx == 0 {
        return Cow::Borrowed(TRUNCATION_INDICATOR);
    }
    let mut result = String::with_capacity(idx + TRUNCATION_INDICATOR.len());
    result.push_str(&s[..idx]);
    result.push_str(TRUNCATION_INDICATOR);
    Cow::Owned(result)
}

#[inline]
pub(crate) fn write_truncated(f: &mut impl fmt::Write, s: &str) -> fmt::Result {
    if s.len() <= MAX_FIELD_OUTPUT_LEN {
        return f.write_str(s);
    }
    let max_content = MAX_FIELD_OUTPUT_LEN.saturating_sub(TRUNCATION_INDICATOR.len());
    let mut idx = max_content;
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    if idx == 0 {
        return f.write_str(TRUNCATION_INDICATOR);
    }
    f.write_str(&s[..idx])?;
    f.write_str(TRUNCATION_INDICATOR)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_at_limit_no_allocation() {
        let s = "a".repeat(MAX_FIELD_OUTPUT_LEN);
        let result = truncate_with_indicator(&s);
        assert!(matches!(result, Cow::Borrowed(_)));
        assert_eq!(result.len(), MAX_FIELD_OUTPUT_LEN);
    }

    #[test]
    fn truncate_over_limit_appends_indicator() {
        let s = "a".repeat(MAX_FIELD_OUTPUT_LEN + 10);
        let result = truncate_with_indicator(&s);
        assert!(matches!(result, Cow::Owned(_)));
        assert!(result.len() <= MAX_FIELD_OUTPUT_LEN);
        assert!(result.ends_with(TRUNCATION_INDICATOR));
    }

    #[test]
    fn truncate_respects_utf8_boundary() {
        let s = "й".repeat(MAX_FIELD_OUTPUT_LEN); // 2 bytes each
        let result = truncate_with_indicator(&s);
        assert!(std::str::from_utf8(result.as_bytes()).is_ok());
        assert!(result.len() <= MAX_FIELD_OUTPUT_LEN);
    }

    #[test]
    fn context_field_zeroizes_owned() {
        let mut field = ContextField::from(String::from("sensitive"));
        assert!(matches!(field.value, Cow::Owned(_)));
        field.zeroize();
        assert_eq!(field.as_str(), "");
    }

    #[test]
    fn context_field_noop_for_borrowed() {
        let mut field = ContextField::from("static");
        assert!(matches!(field.value, Cow::Borrowed(_)));
        field.zeroize(); // must not panic
        assert_eq!(field.as_str(), "static");
    }
}
