//! Internal convenience utilities.
//!
//! All items in this module are `pub(crate)`.  No macros are exported to
//! downstream crates — the public API is exclusively `AgentError::new()`.
//!
//! # Sanitization
//!
//! `sanitize_into` is the production sanitization path.
//! `sanitize_string` is a test-only wrapper used by assertions.

#[cfg(any(feature = "log", test))]
use crate::fixed::FixedString;
#[cfg(any(feature = "log", test))]
use std::fmt::Write as _;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum byte length for a sanitized string embedded in error payloads.
#[cfg(any(feature = "log", test))]
pub(crate) const MAX_SANITIZED_LEN: usize = 256;
#[cfg(any(feature = "log", test))]
const TRUNCATION_INDICATOR: &str = "...[TRUNCATED]";

// ── Sanitization ──────────────────────────────────────────────────────────────

/// Test-only sanitization wrapper that materializes the result as a `String`.
///
/// - Truncates to `MAX_SANITIZED_LEN` characters at a valid UTF-8 boundary.
/// - Replaces control characters, including line and field separators, with
///   `'?'` to prevent log injection or terminal escape-sequence attacks.
/// - Appends `"...[TRUNCATED]"` when truncation occurs so operators know.
/// - Returns a `String`; allocation is confined to tests.
#[cfg(test)]
pub(crate) fn sanitize_string(input: &str) -> String {
    let mut out = FixedString::<MAX_SANITIZED_LEN>::new();
    sanitize_into(&mut out, input, MAX_SANITIZED_LEN);
    out.as_str().to_owned()
}

/// Sanitize `input` into an inline fixed-capacity output buffer.
#[cfg(any(feature = "log", test))]
pub(crate) fn sanitize_into<const N: usize>(
    out: &mut FixedString<N>,
    input: &str,
    max_bytes: usize,
) {
    let capacity = N.min(max_bytes);
    out.clear();
    if capacity == 0 {
        return;
    }

    let mut chars = input.chars().peekable();
    let mut truncated = false;
    while let Some(ch) = chars.next() {
        let safe = if ch.is_control() { '?' } else { ch };

        if out.len() + safe.len_utf8() > capacity {
            truncated = true;
            break;
        }

        out.write_char(safe)
            .expect("fixed string capacity pre-checked");
        if chars.peek().is_some() && out.len() == capacity {
            truncated = true;
            break;
        }
    }

    if truncated {
        let indicator_len = TRUNCATION_INDICATOR.len().min(capacity);
        while out.len() + indicator_len > capacity {
            let mut new_len = out.len().saturating_sub(1);
            while new_len > 0 && !out.as_str().is_char_boundary(new_len) {
                new_len -= 1;
            }
            out.truncate(new_len);
        }
        out.write_str(&TRUNCATION_INDICATOR[..indicator_len])
            .expect("indicator must fit sanitized output");
    }
}

// ── Error-code definition macros (crate-internal only) ───────────────────────

/// Define a single error code as a `pub(crate) static` item.
///
/// Produces a `static` (not `const`) so that `&'static ErrorCode` references
/// can be safely taken in the lookup table in `lib.rs`.
macro_rules! define_error_code {
    ($name:ident, $namespace:expr, $code:expr, $category:expr, $impact:expr) => {
        pub(crate) static $name: $crate::codes::ErrorCode = $crate::codes::ErrorCode::const_new(
            $namespace,
            $code,
            $category,
            $crate::codes::ImpactScore::new($impact),
        );
    };
}

/// Define multiple error codes within the same namespace and category.
///
/// ```text
/// define_error_codes! {
///     &namespaces::CFG, OperationCategory::Configuration => {
///         CFG_PARSE_FAILED        = (100, 200),
///         CFG_VALIDATION_FAILED   = (101, 200),
///     }
/// }
/// ```
///
/// Not exported (`#[macro_export]` is intentionally absent).
macro_rules! define_error_codes {
    ($namespace:expr, $category:expr => {
        $( $name:ident = ($code:expr, $impact:expr) ),+
        $(,)?
    }) => {
        $(
            define_error_code!($name, $namespace, $code, $category, $impact);
        )+
    };
}

// Make the macros available to sibling modules.
pub(crate) use define_error_code;
pub(crate) use define_error_codes;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_truncates_long_strings() {
        let long = "A".repeat(1_000);
        let result = sanitize_string(&long);
        // Character count of the result body is bounded.
        assert!(result.len() <= MAX_SANITIZED_LEN + 14);
        assert!(result.contains("[TRUNCATED]"));
    }

    #[test]
    fn sanitize_replaces_control_chars() {
        let input = "hello\x01wor\tld\n\r\x7f";
        let result = sanitize_string(input);
        assert!(!result.contains('\x01'));
        assert!(!result.contains('\t'));
        assert!(!result.contains('\n'));
        assert!(!result.contains('\r'));
        assert!(!result.contains('\x7f'));
        assert!(result.contains('?'));
    }

    #[test]
    fn sanitize_preserves_short_clean_input() {
        let input = "clean string";
        assert_eq!(sanitize_string(input), "clean string");
    }

    #[test]
    fn sanitize_handles_valid_utf8_multibyte() {
        let emoji = "🔥".repeat(300); // well over limit
        let result = sanitize_string(&emoji);
        // Must remain valid UTF-8 after truncation.
        assert!(std::str::from_utf8(result.as_bytes()).is_ok());
    }
}
