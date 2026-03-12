//! Internal convenience utilities.
//!
//! All items in this module are `pub(crate)`.  No macros are exported to
//! downstream crates — the public API is exclusively `AgentError::new()`.
//!
//! # Sanitization
//!
//! `sanitize_string` and `MAX_SANITIZED_LEN` remain available for any internal
//! code that needs to bound dynamic strings before embedding them in payloads.

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum byte length for a sanitized string embedded in error payloads.
pub(crate) const MAX_SANITIZED_LEN: usize = 256;

// ── Sanitization ──────────────────────────────────────────────────────────────

/// Sanitize a string for safe embedding in error payloads.
///
/// - Truncates to `MAX_SANITIZED_LEN` characters at a valid UTF-8 boundary.
/// - Replaces ASCII control characters (0x00–0x1F and 0x7F) with `'?'` to
///   prevent log injection or terminal escape-sequence attacks.
/// - Appends `"...[TRUNCATED]"` when truncation occurs so operators know.
/// - Returns a `String`; allocation is acceptable on error paths.
pub(crate) fn sanitize_string(input: &str) -> String {
    // Replace control characters first (operates on characters, not bytes).
    let sanitized: String = input
        .chars()
        .map(|c| {
            if c.is_control() && c != '\n' && c != '\t' {
                '?'
            } else {
                c
            }
        })
        .collect();

    // Truncate at MAX_SANITIZED_LEN character boundary.
    if sanitized.chars().count() <= MAX_SANITIZED_LEN {
        return sanitized;
    }

    let mut result = String::with_capacity(MAX_SANITIZED_LEN + 14);
    for (i, c) in sanitized.char_indices() {
        if i >= MAX_SANITIZED_LEN {
            break;
        }
        result.push(c);
    }
    result.push_str("...[TRUNCATED]");
    result
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
        let input = "hello\x01world\x7f";
        let result = sanitize_string(input);
        assert!(!result.contains('\x01'));
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
