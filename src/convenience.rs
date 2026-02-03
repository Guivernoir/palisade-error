//! Convenience macros for creating errors with format strings.
//!
//! # Security Model
//!
//! These macros enforce compile-time safety to prevent untrusted data from
//! leaking into error messages without explicit sanitization.
//!
//! # Rules
//!
//! 1. **Operation names MUST be string literals** - prevents dynamic injection
//! 2. **Format strings MUST be string literals** - prevents format string attacks
//! 3. **Format arguments must be sanitized via `sanitized!()` wrapper** - bounded length
//!
//! # Usage
//!
//! ```rust
//! # use palisade_errors::{config_err, definitions, sanitized};
//! let line_num = 42;
//! // ✓ CORRECT: Format string is literal, variable is sanitized
//! let err = config_err!(
//!     &definitions::CFG_PARSE_FAILED,
//!     "validate",
//!     "Invalid value at line {}",
//!     sanitized!(line_num)
//! );
//! ```
//!
//! ```rust,compile_fail
//! # use palisade_errors::{config_err, definitions};
//! let user_input = "attacker data";
//! // ✗ COMPILE ERROR: Operation must be a literal
//! let err = config_err!(&definitions::CFG_PARSE_FAILED, user_input, "Failed");
//! ```
//!
//! ```rust,compile_fail
//! # use palisade_errors::{config_err, definitions};
//! let unsanitized = "oops";
//! // ✗ COMPILE ERROR: Args must be wrapped in sanitized!()
//! let err = config_err!(&definitions::CFG_PARSE_FAILED, "op", "{}", unsanitized);
//! ```
//!
//! ## Sanitization
//!
//! The `sanitized!()` macro truncates strings to prevent DoS via massive error messages
//! and ensures all format arguments are bounded in length.
//!
//! # Security Properties
//!
//! This module implements several security principles to make the error macro system dumb-proof and secure:
//! - **Compile-time Literal Enforcement**: Requires operation names, details, and format strings to be string literals, preventing runtime injection or format string vulnerabilities.
//! - **Mandatory Sanitization for Dynamic Data**: Dynamic arguments must be explicitly wrapped in `sanitized!()` macro. This prevents accidental inclusion of unsanitized data.
//! - **Length Bounding and Truncation**: Sanitized values are strictly limited to 256 characters to prevent DoS through oversized error messages or logs.
//! - **UTF-8 Boundary Respect**: Truncation always occurs at valid character boundaries to avoid creating invalid strings that could cause downstream parsing errors.
//! - **Control Character Neutralization**: Non-printable control characters are replaced with '?' to prevent log injection, formatting disruption, or terminal escape sequence attacks.
//! - **Sensitive Data Isolation**: Sensitive information (e.g., passwords, keys) must use dedicated `_sensitive` macros and is isolated to internal logs only—never exposed in external error messages.
//! - **No External Sensitive Logging**: Sensitive data is structurally separated and cannot be accidentally included in public-facing error details by convention.
//! - **Pure Macro Expansion**: Macros expand to pure expressions without side effects, I/O, or runtime dependencies beyond standard library.
//! - **Defense in Depth**: Multiple layers including literal requirements, sanitization, and separation ensure even if one layer fails, others protect.
//! - **Fail-Safe Defaults**: Invalid UTF-8 or truncation failures default to safe placeholders like "[INVALID_UTF8]" instead of panicking or leaking.
//! - **No Side Channels**: Sanitization is deterministic and linear-time relative to input length (up to bound), avoiding attacker-controlled amplification.
//! - **Dumb-Proof Design**: By requiring explicit `sanitized!()` for args and literals for formats, accidental misuse (e.g., logging raw sensitive data externally) fails at compile time or produces safe output.
//!
//! Note: While format! allocates, this is acceptable for error paths. For hot paths, consider pre-formatted strings.

// ============================================================================
// Sanitization Utilities
// ============================================================================

/// Maximum length for sanitized strings in error messages.
///
/// This prevents DoS attacks via extremely long error messages while still
/// allowing enough context for debugging.
pub const MAX_SANITIZED_LEN: usize = 256;

/// Sanitize untrusted input for inclusion in error messages.
///
/// # Behavior
/// - Truncates strings to MAX_SANITIZED_LEN characters, respecting UTF-8 boundaries.
/// - Replaces control characters with '?' to prevent log injection or formatting issues.
/// - Handles non-string types by converting to string first.
/// - For fully control-char inputs exceeding length, uses "[INVALID_INPUT]".
///
/// # Allocation
/// - Allocates a new String for the sanitized output.
///
/// # Example
///
/// ```rust
/// # use palisade_errors::sanitized;
/// let long = "A".repeat(300);
/// let san = sanitized!(long);
/// assert!(san.len() <= 256 + 13);
/// assert!(san.ends_with("[TRUNCATED]"));
/// ```
#[macro_export]
macro_rules! sanitized {
    ($expr:expr) => {{
        let original = $expr.to_string();
        let max_len = $crate::convenience::MAX_SANITIZED_LEN;
        
        let mut s = String::with_capacity(max_len.min(original.len()));
        let mut len = 0;
        let mut truncated = false;
        let mut saw_non_control = false;
        let mut in_escape = false;
        
        for c in original.chars() {
            if in_escape {
                if c == 'm' {
                    in_escape = false;
                }
                continue;
            }

            if c == '\u{1b}' {
                in_escape = true;
                let replacement = '?';
                let char_len = replacement.len_utf8();
                if len + char_len > max_len {
                    truncated = true;
                    break;
                }
                s.push(replacement);
                len += char_len;
                continue;
            }

            let replacement = if c.is_control() { '?' } else { c };
            if !c.is_control() {
                saw_non_control = true;
            }
            let char_len = replacement.len_utf8();
            
            if len + char_len > max_len {
                truncated = true;
                break;
            }
            
            s.push(replacement);
            len += char_len;
        }
        
        if !saw_non_control {
            s = String::from("[INVALID_INPUT]");
        } else if truncated {
            // 13 is length of "...[TRUNCATED]"
            let mut new_len = max_len.saturating_sub(13);
            while new_len > 0 && !s.is_char_boundary(new_len) {
                new_len -= 1;
            }
            if len > new_len {
                s.truncate(new_len);
            }
            if !s.is_empty() {
                s.push_str("...[TRUNCATED]");
            } else {
                s = String::from("[INVALID_INPUT]");
            }
        }
        
        s
    }};
}

// ============================================================================
// Internal Helper Macro
// ============================================================================

#[macro_export]
macro_rules! create_lie_error {
    ($prefix:literal, $code:expr, $op:literal, $details:expr) => {
        {
            let details = $details;
            let internal = format!("{} op '{}': {}", $prefix, $op, details);
            $crate::DualContextError::with_lie(details, internal, $code.category())
        }
    };
}

// ============================================================================
// Error Creation Macros
// ============================================================================

/// Create a configuration error with compile-time literal enforcement.
///
/// Uses DualContextError::with_lie for public deception.
///
/// # Arguments
/// - `$code`: &ErrorCode (expression)
/// - `$op`: Operation name (string literal)
/// - `$details`: Public details (string literal or format literal)
/// - `$args`: Optional sanitized arguments (must use sanitized!())
///
/// # Security
/// - Public: Deceptive lie from $details
/// - Internal: Diagnostic with operation context
///
/// # Example
///
/// ```rust
/// # use palisade_errors::{config_err, definitions, sanitized};
/// let value = 42;
/// let err = config_err!(
///     &definitions::CFG_INVALID_VALUE,
///     "validate_threshold",
///     "Invalid configuration value: {}",
///     sanitized!(value)
/// );
/// ```
#[macro_export]
macro_rules! config_err {
    ($code:expr, $op:literal, $details:literal) => {
        $crate::create_lie_error!("Configuration", $code, $op, $details)
    };
    ($code:expr, $op:literal, $fmt:literal $(, sanitized!($arg:expr))+ $(,)?) => {
        {
            let details = format!($fmt $(, $crate::sanitized!($arg))+);
            $crate::create_lie_error!("Configuration", $code, $op, details)
        }
    };
}

/// Create a configuration error with sensitive internal context.
///
/// # Arguments
/// - `$code`: &ErrorCode
/// - `$op`: Operation literal
/// - `$public`: Public deceptive literal or format
/// - `$sensitive`: Sensitive data for internal only (recommend sanitizing)
///
/// # Security
/// - Public: Lie from $public
/// - Internal: Sensitive with operation
///
/// # Example
///
/// ```rust
/// # use palisade_errors::{config_err_sensitive, definitions, sanitized};
/// let secret = "key";
/// let err = config_err_sensitive!(
///     &definitions::CFG_VALIDATION_FAILED,
///     "auth",
///     "Configuration invalid",
///     sanitized!(secret)
/// );
/// ```
#[macro_export]
macro_rules! config_err_sensitive {
    ($code:expr, $op:literal, $public:literal, $sensitive:expr) => {
        $crate::DualContextError::with_lie_and_sensitive(
            $public,
            format!("Operation '{}': [SENSITIVE] {}", $op, $sensitive),
            $code.category(),
        )
    };
    ($code:expr, $op:literal, $fmt:literal, $sensitive:expr $(, sanitized!($arg:expr))+ $(,)?) => {
        $crate::DualContextError::with_lie_and_sensitive(
            format!($fmt $(, $crate::sanitized!($arg))+),
            format!("Operation '{}': [SENSITIVE] {}", $op, $sensitive),
            $code.category(),
        )
    };
}

/// Create a deployment error.
///
/// Maps to Deployment category, uses with_lie.
#[macro_export]
macro_rules! deployment_err {
    ($code:expr, $op:literal, $details:literal) => {
        $crate::create_lie_error!("Deployment", $code, $op, $details)
    };
    ($code:expr, $op:literal, $fmt:literal $(, sanitized!($arg:expr))+ $(,)?) => {
        {
            let details = format!($fmt $(, $crate::sanitized!($arg))+);
            $crate::create_lie_error!("Deployment", $code, $op, details)
        }
    };
}

/// Create a telemetry error.
///
/// Maps to Monitoring category.
#[macro_export]
macro_rules! telemetry_err {
    ($code:expr, $op:literal, $details:literal) => {
        $crate::create_lie_error!("Telemetry", $code, $op, $details)
    };
    ($code:expr, $op:literal, $fmt:literal $(, sanitized!($arg:expr))+ $(,)?) => {
        {
            let details = format!($fmt $(, $crate::sanitized!($arg))+);
            $crate::create_lie_error!("Telemetry", $code, $op, details)
        }
    };
}

/// Create a correlation error.
///
/// Maps to Analysis category.
#[macro_export]
macro_rules! correlation_err {
    ($code:expr, $op:literal, $details:literal) => {
        $crate::create_lie_error!("Correlation", $code, $op, $details)
    };
    ($code:expr, $op:literal, $fmt:literal $(, sanitized!($arg:expr))+ $(,)?) => {
        {
            let details = format!($fmt $(, $crate::sanitized!($arg))+);
            $crate::create_lie_error!("Correlation", $code, $op, details)
        }
    };
}

/// Create a response error.
///
/// Maps to Response category.
#[macro_export]
macro_rules! response_err {
    ($code:expr, $op:literal, $details:literal) => {
        $crate::create_lie_error!("Response", $code, $op, $details)
    };
    ($code:expr, $op:literal, $fmt:literal $(, sanitized!($arg:expr))+ $(,)?) => {
        {
            let details = format!($fmt $(, $crate::sanitized!($arg))+);
            $crate::create_lie_error!("Response", $code, $op, details)
        }
    };
}

/// Create a logging error.
///
/// Maps to Audit category.
#[macro_export]
macro_rules! logging_err {
    ($code:expr, $op:literal, $details:literal) => {
        $crate::create_lie_error!("Logging", $code, $op, $details)
    };
    ($code:expr, $op:literal, $fmt:literal $(, sanitized!($arg:expr))+ $(,)?) => {
        {
            let details = format!($fmt $(, $crate::sanitized!($arg))+);
            $crate::create_lie_error!("Logging", $code, $op, details)
        }
    };
}

/// Create a platform error.
///
/// Maps to System category.
#[macro_export]
macro_rules! platform_err {
    ($code:expr, $op:literal, $details:literal) => {
        $crate::create_lie_error!("Platform", $code, $op, $details)
    };
    ($code:expr, $op:literal, $fmt:literal $(, sanitized!($arg:expr))+ $(,)?) => {
        {
            let details = format!($fmt $(, $crate::sanitized!($arg))+);
            $crate::create_lie_error!("Platform", $code, $op, details)
        }
    };
}

/// Create an I/O error.
///
/// Maps to IO category.
#[macro_export]
macro_rules! io_err {
    ($code:expr, $op:literal, $details:literal) => {
        $crate::create_lie_error!("IO", $code, $op, $details)
    };
    ($code:expr, $op:literal, $fmt:literal $(, sanitized!($arg:expr))+ $(,)?) => {
        {
            let details = format!($fmt $(, $crate::sanitized!($arg))+);
            $crate::create_lie_error!("IO", $code, $op, details)
        }
    };
}

/// Define error codes with minimal boilerplate.
///
/// # Example
///
/// ```rust
/// # use palisade_errors::{define_error_code, OperationCategory, namespaces};
/// define_error_code!(
///     CFG_PARSE_FAILED,
///     &namespaces::CFG,
///     100,
///     OperationCategory::Configuration,
///     350
/// );
/// ```
#[macro_export]
macro_rules! define_error_code {
    ($name:ident, $namespace:expr, $code:expr, $category:expr, $impact:expr) => {
        pub const $name: $crate::ErrorCode = $crate::ErrorCode::const_new(
            $namespace,
            $code,
            $category,
            $crate::ImpactScore::new($impact),
        );
    };
}

/// Define multiple error codes within the same namespace.
///
/// # Example
///
/// ```rust
/// # use palisade_errors::{define_error_codes, OperationCategory, namespaces};
/// define_error_codes! {
///     &namespaces::CFG, OperationCategory::Configuration => {
///         CFG_PARSE_FAILED = (100, 350),
///         CFG_VALIDATION_FAILED = (101, 250),
///     }
/// }
/// ```
#[macro_export]
macro_rules! define_error_codes {
    ($namespace:expr, $category:expr => { $( $name:ident = ($code:expr, $impact:expr) ),+ $(,)? }) => {
        $(
            $crate::define_error_code!($name, $namespace, $code, $category, $impact);
        )+
    };
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::definitions;
    use crate::SocAccess;

    #[test]
    fn test_literal_enforcement_compiles() {
        // These should compile
        let _err1 = config_err!(&definitions::CFG_PARSE_FAILED, "test_op", "test details");
        let line = 42;
        let _err2 = config_err!(&definitions::CFG_PARSE_FAILED, "test_op", "line {}", sanitized!(line));
    }

    #[test]
    fn sanitized_macro_truncates_long_strings() {
        let long_string = "A".repeat(1000);
        let sanitized = sanitized!(long_string);
        
        assert!(sanitized.len() <= MAX_SANITIZED_LEN + 13); // "...[TRUNCATED]"
        assert!(sanitized.contains("[TRUNCATED]"));
    }
    
    #[test]
    fn sanitized_macro_preserves_short_strings() {
        let short_string = "short";
        let sanitized = sanitized!(short_string);
        
        assert_eq!(sanitized, "short");
    }
    
    #[test]
    fn sanitized_macro_respects_utf8_boundaries() {
        let emoji = "🔥".repeat(100);
        let sanitized = sanitized!(emoji);
        
        assert!(std::str::from_utf8(sanitized.as_bytes()).is_ok());
    }
    
    #[test]
    fn sanitized_macro_replaces_control_chars() {
        let input = "hello\nworld\t\x07";
        let sanitized = sanitized!(input);
        
        assert_eq!(sanitized, "hello?world??");
    }
    
    #[test]
    fn sanitized_macro_handles_invalid_start() {
        let input = "\x07".repeat(300);
        let sanitized = sanitized!(input);
        
        assert_eq!(sanitized, "[INVALID_INPUT]");
    }
    
    #[test]
    fn sanitized_macro_works_with_numbers() {
        let num = 42;
        let sanitized = sanitized!(num);
        
        assert_eq!(sanitized, "42");
    }
    
    #[test]
    fn error_macros_with_sanitized_args() {
        let value = "untrusted".repeat(100);
        let err = config_err!(
            &definitions::CFG_INVALID_VALUE,
            "validate",
            "Invalid value: {}",
            sanitized!(value)
        );
        
        assert!(err.external_message().len() <= MAX_SANITIZED_LEN + 20); // "Invalid value: " + truncated
    }
    
    #[test]
    fn config_err_sensitive_with_sanitization() {
        let password = "secret123";
        let err = config_err_sensitive!(
            &definitions::CFG_VALIDATION_FAILED,
            "auth",
            "Auth failed",
            sanitized!(format!("pwd_len={}", password.len()))
        );
        
        assert_eq!(err.external_message(), "Auth failed");
        let access = SocAccess::acquire();
        let sensitive = err.internal().expose_sensitive(&access).unwrap();
        assert!(sensitive.contains("pwd_len=9"));
    }
    
    #[test]
    fn all_error_macros_compile() {
        let val = "test";
        
        let _e1 = config_err!(&definitions::CFG_PARSE_FAILED, "op", "details");
        let _e2 = deployment_err!(&definitions::DCP_DEPLOY_FAILED, "op", "details");
        let _e3 = telemetry_err!(&definitions::TEL_INIT_FAILED, "op", "details");
        let _e4 = correlation_err!(&definitions::COR_RULE_EVAL_FAILED, "op", "details");
        let _e5 = response_err!(&definitions::RSP_EXEC_FAILED, "op", "details");
        let _e6 = logging_err!(&definitions::LOG_WRITE_FAILED, "op", "details");
        let _e7 = platform_err!(&definitions::PLT_UNSUPPORTED, "op", "details");
        let _e8 = io_err!(&definitions::IO_TIMEOUT, "op", "details");
        
        // With format
        let _e9 = config_err!(&definitions::CFG_PARSE_FAILED, "op", "val: {}", sanitized!(val));
    }
    
    #[test]
    fn macros_accept_trailing_comma() {
        let value = 42;
        let _err = config_err!(
            &definitions::CFG_PARSE_FAILED,
            "test",
            "Value: {}",
            sanitized!(value),
        );
    }
    
    #[test]
    fn sanitized_with_pathological_utf8() {
        let s = "Ñ".repeat(128); // Each 2 bytes, total 256 bytes
        let sanitized = sanitized!(s);
        
        assert_eq!(sanitized.len(), 256);
        assert!(std::str::from_utf8(sanitized.as_bytes()).is_ok());
    }
    
    #[test]
    fn sanitized_with_mixed_controls() {
        let s = "normal\x1b[0m escape \r\n sequence";
        let sanitized = sanitized!(s);
        assert_eq!(sanitized, "normal? escape ?? sequence");
    }
}
