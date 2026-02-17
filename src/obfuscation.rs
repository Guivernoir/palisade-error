//! Error code obfuscation (always on).
//!
//! Makes systematic error code fingerprinting harder by adding per-session
//! offsets to error codes. The same semantic error will have different codes
//! across sessions, making it harder for attackers to build a code map.
//!
//! # Security Model
//!
//! - **Namespace preserved**: Still "CFG", "IO", etc. (needed for Display)
//! - **Category preserved**: Still Configuration, I/O, etc.
//! - **Numeric code obfuscated**: E-CFG-100 becomes E-CFG-103, E-CFG-107, etc.
//! - **Session-specific**: Different salt per connection/session
//! - **Deterministic within session**: Same error = same obfuscated code
//!
//! # Threat Mitigation
//!
//! **Without obfuscation:**
//! ```text
//! Attacker triggers 100 errors, sees:
//! E-CFG-100 (repeated 50x)
//! E-CFG-101 (repeated 30x)
//! E-CFG-104 (repeated 20x)
//!
//! Maps to source code, identifies:
//! - 100 = parser.rs:42
//! - 101 = validator.rs:89
//! - 104 = permissions.rs:156
//! ```
//!
//! **With obfuscation:**
//! ```text
//! Session 1: E-CFG-103, E-CFG-104, E-CFG-107
//! Session 2: E-CFG-101, E-CFG-102, E-CFG-105
//! Session 3: E-CFG-106, E-CFG-107, E-CFG-110
//!
//! Attacker cannot correlate codes across sessions.
//! Fingerprinting requires compromising a session to learn its salt.
//! ```
//!
//! # Performance
//!
//! Overhead:
//! Initialize session salt:  352 ps  (2.8T ops/sec)
//! Obfuscate error code:      14 ns  (71.4M ops/sec)
//! Generate random salt:      72 ns  (13.9M ops/sec)
//! Error with obfuscation:   243 ns  (4.1M errors/sec)

use crate::ErrorCode;
use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};

// Thread-local session salt for error code obfuscation.
//
// Each thread/session has its own salt and doesn't share with others.
thread_local! {
    static SESSION_SALT: Cell<u8> = const { Cell::new(0) };
}

/// Counter mixed into generated salts to avoid repeats under high call rates.
static SALT_COUNTER: AtomicU64 = AtomicU64::new(0x9E37_79B9_7F4A_7C15);

/// Initialize session-specific error code salt.
///
/// Call this once per session/connection to enable per-session obfuscation.
/// The salt affects all errors created in this thread until re-initialized.
///
/// # Arguments
///
/// * `seed` - Any u32 value (session ID, connection hash, random number)
///
/// # Implementation Note
///
/// We use only the lower 3 bits (0-7 range) to keep codes within
/// their namespace ranges and avoid collisions.
#[inline]
pub fn init_session_salt(seed: u32) {
    // Use lower 3 bits: gives us 8 different offsets (0-7)
    // This keeps codes well within their 100-range namespaces
    let salt = (seed & 0b111) as u8;
    SESSION_SALT.with(|v| v.set(salt));
}

/// Get current session salt value.
///
/// Useful for debugging or logging which salt is active.
#[inline]
pub fn get_session_salt() -> u32 {
    SESSION_SALT.with(|v| v.get() as u32)
}

/// Clear session salt (revert to no obfuscation).
///
/// Useful for testing or when switching contexts.
#[inline]
pub fn clear_session_salt() {
    SESSION_SALT.with(|v| v.set(0));
}

#[inline]
fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

/// Apply obfuscation to an error code using current session salt.
///
/// Creates a new ErrorCode with:
/// - Same namespace (e.g., "CFG")
/// - Same category (e.g., Configuration)
/// - Offset numeric code (e.g., 100 → 103)
///
/// The offset wraps within the namespace's range to avoid collisions.
///
/// # Example
///
/// ```rust
/// use palisade_errors::{obfuscation, definitions};
///
/// // Base: E-CFG-100
/// obfuscation::init_session_salt(3);
/// let obfuscated = obfuscation::obfuscate_code(&definitions::CFG_PARSE_FAILED);
/// // Result: E-CFG-103
///
/// obfuscation::init_session_salt(7);
/// let obfuscated = obfuscation::obfuscate_code(&definitions::CFG_PARSE_FAILED);
/// // Result: E-CFG-107
/// ```
///
/// # Namespace Safety
///
/// The obfuscation ensures codes stay within their namespace:
/// - CFG (100-199): offsets wrap within 100-199
/// - IO (800-899): offsets wrap within 800-899
/// - etc.
#[inline]
pub fn obfuscate_code(base: &ErrorCode) -> ErrorCode {
    let salt = get_session_salt();
    let base_code = base.code();
    
    // Calculate namespace boundaries
    // E.g., for 150: namespace_base = 100, offset = 50
    let namespace_base = (base_code / 100) * 100;
    let offset = base_code % 100;
    
    // Add salt and wrap within namespace (0-99 range per namespace)
    let new_offset = (offset + salt as u16) % 100;
    let new_code = namespace_base + new_offset;
    
    // Create new code with same namespace and category
    ErrorCode::const_new(base.namespace(), new_code, base.category(), base.impact())
}

/// Generate a random session salt using system entropy.
///
/// Useful for automatically initializing sessions without manual seed management.
///
/// # Example
///
/// ```rust
/// use palisade_errors::obfuscation;
///
/// // Auto-generate salt for this session
/// let salt = obfuscation::generate_random_salt();
/// obfuscation::init_session_salt(salt);
/// ```
#[inline]
pub fn generate_random_salt() -> u32 {
    let now_nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0_u64, |d| d.as_nanos() as u64);
    let counter = SALT_COUNTER.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed);
    let stack_hint = (&now_nanos as *const u64 as usize) as u64;

    let mixed = splitmix64(now_nanos ^ counter.rotate_left(11) ^ stack_hint.rotate_left(17));
    (mixed ^ (mixed >> 32)) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ErrorCode, ImpactScore, OperationCategory};

    #[test]
    fn obfuscation_stays_within_namespace() {
        let base = ErrorCode::const_new(
            &crate::codes::namespaces::CFG,
            150,
            OperationCategory::Configuration,
            ImpactScore::new(100),
        );
        
        for salt in 0..8 {
            init_session_salt(salt);
            let obfuscated = obfuscate_code(&base);
            
            // Should stay in 100-199 range
            assert!(obfuscated.code() >= 100, "Code {} below namespace", obfuscated.code());
            assert!(obfuscated.code() <= 199, "Code {} above namespace", obfuscated.code());
            
            // Namespace and category unchanged
            assert_eq!(obfuscated.namespace().as_str(), "CFG");
            assert_eq!(obfuscated.category(), OperationCategory::Configuration);
        }
    }

    #[test]
    fn different_salts_produce_different_codes() {
        let base = ErrorCode::const_new(
            &crate::codes::namespaces::CFG,
            100,
            OperationCategory::Configuration,
            ImpactScore::new(100),
        );
        
        init_session_salt(0);
        let code1 = obfuscate_code(&base);
        
        init_session_salt(5);
        let code2 = obfuscate_code(&base);
        
        assert_ne!(code1.code(), code2.code());
    }

    #[test]
    fn same_salt_produces_same_code() {
        let base = ErrorCode::const_new(
            &crate::codes::namespaces::CFG,
            100,
            OperationCategory::Configuration,
            ImpactScore::new(100),
        );
        
        init_session_salt(3);
        let code1 = obfuscate_code(&base);
        let code2 = obfuscate_code(&base);
        
        assert_eq!(code1.code(), code2.code());
    }

    #[test]
    fn obfuscation_at_namespace_boundary() {
        // Test edge cases at namespace boundaries
        let base_low = ErrorCode::const_new(
            &crate::codes::namespaces::CFG,
            100,
            OperationCategory::Configuration,
            ImpactScore::new(100),
        );
        let base_high = ErrorCode::const_new(
            &crate::codes::namespaces::CFG,
            199,
            OperationCategory::Configuration,
            ImpactScore::new(100),
        );
        
        init_session_salt(7);
        let obf_low = obfuscate_code(&base_low);
        let obf_high = obfuscate_code(&base_high);
        
        assert!(obf_low.code() >= 100 && obf_low.code() <= 199);
        assert!(obf_high.code() >= 100 && obf_high.code() <= 199);
    }

    #[test]
    fn wrapping_behavior() {
        // Code at 195 + salt 7 = should wrap to 102
        let base = ErrorCode::const_new(
            &crate::codes::namespaces::CFG,
            195,
            OperationCategory::Configuration,
            ImpactScore::new(100),
        );
        init_session_salt(7);
        let obfuscated = obfuscate_code(&base);
        
        // 195 % 100 = 95, (95 + 7) % 100 = 2, 100 + 2 = 102
        assert_eq!(obfuscated.code(), 102);
    }

    #[test]
    fn clear_salt_resets_to_zero() {
        init_session_salt(5);
        assert_eq!(get_session_salt(), 5);
        
        clear_session_salt();
        assert_eq!(get_session_salt(), 0);
    }

    #[test]
    fn random_salt_generation() {
        let salt1 = generate_random_salt();
        let salt2 = generate_random_salt();
        
        // Should be different (extremely high probability)
        assert_ne!(salt1, salt2);
        
        // Should be valid when used
        init_session_salt(salt1);
        assert_eq!(get_session_salt(), salt1 & 0b111);
    }

    #[test]
    fn obfuscation_formatting() {
        let base = ErrorCode::const_new(
            &crate::codes::namespaces::CFG,
            100,
            OperationCategory::Configuration,
            ImpactScore::new(100),
        );
        init_session_salt(3);
        let obfuscated = obfuscate_code(&base);
        
        assert_eq!(obfuscated.to_string(), "E-CFG-103");
    }

    #[test]
    fn multiple_namespaces() {
        init_session_salt(4);
        
        let cfg = ErrorCode::const_new(
            &crate::codes::namespaces::CFG,
            100,
            OperationCategory::Configuration,
            ImpactScore::new(100),
        );
        let io = ErrorCode::const_new(
            &crate::codes::namespaces::IO,
            800,
            OperationCategory::IO,
            ImpactScore::new(100),
        );
        
        let cfg_obf = obfuscate_code(&cfg);
        let io_obf = obfuscate_code(&io);
        
        // Each stays in its namespace
        assert_eq!(cfg_obf.code(), 104);  // 100 + 4
        assert_eq!(io_obf.code(), 804);   // 800 + 4
    }

    #[test]
    fn salt_is_thread_local() {
        clear_session_salt();
        init_session_salt(5);

        let child = std::thread::spawn(get_session_salt)
            .join()
            .expect("thread should not panic");

        // Child thread should not inherit caller's salt.
        assert_eq!(child, 0);
        // Caller thread must keep its own session salt.
        assert_eq!(get_session_salt(), 5);
        clear_session_salt();
    }
}
