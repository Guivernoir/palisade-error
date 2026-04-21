//! Per-session error code obfuscation.
//!
//! # Design
//!
//! A single `SessionSalt` is initialised on first use via `OnceLock`, ensuring
//! every process sees a consistent obfuscated code space for its lifetime while
//! different sessions produce incompatible code spaces.
//!
//! The static-dispatch entry point [`obfuscate_code`] is used by `AgentError::new()`.
//! The `SessionSalt` struct is kept available for unit-tests that need deterministic
//! code values.
//!
//! # Security model
//!
//! | Property              | Guarantee                                          |
//! |-----------------------|----------------------------------------------------|
//! | Namespace preserved   | `CFG`, `IO`, etc. unchanged (needed for Display)   |
//! | Category preserved    | Unchanged                                          |
//! | Numeric code offset   | Per-session random; attacker cannot predict        |
//! | Session isolation     | Global salt is seeded from OS CSPRNG on first call |
//! | Session determinism   | Same error → same code within one process lifetime |
//!
//! # Residual risks
//!
//! With 6-bit salts (1–63), brute-force deduction is feasible if an attacker
//! observes many codes from one session. Use in conjunction with rate-limiting
//! and the ring-buffer DoS guard for defence in depth.

use crate::codes::ErrorCode;
use crate::crypto;
use crate::zeroization::{Zeroize, drop_zeroize};
use std::sync::OnceLock;
#[cfg(test)]
use std::sync::RwLock;
#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};

// ── Global session salt ───────────────────────────────────────────────────────

static GLOBAL_SESSION: OnceLock<SessionSalt> = OnceLock::new();

/// Obfuscate `base` using the process-global session salt.
///
/// The salt is lazily seeded from the OS CSPRNG on the first call and then
/// frozen for the process lifetime. All subsequent calls are a pure read of
/// the `OnceLock` with no further randomness or allocation.
#[inline]
pub(crate) fn obfuscate_code(base: &ErrorCode) -> ErrorCode {
    #[cfg(test)]
    if let Some(salt) = test_override_salt() {
        return SessionSalt { salt }.obfuscate_code(base);
    }

    let salt = GLOBAL_SESSION.get_or_init(SessionSalt::new_random);
    salt.obfuscate_code(base)
}

// ── Test helpers (never compiled into release builds) ─────────────────────────

/// Seed the global salt with a deterministic value for test assertions.
///
/// `OnceLock` only allows one initialisation; if the global has already been
/// seeded (for example by a prior test that triggered `obfuscate_code`), this
/// call is a no-op.
#[cfg(test)]
pub(crate) fn init_session_salt(seed: u32) {
    let salt = SessionSalt::new_pinned(seed).salt();
    with_test_override(|override_slot| *override_slot = Some(salt));
}

/// Retained for existing test call-sites.
///
/// `OnceLock` cannot be reset, so callers that need a fresh salt must use a
/// new process.
#[cfg(test)]
pub(crate) fn clear_session_salt() {
    with_test_override(|override_slot| *override_slot = None);
}

// ── Entropy counter ───────────────────────────────────────────────────────────

/// Weyl-sequence counter mixed into every test-mode salt derivation.
#[cfg(test)]
static SALT_COUNTER: AtomicU64 = AtomicU64::new(0x9E37_79B9_7F4A_7C15);

#[cfg(test)]
static TEST_OVERRIDE_SALT: RwLock<Option<u8>> = RwLock::new(None);

// ── SessionSalt ───────────────────────────────────────────────────────────────

/// Holds the 6-bit (1–63) salt used to offset error codes for one session.
pub(crate) struct SessionSalt {
    salt: u8, // invariant: 1 ≤ salt ≤ 63
}

impl Zeroize for SessionSalt {
    fn zeroize(&mut self) {
        self.salt.zeroize();
    }
}

impl Drop for SessionSalt {
    fn drop(&mut self) {
        drop_zeroize(self);
    }
}

impl SessionSalt {
    /// Create a new salt seeded from the OS CSPRNG.
    #[inline]
    pub(crate) fn new_random() -> Self {
        let seed = generate_entropy();
        Self {
            salt: ((seed & 0b11_1111) as u8).max(1),
        }
    }

    /// Create a salt deterministically from a session identifier and secret.
    ///
    /// A domain-separated HMAC-SHA512 binds the session identifier to the
    /// secret so the identifier alone is insufficient to predict the salt.
    #[cfg(test)]
    #[inline]
    pub(crate) fn new_from_session_id(session_id: &str, secret: &[u8; 32]) -> Self {
        let hash = crypto::hmac_sha512_parts(
            secret,
            &[b"palisade-errors/session-salt/v1", session_id.as_bytes()],
        );
        let seed = u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]);
        Self {
            salt: ((seed & 0b11_1111) as u8).max(1),
        }
    }

    /// Create a salt from a pinned seed value — tests only.
    #[cfg(test)]
    #[inline]
    pub(crate) fn new_pinned(seed: u32) -> Self {
        Self {
            salt: ((seed & 0b11_1111) as u8).max(1),
        }
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn salt(&self) -> u8 {
        self.salt
    }

    /// Return a new `ErrorCode` whose numeric component is shifted by this salt.
    ///
    /// The shift wraps within the 100-code namespace band so codes never escape
    /// their assigned range (for example CFG codes always stay in 100–199).
    #[inline]
    pub(crate) fn obfuscate_code(&self, base: &ErrorCode) -> ErrorCode {
        let salt = self.salt as u16;
        let base_code = base.code();
        let namespace_base = (base_code / 100) * 100;
        let offset = base_code % 100;

        let new_code = if namespace_base == 0 {
            (offset + salt - 1) % 99 + 1
        } else {
            namespace_base + (offset + salt) % 100
        };

        ErrorCode::const_new(
            base.namespace(),
            new_code,
            base.category().duplicate(),
            base.impact().duplicate(),
        )
    }
}

// ── Entropy helpers ───────────────────────────────────────────────────────────

/// Generate a random `u32` for salt derivation.
#[inline]
fn generate_entropy() -> u32 {
    #[cfg(not(test))]
    {
        let mut buf = [0u8; 4];
        crypto::fill_random_array(&mut buf).expect("OS RNG unavailable");
        u32::from_ne_bytes(buf)
    }
    #[cfg(test)]
    {
        use std::time::{SystemTime, UNIX_EPOCH};

        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0_u64, |duration| duration.as_nanos() as u64);
        let counter = SALT_COUNTER.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::SeqCst);
        let mixed = splitmix64(now_ns ^ counter.rotate_left(11));
        (mixed ^ (mixed >> 32)) as u32
    }
}

/// SplitMix64 bijection with full avalanche.
#[cfg(test)]
#[inline]
fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

#[cfg(test)]
fn with_test_override<T>(f: impl FnOnce(&mut Option<u8>) -> T) -> T {
    match TEST_OVERRIDE_SALT.write() {
        Ok(mut guard) => f(&mut guard),
        Err(poisoned) => f(&mut poisoned.into_inner()),
    }
}

#[cfg(test)]
fn test_override_salt() -> Option<u8> {
    match TEST_OVERRIDE_SALT.read() {
        Ok(guard) => *guard,
        Err(poisoned) => *poisoned.into_inner(),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codes::{ImpactScore, namespaces};
    use crate::models::OperationCategory;

    fn cfg(n: u16) -> ErrorCode {
        ErrorCode::const_new(
            &namespaces::CFG,
            n,
            OperationCategory::Configuration,
            ImpactScore::new(100),
        )
    }

    fn core(n: u16) -> ErrorCode {
        ErrorCode::const_new(
            &namespaces::CORE,
            n,
            OperationCategory::System,
            ImpactScore::new(100),
        )
    }

    #[test]
    fn cfg_stays_in_namespace() {
        for salt_seed in 1..=63_u32 {
            let salt = SessionSalt::new_pinned(salt_seed);
            let obfuscated = salt.obfuscate_code(&cfg(150));
            assert!(
                (100..=199).contains(&obfuscated.code()),
                "salt={salt_seed} code={}",
                obfuscated.code()
            );
        }
    }

    #[test]
    fn core_stays_in_range() {
        for salt_seed in 1..=63_u32 {
            let salt = SessionSalt::new_pinned(salt_seed);
            let obfuscated = salt.obfuscate_code(&core(4));
            assert!(
                (1..=99).contains(&obfuscated.code()),
                "salt={salt_seed} code={}",
                obfuscated.code()
            );
        }
    }

    #[test]
    fn different_salts_produce_different_codes() {
        let base = cfg(100);
        let salt_a = SessionSalt::new_pinned(1);
        let salt_b = SessionSalt::new_pinned(5);
        assert_ne!(
            salt_a.obfuscate_code(&base).code(),
            salt_b.obfuscate_code(&base).code()
        );
    }

    #[test]
    fn same_salt_is_deterministic() {
        let base = cfg(100);
        let salt = SessionSalt::new_pinned(3);
        assert_eq!(
            salt.obfuscate_code(&base).code(),
            salt.obfuscate_code(&base).code(),
        );
    }

    #[test]
    fn random_salt_in_valid_range() {
        let salt = SessionSalt::new_random();
        assert!((1..=63).contains(&salt.salt()));
    }

    #[test]
    fn salt_never_zero() {
        let salt = SessionSalt::new_pinned(0);
        assert_eq!(salt.salt(), 1);
    }

    #[test]
    fn session_id_derivation_depends_on_secret() {
        let session_id = "session-42";
        let secret_a = [0x11_u8; 32];
        let secret_b = [0x22_u8; 32];
        let salt_a = SessionSalt::new_from_session_id(session_id, &secret_a);
        let salt_b = SessionSalt::new_from_session_id(session_id, &secret_b);
        assert_ne!(salt_a.salt(), salt_b.salt());
    }
}
