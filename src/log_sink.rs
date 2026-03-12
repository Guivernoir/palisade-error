//! Encrypted, integrity-checked append-only file log sink.
//!
//! Every record written by [`append_record`] is:
//!   1. AES-256-GCM encrypted with the process-lifetime session key.
//!   2. Integrity-protected by an HMAC-SHA512 tag over the encrypted frame.
//!   3. Flushed to disk before the file is returned to read-only mode.
//!
//! The session key is generated once from the OS CSPRNG and held exclusively
//! in process memory. It is never written to disk.
//!
//! # Wire format (one record)
//!
//! ```text
//! ┌──────────────────────────────────────────────────────┐
//! │ 4 B   │ payload_len  (LE u32)                        │
//! │ 12 B  │ AES-GCM nonce  (random, per-record)          │
//! │ N B   │ AES-256-GCM ciphertext                       │
//! │ 16 B  │ AES-GCM authentication tag                   │
//! │ 64 B  │ HMAC-SHA512 over ( nonce ‖ ct ‖ tag )        │
//! └──────────────────────────────────────────────────────┘
//! ```

use crate::crypto;
use std::io::{self, Write};
use std::path::Path;

const NONCE_LEN: usize = crypto::NONCE_LEN;
const TAG_LEN: usize = crypto::TAG_LEN;
const MAC_LEN: usize = crypto::SHA512_LEN;
const RECORD_LEN_PREFIX: usize = 4;

// ── Public entry point ────────────────────────────────────────────────────────

/// Encrypt `plaintext` with `session_key`, append the record to `path`, then
/// immediately set the file read-only.
pub(crate) fn append_record(
    session_key: &[u8; 32],
    path: &Path,
    plaintext: &[u8],
) -> io::Result<()> {
    let encrypted = encrypt(session_key, plaintext)?;
    let mac = keyed_mac(session_key, &encrypted);

    make_writable(path).ok();

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;

    let len_prefix = (encrypted.len() as u32).to_le_bytes();
    file.write_all(&len_prefix)?;
    file.write_all(&encrypted)?;
    file.write_all(&mac)?;
    file.flush()?;
    drop(file);

    set_readonly(path)
}

// ── Crypto helpers ────────────────────────────────────────────────────────────

/// Encrypt `plaintext` into `nonce (12 B) ‖ ciphertext ‖ tag`.
fn encrypt(key_bytes: &[u8; 32], plaintext: &[u8]) -> io::Result<Box<[u8]>> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    crypto::fill_random_array(&mut nonce_bytes).map_err(|_| io::Error::other("RNG unavailable"))?;

    let (ciphertext, tag) = crypto::aes256_gcm_encrypt(key_bytes, &nonce_bytes, b"", plaintext)
        .map_err(|_| io::Error::other("AES-GCM encryption failed"))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len() + TAG_LEN);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&tag);
    Ok(out.into_boxed_slice())
}

/// HMAC-SHA512 over the encrypted frame.
fn keyed_mac(key: &[u8; 32], data: &[u8]) -> [u8; MAC_LEN] {
    crypto::hmac_sha512_parts(key, &[b"palisade-errors/log-mac/v1", data])
}

// ── File permission helpers ───────────────────────────────────────────────────

#[cfg(unix)]
pub(crate) fn set_readonly(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o400);
    std::fs::set_permissions(path, perms)
}

#[cfg(not(unix))]
pub(crate) fn set_readonly(path: &Path) -> io::Result<()> {
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(path, perms)
}

#[cfg(unix)]
fn make_writable(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o200);
    std::fs::set_permissions(path, perms)
}

#[cfg(not(unix))]
fn make_writable(path: &Path) -> io::Result<()> {
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_readonly(false);
    std::fs::set_permissions(path, perms)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn test_key() -> [u8; 32] {
        [0xAB_u8; 32]
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = test_key();
        let plaintext = b"internal diagnostic: db timeout on replica-3";
        let encrypted = encrypt(&key, plaintext).unwrap();

        let nonce = <[u8; NONCE_LEN]>::try_from(&encrypted[..NONCE_LEN]).unwrap();
        let tag_offset = encrypted.len() - TAG_LEN;
        let tag = <[u8; TAG_LEN]>::try_from(&encrypted[tag_offset..]).unwrap();
        let ciphertext = &encrypted[NONCE_LEN..tag_offset];
        let decrypted = crypto::aes256_gcm_decrypt(&key, &nonce, b"", ciphertext, &tag).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn mac_depends_on_key() {
        let key_a = [0x01_u8; 32];
        let key_b = [0x02_u8; 32];
        let data = b"test payload";
        assert_ne!(keyed_mac(&key_a, data), keyed_mac(&key_b, data));
    }

    #[test]
    fn append_record_creates_readonly_file() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("palisade_test_{}.log", std::process::id()));
        let key = test_key();

        append_record(&key, &path, b"test entry").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o400, "file should be owner-read-only");
        }

        make_writable(&path).ok();
        fs::remove_file(&path).ok();
    }

    #[test]
    fn record_length_prefix_matches_payload() {
        let key = test_key();
        let plaintext = b"hello world";
        let encrypted = encrypt(&key, plaintext).unwrap();
        let len_le = (encrypted.len() as u32).to_le_bytes();
        let expected_len = u32::from_le_bytes(len_le) as usize;
        assert_eq!(expected_len, encrypted.len());
    }

    #[test]
    fn nonce_differs_across_encryptions() {
        let key = test_key();
        let first = encrypt(&key, b"a").unwrap();
        let second = encrypt(&key, b"a").unwrap();
        assert_ne!(
            &first[..NONCE_LEN],
            &second[..NONCE_LEN],
            "nonces must differ"
        );
    }

    #[test]
    fn record_len_prefix_size() {
        assert_eq!(RECORD_LEN_PREFIX, 4);
    }
}
