//! Internal cryptographic helpers backed by `crypto_bastion`.
//!
//! Public code in this crate calls into this module rather than depending on
//! third-party crypto crates directly.

use crate::zeroization::Zeroize;
use std::io;

/// AES-GCM nonce length in bytes.
pub(crate) const NONCE_LEN: usize = 12;
/// AES-GCM authentication tag length in bytes.
pub(crate) const TAG_LEN: usize = 16;
/// SHA-512 digest length in bytes.
pub(crate) const SHA512_LEN: usize = 64;

const SHA512_BLOCK_LEN: usize = 128;

/// Fill `out` with cryptographically secure random bytes from the OS.
pub(crate) fn fill_random(out: &mut [u8]) -> io::Result<()> {
    fill_random_inner(out)
}

/// Fill a fixed-size array with cryptographically secure random bytes.
#[inline]
pub(crate) fn fill_random_array<const N: usize>(out: &mut [u8; N]) -> io::Result<()> {
    fill_random(out.as_mut_slice())
}

/// SHA-512 digest using `crypto_bastion`.
#[inline]
pub(crate) fn sha512(data: &[u8]) -> [u8; SHA512_LEN] {
    crypto_bastion::hash(data)
}

/// Constant-time byte-slice equality comparison.
#[inline]
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    crypto_bastion::compare(a, b)
}

/// HMAC-SHA512 implemented on top of `crypto_bastion::hash`.
pub(crate) fn hmac_sha512_parts(key: &[u8], parts: &[&[u8]]) -> [u8; SHA512_LEN] {
    let mut key_block = [0u8; SHA512_BLOCK_LEN];
    if key.len() > SHA512_BLOCK_LEN {
        let mut digest = sha512(key);
        key_block[..digest.len()].copy_from_slice(&digest);
        digest.zeroize();
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0x36_u8; SHA512_BLOCK_LEN];
    let mut outer_pad = [0x5C_u8; SHA512_BLOCK_LEN];
    for (pad, key_byte) in inner_pad.iter_mut().zip(key_block.iter()) {
        *pad ^= *key_byte;
    }
    for (pad, key_byte) in outer_pad.iter_mut().zip(key_block.iter()) {
        *pad ^= *key_byte;
    }

    let mut inner_input = Vec::with_capacity(total_len(SHA512_BLOCK_LEN, parts));
    inner_input.extend_from_slice(&inner_pad);
    for part in parts {
        inner_input.extend_from_slice(part);
    }
    let mut inner_hash = sha512(&inner_input);

    let mut outer_input = Vec::with_capacity(SHA512_BLOCK_LEN + inner_hash.len());
    outer_input.extend_from_slice(&outer_pad);
    outer_input.extend_from_slice(&inner_hash);
    let mac = sha512(&outer_input);

    inner_input.zeroize();
    outer_input.zeroize();
    inner_hash.zeroize();
    inner_pad.zeroize();
    outer_pad.zeroize();
    key_block.zeroize();

    mac
}

/// Encrypt `plaintext` with AES-256-GCM into a fresh ciphertext buffer.
pub(crate) fn aes256_gcm_encrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> io::Result<(Vec<u8>, [u8; TAG_LEN])> {
    let mut ciphertext = vec![0u8; plaintext.len()];
    let mut tag = [0u8; TAG_LEN];
    crypto_bastion::encrypt(key, nonce, aad, plaintext, &mut ciphertext, &mut tag)
        .map_err(io::Error::other)?;
    Ok((ciphertext, tag))
}

/// Decrypt `ciphertext` with AES-256-GCM into a fresh plaintext buffer.
pub(crate) fn aes256_gcm_decrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; TAG_LEN],
) -> io::Result<Vec<u8>> {
    let mut plaintext = vec![0u8; ciphertext.len()];
    crypto_bastion::decrypt(key, nonce, aad, ciphertext, tag, &mut plaintext)
        .map_err(io::Error::other)?;
    Ok(plaintext)
}

fn total_len(base: usize, parts: &[&[u8]]) -> usize {
    parts
        .iter()
        .fold(base, |len, part| len.saturating_add(part.len()))
}

#[cfg(unix)]
fn fill_random_inner(out: &mut [u8]) -> io::Result<()> {
    use std::fs::File;
    use std::io::Read;

    File::open("/dev/urandom")?.read_exact(out)
}

#[cfg(windows)]
fn fill_random_inner(out: &mut [u8]) -> io::Result<()> {
    use core::ffi::c_void;

    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;
    const STATUS_SUCCESS: i32 = 0;

    #[link(name = "bcrypt")]
    unsafe extern "system" {
        fn BCryptGenRandom(
            algorithm: *mut c_void,
            buffer: *mut u8,
            buffer_len: u32,
            flags: u32,
        ) -> i32;
    }

    let len = u32::try_from(out.len()).map_err(|_| io::Error::other("random buffer too large"))?;
    // SAFETY: The OS API writes exactly `len` bytes into the valid output slice.
    let status = unsafe {
        BCryptGenRandom(
            core::ptr::null_mut(),
            out.as_mut_ptr(),
            len,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status == STATUS_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::other("BCryptGenRandom failed"))
    }
}

#[cfg(not(any(unix, windows)))]
fn fill_random_inner(_out: &mut [u8]) -> io::Result<()> {
    Err(io::Error::other(
        "OS random source is unsupported on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        NONCE_LEN, SHA512_LEN, TAG_LEN, aes256_gcm_decrypt, aes256_gcm_encrypt, ct_eq,
        hmac_sha512_parts, sha512,
    };

    #[test]
    fn sha512_matches_expected_length() {
        assert_eq!(sha512(b"hello").len(), SHA512_LEN);
    }

    #[test]
    fn hmac_depends_on_key() {
        let mac_a = hmac_sha512_parts(b"key-a", &[b"payload"]);
        let mac_b = hmac_sha512_parts(b"key-b", &[b"payload"]);
        assert!(!ct_eq(&mac_a, &mac_b));
    }

    #[test]
    fn aes_gcm_roundtrip() {
        let key = [0xAB_u8; 32];
        let nonce = [0x11_u8; NONCE_LEN];
        let plaintext = b"palisade";
        let (ciphertext, tag) = aes256_gcm_encrypt(&key, &nonce, b"", plaintext).unwrap();
        assert_eq!(tag.len(), TAG_LEN);
        let decrypted = aes256_gcm_decrypt(&key, &nonce, b"", &ciphertext, &tag).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
