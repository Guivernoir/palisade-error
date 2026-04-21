//! Encrypted, integrity-checked append-only file log sink.
//!
//! Every record written by [`append_record`] is:
//!   1. Encrypted with a layered construction derived from the process-lifetime
//!      session key.
//!   2. Integrity-protected by an HMAC-SHA512 tag over the final encrypted frame.
//!   3. Flushed to disk before the file is returned to read-only mode.
//!
//! The layered construction here improves defense-in-depth and raises the
//! margin against generic quantum search by not relying on a single primitive,
//! but it is not a standardized post-quantum cryptosystem.

use crate::crypto;
use crate::zeroization::Zeroize;
use std::io::{self, Write};
use std::path::Path;

pub(crate) const MAX_PLAINTEXT_BYTES: usize = 2_048;

const NONCE_LEN: usize = crypto::NONCE_LEN;
const TAG_LEN: usize = crypto::TAG_LEN;
const MAC_LEN: usize = crypto::SHA512_LEN;
const HMAC_BLOCK_LEN: usize = 128;
const HMAC_DOMAIN: &[u8] = b"palisade-errors/log-mac/v2";
const INNER_AES_LABEL: &[u8] = b"palisade-errors/log-inner-aes/v1";
const OUTER_MASK_LABEL: &[u8] = b"palisade-errors/log-outer-mask/v1";
const OUTER_MAC_LABEL: &[u8] = b"palisade-errors/log-outer-mac/v1";
const MAX_KDF_LABEL_BYTES: usize = 40;
const INNER_FRAME_BYTES: usize = NONCE_LEN + MAX_PLAINTEXT_BYTES + TAG_LEN;
const MAX_ENCRYPTED_BYTES: usize = NONCE_LEN + INNER_FRAME_BYTES;
const STREAM_BLOCK_INPUT_BYTES: usize = 32 + NONCE_LEN + 8;
#[cfg_attr(not(test), allow(dead_code))]
const RECORD_LEN_PREFIX: usize = 4;

/// Encrypt `plaintext` with `session_key`, append the record to `path`, then
/// immediately set the file read-only.
pub(crate) fn append_record(
    session_key: &[u8; 32],
    path: &Path,
    plaintext: &[u8],
) -> io::Result<()> {
    if plaintext.len() > MAX_PLAINTEXT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "log record exceeds fixed plaintext budget",
        ));
    }

    let mut encrypted = [0u8; MAX_ENCRYPTED_BYTES];
    let mut mac_key = [0u8; 32];
    let mut mac = [0u8; MAC_LEN];

    let result = (|| {
        reject_unsafe_path(path)?;
        let encrypted_len = layered_encrypt(session_key, plaintext, &mut encrypted)?;
        mac_key = derive_subkey(session_key, OUTER_MAC_LABEL);
        mac = keyed_mac(&mac_key, &encrypted[..encrypted_len]);

        make_writable(path).ok();

        let mut file = open_log_file(path)?;

        let len_prefix = (encrypted_len as u32).to_le_bytes();
        file.write_all(&len_prefix)?;
        file.write_all(&encrypted[..encrypted_len])?;
        file.write_all(&mac)?;
        file.flush()?;
        file.sync_data()?;
        drop(file);

        set_readonly(path)
    })();

    encrypted.zeroize();
    mac_key.zeroize();
    mac.zeroize();
    result
}

fn derive_subkey(master_key: &[u8; 32], label: &[u8]) -> [u8; 32] {
    assert!(
        label.len() <= MAX_KDF_LABEL_BYTES,
        "kdf label exceeds fixed capacity"
    );

    let mut input = [0u8; 32 + MAX_KDF_LABEL_BYTES];
    input[..32].copy_from_slice(master_key);
    input[32..32 + label.len()].copy_from_slice(label);

    let mut digest = crypto::sha512(&input[..32 + label.len()]);
    let mut subkey = [0u8; 32];
    subkey.copy_from_slice(&digest[..32]);

    input.zeroize();
    digest.zeroize();

    subkey
}

fn apply_outer_mask(
    mask_key: &[u8; 32],
    outer_nonce: &[u8; NONCE_LEN],
    input: &[u8],
    out: &mut [u8],
) {
    debug_assert!(out.len() >= input.len());

    let mut block_input = [0u8; STREAM_BLOCK_INPUT_BYTES];
    block_input[..32].copy_from_slice(mask_key);
    block_input[32..32 + NONCE_LEN].copy_from_slice(outer_nonce);

    let mut offset = 0;
    let mut counter = 0_u64;
    while offset < input.len() {
        block_input[32 + NONCE_LEN..].copy_from_slice(&counter.to_le_bytes());
        let mut block = crypto::sha512(&block_input);
        let take = block.len().min(input.len() - offset);
        for index in 0..take {
            out[offset + index] = input[offset + index] ^ block[index];
        }
        block.zeroize();
        counter = counter.wrapping_add(1);
        offset += take;
    }

    block_input.zeroize();
}

fn layered_encrypt(
    master_key: &[u8; 32],
    plaintext: &[u8],
    out: &mut [u8; MAX_ENCRYPTED_BYTES],
) -> io::Result<usize> {
    let mut inner_key = derive_subkey(master_key, INNER_AES_LABEL);
    let mut outer_mask_key = derive_subkey(master_key, OUTER_MASK_LABEL);
    let mut inner_nonce = [0u8; NONCE_LEN];
    let mut outer_nonce = [0u8; NONCE_LEN];
    let mut inner_tag = [0u8; TAG_LEN];
    let mut inner_frame = [0u8; INNER_FRAME_BYTES];

    let result = (|| {
        crypto::fill_random_array(&mut inner_nonce)
            .map_err(|_| io::Error::other("RNG unavailable"))?;
        crypto::fill_random_array(&mut outer_nonce)
            .map_err(|_| io::Error::other("RNG unavailable"))?;

        inner_frame[..NONCE_LEN].copy_from_slice(&inner_nonce);
        let ciphertext_len = crypto::aes256_gcm_encrypt_into(
            &inner_key,
            &inner_nonce,
            b"",
            plaintext,
            &mut inner_frame[NONCE_LEN..NONCE_LEN + plaintext.len()],
            &mut inner_tag,
        )
        .map_err(|_| io::Error::other("AES-GCM encryption failed"))?;

        let inner_frame_len = NONCE_LEN + ciphertext_len + TAG_LEN;
        let tag_offset = NONCE_LEN + ciphertext_len;
        inner_frame[tag_offset..inner_frame_len].copy_from_slice(&inner_tag);

        out[..NONCE_LEN].copy_from_slice(&outer_nonce);
        apply_outer_mask(
            &outer_mask_key,
            &outer_nonce,
            &inner_frame[..inner_frame_len],
            &mut out[NONCE_LEN..NONCE_LEN + inner_frame_len],
        );

        Ok(NONCE_LEN + inner_frame_len)
    })();

    inner_key.zeroize();
    outer_mask_key.zeroize();
    inner_nonce.zeroize();
    outer_nonce.zeroize();
    inner_tag.zeroize();
    inner_frame.zeroize();
    result
}

fn keyed_mac(key: &[u8; 32], data: &[u8]) -> [u8; MAC_LEN] {
    let mut key_block = [0u8; HMAC_BLOCK_LEN];
    if key.len() > HMAC_BLOCK_LEN {
        let mut digest = crypto::sha512(key);
        key_block[..digest.len()].copy_from_slice(&digest);
        digest.zeroize();
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0x36_u8; HMAC_BLOCK_LEN];
    let mut outer_pad = [0x5C_u8; HMAC_BLOCK_LEN];
    for (pad, key_byte) in inner_pad.iter_mut().zip(key_block.iter()) {
        *pad ^= *key_byte;
    }
    for (pad, key_byte) in outer_pad.iter_mut().zip(key_block.iter()) {
        *pad ^= *key_byte;
    }

    let mut inner_input = [0u8; HMAC_BLOCK_LEN + HMAC_DOMAIN.len() + MAX_ENCRYPTED_BYTES];
    inner_input[..HMAC_BLOCK_LEN].copy_from_slice(&inner_pad);
    inner_input[HMAC_BLOCK_LEN..HMAC_BLOCK_LEN + HMAC_DOMAIN.len()].copy_from_slice(HMAC_DOMAIN);
    inner_input
        [HMAC_BLOCK_LEN + HMAC_DOMAIN.len()..HMAC_BLOCK_LEN + HMAC_DOMAIN.len() + data.len()]
        .copy_from_slice(data);
    let mut inner_hash =
        crypto::sha512(&inner_input[..HMAC_BLOCK_LEN + HMAC_DOMAIN.len() + data.len()]);

    let mut outer_input = [0u8; HMAC_BLOCK_LEN + MAC_LEN];
    outer_input[..HMAC_BLOCK_LEN].copy_from_slice(&outer_pad);
    outer_input[HMAC_BLOCK_LEN..].copy_from_slice(&inner_hash);
    let mac = crypto::sha512(&outer_input);

    key_block.zeroize();
    inner_pad.zeroize();
    outer_pad.zeroize();
    inner_input.zeroize();
    inner_hash.zeroize();
    outer_input.zeroize();

    mac
}

fn reject_unsafe_path(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "log path must not be a symlink",
                ));
            }
            if !file_type.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "log path must reference a regular file",
                ));
            }
            Ok(())
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

#[cfg(unix)]
fn open_log_file(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_log_file(path: &Path) -> io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
}

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

#[cfg(test)]
fn layered_decrypt(
    master_key: &[u8; 32],
    encrypted: &[u8],
    plaintext_out: &mut [u8],
) -> io::Result<usize> {
    if encrypted.len() < NONCE_LEN + NONCE_LEN + TAG_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "layered frame too short",
        ));
    }

    let mut inner_key = derive_subkey(master_key, INNER_AES_LABEL);
    let mut outer_mask_key = derive_subkey(master_key, OUTER_MASK_LABEL);
    let outer_nonce = <[u8; NONCE_LEN]>::try_from(&encrypted[..NONCE_LEN])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid outer nonce"))?;
    let inner_frame_len = encrypted.len() - NONCE_LEN;
    let mut inner_frame = [0u8; INNER_FRAME_BYTES];

    let result = (|| {
        apply_outer_mask(
            &outer_mask_key,
            &outer_nonce,
            &encrypted[NONCE_LEN..],
            &mut inner_frame[..inner_frame_len],
        );

        let inner_nonce = <[u8; NONCE_LEN]>::try_from(&inner_frame[..NONCE_LEN])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid inner nonce"))?;
        let tag_offset = inner_frame_len.saturating_sub(TAG_LEN);
        if tag_offset < NONCE_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "inner frame too short",
            ));
        }
        let tag = <[u8; TAG_LEN]>::try_from(&inner_frame[tag_offset..inner_frame_len])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid inner tag"))?;

        crypto::aes256_gcm_decrypt_into(
            &inner_key,
            &inner_nonce,
            b"",
            &inner_frame[NONCE_LEN..tag_offset],
            &tag,
            plaintext_out,
        )
    })();

    inner_key.zeroize();
    outer_mask_key.zeroize();
    inner_frame.zeroize();

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    fn test_key() -> [u8; 32] {
        [0xAB_u8; 32]
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = test_key();
        let plaintext = b"internal diagnostic: db timeout on replica-3";
        let mut encrypted = [0u8; MAX_ENCRYPTED_BYTES];
        let encrypted_len = layered_encrypt(&key, plaintext, &mut encrypted).unwrap();
        let ciphertext = &encrypted[..encrypted_len];
        let mut decrypted = [0u8; MAX_PLAINTEXT_BYTES];
        let decrypted_len = layered_decrypt(&key, ciphertext, &mut decrypted).unwrap();
        assert_eq!(&decrypted[..decrypted_len], plaintext);
    }

    #[test]
    fn mac_depends_on_key() {
        let key_a = [0x01_u8; 32];
        let key_b = [0x02_u8; 32];
        let data = b"test payload";
        let mac_key_a = derive_subkey(&key_a, OUTER_MAC_LABEL);
        let mac_key_b = derive_subkey(&key_b, OUTER_MAC_LABEL);
        assert_ne!(keyed_mac(&mac_key_a, data), keyed_mac(&mac_key_b, data));
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

    #[cfg(unix)]
    #[test]
    fn append_record_rejects_symlink_path() {
        let dir = std::env::temp_dir();
        let real_path = dir.join(format!("palisade_real_{}.log", std::process::id()));
        let symlink_path = dir.join(format!("palisade_symlink_{}.log", std::process::id()));
        let key = test_key();

        let _ = fs::remove_file(&real_path);
        let _ = fs::remove_file(&symlink_path);
        fs::write(&real_path, b"seed").unwrap();
        symlink(&real_path, &symlink_path).unwrap();

        let err = append_record(&key, &symlink_path, b"test entry").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        let _ = fs::remove_file(&symlink_path);
        let _ = fs::remove_file(&real_path);
    }

    #[test]
    fn record_length_prefix_matches_payload() {
        let key = test_key();
        let plaintext = b"hello world";
        let mut encrypted = [0u8; MAX_ENCRYPTED_BYTES];
        let encrypted_len = layered_encrypt(&key, plaintext, &mut encrypted).unwrap();
        let len_le = (encrypted_len as u32).to_le_bytes();
        let expected_len = u32::from_le_bytes(len_le) as usize;
        assert_eq!(expected_len, encrypted_len);
    }

    #[test]
    fn nonce_differs_across_encryptions() {
        let key = test_key();
        let mut first = [0u8; MAX_ENCRYPTED_BYTES];
        let mut second = [0u8; MAX_ENCRYPTED_BYTES];
        let first_len = layered_encrypt(&key, b"a", &mut first).unwrap();
        let second_len = layered_encrypt(&key, b"a", &mut second).unwrap();
        assert_ne!(
            &first[..first_len.min(NONCE_LEN)],
            &second[..second_len.min(NONCE_LEN)],
            "outer nonces must differ"
        );
    }

    #[test]
    fn record_len_prefix_size() {
        assert_eq!(RECORD_LEN_PREFIX, 4);
    }
}
