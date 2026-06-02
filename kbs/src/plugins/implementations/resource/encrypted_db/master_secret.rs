// Copyright (c) 2026 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Master secret loading and KDF for the `EncryptedDb` backend.
//!
//! Operators provision a passphrase via a Kubernetes Secret mounted as a
//! tmpfs file (default path `/run/trustee/master.passphrase`). On startup,
//! KBS reads the file, derives a 32-byte master key with Argon2id using a
//! salt + parameters persisted in the database, and uses that master key to
//! AES-GCM-encrypt every wrap private key at rest. The passphrase bytes are
//! zeroed immediately after derivation; only the derived master key remains
//! in memory for the process lifetime.
//!
//! The database also stores a "canary" — a fixed plaintext encrypted with
//! the master key — so a wrong passphrase is detected on startup and KBS
//! refuses to start, preventing follow-up writes from poisoning the table
//! with garbage-keyed entries.

use std::fs;

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

/// Plaintext that the canary row encrypts. Includes a version tag so we can
/// rotate the canary scheme without breaking existing deployments.
pub const CANARY_PLAINTEXT: &[u8] = b"trustee-master-canary-v1";

/// Length in bytes of the AES-256 master key derived from the passphrase.
pub const MASTER_KEY_LEN: usize = 32;

/// Length in bytes of the random salt persisted in `kbs_meta.kdf.salt_b64`.
pub const SALT_LEN: usize = 32;

/// Length in bytes of an AES-GCM nonce (per call, randomly generated).
pub const NONCE_LEN: usize = 12;

/// Length in bytes of the AES-GCM authentication tag.
pub const TAG_LEN: usize = 16;

/// Default Argon2id parameters: tuned to derive a master key in well under
/// one second on a modest VM while making offline brute-force expensive.
pub const DEFAULT_ARGON2_M_COST: u32 = 65_536; // 64 MiB
pub const DEFAULT_ARGON2_T_COST: u32 = 3;
pub const DEFAULT_ARGON2_P_COST: u32 = 4;

/// Loaded master key. The inner buffer is wiped on drop.
pub type MasterKey = Zeroizing<[u8; MASTER_KEY_LEN]>;

/// Argon2id parameters persisted in the database alongside the salt.
#[derive(Debug, Clone, Copy)]
pub struct Argon2Params {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            m_cost: DEFAULT_ARGON2_M_COST,
            t_cost: DEFAULT_ARGON2_T_COST,
            p_cost: DEFAULT_ARGON2_P_COST,
        }
    }
}

/// Reads the master passphrase from a file (typically a Kubernetes Secret
/// mounted as a tmpfs file at `/run/trustee/master.passphrase`).
pub struct FileMasterSecretProvider {
    path: String,
}

impl FileMasterSecretProvider {
    pub fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
        }
    }

    /// Read the passphrase, trim trailing whitespace (most editors / tools
    /// add a trailing `\n`), and return the bytes wrapped for zeroization.
    pub fn fetch(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut bytes = fs::read(&self.path).with_context(|| {
            format!(
                "read master secret file `{}`; ensure it is mounted (e.g. as a Kubernetes Secret)",
                self.path
            )
        })?;
        // Trim trailing whitespace in place. We can't simply call .trim_end()
        // and copy because that would leave the original bytes in memory.
        while bytes
            .last()
            .copied()
            .is_some_and(|b| b == b'\n' || b == b'\r' || b == b' ' || b == b'\t')
        {
            let last_index = bytes.len() - 1;
            bytes[last_index] = 0;
            bytes.truncate(last_index);
        }
        if bytes.is_empty() {
            bail!(
                "master secret file `{}` is empty after trimming whitespace",
                self.path
            );
        }
        Ok(Zeroizing::new(bytes))
    }
}

/// Generate a fresh random salt of the canonical length.
pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Derive the 32-byte master key from the passphrase using Argon2id with the
/// given salt and parameters. The passphrase argument is consumed (zeroed) by
/// the caller via `Zeroizing`.
pub fn derive_master_key(
    passphrase: &[u8],
    salt: &[u8],
    params: Argon2Params,
) -> Result<MasterKey> {
    let argon2_params = Params::new(params.m_cost, params.t_cost, params.p_cost, None)
        .map_err(|e| anyhow!("invalid argon2id parameters: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut out = [0u8; MASTER_KEY_LEN];
    argon2
        .hash_password_into(passphrase, salt, &mut out)
        .map_err(|e| anyhow!("argon2id derivation failed: {e}"))?;
    Ok(Zeroizing::new(out))
}

/// AES-256-GCM encrypt with a fresh random nonce. Returns `(nonce, tag, ciphertext)`.
pub fn aes_gcm_encrypt(
    key: &MasterKey,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let cipher = Aes256Gcm::new_from_slice(&**key).map_err(|e| anyhow!("aes-gcm key: {e}"))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    let ct_with_tag = cipher
        .encrypt(nonce, payload)
        .map_err(|e| anyhow!("aes-gcm encrypt: {e}"))?;
    if ct_with_tag.len() < TAG_LEN {
        bail!("aes-gcm output shorter than tag length");
    }
    let tag_offset = ct_with_tag.len() - TAG_LEN;
    let ciphertext = ct_with_tag[..tag_offset].to_vec();
    let tag = ct_with_tag[tag_offset..].to_vec();
    Ok((nonce_bytes.to_vec(), tag, ciphertext))
}

/// AES-256-GCM decrypt. Authentication failure (wrong key, tampered ciphertext,
/// or wrong AAD) returns `Err`.
pub fn aes_gcm_decrypt(
    key: &MasterKey,
    nonce: &[u8],
    tag: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if nonce.len() != NONCE_LEN {
        bail!(
            "aes-gcm nonce must be {NONCE_LEN} bytes, got {}",
            nonce.len()
        );
    }
    if tag.len() != TAG_LEN {
        bail!("aes-gcm tag must be {TAG_LEN} bytes, got {}", tag.len());
    }
    let cipher = Aes256Gcm::new_from_slice(&**key).map_err(|e| anyhow!("aes-gcm key: {e}"))?;
    let nonce = Nonce::from_slice(nonce);
    let mut joined = Vec::with_capacity(ciphertext.len() + tag.len());
    joined.extend_from_slice(ciphertext);
    joined.extend_from_slice(tag);
    let payload = Payload { msg: &joined, aad };
    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| anyhow!("aes-gcm authentication failed"))?;
    joined.zeroize();
    Ok(Zeroizing::new(plaintext))
}

/// Encrypt `CANARY_PLAINTEXT` under the master key. The result is what gets
/// persisted into `kbs_meta` on first startup.
pub fn encrypt_canary(key: &MasterKey) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    aes_gcm_encrypt(key, CANARY_PLAINTEXT, b"canary")
}

/// Verify that the master key decrypts the persisted canary to the expected
/// plaintext. Returns `Ok(())` on match, `Err` otherwise (wrong passphrase or
/// tampered canary).
pub fn verify_canary(key: &MasterKey, nonce: &[u8], tag: &[u8], ciphertext: &[u8]) -> Result<()> {
    let plaintext = aes_gcm_decrypt(key, nonce, tag, ciphertext, b"canary")
        .context("master secret canary did not decrypt; passphrase is wrong or has been changed")?;
    if &**plaintext != CANARY_PLAINTEXT {
        bail!("master secret canary plaintext mismatch (corrupted entry?)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn fast_params() -> Argon2Params {
        // Smaller knobs for fast unit tests; production uses defaults.
        Argon2Params {
            m_cost: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
        }
    }

    #[test]
    fn fetch_trims_trailing_whitespace() {
        let mut f = NamedTempFile::new().expect("tempfile");
        writeln!(f, "hunter2").expect("write");
        let provider = FileMasterSecretProvider::new(f.path().to_str().unwrap());
        let bytes = provider.fetch().expect("fetch");
        assert_eq!(&bytes[..], b"hunter2");
    }

    #[test]
    fn fetch_rejects_empty_file() {
        let f = NamedTempFile::new().expect("tempfile");
        let provider = FileMasterSecretProvider::new(f.path().to_str().unwrap());
        let err = provider.fetch().expect_err("must error on empty");
        assert!(format!("{err:#}").contains("empty"));
    }

    #[test]
    fn kdf_is_deterministic_per_salt_and_params() {
        let salt = [7u8; SALT_LEN];
        let p = fast_params();
        let k1 = derive_master_key(b"password", &salt, p).unwrap();
        let k2 = derive_master_key(b"password", &salt, p).unwrap();
        assert_eq!(*k1, *k2);
    }

    #[test]
    fn kdf_diverges_on_different_passphrase_or_salt() {
        let p = fast_params();
        let s1 = [1u8; SALT_LEN];
        let s2 = [2u8; SALT_LEN];
        let k1 = derive_master_key(b"a", &s1, p).unwrap();
        let k2 = derive_master_key(b"b", &s1, p).unwrap();
        let k3 = derive_master_key(b"a", &s2, p).unwrap();
        assert_ne!(*k1, *k2);
        assert_ne!(*k1, *k3);
    }

    #[test]
    fn aes_gcm_round_trip() {
        let key: MasterKey = Zeroizing::new([9u8; MASTER_KEY_LEN]);
        let (nonce, tag, ct) = aes_gcm_encrypt(&key, b"hello world", b"aad").unwrap();
        let pt = aes_gcm_decrypt(&key, &nonce, &tag, &ct, b"aad").unwrap();
        assert_eq!(&**pt, b"hello world");
    }

    #[test]
    fn aes_gcm_rejects_wrong_aad() {
        let key: MasterKey = Zeroizing::new([9u8; MASTER_KEY_LEN]);
        let (nonce, tag, ct) = aes_gcm_encrypt(&key, b"hello", b"aad-1").unwrap();
        assert!(aes_gcm_decrypt(&key, &nonce, &tag, &ct, b"aad-2").is_err());
    }

    #[test]
    fn canary_round_trip_and_wrong_key_rejected() {
        let key_good: MasterKey = Zeroizing::new([4u8; MASTER_KEY_LEN]);
        let key_bad: MasterKey = Zeroizing::new([5u8; MASTER_KEY_LEN]);
        let (nonce, tag, ct) = encrypt_canary(&key_good).unwrap();
        verify_canary(&key_good, &nonce, &tag, &ct).expect("good key verifies");
        let err = verify_canary(&key_bad, &nonce, &tag, &ct).expect_err("bad key rejected");
        assert!(format!("{err:#}").contains("canary"));
    }
}
