// Copyright (c) 2026 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Envelope (de)crypt helpers, mirroring the wire format used by
//! `EncryptedLocalFs` so the two backends are interchangeable on the wire.
//! When time allows, the helpers in `encrypted_local_fs.rs` should be
//! refactored to call into this module instead — for now we keep the two in
//! lock-step by accident.

use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rsa::sha2::Sha256;
use rsa::{Oaep, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};

pub const ALG_RSA1_5: &str = "RSA1_5";
pub const ALG_RSA_OAEP_256: &str = "RSA-OAEP-256";
pub const AES_GCM_KEY_LEN: usize = 32;
pub const AES_GCM_TAG_LEN: usize = 16;
pub const AES_GCM_NONCE_LEN: usize = 12;

/// Wire format of an encrypted resource. Compatible byte-for-byte with the
/// envelope written by `EncryptedLocalFs`.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct Envelope {
    pub alg: String,
    pub enc_key: String,
    pub iv: String,
    pub ciphertext: String,
    pub tag: String,
}

fn decode_b64(name: &str, v: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(v)
        .with_context(|| format!("base64 decode `{name}`"))
}

/// Try every key in `keys` (newest-first) and return the plaintext when one
/// successfully decrypts both the CEK and the AES-GCM body. Errors when none
/// of the supplied keys works.
pub fn decrypt_envelope_with_ring(env: &Envelope, keys: &[RsaPrivateKey]) -> Result<Vec<u8>> {
    let enc_key = decode_b64("enc_key", &env.enc_key)?;
    let iv = decode_b64("iv", &env.iv)?;
    let ciphertext = decode_b64("ciphertext", &env.ciphertext)?;
    let tag = decode_b64("tag", &env.tag)?;

    if !matches!(env.alg.as_str(), ALG_RSA1_5 | ALG_RSA_OAEP_256) {
        bail!("unsupported envelope alg `{}`", env.alg);
    }
    if iv.len() != AES_GCM_NONCE_LEN {
        bail!(
            "unexpected GCM nonce length {}, expect {AES_GCM_NONCE_LEN} bytes",
            iv.len()
        );
    }
    if tag.len() != AES_GCM_TAG_LEN {
        bail!(
            "unexpected GCM tag length {}, expect {AES_GCM_TAG_LEN} bytes",
            tag.len()
        );
    }
    if keys.is_empty() {
        bail!("no decryption keys configured");
    }

    let mut last_err = None;
    for key in keys {
        match recover_cek(key, &env.alg, &enc_key)
            .and_then(|cek| aes_decrypt(&cek, &iv, &ciphertext, &tag))
        {
            Ok(plain) => return Ok(plain),
            Err(e) => last_err = Some(e),
        }
    }
    Err(anyhow!(
        "failed to decrypt resource with any of the {} key(s): {}",
        keys.len(),
        last_err.expect("at least one error")
    ))
}

/// Re-wrap the CEK of an envelope onto a new public key, returning the new
/// envelope JSON bytes. Returns `None` when:
///   * the input bytes are not a parseable envelope (assumed plaintext —
///     leave as-is, matching EncryptedLocalFs's `try_decrypt` semantics), or
///   * the envelope is already RSA-OAEP-256 wrapped under `primary_public`.
///
/// Returns `Err` when the envelope is malformed or no `decrypt_keys` can
/// decrypt it.
pub fn rewrap_envelope(
    raw: &[u8],
    decrypt_keys: &[RsaPrivateKey],
    primary_public: &RsaPublicKey,
) -> Result<Option<Vec<u8>>> {
    let env: Envelope = match serde_json::from_slice(raw) {
        Ok(e) => e,
        Err(_) => return Ok(None), // not an envelope; leave as plaintext
    };

    let enc_key = decode_b64("enc_key", &env.enc_key)?;
    let iv = decode_b64("iv", &env.iv)?;
    let ciphertext = decode_b64("ciphertext", &env.ciphertext)?;
    let tag = decode_b64("tag", &env.tag)?;

    // Fast-path: if the first key already decrypts under OAEP, we're already
    // current and skip the rewrap. This mirrors EncryptedLocalFs::rewrap_one.
    if env.alg == ALG_RSA_OAEP_256 && !decrypt_keys.is_empty() {
        if let Ok(cek) = recover_cek(&decrypt_keys[0], &env.alg, &enc_key) {
            if aes_decrypt(&cek, &iv, &ciphertext, &tag).is_ok() {
                return Ok(None);
            }
        }
    }

    // Find a key that decrypts both the CEK and the body, then re-wrap with
    // the new public key.
    let cek = decrypt_keys
        .iter()
        .find_map(|key| {
            let cek = recover_cek(key, &env.alg, &enc_key).ok()?;
            aes_decrypt(&cek, &iv, &ciphertext, &tag).ok()?;
            Some(cek)
        })
        .context("no configured key can decrypt this resource")?;

    let new_enc_key = {
        let mut rng = rand::thread_rng();
        primary_public
            .encrypt(&mut rng, Oaep::new::<Sha256>(), &cek)
            .context("re-wrap CEK with primary public key")?
    };

    let new_env = Envelope {
        alg: ALG_RSA_OAEP_256.to_string(),
        enc_key: STANDARD.encode(new_enc_key),
        iv: env.iv,
        ciphertext: env.ciphertext,
        tag: env.tag,
    };
    let bytes = serde_json::to_vec(&new_env).context("serialize re-wrapped envelope")?;
    Ok(Some(bytes))
}

fn recover_cek(private_key: &RsaPrivateKey, alg: &str, enc_key: &[u8]) -> Result<Vec<u8>> {
    let cek = match alg {
        ALG_RSA1_5 => private_key
            .decrypt(Pkcs1v15Encrypt, enc_key)
            .context("RSA1_5 decrypt CEK")?,
        ALG_RSA_OAEP_256 => {
            let padding = Oaep::new::<Sha256>();
            private_key
                .decrypt(padding, enc_key)
                .context("RSA-OAEP-256 decrypt CEK")?
        }
        _ => bail!("unsupported envelope alg `{alg}`"),
    };
    if cek.len() != AES_GCM_KEY_LEN {
        bail!(
            "unexpected CEK length {}, expect {AES_GCM_KEY_LEN} bytes",
            cek.len()
        );
    }
    Ok(cek)
}

fn aes_decrypt(cek: &[u8], iv: &[u8], ciphertext: &[u8], tag: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(cek).context("build AES-256-GCM cipher with CEK")?;
    let nonce = Nonce::from_slice(iv);
    let mut plaintext = ciphertext.to_vec();
    let tag_arr = aes_gcm::aead::generic_array::GenericArray::from_slice(tag);
    cipher
        .decrypt_in_place_detached(nonce, b"", &mut plaintext, tag_arr)
        .map_err(|e| anyhow!("AES-256-GCM decrypt resource payload: {e:?}"))?;
    Ok(plaintext)
}
