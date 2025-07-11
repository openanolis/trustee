// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use kbs_types::{Response, TeePubKey};
use rand::{rngs::OsRng, Rng};
use rsa::{BigUint, Pkcs1v15Encrypt, RsaPublicKey};
use serde_json::json;

const RSA_ALGORITHM: &str = "RSA1_5";
const AES_GCM_256_ALGORITHM: &str = "A256GCM";

pub fn jwe(tee_pub_key: TeePubKey, payload_data: Vec<u8>) -> Result<Response> {
    if tee_pub_key.alg != *RSA_ALGORITHM {
        bail!("algorithm is not {RSA_ALGORITHM} but {}", tee_pub_key.alg);
    }

    let mut rng = rand::thread_rng();

    let aes_sym_key = Aes256Gcm::generate_key(&mut OsRng);
    let cipher = Aes256Gcm::new(&aes_sym_key);
    let iv = rng.gen::<[u8; 12]>();
    let nonce = Nonce::from_slice(&iv);
    let encrypted_payload_data = cipher
        .encrypt(nonce, payload_data.as_slice())
        .map_err(|e| anyhow!("AES encrypt Resource payload failed: {e}"))?;

    let k_mod = URL_SAFE_NO_PAD
        .decode(&tee_pub_key.k_mod)
        .context("base64 decode k_mod failed")?;
    let n = BigUint::from_bytes_be(&k_mod);
    let k_exp = URL_SAFE_NO_PAD
        .decode(&tee_pub_key.k_exp)
        .context("base64 decode k_exp failed")?;
    let e = BigUint::from_bytes_be(&k_exp);

    let rsa_pub_key =
        RsaPublicKey::new(n, e).context("Building RSA key from modulus and exponent failed")?;
    let sym_key: &[u8] = aes_sym_key.as_slice();
    let wrapped_sym_key = rsa_pub_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, sym_key)
        .context("RSA encrypt sym key failed")?;

    let protected_header = json!(
    {
       "alg": RSA_ALGORITHM.to_string(),
       "enc": AES_GCM_256_ALGORITHM.to_string(),
    });

    Ok(Response {
        protected: serde_json::to_string(&protected_header)
            .context("serde protected_header failed")?,
        encrypted_key: URL_SAFE_NO_PAD.encode(wrapped_sym_key),
        iv: URL_SAFE_NO_PAD.encode(iv),
        ciphertext: URL_SAFE_NO_PAD.encode(encrypted_payload_data),
        tag: "".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPrivateKey;
    use serde_json::Value;

    #[test]
    fn test_jwe_invalid_algorithm() {
        // Create a TeePubKey with an invalid algorithm
        let tee_pub_key = TeePubKey {
            kty: "RSA".to_string(),
            alg: "INVALID_ALG".to_string(),
            k_mod: "".to_string(),
            k_exp: "".to_string(),
        };

        // Test with some payload data
        let payload_data = b"test payload data".to_vec();

        // Attempt to encrypt
        let result = jwe(tee_pub_key, payload_data);

        // Verify error
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("algorithm is not RSA1_5 but INVALID_ALG"));
    }

    #[test]
    fn test_jwe_invalid_key_mod() {
        // Create a TeePubKey with invalid base64 modulus
        let tee_pub_key = TeePubKey {
            kty: "RSA".to_string(),
            alg: RSA_ALGORITHM.to_string(),
            k_mod: "invalid-base64".to_string(),
            k_exp: "AQAB".to_string(), // Standard RSA exponent 65537 in base64
        };

        // Test with some payload data
        let payload_data = b"test payload data".to_vec();

        // Attempt to encrypt
        let result = jwe(tee_pub_key, payload_data);

        // Verify error
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("base64 decode k_mod failed"));
    }

    #[test]
    fn test_jwe_invalid_key_exp() {
        // Create a TeePubKey with valid modulus but invalid exponent
        let tee_pub_key = TeePubKey {
            kty: "RSA".to_string(),
            alg: RSA_ALGORITHM.to_string(),
            // This is a valid base64 string but not a real key modulus
            k_mod: URL_SAFE_NO_PAD.encode([0u8; 32]),
            k_exp: "invalid-base64".to_string(),
        };

        // Test with some payload data
        let payload_data = b"test payload data".to_vec();

        // Attempt to encrypt
        let result = jwe(tee_pub_key, payload_data);

        // Verify error
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("base64 decode k_exp failed"));
    }

    #[test]
    fn test_jwe_valid_encryption() {
        // Skip the RSA key generation part and use a simpler approach for testing
        let mut rng = rand::thread_rng();

        // Create a simpler RSA key
        let bits = 2048; // Use smaller key size for test
        let private_key = RsaPrivateKey::new(&mut rng, bits).expect("Failed to generate key");

        // Create a TeePubKey from the public key components
        let public_key = private_key.to_public_key();
        let k_mod = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
        let k_exp = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

        let tee_pub_key = TeePubKey {
            kty: "RSA".to_string(),
            alg: RSA_ALGORITHM.to_string(),
            k_mod,
            k_exp,
        };

        // Test with some payload data
        let payload_data = b"test payload data".to_vec();

        // Encrypt the data
        let response = jwe(tee_pub_key, payload_data).unwrap();

        // Verify response structure
        assert!(!response.protected.is_empty());
        assert!(!response.encrypted_key.is_empty());
        assert!(!response.iv.is_empty());
        assert!(!response.ciphertext.is_empty());
        assert_eq!(response.tag, "");

        // Parse protected header
        let protected_header: Value = serde_json::from_str(&response.protected).unwrap();
        assert_eq!(protected_header["alg"], RSA_ALGORITHM);
        assert_eq!(protected_header["enc"], AES_GCM_256_ALGORITHM);
    }
}
