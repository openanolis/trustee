// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use jwk::JwkAttestationTokenVerifier;
use kbs_types::TeePubKey;
use log::debug;
use serde::Deserialize;
use serde_json::Value;

mod error;
pub(crate) mod jwk;
pub use error::*;

pub const TOKEN_TEE_PUBKEY_PATH_COCO: &str = "/customized_claims/runtime_data/tee-pubkey";
pub const TOKEN_TEE_PUBKEY_PATH_EAR: &str =
    "/submods/cpu/ear.veraison.annotated-evidence/runtime_data_claims/tee-pubkey";

#[derive(Deserialize, Debug, Clone, PartialEq, Default)]
pub struct AttestationTokenVerifierConfig {
    #[serde(default)]
    /// The paths to the tee public key in the JWT body. For example,
    /// `/attester_runtime_data/tee-pubkey` refers to the key
    /// `attester_runtime_data.tee-pubkey` inside the JWT body claims.
    ///
    /// If a JWT is received, the [`TokenVerifier`] will try to extract
    /// the tee public key from built-in ones (
    /// [`TOKEN_TEE_PUBKEY_PATH_COCO`]) and the configured `extra_teekey_paths`.
    ///
    /// This field will default to an empty vector.
    pub extra_teekey_paths: Vec<String>,

    /// File paths of trusted certificates in PEM format used to verify
    /// the signature of the Attestation Token.
    #[serde(default)]
    pub trusted_certs_paths: Vec<String>,

    /// URLs (file:// and https:// schemes accepted) pointing to a local JWKSet file
    /// or to an OpenID configuration url giving a pointer to JWKSet certificates
    /// (for "Jwk") to verify Attestation Token Signature.
    #[serde(default)]
    pub trusted_jwk_sets: Vec<String>,

    /// Whether the token signing key is (not) validated.
    /// If true, the attestation token can be modified in flight.
    /// This should only be set to true for testing.
    /// While the token signature is still validated, the provenance of the
    /// signing key is not checked and the key could be replaced.
    ///
    /// When false, the key must be endorsed by the certificates or JWK sets
    /// specified above.
    ///
    /// Default: false
    #[serde(default = "bool::default")]
    pub insecure_key: bool,
}

#[derive(Clone)]
pub struct TokenVerifier {
    verifier: JwkAttestationTokenVerifier,
    extra_teekey_paths: Vec<String>,
}

impl TokenVerifier {
    pub async fn verify(&self, token: String) -> Result<Value> {
        self.verifier
            .verify(token)
            .await
            .map_err(|e| Error::TokenVerificationFailed { source: e })
    }

    pub async fn from_config(config: AttestationTokenVerifierConfig) -> Result<Self> {
        let verifier = JwkAttestationTokenVerifier::new(&config)
            .await
            .map_err(|e| Error::TokenVerifierInitialization { source: e })?;

        let mut extra_teekey_paths = config.extra_teekey_paths;
        extra_teekey_paths.push(TOKEN_TEE_PUBKEY_PATH_COCO.into());
        extra_teekey_paths.push(TOKEN_TEE_PUBKEY_PATH_EAR.into());

        Ok(Self {
            verifier,
            extra_teekey_paths,
        })
    }

    /// Different types of attestation tokens store the tee public key in
    /// different places.
    /// Try extracting the key from multiple built-in paths as well as any extras
    /// specified in the config file.
    pub fn extract_tee_public_key(&self, claim: Value) -> Result<TeePubKey> {
        for path in &self.extra_teekey_paths {
            if let Some(pkey_value) = claim.pointer(path) {
                debug!("Extract tee public key from {path}");
                return TeePubKey::deserialize(pkey_value).map_err(|_| Error::TeePubKeyParseFailed);
            }
        }

        Err(Error::NoTeePubKeyClaimFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_extract_tee_public_key_coco_path() {
        // Create a TokenVerifier with default paths
        let verifier = TokenVerifier {
            verifier: jwk::JwkAttestationTokenVerifier::default(),
            extra_teekey_paths: vec![
                TOKEN_TEE_PUBKEY_PATH_COCO.to_string(),
                TOKEN_TEE_PUBKEY_PATH_EAR.to_string(),
            ],
        };

        // Create a claim with a tee public key at the COCO path
        let claim = json!({
            "customized_claims": {
                "runtime_data": {
                    "tee-pubkey": {
                        "kty": "RSA",
                        "alg": "RSA1_5",
                        "n": "mod123",
                        "e": "exp123"
                    }
                }
            }
        });

        // Extract the tee public key
        let result = verifier.extract_tee_public_key(claim);
        assert!(result.is_ok());

        let key = result.unwrap();
        assert_eq!(key.alg, "RSA1_5");
        assert_eq!(key.k_mod, "mod123");
        assert_eq!(key.k_exp, "exp123");
        assert_eq!(key.kty, "RSA");
    }

    #[test]
    fn test_extract_tee_public_key_ear_path() {
        // Create a TokenVerifier with default paths
        let verifier = TokenVerifier {
            verifier: jwk::JwkAttestationTokenVerifier::default(),
            extra_teekey_paths: vec![
                TOKEN_TEE_PUBKEY_PATH_COCO.to_string(),
                TOKEN_TEE_PUBKEY_PATH_EAR.to_string(),
            ],
        };

        // Create a claim with a tee public key at the EAR path
        let claim = json!({
            "submods": {
                "cpu": {
                    "ear.veraison.annotated-evidence": {
                        "runtime_data_claims": {
                            "tee-pubkey": {
                                "kty": "RSA",
                                "alg": "RSA1_5",
                                "n": "mod456",
                                "e": "exp456"
                            }
                        }
                    }
                }
            }
        });

        // Extract the tee public key
        let result = verifier.extract_tee_public_key(claim);
        assert!(result.is_ok());

        let key = result.unwrap();
        assert_eq!(key.alg, "RSA1_5");
        assert_eq!(key.k_mod, "mod456");
        assert_eq!(key.k_exp, "exp456");
        assert_eq!(key.kty, "RSA");
    }

    #[test]
    fn test_extract_tee_public_key_custom_path() {
        // Create a TokenVerifier with a custom path
        let verifier = TokenVerifier {
            verifier: jwk::JwkAttestationTokenVerifier::default(),
            extra_teekey_paths: vec![
                "/custom/path/tee-pubkey".to_string(),
                TOKEN_TEE_PUBKEY_PATH_COCO.to_string(),
                TOKEN_TEE_PUBKEY_PATH_EAR.to_string(),
            ],
        };

        // Create a claim with a tee public key at the custom path
        let claim = json!({
            "custom": {
                "path": {
                    "tee-pubkey": {
                        "kty": "RSA",
                        "alg": "RSA1_5",
                        "n": "mod789",
                        "e": "exp789"
                    }
                }
            }
        });

        // Extract the tee public key
        let result = verifier.extract_tee_public_key(claim);
        assert!(result.is_ok());

        let key = result.unwrap();
        assert_eq!(key.alg, "RSA1_5");
        assert_eq!(key.k_mod, "mod789");
        assert_eq!(key.k_exp, "exp789");
        assert_eq!(key.kty, "RSA");
    }

    #[test]
    fn test_extract_tee_public_key_not_found() {
        // Create a TokenVerifier with default paths
        let verifier = TokenVerifier {
            verifier: jwk::JwkAttestationTokenVerifier::default(),
            extra_teekey_paths: vec![
                TOKEN_TEE_PUBKEY_PATH_COCO.to_string(),
                TOKEN_TEE_PUBKEY_PATH_EAR.to_string(),
            ],
        };

        // Create a claim without a tee public key
        let claim = json!({
            "some": "other",
            "data": "here"
        });

        // Extract the tee public key
        let result = verifier.extract_tee_public_key(claim);
        assert!(result.is_err());

        match result {
            Err(Error::NoTeePubKeyClaimFound) => {} // Expected error
            _ => panic!("Expected NoTeePubKeyClaimFound error"),
        }
    }

    #[test]
    fn test_extract_tee_public_key_invalid_format() {
        // Create a TokenVerifier with default paths
        let verifier = TokenVerifier {
            verifier: jwk::JwkAttestationTokenVerifier::default(),
            extra_teekey_paths: vec![TOKEN_TEE_PUBKEY_PATH_COCO.to_string()],
        };

        // Create a claim with an invalid tee public key format
        let claim = json!({
            "customized_claims": {
                "runtime_data": {
                    "tee-pubkey": {
                        // Missing required fields
                        "alg": "RSA1_5"
                        // n and e are missing
                    }
                }
            }
        });

        // Extract the tee public key
        let result = verifier.extract_tee_public_key(claim);
        assert!(result.is_err());

        match result {
            Err(Error::TeePubKeyParseFailed) => {} // Expected error
            _ => panic!("Expected TeePubKeyParseFailed error"),
        }
    }

    #[test]
    fn test_attestation_token_verifier_config_default() {
        let config = AttestationTokenVerifierConfig::default();

        assert!(config.extra_teekey_paths.is_empty());
        assert!(config.trusted_certs_paths.is_empty());
        assert!(config.trusted_jwk_sets.is_empty());
        assert!(!config.insecure_key);
    }
}
