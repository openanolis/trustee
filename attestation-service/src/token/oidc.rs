// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! # OIDC Token Broker
//!
//! This is an implementation of Token Broker that uses OPA for
//! policy evaluation.

use anyhow::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use log::info;
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use openssl::x509::X509;
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private},
};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use serde_variant::to_variant_name;
use shadow_rs::concatcp;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use crate::policy_engine::{PolicyEngine, PolicyEngineType};
use crate::token::{AttestationTokenBroker, DEFAULT_TOKEN_WORK_DIR};
use crate::TeeClaims;

use super::{COCO_AS_ISSUER_NAME, DEFAULT_TOKEN_DURATION};

const RSA_KEY_BITS: u32 = 2048;
const OIDC_TOKEN_ALG: &str = "RS256";
const DEFAULT_OIDC_AUDIENCE: &str = "sigstore";

const DEFAULT_POLICY_DIR: &str = concatcp!(DEFAULT_TOKEN_WORK_DIR, "/oidc/policies");

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct TokenSignerConfig {
    pub key_path: String,
    pub cert_url: Option<String>,

    // PEM format certificate chain.
    pub cert_path: Option<String>,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct OpenIDConfig {
    pub issuer: String,

    pub jwks_uri: String,

    #[serde(default = "default_signing_algs")]
    pub id_token_signing_alg_values_supported: Vec<String>,

    #[serde(default = "default_oidc_audience")]
    pub audience: String,

    pub sub_claims: Option<Vec<String>>,

    pub additional_claims: Option<Vec<String>>,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct Configuration {
    /// The Attestation Results Token duration time (in minutes)
    /// Default: 5 minutes
    #[serde(default = "default_duration")]
    pub duration_min: i64,

    /// the issuer of the token
    #[serde(default = "default_issuer_name")]
    pub issuer_name: String,

    /// Configuration for signing the token.
    /// If this is not specified, the token
    /// will be signed with an ephemeral private key.
    pub signer: Option<TokenSignerConfig>,

    pub oid_config: Option<OpenIDConfig>,

    /// The path to the work directory that contains policies
    /// to provision the tokens.
    #[serde(default = "default_policy_dir")]
    pub policy_dir: String,
}

#[inline]
fn default_oidc_audience() -> String {
    DEFAULT_OIDC_AUDIENCE.to_string()
}

#[inline]
fn default_signing_algs() -> Vec<String> {
    vec![OIDC_TOKEN_ALG.to_string()]
}

#[inline]
fn default_duration() -> i64 {
    DEFAULT_TOKEN_DURATION
}

#[inline]
fn default_issuer_name() -> String {
    COCO_AS_ISSUER_NAME.to_string()
}

#[inline]
fn default_policy_dir() -> String {
    DEFAULT_POLICY_DIR.to_string()
}

impl Default for Configuration {
    fn default() -> Self {
        Self {
            duration_min: default_duration(),
            issuer_name: default_issuer_name(),
            signer: None,
            oid_config: None,
            policy_dir: default_policy_dir(),
        }
    }
}

pub struct OIDCAttestationTokenBroker {
    private_key: Rsa<Private>,
    config: Configuration,
    cert_url: Option<String>,
    cert_chain: Option<Vec<X509>>,
    policy_engine: Arc<dyn PolicyEngine>,
}

impl OIDCAttestationTokenBroker {
    pub fn new(config: Configuration) -> Result<Self> {
        let policy_engine = PolicyEngineType::OPA.to_policy_engine(
            Path::new(&config.policy_dir),
            include_str!("oidc_default_policy.rego"),
            "default.rego",
        )?;
        info!("Loading default AS policy \"oidc_default_policy.rego\"");

        if config.signer.is_none() {
            log::info!("No Token Signer key in config file, create an ephemeral key and without CA pubkey cert");
            return Ok(Self {
                private_key: Rsa::generate(RSA_KEY_BITS)?,
                config,
                cert_url: None,
                cert_chain: None,
                policy_engine,
            });
        }

        let signer = config.signer.clone().unwrap();
        let pem_data = std::fs::read(&signer.key_path)
            .map_err(|e| anyhow!("Read Token Signer private key failed: {:?}", e))?;
        let private_key = Rsa::private_key_from_pem(&pem_data)?;

        let cert_chain = signer
            .cert_path
            .as_ref()
            .map(|cert_path| -> Result<Vec<X509>> {
                let pem_cert_chain = std::fs::read_to_string(cert_path)
                    .map_err(|e| anyhow!("Read Token Signer cert file failed: {:?}", e))?;
                let mut chain = Vec::new();

                for pem in pem_cert_chain.split("-----END CERTIFICATE-----") {
                    let trimmed = format!("{}\n-----END CERTIFICATE-----", pem.trim());
                    if !trimmed.starts_with("-----BEGIN CERTIFICATE-----") {
                        continue;
                    }
                    let cert = X509::from_pem(trimmed.as_bytes())
                        .map_err(|_| anyhow!("Invalid PEM certificate chain"))?;
                    chain.push(cert);
                }
                Ok(chain)
            })
            .transpose()?;

        Ok(Self {
            private_key,
            config,
            cert_url: signer.cert_url,
            cert_chain,
            policy_engine,
        })
    }
}

impl OIDCAttestationTokenBroker {
    fn rs256_sign(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let rsa_pkey = PKey::from_rsa(self.private_key.clone())?;
        let mut signer = Signer::new(MessageDigest::sha256(), &rsa_pkey)?;
        signer.update(payload)?;
        let signature = signer.sign_to_vec()?;

        Ok(signature)
    }

    fn pubkey_jwks(&self) -> Result<String> {
        let n = self.private_key.n().to_vec();
        let e = self.private_key.e().to_vec();

        let mut jwk = Jwk {
            kty: "RSA".to_string(),
            alg: OIDC_TOKEN_ALG.to_string(),
            n: URL_SAFE_NO_PAD.encode(n),
            e: URL_SAFE_NO_PAD.encode(e),
            x5u: None,
            x5c: None,
        };

        jwk.x5u.clone_from(&self.cert_url);
        if let Some(cert_chain) = self.cert_chain.clone() {
            let mut x5c = Vec::new();
            for cert in cert_chain {
                let der = cert.to_der()?;
                x5c.push(URL_SAFE_NO_PAD.encode(der));
            }
            jwk.x5c = Some(x5c);
        }

        let jwks = json!({
            "keys": vec![jwk],
        });

        Ok(serde_json::to_string(&jwks)?)
    }
}

#[async_trait::async_trait]
impl AttestationTokenBroker for OIDCAttestationTokenBroker {
    async fn issue(
        &self,
        all_tee_claims: Vec<TeeClaims>,
        policy_ids: Vec<String>,
        reference_data_map: HashMap<String, Vec<String>>,
    ) -> Result<String> {
        let mut collected_claims: Map<String, Value> = Map::new();
        for tee_claims in &all_tee_claims {
            collect_claims(
                tee_claims.claims.clone(),
                tee_claims.init_data_claims.clone(),
                tee_claims.runtime_data_claims.clone(),
                tee_claims.tee,
                &mut collected_claims,
            );
        }

        let reference_data = json!({
            "reference": reference_data_map,
        });
        let reference_data = serde_json::to_string(&reference_data)?;
        let tcb_claims = serde_json::to_string(&collected_claims)?;

        let rules = vec!["allow".to_string()];

        let mut policies = HashMap::new();
        for policy_id in policy_ids {
            let policy_results = self
                .policy_engine
                .evaluate(&reference_data, &tcb_claims, &policy_id, rules.clone())
                .await?;

            // TODO add policy allowlist
            let Some(result) = policy_results.rules_result.get("allow") else {
                bail!("Policy results must contain `allow` claim");
            };

            let result = result
                .as_bool()
                .context("value `allow` must be a bool in policy")?;
            if !result {
                bail!("Reject by policy {policy_id}");
            }

            policies.insert(policy_id, policy_results.policy_hash);
        }

        let policies: Vec<_> = policies
            .into_iter()
            .map(|(k, v)| {
                json!({
                    "policy-id": k,
                    "policy-hash": v,
                })
            })
            .collect();

        let token_claims = json!({
            "tee": to_variant_name(&all_tee_claims[0].tee)?,
            "evaluation-reports": policies,
            // "tcb-status": tcb_claims, // omitted due to size limit
            "customized_claims": {
                "init_data": all_tee_claims[0].init_data_claims,
                "runtime_data": all_tee_claims[0].runtime_data_claims,
            },
        });

        let header_value = json!({
            "typ": "JWT",
            "alg": OIDC_TOKEN_ALG,
            "jwk": serde_json::from_str::<Value>(&self.pubkey_jwks()?)?["keys"][0].clone(),
        });
        let header_string = serde_json::to_string(&header_value)?;
        let header_b64 = URL_SAFE_NO_PAD.encode(header_string.as_bytes());

        let now = time::OffsetDateTime::now_utc();
        let exp = now + time::Duration::minutes(self.config.duration_min);

        let id: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();

        let audience: String = if let Some(oidc) = &self.config.oid_config {
            oidc.audience.clone()
        } else {
            default_oidc_audience()
        };

        let sub: String = if let Some(oidc) = &self.config.oid_config {
            let parts: Vec<String> = oidc.sub_claims
                .as_ref()
                .map_or_else(Vec::new, |k| {
                    k.iter().map(|s| {
                        // Extract value from collected_claims which has top-level keys like "tdx", "sev", "sgx"
                        // and the corresponding values are objects containing nested fields
                        let current_value = &collected_claims;
                        let mut segments = s.split('.');

                        // Get the first segment which should be the TEE type like "tdx", "sev", "sgx"
                        if let Some(first_segment) = segments.next() {
                            if let Some(tee_obj) = current_value.get(first_segment) {
                                // Navigate through the nested object using remaining segments
                                let mut current_obj = tee_obj;
                                for segment in segments {
                                    match current_obj {
                                        Value::Object(map) => {
                                            if let Some(next_value) = map.get(segment) {
                                                current_obj = next_value;
                                            } else {
                                                return "".to_string();
                                            }
                                        }
                                        _ => return "".to_string(),
                                    }
                                }
                                // Convert the final value to string
                                match current_obj {
                                    Value::String(s) => s.clone(),
                                    other => other.to_string(),
                                }
                            } else {
                                // Key doesn't exist in collected_claims
                                "".to_string()
                            }
                        } else {
                            // Empty key
                            "".to_string()
                        }
                    })
                    .collect::<Vec<String>>()
                });
            parts.join(".")
        } else {
            "".to_string()
        };

        let sub = if sub.is_empty() { "none".to_string() } else { sub }; // Some OIDC clients require non-empty sub

        let mut jwt_claims = json!({
            "iss": self.config.issuer_name.clone(),
            "aud": audience,
            "sub": sub,
            "iat": now.unix_timestamp(),
            "jti": id,
            "nbf": now.unix_timestamp(),
            "exp": exp.unix_timestamp(),
        })
        .as_object()
        .ok_or_else(|| anyhow!("Internal Error: generate claims failed"))?
        .clone();

        jwt_claims.extend(
            token_claims
                .as_object()
                .ok_or_else(|| anyhow!("Illegal token custom claims"))?
                .to_owned(),
        );

        let additional_claims: HashSet<String> = if let Some(oidc) = &self.config.oid_config {
            oidc.additional_claims.as_ref().map_or_else(HashSet::new, |v| v.iter().cloned().collect())
        } else {
            HashSet::new()
        };

        for tee_claims in &all_tee_claims {
            if let Some(obj) = tee_claims.additional_data.as_object() {
                for (k, v) in obj {
                    if let Some(_v_str) = v.as_str() {
                        if additional_claims.contains(k.as_str()) {
                            jwt_claims.insert(k.clone(), v.clone());
                        }
                    }
                }
            }
        }

        let claims_value = Value::Object(jwt_claims);
        let claims_string = serde_json::to_string(&claims_value)?;
        let claims_b64 = URL_SAFE_NO_PAD.encode(claims_string.as_bytes());

        let signature_payload = format!("{header_b64}.{claims_b64}");
        let signature = self.rs256_sign(signature_payload.as_bytes())?;
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature);

        let token = format!("{signature_payload}.{signature_b64}");

        Ok(token)
    }

    async fn set_policy(&self, policy_id: String, policy: String) -> Result<()> {
        self.policy_engine
            .set_policy(policy_id, policy)
            .await
            .map_err(Error::from)
    }

    async fn list_policies(&self) -> Result<HashMap<String, String>> {
        self.policy_engine
            .list_policies()
            .await
            .map_err(Error::from)
    }

    async fn get_policy(&self, policy_id: String) -> Result<String> {
        self.policy_engine
            .get_policy(policy_id)
            .await
            .map_err(Error::from)
    }

    async fn delete_policy(&self, policy_id: String) -> Result<()> {
        self.policy_engine
            .delete_policy(policy_id)
            .await
            .map_err(Error::from)
    }
}

#[derive(serde::Serialize, Debug, Clone)]
struct Jwk {
    kty: String,
    alg: String,
    n: String,
    e: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,
}

pub fn collect_claims(
    mut input_claims: Value,
    init_data_claims: Value,
    runtime_data_claims: Value,
    tee: kbs_types::Tee,
    output_claims: &mut Map<String, Value>,
) {
    // Ensure input_claims is an object so we can insert fields into it.
    if let Some(obj) = input_claims.as_object_mut() {
        obj.insert("init_data_claims".to_string(), init_data_claims);
        obj.insert("runtime_data_claims".to_string(), runtime_data_claims);
    }

    output_claims.insert(to_variant_name(&tee).unwrap().to_string(), input_claims);
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::TeeClaims;
    use assert_json_diff::assert_json_eq;
    use kbs_types::Tee;
    use serde_json::json;

    use crate::token::{
        oidc::{Configuration, OIDCAttestationTokenBroker},
        AttestationTokenBroker,
    };

    use super::flatten_claims;

    #[tokio::test]
    async fn test_issue_oidc_ephemeral_key() {
        // use default config with no signer.
        // this will sign the token with an ephemeral key.
        let config = Configuration::default();
        let broker = OIDCAttestationTokenBroker::new(config).unwrap();

        let _token = broker
            .issue(
                vec![TeeClaims {
                    tee: Tee::Sample,
                    tee_class: "cpu".to_string(),
                    claims: json!({"claim": "claim1"}),
                    runtime_data_claims: json!({"runtime_data": "111"}),
                    init_data_claims: json!({"initdata": "111"}),
                }],
                vec!["default".into()],
                HashMap::new(),
            )
            .await
            .unwrap();
    }
}
