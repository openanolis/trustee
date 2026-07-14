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
use rand::distributions::Alphanumeric;
use rand::rngs::OsRng;
use rand::{thread_rng, Rng};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::{Signature, SigningKey};
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::Signer;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use serde_variant::to_variant_name;
use sha2::Sha256;
use shadow_rs::concatcp;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use x509_cert::der::{DecodePem, Encode};
use x509_cert::Certificate;

use crate::policy_engine::{PolicyEngine, PolicyEngineType};
use crate::token::{AttestationTokenBroker, DEFAULT_TOKEN_WORK_DIR};
use crate::TeeClaims;

use super::{signer_transparency, COCO_AS_ISSUER_NAME, DEFAULT_TOKEN_DURATION};

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
    private_key: RsaPrivateKey,
    config: Configuration,
    cert_url: Option<String>,
    cert_chain: Option<Vec<Certificate>>,
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
            let mut rng = OsRng;
            return Ok(Self {
                private_key: RsaPrivateKey::new(&mut rng, RSA_KEY_BITS as usize)?,
                config,
                cert_url: None,
                cert_chain: None,
                policy_engine,
            });
        }

        let signer = config.signer.clone().unwrap();
        let pem_data = std::fs::read_to_string(&signer.key_path)
            .context("Read Token Signer private key failed")?;
        let private_key = RsaPrivateKey::from_pkcs8_pem(&pem_data)
            .or_else(|_| RsaPrivateKey::from_pkcs1_pem(&pem_data))
            .context("Parse Token Signer private key failed")?;

        let cert_chain = signer
            .cert_path
            .as_ref()
            .map(|cert_path| -> Result<Vec<Certificate>> {
                let pem_cert_chain = std::fs::read_to_string(cert_path)
                    .context("Read Token Signer cert file failed")?;
                let mut chain = Vec::new();

                for pem in pem_cert_chain.split("-----END CERTIFICATE-----") {
                    let trimmed = format!("{}\n-----END CERTIFICATE-----", pem.trim());
                    if !trimmed.starts_with("-----BEGIN CERTIFICATE-----") {
                        continue;
                    }
                    // x509-cert's DecodePem expects a single PEM block; the split
                    // above already isolates one. Use the Label-aware decoder.
                    let cert = Certificate::from_pem(trimmed.as_bytes())
                        .context("Invalid PEM certificate chain")?;
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
        let signing_key = SigningKey::<Sha256>::new(self.private_key.clone());
        let sig: Signature = signing_key.sign(payload);
        Ok(Box::<[u8]>::from(sig).to_vec())
    }

    fn pubkey_jwks(&self) -> Result<String> {
        let n = self.private_key.n().to_bytes_be();
        let e = self.private_key.e().to_bytes_be();

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
            let parts: Vec<String> = oidc.sub_claims.as_ref().map_or_else(Vec::new, |k| {
                k.iter()
                    .map(|s| {
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

        let sub = if sub.is_empty() {
            "none".to_string()
        } else {
            sub
        }; // Some OIDC clients require non-empty sub

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
        if let Some(transparency) = signer_transparency::load_signer_transparency() {
            jwt_claims.insert("signer_transparency".to_string(), transparency);
        }

        let additional_claims: HashSet<String> = if let Some(oidc) = &self.config.oid_config {
            oidc.additional_claims
                .as_ref()
                .map_or_else(HashSet::new, |v| v.iter().cloned().collect())
        } else {
            HashSet::new()
        };

        for tee_claims in &all_tee_claims {
            if let Some(obj) = tee_claims
                .additional_data
                .as_ref()
                .and_then(|v| v.as_object())
            {
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
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use kbs_types::Tee;
    use serde_json::json;
    use tempfile::NamedTempFile;
    use x509_cert::der::Decode;
    use x509_cert::Certificate;

    use crate::token::{
        oidc::{Configuration, OIDCAttestationTokenBroker, TokenSignerConfig},
        AttestationTokenBroker,
    };

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
                    additional_data: Some(json!({"additional_data": "111"})),
                }],
                vec!["default".into()],
                HashMap::new(),
            )
            .await
            .unwrap();
    }

    // A pre-generated RSA-2048 PKCS#8 private key (PEM). Used together with
    // `TEST_CERT_CHAIN_PEM` to exercise the `signer = Some(...)` branch of
    // `OIDCAttestationTokenBroker::new`, which parses the PEM cert chain via
    // `Certificate::from_pem` and later encodes it into the JWK `x5c` array via
    // `Certificate::to_der`. Generated with `openssl genpkey` / `openssl req
    // -x509`; embedded as text so no binary fixture is committed.
    const TEST_SIGNER_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCdazaeItcE7c8W
cuc3i+KE94fKdLt/aOw2oIr6lVlzW95cwuok35uTYlJwTrvhPd8Qz1xBuerk9qAQ
hMhEtslKX96ZBUHn/St7ajIvLAJahW4VdaOd8hcakS2b9sSaIaw84rtcpaGa/w1k
fQglM5w2zClbfWnhwLYr4Fp0tzhI3hWuqmQs3S7uGc0An1vcb9TZDkgt6hhB6Fpr
LHZcodgKbNHkM/WrNRKqJxFmwgSQc2v0VdA0QQyP7fNpuPdjdqrkSCQH7mMWQh2e
mbifKalRHAj5jzSrmhxfXis+yJ5yU/dij3TwG9JAWuYRR7hbgeKHEq9FMsWoNRCf
0TirPKjJAgMBAAECggEAFnLtrQuG4lsPh0IHmzJFsXSjVsni2z6ZQQkQCMA3q23U
fiIFxhBlXVVOMFnqDSsHnpwTqgPbbZ+GIBTvgm0Ws5aMZgIL7gt6ofT5ByUdiM8y
bbkDBkk55j4B5RYB34Eh0OT8ly+/phztSgFSoguEIYRn+XYfHWSgFg2+mJpwWmOo
KG1xGNSgpaAmjwpaMDWZkvOxeyPUZa7SZ8Qs+IaNd34KdbuCf0Bry5IB2aeNuQX4
YISpeNa+7ZFk+I9zbHtHMQuUNBYTeTRD6m7nyuKYfTghuooHbJMGDbCCOjHZZ+7+
wdvtKe3uw8v7bvmYL0YTit46XN45nD+2ZaU7LEPYIQKBgQDOf19oRzRgtMI84XTK
DheTgaZnkH0scBcNTF1InXLrJtD7SaAeDVAKpSjcp9j0ztCfVRqAR86FDJK5N9Sj
y5+F2Za3I6Y84Jv2cEOqlRADDmMZ3T3X1g2AIb4pB53+uqQXSCp7xHc1Y8u/v2tB
kZ/4iYxvdUL1kfgw4chaCDZCrQKBgQDDJ+h/Xkx0wbq2/CKXpwQ5cAX3+//cfmef
cVneWOq4kf7xEfM2es763zLCNEV/R0Jz6k94+Dg/MPRGk7jwYiJQzer3xnjrAlMg
Xmm3NubiCKK4lVbzlHR9GsSNEhOSPzVqvCY4EKjr66ilD5nC97qAugnNx3vvIr8v
P+9Rh7ceDQKBgDpUIE8ETfdDF9q6lJK+iEpSRP7cAX+b6ecHuxHX564kuMNCeMgE
WqenH3O0tcPw510aXPH/VoaelpNbAeWCjvzwCXKRz1NC3sstyu9US8GRPsz/gYiG
HiojXeOZEzfw4IjzCY0MYd/i4Jq5J0LOL7G0qMaTCOb05HZqUH2d9DXBAoGBAMKA
MttGe4LeVh3revqUTcSFHp3CPYZfQR2K1luhWQZtE57mGfVRPpqP+0HM4PryZYur
mlthYIWyX7M7pVWHKNZJ9IXP/FGU9o5LKqecg04B91NqG8gWTGcnV3+V5YWbk7x2
Gs1D5WeEbodb3g6P4gRL5lt+FsoGYm9QFE+4qEu9AoGBAIYroZ3Zcn/cuZrxd86+
IfhfMSAQFBcGy3mxwNnFK1oYNsaI2Q58XpmE2Szq3xKCJvxaySoaCYMI0gLnsNIY
cuYg+Fi67/AQ/dSefVb47kn9YnX8xAi2HfTvaX5M3z7bM00W/3aWAL+c785+L15/
wihjpplQnoBixGHV/2XFex6x
-----END PRIVATE KEY-----
";

    // A 2-cert PEM chain (leaf + CA). The split-on-`-----END CERTIFICATE-----`
    // loop in `OIDCAttestationTokenBroker::new` parses both entries.
    const TEST_CERT_CHAIN_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUdzxyN1GLEQxMXM8WxZBC8XyZgLswDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJdGVzdC1sZWFmMB4XDTI2MDcxMzEzMzMyOFoXDTI2MDcx
NDEzMzMyOFowFDESMBAGA1UEAwwJdGVzdC1sZWFmMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAnWs2niLXBO3PFnLnN4vihPeHynS7f2jsNqCK+pVZc1ve
XMLqJN+bk2JScE674T3fEM9cQbnq5PagEITIRLbJSl/emQVB5/0re2oyLywCWoVu
FXWjnfIXGpEtm/bEmiGsPOK7XKWhmv8NZH0IJTOcNswpW31p4cC2K+BadLc4SN4V
rqpkLN0u7hnNAJ9b3G/U2Q5ILeoYQehaayx2XKHYCmzR5DP1qzUSqicRZsIEkHNr
9FXQNEEMj+3zabj3Y3aq5EgkB+5jFkIdnpm4nympURwI+Y80q5ocX14rPsieclP3
Yo908BvSQFrmEUe4W4HihxKvRTLFqDUQn9E4qzyoyQIDAQABo1MwUTAdBgNVHQ4E
FgQU8wNZeMzYYavyOsdZiCaCRilG0h0wHwYDVR0jBBgwFoAU8wNZeMzYYavyOsdZ
iCaCRilG0h0wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAQ1EE
2oW6T0isfKL+JDVUJ+SQNj78XrZD/j4Yz1TelUcWisKXy2yLlaS6b5kc76uBt5fq
2k9zIL++DgrJKwLxLQLtzyzjSQfZjUL8droACYpHib68Lrndb5Wcj9a3Wcfiiapj
vvpS0AsewA7vJDbMT20ysk5UXuOhtzBHUGMJ3T8L4SI9DtcPhAHH+xsVj7m/bQSX
lH9fNZ3BtwToqc+EYJGpG73/ywyAIoXPKJz/QzKNgg9AEI+zii+jDp7kmb4/hDzQ
Zec2jczp/Dz57pSUaFnTwESsnxV5MSyYzuS7dtRzznvvUd5zcXmxDM1a9yIb1Odi
IC3JTM1/6bvS5z8fqQ==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDBTCCAe2gAwIBAgIUZXV/g7lAiljh80f59PX8tfvJOpEwDQYJKoZIhvcNAQEL
BQAwEjEQMA4GA1UEAwwHdGVzdC1jYTAeFw0yNjA3MTMxMzMzMjhaFw0yNjA3MTQx
MzMzMjhaMBIxEDAOBgNVBAMMB3Rlc3QtY2EwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDETWzpRRPicHUs5jm7jqm3HwuWB4cTHVOyoq87ttlEVVsVYpni
g2DLSUvDu0qXTNf8KaA5IYlqCIcEuDrKYNl0o1vcL79FFT/URFsZVr0Q6R1PjrKf
9nWN7df9sFCvMokJOpIxtBc0t4jFcYJKIS9EGBykP83zmDPv3+9KhLtlOq5cHEvM
89TSLvLn6sCHYwqFvOLlfNVrMGMAbDG656tnIcWXor3AFa/ghlLgsAeJgimfhaDM
I/JjZVZwKK5u3Vm027sKRPcv/U90wtRw7+HL84Cm++HtX71uBPcU8MyeCPV+IziN
ruWeTq9XbfCwMknU8G2/sHplwD4LJbgVUXxXAgMBAAGjUzBRMB0GA1UdDgQWBBSO
UCn2c7P9LIuWx588AgyQ90Y7wjAfBgNVHSMEGDAWgBSOUCn2c7P9LIuWx588AgyQ
90Y7wjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQB4UD93ayQK
JhhRqNdusfXGKanIoIxDRbTR6tzCjquJpFl+BuPZtYOQYQr/ZLaF+KlWoKnabTnN
Szdn92fQ0lTrc9T/gGI7MKm7w2iUXN4NYF40NOGl6fwf755+drDZ96uPbbB+ezMW
VLwu9FhLqR+i0ezsjjc4SvKTywsANT2tiheLgOlF//p9WoGSHPfnh57Yrn6TP+NI
6nW8UlqfXfdSjYugZILyU9KM5sMOJJSA8eIFuBApvzIwsxPZlIlfKxOKjaDQlVIE
qSF2UcxxPZ/OQ8T2kTNYWr0OAQ5Xd8niWu7KU6ZX0miQNIv2c7qsYDR14JEroeo0
frJCGYDUg+8c
-----END CERTIFICATE-----
";

    #[test]
    fn test_oidc_signer_cert_chain_x5c() {
        // Exercise the `signer = Some(...)` branch of
        // `OIDCAttestationTokenBroker::new` with a PEM private key and a
        // 2-cert PEM chain. This drives the previously-untested cert-chain
        // parse closure (`Certificate::from_pem`) and the `pubkey_jwks()`
        // `x5c`-encoding branch (`Certificate::to_der` + base64url).

        let key_file = NamedTempFile::new().expect("create temp key file");
        std::fs::write(&key_file, TEST_SIGNER_KEY_PEM).expect("write temp key file");
        let chain_file = NamedTempFile::new().expect("create temp chain file");
        std::fs::write(&chain_file, TEST_CERT_CHAIN_PEM).expect("write temp chain file");

        let config = Configuration {
            signer: Some(TokenSignerConfig {
                key_path: key_file.path().to_string_lossy().to_string(),
                cert_url: None,
                cert_path: Some(chain_file.path().to_string_lossy().to_string()),
            }),
            oid_config: None,
            ..Configuration::default()
        };

        let broker = OIDCAttestationTokenBroker::new(config)
            .expect("broker construction with signer + cert chain must succeed");

        let jwks = serde_json::from_str::<serde_json::Value>(
            &broker.pubkey_jwks().expect("pubkey_jwks must succeed"),
        )
        .expect("pubkey_jwks must return valid JSON");

        let keys = jwks
            .get("keys")
            .and_then(|v| v.as_array())
            .expect("JWKS must contain a `keys` array");
        assert_eq!(keys.len(), 1, "exactly one JWK expected");

        let jwk = &keys[0];

        // RSA public-key fields derived from the configured private key.
        let n = jwk
            .get("n")
            .and_then(|v| v.as_str())
            .expect("`n` must be present");
        let e = jwk
            .get("e")
            .and_then(|v| v.as_str())
            .expect("`e` must be present");
        assert!(!n.is_empty(), "`n` must be non-empty");
        assert!(!e.is_empty(), "`e` must be non-empty");

        // x5c round-trips the `to_der` encode + `from_pem` parse: each entry
        // base64url-decodes back to a DER blob that `Certificate::from_der`
        // accepts.
        let x5c = jwk
            .get("x5c")
            .and_then(|v| v.as_array())
            .expect("`x5c` must be present when a cert chain is configured");
        assert_eq!(x5c.len(), 2, "x5c must contain exactly 2 cert entries");

        for entry in x5c {
            let b64 = entry
                .as_str()
                .expect("each x5c entry must be a base64url string");
            let der = URL_SAFE_NO_PAD
                .decode(b64)
                .expect("each x5c entry must base64url-decode to DER bytes");
            Certificate::from_der(&der).expect("decoded x5c entry must be a valid DER certificate");
        }
    }
}
