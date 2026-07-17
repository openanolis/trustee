// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! # Simple Token Broker
//!
//! This is an implementation of Token Broker that uses OPA for
//! policy evaluation.

use anyhow::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use const_format::concatcp;
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
use sha2::Sha384;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use x509_cert::der::{DecodePem, Encode};
use x509_cert::Certificate;

use crate::policy_engine::{PolicyEngine, PolicyEngineType};
use crate::token::{AttestationTokenBroker, DEFAULT_TOKEN_WORK_DIR};
use crate::{TeeClaims, TeeEvidenceParsedClaim};

use super::{signer_transparency, COCO_AS_ISSUER_NAME, DEFAULT_TOKEN_DURATION};

const RSA_KEY_BITS: u32 = 2048;
const SIMPLE_TOKEN_ALG: &str = "RS384";

const DEFAULT_POLICY_DIR: &str = concatcp!(DEFAULT_TOKEN_WORK_DIR, "/simple/policies");

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct TokenSignerConfig {
    pub key_path: String,
    pub cert_url: Option<String>,

    // PEM format certificate chain.
    pub cert_path: Option<String>,
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

    /// The path to the work directory that contains policies
    /// to provision the tokens.
    #[serde(default = "default_policy_dir")]
    pub policy_dir: String,
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
            policy_dir: default_policy_dir(),
        }
    }
}

pub struct SimpleAttestationTokenBroker {
    private_key: RsaPrivateKey,
    config: Configuration,
    cert_url: Option<String>,
    cert_chain: Option<Vec<Certificate>>,
    policy_engine: Arc<dyn PolicyEngine>,
}

impl SimpleAttestationTokenBroker {
    pub fn new(config: Configuration) -> Result<Self> {
        let policy_engine = PolicyEngineType::OPA.to_policy_engine(
            Path::new(&config.policy_dir),
            include_str!("simple_default_policy.rego"),
            "default.rego",
        )?;
        info!("Loading default AS policy \"simple_default_policy.rego\"");

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

impl SimpleAttestationTokenBroker {
    fn rs384_sign(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let signing_key = SigningKey::<Sha384>::new(self.private_key.clone());
        let sig: Signature = signing_key.sign(payload);
        Ok(Box::<[u8]>::from(sig).to_vec())
    }

    fn pubkey_jwks(&self) -> Result<String> {
        let n = self.private_key.n().to_bytes_be();
        let e = self.private_key.e().to_bytes_be();

        let mut jwk = Jwk {
            kty: "RSA".to_string(),
            alg: SIMPLE_TOKEN_ALG.to_string(),
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
impl AttestationTokenBroker for SimpleAttestationTokenBroker {
    async fn issue(
        &self,
        all_tee_claims: Vec<TeeClaims>,
        policy_ids: Vec<String>,
        reference_data_map: HashMap<String, Vec<String>>,
    ) -> Result<String> {
        // Take claims from all verifiers, flatten them and add them to one map.
        let mut flattened_claims: Map<String, Value> = Map::new();
        for tee_claims in &all_tee_claims {
            flattened_claims.append(&mut flatten_claims(tee_claims.tee, &tee_claims.claims)?);
        }

        let reference_data = json!({
            "reference": reference_data_map,
        });
        let reference_data = serde_json::to_string(&reference_data)?;
        let tcb_claims = serde_json::to_string(&flattened_claims)?;

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
            "tcb-status": tcb_claims,
            "customized_claims": {
                "init_data": all_tee_claims[0].init_data_claims,
                "runtime_data": all_tee_claims[0].runtime_data_claims,
            },
        });

        let header_value = json!({
            "typ": "JWT",
            "alg": SIMPLE_TOKEN_ALG,
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

        let mut jwt_claims = json!({
            "iss": self.config.issuer_name.clone(),
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

        let claims_value = Value::Object(jwt_claims);
        let claims_string = serde_json::to_string(&claims_value)?;
        let claims_b64 = URL_SAFE_NO_PAD.encode(claims_string.as_bytes());

        let signature_payload = format!("{header_b64}.{claims_b64}");
        let signature = self.rs384_sign(signature_payload.as_bytes())?;
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

/// This funciton will transpose the following structured json
/// ```json
/// {
///     "a" : {
///         "b": "c"
///     },
///     "d": "e"
/// }
/// ```
/// into a flatten one with '.' to separate and also be added a prefix of tee name, e.g.
/// ```json
/// {
///     "sample.a.b": "c",
///     "sample.d": "e"
/// }
/// ```
///
/// But the key `init_data` and `report_data` will not be added the prefix.
fn flatten_claims(
    tee: kbs_types::Tee,
    claims: &TeeEvidenceParsedClaim,
) -> Result<Map<String, Value>> {
    let mut map = Map::new();
    let tee_type = to_variant_name(&tee)?;
    match claims {
        Value::Object(obj) => {
            for (k, v) in obj {
                if k != "report_data" && k != "init_data" {
                    flatten_helper(&mut map, v, format!("{tee_type}.{}", k.clone()));
                }
            }
            let report_data = obj
                .get("report_data")
                .cloned()
                .unwrap_or(Value::String(String::new()));
            map.insert("report_data".to_string(), report_data.clone());

            let report_data = obj
                .get("init_data")
                .cloned()
                .unwrap_or(Value::String(String::new()));
            map.insert("init_data".to_string(), report_data.clone());
        }
        _ => bail!("input claims must be a map"),
    }

    Ok(map)
}

/// Recursion algorithm helper of `flatten_claims`
fn flatten_helper(parent: &mut Map<String, Value>, child: &serde_json::Value, prefix: String) {
    match child {
        Value::Null => {
            let _ = parent.insert(prefix, Value::Null);
        }
        Value::Bool(v) => {
            let _ = parent.insert(prefix, Value::Bool(*v));
        }
        Value::Number(v) => {
            let _ = parent.insert(prefix, Value::Number(v.clone()));
        }
        Value::String(str) => {
            let _ = parent.insert(prefix, Value::String(str.clone()));
        }
        Value::Array(arr) => {
            let _ = parent.insert(prefix, Value::Array(arr.clone()));
        }
        Value::Object(obj) => {
            for (k, v) in obj {
                let sub_prefix = format!("{prefix}.{k}");
                flatten_helper(parent, v, sub_prefix);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::TeeClaims;
    use assert_json_diff::assert_json_eq;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use kbs_types::Tee;
    use serde_json::json;
    use tempfile::NamedTempFile;
    use x509_cert::der::Decode;
    use x509_cert::Certificate;

    use crate::token::{
        simple::{Configuration, SimpleAttestationTokenBroker, TokenSignerConfig},
        AttestationTokenBroker,
    };

    use super::flatten_claims;

    #[tokio::test]
    async fn test_issue_simple_ephemeral_key() {
        // use default config with no signer.
        // this will sign the token with an ephemeral key.
        let config = Configuration::default();
        let broker = SimpleAttestationTokenBroker::new(config).unwrap();

        let _token = broker
            .issue(
                vec![TeeClaims {
                    tee: Tee::Sample,
                    tee_class: "cpu".to_string(),
                    claims: json!({"claim": "claim1"}),
                    runtime_data_claims: json!({"runtime_data": "111"}),
                    init_data_claims: json!({"initdata": "111"}),
                    additional_data: None,
                }],
                vec!["default".into()],
                HashMap::new(),
            )
            .await
            .unwrap();
    }

    #[test]
    fn flatten() {
        let json = json!({
            "ccel": {
                "kernel": "5b7aa6572f649714ff00b6a2b9170516a068fd1a0ba72aa8de27574131d454e6396d3bfa1727d9baf421618a942977fa",
                "kernel_parameters": {
                    "console": "hvc0",
                    "root": "/dev/vda1",
                    "rw": null
                }
            },
            "quote": {
                "header":{
                    "version": "0400",
                    "att_key_type": "0200",
                    "tee_type": "81000000",
                    "reserved": "00000000",
                    "vendor_id": "939a7233f79c4ca9940a0db3957f0607",
                    "user_data": "d099bfec0a477aa85a605dceabf2b10800000000"
                },
                "body":{
                    "mr_config_id": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "mr_owner": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "mr_owner_config": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "mr_td": "705ee9381b8633a9fbe532b52345e8433343d2868959f57889d84ca377c395b689cac1599ccea1b7d420483a9ce5f031",
                    "mrsigner_seam": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "report_data": "7c71fe2c86eff65a7cf8dbc22b3275689fd0464a267baced1bf94fc1324656aeb755da3d44d098c0c87382f3a5f85b45c8a28fee1d3bdb38342bf96671501429",
                    "seam_attributes": "0000000000000000",
                    "td_attributes": "0100001000000000",
                    "mr_seam": "2fd279c16164a93dd5bf373d834328d46008c2b693af9ebb865b08b2ced320c9a89b4869a9fab60fbe9d0c5a5363c656",
                    "tcb_svn": "03000500000000000000000000000000",
                    "xfam": "e742060000000000"
                }
            },
            "report_data": "7c71fe2c86eff65a7cf8dbc22b3275689fd0464a267baced1bf94fc1324656aeb755da3d44d098c0c87382f3a5f85b45c8a28fee1d3bdb38342bf96671501429",
            "init_data": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        });
        let flatten = flatten_claims(kbs_types::Tee::Tdx, &json).expect("flatten failed");
        let expected = json!({
                "tdx.ccel.kernel": "5b7aa6572f649714ff00b6a2b9170516a068fd1a0ba72aa8de27574131d454e6396d3bfa1727d9baf421618a942977fa",
                "tdx.ccel.kernel_parameters.console": "hvc0",
                "tdx.ccel.kernel_parameters.root": "/dev/vda1",
                "tdx.ccel.kernel_parameters.rw": null,
                "tdx.quote.header.version": "0400",
                "tdx.quote.header.att_key_type": "0200",
                "tdx.quote.header.tee_type": "81000000",
                "tdx.quote.header.reserved": "00000000",
                "tdx.quote.header.vendor_id": "939a7233f79c4ca9940a0db3957f0607",
                "tdx.quote.header.user_data": "d099bfec0a477aa85a605dceabf2b10800000000",
                "tdx.quote.body.mr_config_id": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "tdx.quote.body.mr_owner": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "tdx.quote.body.mr_owner_config": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "tdx.quote.body.mr_td": "705ee9381b8633a9fbe532b52345e8433343d2868959f57889d84ca377c395b689cac1599ccea1b7d420483a9ce5f031",
                "tdx.quote.body.mrsigner_seam": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "tdx.quote.body.report_data": "7c71fe2c86eff65a7cf8dbc22b3275689fd0464a267baced1bf94fc1324656aeb755da3d44d098c0c87382f3a5f85b45c8a28fee1d3bdb38342bf96671501429",
                "tdx.quote.body.seam_attributes": "0000000000000000",
                "tdx.quote.body.td_attributes": "0100001000000000",
                "tdx.quote.body.mr_seam": "2fd279c16164a93dd5bf373d834328d46008c2b693af9ebb865b08b2ced320c9a89b4869a9fab60fbe9d0c5a5363c656",
                "tdx.quote.body.tcb_svn": "03000500000000000000000000000000",
                "tdx.quote.body.xfam": "e742060000000000",
                "report_data": "7c71fe2c86eff65a7cf8dbc22b3275689fd0464a267baced1bf94fc1324656aeb755da3d44d098c0c87382f3a5f85b45c8a28fee1d3bdb38342bf96671501429",
                "init_data": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        });
        assert_json_eq!(expected, flatten);
    }

    // A pre-generated RSA-2048 PKCS#8 private key (PEM). Used together with
    // `TEST_CERT_CHAIN_PEM` to exercise the `signer = Some(...)` branch of
    // `SimpleAttestationTokenBroker::new`, which parses the PEM cert chain via
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
    // loop in `SimpleAttestationTokenBroker::new` parses both entries.
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
    fn test_simple_signer_cert_chain_x5c() {
        // Exercise the `signer = Some(...)` branch of
        // `SimpleAttestationTokenBroker::new` with a PEM private key and a
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
            ..Configuration::default()
        };

        let broker = SimpleAttestationTokenBroker::new(config)
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
