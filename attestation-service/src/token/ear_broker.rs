// Copyright (c) 2024 IBM
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use const_format::concatcp;
use ear::{
    Algorithm, Appraisal, Ear, ExtensionKind, ExtensionValue, Extensions, RawValue, TrustVector,
    VerifierID,
};
use jsonwebtoken::jwk;
use kbs_types::Tee;
use log::{debug, warn};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::{EncodePrivateKey, LineEnding};
use p256::SecretKey;
use serde::Deserialize;
#[cfg(test)]
use serde_json::json;
use serde_json::Value;
use serde_variant::to_variant_name;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};

use crate::policy_engine::PolicyEngine;
use crate::rvps::ReferenceValueResolver;
use crate::token::DEFAULT_TOKEN_WORK_DIR;
use crate::{AttestationTokenBroker, TeeClaims};

use super::signer::SignKeyProvider;
#[cfg(feature = "fs")]
use super::signer_transparency;
use super::{COCO_AS_ISSUER_NAME, DEFAULT_TOKEN_DURATION};

pub const DEFAULT_PROFILE: &str = "tag:github.com,2024:confidential-containers/Trustee";
pub const DEFAULT_DEVELOPER_NAME: &str = "https://confidentialcontainers.org";

const DEFAULT_POLICY_DIR: &str = concatcp!(DEFAULT_TOKEN_WORK_DIR, "/ear/policies");
pub const DEFAULT_POLICY: &str = include_str!("ear_default_policy_cpu.rego");
pub const DEFAULT_POLICY_ID: &str = "default.rego";

pub use super::signer::SignerConfig;

/// Part 1 — fs-free token-issuance metadata. This is the *only* part of the
/// config the broker holds at runtime.
#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct TokenBrokerSettings {
    /// The Attestation Results Token duration time (in minutes)
    /// Default: 5 minutes
    #[serde(default = "default_duration")]
    pub duration_min: i64,

    /// For tokens, the issuer of the token
    #[serde(default = "default_issuer_name")]
    pub issuer_name: String,

    /// The developer name to be used as part of the Verifier ID in the EAR.
    /// Default: `https://confidentialcontainers.org`
    #[serde(default = "default_developer")]
    pub developer_name: String,

    /// The build name to be used as part of the Verifier ID in the EAR.
    /// The default value will be generated from the Cargo package
    /// name and version of the AS.
    #[serde(default = "default_build")]
    pub build_name: String,

    /// The Profile that describes the EAR token
    /// Default: `tag:github.com,2024:confidential-containers/Trustee`
    #[serde(default = "default_profile")]
    pub profile_name: String,
}

impl Default for TokenBrokerSettings {
    fn default() -> Self {
        Self {
            duration_min: default_duration(),
            issuer_name: default_issuer_name(),
            developer_name: default_developer(),
            build_name: default_build(),
            profile_name: default_profile(),
        }
    }
}

/// The serde Configuration = parts 1 + 2 + 3, composed. `#[serde(flatten)]`
/// on `settings` keeps the existing flat JSON/TOML config format working.
#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct Configuration {
    #[serde(flatten)]
    pub settings: TokenBrokerSettings,

    /// Configuration for signing the EAR
    /// If this is not specified, the EAR
    /// will be signed with an ephemeral private key.
    #[serde(default = "Option::default")]
    pub signer: Option<SignerConfig>,

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
fn default_developer() -> String {
    DEFAULT_DEVELOPER_NAME.to_string()
}

#[inline]
fn default_profile() -> String {
    DEFAULT_PROFILE.to_string()
}

#[inline]
fn default_build() -> String {
    format!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
}

#[inline]
fn default_policy_dir() -> String {
    DEFAULT_POLICY_DIR.to_string()
}

impl Default for Configuration {
    fn default() -> Self {
        Self {
            settings: TokenBrokerSettings::default(),
            signer: None,
            policy_dir: default_policy_dir(),
        }
    }
}

pub struct EarAttestationTokenBroker {
    settings: TokenBrokerSettings,
    signer: Arc<dyn SignKeyProvider<SecretKey>>,
    policy_engine: Arc<dyn PolicyEngine>,
}

impl EarAttestationTokenBroker {
    /// Native / serde path. Resolves the signer from `SignerConfig`
    /// (`key_path`, fs-gated) and builds the `PolicyEngine` from
    /// `policy_dir` (OPA fs / InMemory). Replaces the old `new(config)`.
    #[cfg(feature = "fs")]
    pub fn from_config(config: Configuration, artifact_server_address: &str) -> Result<Self> {
        let policy_engine = crate::policy_engine::PolicyEngineType::OPA.to_policy_engine(
            std::path::Path::new(&config.policy_dir),
            DEFAULT_POLICY,
            DEFAULT_POLICY_ID,
            artifact_server_address,
        )?;
        log::info!("Loading default AS policy \"default.rego\"");

        let signer: Arc<dyn SignKeyProvider<SecretKey>> = match config.signer {
            Some(sc) => Arc::new(super::signer::FsSigner::<SecretKey>::from_config(sc)?),
            None => {
                log::info!(
                    "No Token Signer key in config file, create an ephemeral key and without CA pubkey cert"
                );
                Arc::new(super::signer::EphemeralSigner::<SecretKey>::new())
            }
        };

        Ok(Self {
            settings: config.settings,
            signer,
            policy_engine,
        })
    }

    pub fn from_components(
        settings: TokenBrokerSettings,
        signer: Arc<dyn SignKeyProvider<SecretKey>>,
        policy_engine: Arc<dyn PolicyEngine>,
    ) -> Self {
        Self {
            settings,
            signer,
            policy_engine,
        }
    }
}

#[cfg_attr(all(target_arch = "wasm32", target_vendor = "unknown", target_os = "unknown"), async_trait::async_trait(?Send))]
#[cfg_attr(
    not(all(
        target_arch = "wasm32",
        target_vendor = "unknown",
        target_os = "unknown"
    )),
    async_trait::async_trait
)]
impl AttestationTokenBroker for EarAttestationTokenBroker {
    async fn issue(
        &self,
        all_tee_claims: Vec<TeeClaims>,
        policy_ids: Vec<String>,
        reference_value_resolver: Arc<ReferenceValueResolver>,
    ) -> Result<String> {
        debug!("all_tee_claims: {:#?}", all_tee_claims);

        if policy_ids.len() > 1 {
            warn!("EAR token only accepts the first policy. The rest will be ignored.");
        }

        if policy_ids.is_empty() {
            bail!("No policy is given for EAR token generation.");
        }

        let mut tee_class_indices: HashMap<String, u8> = HashMap::new();
        let mut submods = BTreeMap::new();

        // Create an appraisal for each device
        for tee_claims in all_tee_claims {
            let mut appraisal = Appraisal::new();

            let tcb_claims = transform_claims(
                tee_claims.claims,
                tee_claims.init_data_claims.clone(),
                tee_claims.runtime_data_claims.clone(),
                tee_claims.tee,
            )?;

            let tcb_claims_json = serde_json::to_string(&tcb_claims)?;

            let rules = TrustVector::new()
                .into_iter()
                .map(|c| c.tag().replace('-', "_").to_string())
                .collect();

            // There is a policy for each tee class.
            // The cpu tee class is loaded as the default.
            let policy_results = self
                .policy_engine
                .evaluate(
                    &tcb_claims_json,
                    &policy_ids[0],
                    rules,
                    Arc::clone(&reference_value_resolver),
                )
                .await?;

            for (k, v) in &policy_results.rules_result {
                let claim_value =
                    i8::try_from(v.as_i64().context("Policy claim value is not an integer")?)
                        .context("Policy claim value is outside the i8 range")?;
                debug!("Policy claim: {}: {}", k, claim_value);

                // The definition of Trustworthiness Claims in AR4SI
                // (https://www.ietf.org/archive/id/draft-ietf-rats-ar4si-09.html#name-supportable-trustworthiness-cl)
                // uses hyphens while the policy engine uses underscores.
                // so we need to convert underscores to hyphens here.
                let k = k.replace('_', "-");

                appraisal
                    .trust_vector
                    .mut_by_name(&k)
                    .unwrap()
                    .set(claim_value);
            }

            if !appraisal.trust_vector.any_set() {
                bail!("At least one policy claim must be set.");
            }

            appraisal.update_status_from_trust_vector();
            appraisal.annotated_evidence = tcb_claims;
            appraisal.policy_id = Some(policy_ids[0].clone());

            if let Some(index) = tee_class_indices.get_mut(&tee_claims.tee_class) {
                *index += 1;
            } else {
                tee_class_indices.insert(tee_claims.tee_class.clone(), 0);
            }

            let submod_name = format!(
                "{}{}",
                tee_claims.tee_class,
                // We know this key will exist because of the logic above.
                tee_class_indices.get(&tee_claims.tee_class).unwrap()
            );
            submods.insert(submod_name, appraisal);
        }

        let now = OffsetDateTime::now_utc();
        let exp = now
            .checked_add(Duration::minutes(self.settings.duration_min))
            .ok_or(anyhow!("Token expiration overflow."))?;

        let mut extensions = Extensions::new();
        extensions.register("exp", 4, ExtensionKind::Integer)?;
        extensions.set_by_name("exp", ExtensionValue::Integer(exp.unix_timestamp()))?;

        let ear = Ear {
            profile: self.settings.profile_name.clone(),
            iat: now.unix_timestamp(),
            vid: VerifierID {
                build: self.settings.build_name.clone(),
                developer: self.settings.developer_name.clone(),
            },
            raw_evidence: None,
            nonce: None,
            submods,
            extensions,
        };
        let mut jwt_header = ear::new_jwt_header(&Algorithm::ES256)?;
        jwt_header.jwk = Some(self.pubkey_jwk()?);

        let private_key_bytes = self
            .signer
            .private_key()
            .to_pkcs8_pem(LineEnding::LF)
            .context("serialize EC private key to PKCS#8 PEM")?;
        let private_key_bytes: &[u8] = private_key_bytes.as_bytes();

        #[cfg(feature = "fs")]
        let signed_ear = if let Some(transparency) = signer_transparency::load_signer_transparency()
        {
            let mut ear_claims = serde_json::to_value(&ear)?
                .as_object()
                .cloned()
                .ok_or_else(|| {
                    anyhow!("Internal Error: serialize EAR claims to JSON object failed")
                })?;
            ear_claims.insert("signer_transparency".to_string(), transparency);
            jsonwebtoken::encode(
                &jwt_header,
                &Value::Object(ear_claims),
                &jsonwebtoken::EncodingKey::from_ec_pem(private_key_bytes)?,
            )?
        } else {
            ear.sign_jwt_pem_with_header(&jwt_header, private_key_bytes)?
        };
        #[cfg(not(feature = "fs"))]
        let signed_ear = ear.sign_jwt_pem_with_header(&jwt_header, private_key_bytes)?;

        Ok(signed_ear)
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

    async fn signer_cert_pem_live(&self) -> Option<Result<Vec<u8>>> {
        self.signer.cert_pem_live()
    }

    fn signer_cert_url(&self) -> Option<&str> {
        self.signer.cert_url()
    }
}

impl EarAttestationTokenBroker {
    // TODO: converge this with the jwk function in the simple token broker
    fn pubkey_jwk(&self) -> Result<jwk::Jwk> {
        let chain = self
            .signer
            .cert_chain()
            .transpose()?
            .map(|certs| -> Vec<String> {
                let mut chain = vec![];
                for cert in certs {
                    chain.push(URL_SAFE_NO_PAD.encode(cert));
                }
                chain
            });

        let common = jwk::CommonParameters {
            key_algorithm: Some(jwk::KeyAlgorithm::ES256),
            x509_url: self.signer.cert_url().map(str::to_owned),
            x509_chain: chain,
            ..Default::default()
        };

        let public_key = self.signer.private_key().public_key();
        let encoded = public_key.to_encoded_point(false);
        let x = encoded
            .x()
            .ok_or_else(|| anyhow!("EC public key has no x coordinate"))?;
        let y = encoded
            .y()
            .ok_or_else(|| anyhow!("EC public key has no y coordinate"))?;

        let algorithm = jwk::AlgorithmParameters::EllipticCurve(jwk::EllipticCurveKeyParameters {
            key_type: jwk::EllipticCurveKeyType::EC,
            curve: jwk::EllipticCurve::P256,
            x: URL_SAFE_NO_PAD.encode(x.as_slice()),
            y: URL_SAFE_NO_PAD.encode(y.as_slice()),
        });

        let jwk = jwk::Jwk { common, algorithm };

        Ok(jwk)
    }
}

#[cfg(all(test, feature = "fs"))]
fn generate_ec_keys() -> Result<(SecretKey, Vec<u8>, Vec<u8>)> {
    use rsa::pkcs8::EncodePublicKey as _;

    let mut rng = rand::rngs::OsRng;
    let secret = SecretKey::random(&mut rng);
    let priv_pem = secret
        .to_pkcs8_pem(LineEnding::LF)
        .context("serialize EC private key to PKCS#8 PEM")?;
    let pub_pem = secret
        .public_key()
        .to_public_key_pem(LineEnding::LF)
        .context("serialize EC public key to SPKI PEM")?;
    Ok((
        secret,
        priv_pem.as_bytes().to_vec(),
        pub_pem.as_bytes().to_vec(),
    ))
}

/// This function does three things.
///
/// 1) If the input claims include an init_data claim (meaning that
///    the verifier has validated the init_data), add the JSON
///    init_data_claims to the output claims. Do the same thing
///    for the report_data and runtime_data_claims.
///
///    This means that the full init_data and report_data will be
///    available in the token.
///
/// 2) Move all claims from input_claims except the ones mentioned
///    in the previous step into their own Object under the tee name.
///
/// 3) Convert the claims from serde_json Values to RawValues from the
///    EAR crate.
///
pub fn transform_claims(
    mut input_claims: Value,
    init_data_claims: Value,
    runtime_data_claims: Value,
    tee: Tee,
) -> Result<BTreeMap<String, RawValue>> {
    let mut output_claims = BTreeMap::new();

    // If the verifier produces an init_data claim (meaning that
    // it has validated the init_data hash), add the JSON init_data_claims,
    // to the claims map. Do the same for the report data.
    //
    // These claims will be flattened and provided to the policy engine.
    // They will also end up in the EAR token as part of the annotated evidence.
    if let Some(claims_map) = input_claims.as_object_mut() {
        if let Some(init_data) = claims_map.remove("init_data") {
            output_claims.insert(
                "init_data".to_string(),
                RawValue::Text(init_data.as_str().unwrap().to_string()),
            );

            let transformed_claims: RawValue =
                serde_json::from_str(&serde_json::to_string(&init_data_claims)?)?;
            output_claims.insert("init_data_claims".to_string(), transformed_claims);
        }

        if let Some(report_data) = claims_map.remove("report_data") {
            output_claims.insert(
                "report_data".to_string(),
                RawValue::Text(report_data.as_str().unwrap().to_string()),
            );

            let transformed_claims: RawValue =
                serde_json::from_str(&serde_json::to_string(&runtime_data_claims)?)?;
            output_claims.insert("runtime_data_claims".to_string(), transformed_claims);
        }
    }

    let transformed_claims: RawValue =
        serde_json::from_str(&serde_json::to_string(&input_claims)?)?;
    output_claims.insert(to_variant_name(&tee)?.to_string(), transformed_claims);

    Ok(output_claims)
}

#[cfg(test)]
mod tests {
    use assert_json_diff::assert_json_eq;
    use jsonwebtoken::DecodingKey;
    use std::io::Write;
    use tempfile::NamedTempFile;

    use crate::TeeClaims;

    use super::*;

    #[cfg(feature = "fs")]
    #[tokio::test]
    async fn test_issue_ear_ephemeral_key() {
        // use default config with no signer.
        // this will sign the token with an ephemeral key.
        let config = Configuration::default();
        let broker = EarAttestationTokenBroker::from_config(
            config,
            crate::config::DEFAULT_ARTIFACT_SERVER_ADDRESS,
        )
        .unwrap();

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
                crate::rvps::empty_test_resolver(),
            )
            .await
            .unwrap();
    }

    #[cfg(feature = "fs")]
    #[tokio::test]
    async fn test_issue_and_validate_ear() {
        let (_pkey, private_key_bytes, public_key_bytes) = generate_ec_keys().unwrap();
        let mut private_key_file = NamedTempFile::new().unwrap();
        private_key_file.write_all(&private_key_bytes).unwrap();

        let signer = SignerConfig {
            key_path: private_key_file.path().to_str().unwrap().to_string(),
            cert_url: None,
            cert_path: None,
        };

        let mut config = Configuration::default();
        config.signer = Some(signer);

        let broker = EarAttestationTokenBroker::from_config(
            config,
            crate::config::DEFAULT_ARTIFACT_SERVER_ADDRESS,
        )
        .unwrap();
        let token = broker
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
                crate::rvps::empty_test_resolver(),
            )
            .await
            .unwrap();

        let public_key = DecodingKey::from_ec_pem(&public_key_bytes).unwrap();

        let ear = Ear::from_jwt(&token, jsonwebtoken::Algorithm::ES256, &public_key).unwrap();
        ear.validate().unwrap();
    }

    #[cfg(feature = "fs")]
    async fn issue_snp_ear(debug_allowed: &str) -> Value {
        let policy_dir = tempfile::tempdir().unwrap();
        let config = Configuration {
            policy_dir: policy_dir.path().to_string_lossy().into_owned(),
            ..Configuration::default()
        };
        let broker = EarAttestationTokenBroker::from_config(
            config,
            crate::config::DEFAULT_ARTIFACT_SERVER_ADDRESS,
        )
        .unwrap();
        let token = broker
            .issue(
                vec![TeeClaims {
                    tee: Tee::Snp,
                    tee_class: "cpu".to_string(),
                    claims: json!({
                        "measurement": "test-snp-launch-measurement",
                        "policy_debug_allowed": debug_allowed,
                        "policy_migrate_ma": "0",
                        "reported_tcb_bootloader": "0",
                        "reported_tcb_tee": "0",
                        "reported_tcb_snp": "0",
                        "reported_tcb_microcode": "37",
                        "reported_tcb_fmc": "0",
                    }),
                    runtime_data_claims: Value::Null,
                    init_data_claims: Value::Null,
                    additional_data: None,
                }],
                vec!["default".into()],
                crate::rvps::empty_test_resolver(),
            )
            .await
            .unwrap();

        let payload = token.split('.').nth(1).unwrap();
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
    }

    #[cfg(feature = "fs")]
    #[tokio::test]
    async fn test_snp_default_policy_affirms_without_reference_values() {
        let ear = issue_snp_ear("0").await;
        assert_eq!(ear["submods"]["cpu0"]["ear.status"], "affirming");
    }

    #[cfg(feature = "fs")]
    #[tokio::test]
    async fn test_snp_default_policy_rejects_debug_guest() {
        let ear = issue_snp_ear("1").await;
        assert_eq!(ear["submods"]["cpu0"]["ear.status"], "warning");
    }

    #[cfg(not(feature = "fs"))]
    #[tokio::test]
    async fn from_components_issues_without_fs() {
        // Programmatic path: inject an fs-free InMemory policy engine
        // (constructed directly, bypassing the fs-gated `PolicyEngineType`)
        // and an ephemeral EC key. Proves issue() works with no fs feature,
        // no policy_dir, no SignerConfig. A stripped-down policy (just the
        // AR4SI trust-vector defaults, copied from the real default policy) is
        // used instead of `DEFAULT_POLICY` because the real one calls the
        // `query_reference_value` regorus extension, only registered under the
        // `policy-rvps` feature — off under `--no-default-features`.
        const TRIVIAL_EAR_POLICY: &str = r#"package policy
import rego.v1
default executables := 33
default hardware := 97
default configuration := 36
default file_system := 35
"#;
        use crate::policy_engine::opa::OPAInMemory;
        let policy_engine: Arc<dyn PolicyEngine> = Arc::new(
            OPAInMemory::with_raw_default_policy(
                TRIVIAL_EAR_POLICY,
                DEFAULT_POLICY_ID,
                crate::config::DEFAULT_ARTIFACT_SERVER_ADDRESS,
            )
            .unwrap(),
        );
        let broker = EarAttestationTokenBroker::from_components(
            TokenBrokerSettings::default(),
            Arc::new(crate::token::signer::EphemeralSigner::<SecretKey>::new()),
            policy_engine,
        );

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
                crate::rvps::empty_test_resolver(),
            )
            .await
            .unwrap();
    }

    #[test]
    fn test_transform_claims() {
        let json = json!({
            "ccel": {
                "kernel": "5b7aa6572f649714ff00b6a2b9170516a068fd1a0ba72aa8de27574131d454e6396d3bfa1727d9baf421618a942977fa",
                "kernel_parameters": {
                    "console": "hvc0",
                    "root": "/dev/vda1",
                    "rw": ""
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

        let init_data_claims = Value::String("".to_string());
        let runtime_data_claims = Value::String("".to_string());
        let transformed_claims =
            transform_claims(json, init_data_claims, runtime_data_claims, Tee::Tdx)
                .expect("flatten failed");

        let expected_claims = json!({
            "tdx": {
                "ccel": {
                    "kernel": "5b7aa6572f649714ff00b6a2b9170516a068fd1a0ba72aa8de27574131d454e6396d3bfa1727d9baf421618a942977fa",
                    "kernel_parameters": {
                        "console": "hvc0",
                        "root": "/dev/vda1",
                        "rw": ""
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
                }
            },
            "report_data": "7c71fe2c86eff65a7cf8dbc22b3275689fd0464a267baced1bf94fc1324656aeb755da3d44d098c0c87382f3a5f85b45c8a28fee1d3bdb38342bf96671501429",
            "init_data": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "runtime_data_claims": "",
            "init_data_claims": ""
        });

        assert_json_eq!(expected_claims, transformed_claims);
    }
}
