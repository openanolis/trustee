//! Attestation Service
//!
//! # Features
//! - `rvps-grpc`: The AS will connect a remote RVPS.

pub mod challenge;
pub mod config;
pub mod policy_engine;
pub mod rvps;
pub mod token;

mod composite;

use crate::{rvps::ReferenceValueResolver, token::AttestationTokenBroker};

use anyhow::{anyhow, Context, Result};
use canon_json::CanonicalFormatter;
use config::Config;
pub use kbs_types::{Attestation, Tee};
use log::info;
use reqwest::Client;
use rvps::{RvpsApi, RvpsError};
use serde::{Deserialize, Serialize};
pub use serde_json::Value;
use sha2::{Digest, Sha256, Sha384, Sha512};
use sm3::Sm3;
use std::{collections::HashMap, sync::Arc};
use strum::{AsRefStr, Display, EnumString};
use thiserror::Error;
#[cfg(feature = "fs")]
use tokio::fs;
use verifier::{InitDataHash, ReportData, TeeEvidenceParsedClaim};

/// Hash algorithms used to calculate runtime/init data binding
#[derive(Debug, Display, EnumString, AsRefStr, Serialize, Deserialize)]
pub enum HashAlgorithm {
    #[strum(ascii_case_insensitive)]
    #[serde(rename = "sha256")]
    Sha256,

    #[strum(ascii_case_insensitive)]
    #[serde(rename = "sha384")]
    Sha384,

    #[strum(ascii_case_insensitive)]
    #[serde(rename = "sha512")]
    Sha512,

    #[strum(ascii_case_insensitive)]
    #[serde(rename = "sm3")]
    Sm3,
}

impl HashAlgorithm {
    fn accumulate_hash(&self, materials: Vec<u8>) -> Vec<u8> {
        match self {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(materials);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha384 => {
                let mut hasher = Sha384::new();
                hasher.update(materials);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha512 => {
                let mut hasher = Sha512::new();
                hasher.update(materials);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sm3 => {
                let mut hasher = Sm3::new();
                hasher.update(materials);
                hasher.finalize().to_vec()
            }
        }
    }
}

fn serialize_canon_json<T: Serialize>(value: T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, CanonicalFormatter::new());
    value.serialize(&mut ser)?;
    Ok(buf)
}

pub type TeeEvidence = serde_json::Value;
pub type TeeClass = String;

/// Tee Claims are the output of the verifier plus some metadata
/// that identifies the TEE type and class.
#[derive(Debug)]
pub struct TeeClaims {
    tee: Tee,
    tee_class: TeeClass,
    claims: TeeEvidenceParsedClaim,
    init_data_claims: serde_json::Value,
    runtime_data_claims: serde_json::Value,
    additional_data: Option<serde_json::Value>,
}

/// Runtime Data used to check the binding relationship with report data
/// in Evidence
#[derive(Debug)]
pub enum RuntimeData {
    /// This will be used as the expected runtime data to check against
    /// the one inside evidence.
    Raw(Vec<u8>),

    /// Runtime data in a JSON map. CoCoAS will rearrange each layer of the
    /// data JSON object in dictionary order by key, then serialize and output
    /// it into a compact string, and perform hash calculation on the whole
    /// to check against the one inside evidence.
    Structured(Value),
}

#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("io error: {0}")]
    IO(#[from] std::io::Error),
    #[error("Create AS work dir failed: {0}")]
    CreateDir(#[source] std::io::Error),
    #[error("Policy Engine is not supported: {0}")]
    UnsupportedPolicy(#[source] strum::ParseError),
    #[error("Create rvps failed: {0}")]
    Rvps(#[source] RvpsError),
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

/// Errors whose request context must survive from the service layer to a
/// transport such as REST or gRPC.
///
/// The public `evaluate` API remains `anyhow::Result` for compatibility. These
/// values are inserted into its error chain so transports can downcast them
/// and classify failures without matching display strings.
#[derive(Error, Debug)]
pub enum AttestationError {
    #[error("invalid attestation request field `{field}`")]
    InvalidRequest {
        request_index: Option<usize>,
        field: &'static str,
        #[source]
        source: anyhow::Error,
    },

    #[error("verification request {request_index} uses unsupported TEE {tee:?}")]
    UnsupportedTee {
        request_index: usize,
        tee: Tee,
        #[source]
        source: anyhow::Error,
    },

    #[error("verification request {request_index} ({tee:?}) failed")]
    Verification {
        request_index: usize,
        tee: Tee,
        #[source]
        source: anyhow::Error,
    },
}

/// Initdata defined in
/// <https://github.com/confidential-containers/trustee/blob/47d7a2338e0be76308ac19be5c0c172c592780aa/kbs/docs/initdata.md>
#[derive(Debug, Deserialize, Serialize)]
pub struct Initdata {
    pub version: String,
    pub algorithm: HashAlgorithm,
    pub data: HashMap<String, String>,
}

/// Init Data used to check the binding relationship with report data
/// in Evidence
#[derive(Debug)]
pub enum InitDataInput {
    /// This will be used as the expected init data to check against
    /// the one inside evidence.
    Digest(Vec<u8>),

    /// Init data TOML. CoCoAS will perform hash calculation on the whole
    /// to check against the one inside evidence.
    ///
    /// After the verification, the `.data` field of init data field will
    /// be included inside the token claims.
    Toml(String),
}

/// A VerificationRequest contains hw evidence that the AS will verify along with some
/// metadata required for verification.
///
pub struct VerificationRequest {
    /// TEE evidence bytes. This might not be the raw hardware evidence bytes. Definitions
    /// are in `verifier` crate.
    pub evidence: TeeEvidence,
    /// concrete TEE type
    pub tee: Tee,
    /// These data field will be used to check against the counterpart inside the evidence.
    /// The concrete way of checking is decide by the enum type. If this parameter is set `None`, the comparation
    /// will not be performed.
    pub runtime_data: Option<RuntimeData>,
    /// The hash algorithm that is used to calculate the digest of `runtime_data`.
    pub runtime_data_hash_algorithm: HashAlgorithm,
    /// These data field will be used to check against the counterpart inside the evidence.
    /// The concrete way of checking is decide by the enum type. If this parameter is set `None`, the comparation
    /// will not be performed.
    pub init_data: Option<InitDataInput>,
    pub additional_data: Option<String>,
}

pub struct AttestationService {
    _config: Config,
    rvps: Arc<dyn RvpsApi>,
    token_broker: Box<dyn AttestationTokenBroker + Send + Sync>,
}

/// Transport-neutral runtime status exposed by REST and gRPC AS binaries.
/// Verifier dependencies use a generic list so future KDS, RIM, registrar, or
/// other cache-backed integrations can report state without changing the
/// top-level API shape.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ServiceStatus {
    pub service: String,
    pub status: String,
    pub dependencies: Vec<verifier::DependencyStatus>,
}

impl AttestationService {
    /// Create a new Attestation Service instance.
    #[cfg(feature = "fs")]
    pub async fn new(config: Config) -> Result<Self, ServiceError> {
        if !config.work_dir.as_path().exists() {
            fs::create_dir_all(&config.work_dir)
                .await
                .map_err(ServiceError::CreateDir)?;
        }

        let rvps = rvps::initialize_rvps_client(&config.rvps_config)
            .await
            .map_err(ServiceError::Rvps)?;

        let token_broker = config
            .attestation_token_broker
            .to_token_broker(&config.artifact_server_address)?;

        Ok(Self {
            _config: config,
            rvps,
            token_broker,
        })
    }

    /// Return AS and verifier dependency status without performing network I/O.
    pub async fn status(&self) -> ServiceStatus {
        let dependencies = verifier::dependency_statuses().await;
        let status = if dependencies.iter().any(|status| status.is_unhealthy()) {
            "unhealthy"
        } else if dependencies.iter().any(|status| status.is_degraded()) {
            "degraded"
        } else {
            "ok"
        };

        ServiceStatus {
            service: "attestation-service".into(),
            status: status.into(),
            dependencies,
        }
    }

    /// Set Attestation Verification Policy.
    pub async fn set_policy(&mut self, policy_id: String, policy: String) -> Result<()> {
        self.token_broker.set_policy(policy_id, policy).await?;
        Ok(())
    }

    /// Get Attestation Verification Policy List.
    /// The result is a `policy-id` -> `policy hash` map.
    pub async fn list_policies(&self) -> Result<HashMap<String, String>> {
        self.token_broker
            .list_policies()
            .await
            .context("Cannot List Policy")
    }

    /// Get a single Policy content.
    pub async fn get_policy(&self, policy_id: String) -> Result<String> {
        self.token_broker
            .get_policy(policy_id)
            .await
            .context("Cannot Get Policy")
    }

    /// Delete a single Policy.
    pub async fn delete_policy(&self, policy_id: String) -> Result<()> {
        self.token_broker
            .delete_policy(policy_id)
            .await
            .context("Cannot Delete Policy")
    }

    /// Evaluate Attestation Evidence.
    /// Issue an attestation results token which contain TCB status and TEE public key.
    /// An evaluation can cover one more pieces of TEE Evidence which represent the TCB.
    /// The results will be combined into one attestation token.
    /// For more information, see the definition of VerificationRequest above.
    pub async fn evaluate(
        &self,
        verification_requests: Vec<VerificationRequest>,
        policy_ids: Vec<String>,
    ) -> Result<String> {
        let mut tee_claims: Vec<TeeClaims> = vec![];

        if verification_requests.is_empty() {
            return Err(AttestationError::InvalidRequest {
                request_index: None,
                field: "verification_requests",
                source: anyhow!("no verification requests provided"),
            }
            .into());
        }

        composite::verify_composite_bindings(&verification_requests)?;

        for (request_index, verification_request) in verification_requests.into_iter().enumerate() {
            let verifier = verifier::to_verifier(&verification_request.tee).map_err(|source| {
                AttestationError::UnsupportedTee {
                    request_index,
                    tee: verification_request.tee,
                    source,
                }
            })?;

            let (report_data, runtime_data_claims) = parse_runtime_data(
                verification_request.runtime_data,
                &verification_request.runtime_data_hash_algorithm,
            )
            .context("parse runtime data")
            .map_err(|source| AttestationError::InvalidRequest {
                request_index: Some(request_index),
                field: "runtime_data",
                source,
            })?;

            let report_data = match &report_data {
                Some(data) => ReportData::Value(data),
                None => ReportData::NotProvided,
            };

            let (init_data, init_data_claims) = parse_init_data(verification_request.init_data)
                .context("parse init data")
                .map_err(|source| AttestationError::InvalidRequest {
                    request_index: Some(request_index),
                    field: "init_data",
                    source,
                })?;

            let init_data_hash = match &init_data {
                Some(data) => InitDataHash::Value(data),
                None => InitDataHash::NotProvided,
            };

            let (claims_from_tee_evidence, tee_class) = verifier
                .evaluate(verification_request.evidence, &report_data, &init_data_hash)
                .await
                .map_err(|source| AttestationError::Verification {
                    request_index,
                    tee: verification_request.tee,
                    source,
                })?;
            info!(
                "{:?} Verifier/endorsement check passed.",
                verification_request.tee
            );

            let additional_data: Option<Value> = verification_request.additional_data.map(|ad| {
                match serde_json::from_str::<Value>(&ad) {
                    Ok(v) => v,
                    Err(_) => Value::String(ad),
                }
            });

            tee_claims.push(TeeClaims {
                tee: verification_request.tee,
                tee_class,
                claims: claims_from_tee_evidence,
                init_data_claims,
                runtime_data_claims,
                additional_data,
            });
        }

        let reference_value_resolver =
            Arc::new(ReferenceValueResolver::new(Arc::clone(&self.rvps)));

        let attestation_results_token = self
            .token_broker
            .issue(tee_claims, policy_ids, reference_value_resolver)
            .await?;
        Ok(attestation_results_token)
    }

    /// Registry a new reference value
    pub async fn register_reference_value(&self, message: &str) -> Result<()> {
        self.rvps
            .verify_and_extract(message)
            .await
            .context("register reference value")
    }

    /// Set reference value list via RVPS
    pub async fn set_reference_value_list(&self, payload: &str) -> Result<()> {
        self.rvps
            .set_reference_value_list(payload)
            .await
            .context("set reference value list")
    }

    /// Delete a reference value by name
    pub async fn delete_reference_value(&self, name: String) -> Result<bool> {
        self.rvps
            .delete_reference_value(&name)
            .await
            .context("delete reference value")
    }

    /// Query Reference Values
    pub async fn query_reference_values(&self) -> Result<HashMap<String, Value>> {
        self.rvps
            .get_reference_values()
            .await
            .context("query reference values")
    }

    /// Query one Reference Value by identifier.
    pub async fn query_reference_value(&self, reference_value_id: &str) -> Result<Option<Value>> {
        self.rvps
            .query_reference_value(reference_value_id)
            .await
            .context("query reference value")
    }

    pub async fn generate_supplemental_challenge(
        &self,
        tee: Tee,
        tee_parameters: String,
    ) -> Result<String> {
        let verifier = verifier::to_verifier(&tee)?;
        verifier
            .generate_supplemental_challenge(tee_parameters)
            .await
    }

    /// Filesystem path of the RSA private key used to sign and verify
    /// attestation challenge (nonce) tokens. Falls back to the built-in
    /// default when not set in the config.
    pub fn challenge_key_path(&self) -> std::path::PathBuf {
        self._config
            .challenge_key_path
            .clone()
            .unwrap_or_else(challenge::default_challenge_key_path)
    }

    pub async fn generate_challenge(
        &self,
        tee: Option<Tee>,
        tee_parameters: Option<String>,
    ) -> Result<String> {
        match tee {
            None => challenge::generate_common_challenge(&self.challenge_key_path()),
            Some(t) => {
                self.generate_supplemental_challenge(t, tee_parameters.unwrap_or_default())
                    .await
            }
        }
    }

    /// Get token broker signer certificate content.
    ///
    /// The broker self-reports the local cert it loaded at construction (from
    /// an inline `cert_pem` or a `cert_path`); if it has none, the service
    /// HTTP-fetches the broker's published `cert_url`. Returns the binary PEM
    /// bytes, or `None` when no cert is available.
    pub async fn get_token_broker_cert_config(&self) -> Result<Option<Vec<u8>>> {
        if let Some(content) = self.token_broker.signer_cert_pem_live().await {
            return Ok(Some(content?));
        }
        match self.token_broker.signer_cert_url() {
            Some(url) => self.fetch_cert_url(url).await,
            None => Ok(None),
        }
    }

    /// Fetch certificate content from a URL (the broker's published x5u).
    /// Inherent async (not behind the `Send`-bound broker trait), so it stays
    /// wasm-compatible — reqwest-wasm futures need not be `Send` here.
    async fn fetch_cert_url(&self, url: &str) -> Result<Option<Vec<u8>>> {
        let client = Client::new();
        let response = client
            .get(url)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to fetch certificate from URL: {}", e))?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "Failed to fetch certificate: HTTP {}",
                response.status()
            ));
        }

        let content = response
            .bytes()
            .await
            .map_err(|e| anyhow!("Failed to read certificate content: {}", e))?;

        Ok(Some(content.to_vec()))
    }

    /// Get the token broker's public key set (JWKS JSON). Delegates to the
    /// broker; only brokers that publish a public key (e.g. OIDC with a
    /// configured signer) return `Some`.
    pub async fn get_token_broker_public_key(&self) -> Result<Option<String>> {
        self.token_broker.configured_signer_jwks().await
    }

    /// Get the token broker's OIDC discovery configuration (JSON). Delegates to
    /// the broker; only the OIDC broker with a configured `oid_config` returns
    /// `Some`.
    pub async fn get_token_broker_oid_config(&self) -> Result<Option<String>> {
        self.token_broker.oid_config_json().await
    }
}

/// Get the expected runtime data and potential claims due to the given input
/// and the hash algorithm
fn parse_runtime_data(
    data: Option<RuntimeData>,
    hash_algorithm: &HashAlgorithm,
) -> Result<(Option<Vec<u8>>, Value)> {
    match data {
        Some(value) => match value {
            RuntimeData::Raw(raw) => Ok((Some(raw), Value::Null)),
            RuntimeData::Structured(structured) => {
                // by default serde_json will enforence the alphabet order for keys
                let hash_materials =
                    serialize_canon_json(&structured).context("parse JSON structured data")?;
                let digest = hash_algorithm.accumulate_hash(hash_materials);
                Ok((Some(digest), structured))
            }
        },
        None => Ok((None, Value::Null)),
    }
}

/// Get the expected init data and potential claims due to the given input
/// and the hash algorithm
fn parse_init_data(data: Option<InitDataInput>) -> Result<(Option<Vec<u8>>, Value)> {
    match data {
        Some(value) => match value {
            InitDataInput::Digest(raw) => Ok((Some(raw), Value::Null)),
            InitDataInput::Toml(structured) => {
                let initdata = toml::from_str::<Initdata>(&structured)
                    .context("parse TOML structured data")?;
                let digest = initdata.algorithm.accumulate_hash(structured.into_bytes());
                let claims = serde_json::to_value(initdata.data)?;
                Ok((Some(digest), claims))
            }
        },
        None => Ok((None, Value::Null)),
    }
}

#[cfg(test)]
mod tests {
    use assert_json_diff::assert_json_eq;
    use rstest::rstest;
    use serde_json::{json, Value};

    use crate::{HashAlgorithm, RuntimeData};

    #[rstest]
    #[case(Some(RuntimeData::Raw(b"aaaaa".to_vec())), Some(b"aaaaa".to_vec()), HashAlgorithm::Sha384, Value::Null)]
    #[case(None, None, HashAlgorithm::Sha384, Value::Null)]
    #[case(Some(RuntimeData::Structured(json!({"b": 1, "a": "test", "c": {"d": "e"}}))), Some(hex::decode(b"e71ce8e70d814ba6639c3612ebee0ff1f76f650f8dbb5e47157e0f3f525cd22c4597480a186427c813ca941da78870c3").unwrap()), HashAlgorithm::Sha384, json!({"b": 1, "a": "test", "c": {"d": "e"}}))]
    fn parse_runtimedata_json_binding(
        #[case] input: Option<RuntimeData>,
        #[case] expected_data: Option<Vec<u8>>,
        #[case] hash_algorithm: HashAlgorithm,
        #[case] expected_claims: Value,
    ) {
        let (data, data_claims) =
            crate::parse_runtime_data(input, &hash_algorithm).expect("parse failed");
        assert_eq!(data, expected_data);
        assert_json_eq!(data_claims, expected_claims);
    }
}
