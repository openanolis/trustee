use crate::rvps::ReferenceValueResolver;
use anyhow::Result;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::io;
#[cfg(feature = "fs")]
use std::path::Path;
use std::sync::Arc;
use strum::EnumString;
use thiserror::Error;

pub mod opa;

#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("Failed to create policy directory: {0}")]
    CreatePolicyDirFailed(#[source] io::Error),
    #[error("Failed to convert policy directory path to string")]
    PolicyDirPathToStringFailed,
    #[error("Failed to write default policy: {0}")]
    WriteDefaultPolicyFailed(#[source] io::Error),
    #[error("Failed to read attestation service policy file: {0}")]
    ReadPolicyFileFailed(#[source] io::Error),
    #[error("Failed to write attestation service policy to file: {0}")]
    WritePolicyFileFailed(#[source] io::Error),
    #[error("Failed to load policy: {0}")]
    LoadPolicyFailed(#[source] anyhow::Error),
    #[error("Policy evaluation denied for {policy_id}")]
    PolicyDenied { policy_id: String },
    #[error("Serde json error: {0}")]
    SerdeJsonError(#[from] serde_json::Error),
    #[error("IO error: {0}")]
    IOError(#[from] std::io::Error),
    #[error("Base64 decode attestation service policy string failed: {0}")]
    Base64DecodeFailed(#[from] base64::DecodeError),
    #[error("Illegal policy id. Only support alphabet, numeric, `-` or `_`")]
    InvalidPolicyId,
    #[error("Illegal policy: {0}")]
    InvalidPolicy(#[source] anyhow::Error),
    #[error("Failed to load reference data: {0}")]
    LoadReferenceDataFailed(#[source] anyhow::Error),
    #[error("Failed to set input data: {0}")]
    SetInputDataFailed(#[source] anyhow::Error),
    #[error("Failed to evaluate policy: {0}")]
    EvalPolicyFailed(#[source] anyhow::Error),
    #[error("json serialization failed: {0}")]
    JsonSerializationFailed(#[source] anyhow::Error),
    #[error("Policy claim value not valid (must be between -127 and 127)")]
    InvalidClaimValue,
    #[error("Cannot delete default policy")]
    CannotDeleteDefaultPolicy,

    #[cfg(feature = "policy-artifact-server")]
    #[error("Failed to create artifact server client: {0}")]
    ArtifactServerClientCreationFailed(#[source] artifact_resolve_sdk::Error),
}

#[derive(Debug, EnumString, Deserialize)]
#[strum(ascii_case_insensitive)]
pub enum PolicyEngineType {
    #[cfg(feature = "fs")]
    OPA,
}

impl PolicyEngineType {
    #[cfg(feature = "fs")]
    pub fn to_policy_engine(
        &self,
        work_dir: &Path,
        default_policy: &str,
        default_policy_id: &str,
        artifact_server_address: &str,
    ) -> Result<Arc<dyn PolicyEngine>> {
        match self {
            PolicyEngineType::OPA => Ok(Arc::new(opa::OPA::new(
                work_dir.to_path_buf(),
                default_policy,
                default_policy_id,
                artifact_server_address,
            )?) as Arc<dyn PolicyEngine>),
        }
    }
}

type PolicyDigest = String;

#[derive(Debug)]
pub struct EvaluationResult {
    pub rules_result: HashMap<String, Value>,
    pub policy_hash: String,
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
pub trait PolicyEngine: Send + Sync {
    /// The inputs to an policy engine. Inspired by OPA, we divided the inputs
    /// into three parts:
    /// - `policy id`: indicates the policy id that will be used to perform policy
    /// enforcement
    /// - `input`: dynamic data that will help to enforce the policy.
    /// - `rules`: the decision statement to be executed by the policy engine
    /// to determine the final output.
    /// - `reference_value_resolver`: the per-attestation RVPS snapshot. Policies
    /// can query it through `query_reference_value(key)`. Legacy
    /// `data.reference` policies are populated lazily by the engine.
    /// Artifact Server queries use the address configured on the engine.
    async fn evaluate(
        &self,
        input: &str,
        policy_id: &str,
        evaluation_rules: Vec<String>,
        reference_value_resolver: Arc<ReferenceValueResolver>,
    ) -> Result<EvaluationResult, PolicyError>;

    async fn set_policy(&self, policy_id: String, policy: String) -> Result<(), PolicyError>;

    /// The result is a map. The key is the policy id, and the
    /// value is the digest of the policy (using **Sha384**).
    async fn list_policies(&self) -> Result<HashMap<String, PolicyDigest>, PolicyError>;

    async fn get_policy(&self, policy_id: String) -> Result<String, PolicyError>;

    async fn delete_policy(&self, policy_id: String) -> Result<(), PolicyError>;
}
