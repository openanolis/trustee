use anyhow::Result;
use async_trait::async_trait;
use regorus::Value;
use serde::Deserialize;
use std::collections::HashMap;
use std::io;
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
}

#[derive(Debug, EnumString, Deserialize)]
#[strum(ascii_case_insensitive)]
pub enum PolicyEngineType {
    OPA,
}

impl PolicyEngineType {
    pub fn to_policy_engine(
        &self,
        work_dir: &Path,
        default_policy: &str,
    ) -> Result<Arc<dyn PolicyEngine>> {
        match self {
            PolicyEngineType::OPA => Ok(Arc::new(opa::OPA::new(
                work_dir.to_path_buf(),
                default_policy,
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

#[async_trait]
pub trait PolicyEngine: Send + Sync {
    /// The inputs to an policy engine. Inspired by OPA, we divided the inputs
    /// into three parts:
    /// - `policy id`: indicates the policy id that will be used to perform policy
    /// enforcement
    /// - `data`: static data that will help to enforce the policy.
    /// - `input`: dynamic data that will help to enforce the policy.
    /// - `rules`: the decision statement to be executed by the policy engine
    /// to determine the final output.
    ///
    /// In CoCoAS scenarios, `data` is recommended to carry reference values as
    /// it is relatively static. `input` is recommended to carry `tcb_claims`
    /// returned by `verifier` module. Concrete implementation can be different
    /// due to different needs.
    async fn evaluate(
        &self,
        data: &str,
        input: &str,
        policy_id: &str,
        evaluation_rules: Vec<String>,
    ) -> Result<EvaluationResult, PolicyError>;

    async fn set_policy(&self, policy_id: String, policy: String) -> Result<(), PolicyError>;

    /// The result is a map. The key is the policy id, and the
    /// value is the digest of the policy (using **Sha384**).
    async fn list_policies(&self) -> Result<HashMap<String, PolicyDigest>, PolicyError>;

    async fn get_policy(&self, policy_id: String) -> Result<String, PolicyError>;

    async fn delete_policy(&self, policy_id: String) -> Result<(), PolicyError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_policy_error_display() {
        // Test various PolicyError variants for their display implementation

        // CreatePolicyDirFailed
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "permission denied");
        let err = PolicyError::CreatePolicyDirFailed(io_err);
        assert_eq!(
            format!("{}", err),
            "Failed to create policy directory: permission denied"
        );

        // PolicyDirPathToStringFailed
        let err = PolicyError::PolicyDirPathToStringFailed;
        assert_eq!(
            format!("{}", err),
            "Failed to convert policy directory path to string"
        );

        // PolicyDenied
        let err = PolicyError::PolicyDenied {
            policy_id: "test_policy".to_string(),
        };
        assert_eq!(
            format!("{}", err),
            "Policy evaluation denied for test_policy"
        );

        // InvalidPolicyId
        let err = PolicyError::InvalidPolicyId;
        assert_eq!(
            format!("{}", err),
            "Illegal policy id. Only support alphabet, numeric, `-` or `_`"
        );

        // CannotDeleteDefaultPolicy
        let err = PolicyError::CannotDeleteDefaultPolicy;
        assert_eq!(format!("{}", err), "Cannot delete default policy");
    }

    #[test]
    fn test_policy_engine_type_from_str() {
        // Test case-insensitive parsing of PolicyEngineType

        // Lowercase
        let engine_type = PolicyEngineType::from_str("opa").unwrap();
        match engine_type {
            PolicyEngineType::OPA => {} // Expected
        }

        // Uppercase
        let engine_type = PolicyEngineType::from_str("OPA").unwrap();
        match engine_type {
            PolicyEngineType::OPA => {} // Expected
        }

        // Mixed case
        let engine_type = PolicyEngineType::from_str("OpA").unwrap();
        match engine_type {
            PolicyEngineType::OPA => {} // Expected
        }

        // Invalid value
        let result = PolicyEngineType::from_str("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_evaluation_result() {
        // Create a simple EvaluationResult
        let mut rules_result = HashMap::new();
        rules_result.insert("rule1".to_string(), Value::Bool(true));
        rules_result.insert("rule2".to_string(), Value::Bool(false));

        let result = EvaluationResult {
            rules_result,
            policy_hash: "abc123".to_string(),
        };

        // Verify fields
        assert_eq!(result.rules_result.len(), 2);
        assert_eq!(result.rules_result.get("rule1"), Some(&Value::Bool(true)));
        assert_eq!(result.rules_result.get("rule2"), Some(&Value::Bool(false)));
        assert_eq!(result.policy_hash, "abc123");
    }
}
