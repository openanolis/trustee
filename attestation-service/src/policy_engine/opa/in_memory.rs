//! fs-free `PolicyEngine`: holds rego policy sources in memory and evaluates
//! them with Regorus, mirroring `opa::OPA`'s engine usage but without any
//! filesystem access. Selected by `PolicyEngineType::InMemory`.

use std::collections::HashMap;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha384};
use tokio::sync::RwLock;

use crate::{
    policy_engine::{EvaluationResult, PolicyDigest, PolicyEngine, PolicyError},
    rvps::ReferenceValueResolver,
};

/// In-memory policy store: `policy_id` -> raw rego source (decoded from the
/// base64url wire format `set_policy` receives, matching `opa::OPA`).
pub struct OPAInMemory {
    policies: RwLock<HashMap<String, Vec<u8>>>,
    #[cfg(feature = "policy-artifact-server")]
    artifact_server_client: Arc<artifact_resolve_sdk::Client>,
}

impl OPAInMemory {
    /// Build an engine with a default policy preloaded, mirroring `opa::OPA::new`
    /// which writes the default policy to `{dir}/{default_policy_id}` on disk.
    /// The policy is stored under the stem of `default_policy_id` (`.rego`
    /// stripped), matching how `opa::OPA::evaluate` looks up `{policy_id}.rego`.
    /// This lets a broker's default policy flow (`evaluate(..., "default", ...)`)
    /// succeed without any filesystem access.
    pub fn with_raw_default_policy(
        raw_default_policy: &str,
        default_policy_id: &str,
        #[cfg_attr(not(feature = "policy-artifact-server"), allow(unused_variables))]
        artifact_server_address: &str,
    ) -> Result<Self, PolicyError> {
        #[cfg(not(feature = "policy-artifact-server"))]
        let _ = artifact_server_address;

        let stem = default_policy_id.trim_end_matches(".rego");
        let mut policies = HashMap::new();
        policies.insert(stem.to_string(), raw_default_policy.as_bytes().to_vec());
        Ok(Self {
            policies: RwLock::new(policies),
            #[cfg(feature = "policy-artifact-server")]
            artifact_server_client: Arc::new(
                artifact_resolve_sdk::Client::new(artifact_server_address)
                    .map_err(PolicyError::ArtifactServerClientCreationFailed)?,
            ),
        })
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
impl PolicyEngine for OPAInMemory {
    async fn evaluate(
        &self,
        input: &str,
        policy_id: &str,
        evaluation_rules: Vec<String>,
        reference_value_resolver: Arc<ReferenceValueResolver>,
    ) -> Result<EvaluationResult, PolicyError> {
        let policies = self.policies.read().await;
        let policy = policies
            .get(policy_id)
            .map(|b| b.as_slice())
            .ok_or_else(|| {
                PolicyError::ReadPolicyFileFailed(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("policy {policy_id} not found"),
                ))
            })?;
        let policy =
            std::str::from_utf8(policy).map_err(|e| PolicyError::InvalidPolicy(e.into()))?;

        super::common_evaluate(
            policy.to_string(),
            input.to_string(),
            policy_id.to_string(),
            evaluation_rules,
            reference_value_resolver,
            #[cfg(feature = "policy-artifact-server")]
            self.artifact_server_client.clone(),
        )
        .await
    }

    async fn set_policy(&self, policy_id: String, policy: String) -> Result<(), PolicyError> {
        if !super::is_valid_policy_id(&policy_id) {
            return Err(PolicyError::InvalidPolicyId);
        }
        let bytes = URL_SAFE_NO_PAD.decode(policy)?;
        // validate it compiles as rego
        {
            let src =
                std::str::from_utf8(&bytes).map_err(|e| PolicyError::InvalidPolicy(e.into()))?;
            let mut engine = regorus::Engine::new();
            engine
                .add_policy(policy_id.clone(), src.to_string())
                .map_err(PolicyError::InvalidPolicy)?;
        }
        let mut policies = self.policies.write().await;
        policies.insert(policy_id, bytes);
        Ok(())
    }

    async fn list_policies(&self) -> Result<HashMap<String, PolicyDigest>, PolicyError> {
        let policies = self.policies.read().await;
        let mut out = HashMap::new();
        for (id, bytes) in policies.iter() {
            let mut h = Sha384::new();
            h.update(bytes);
            out.insert(id.clone(), URL_SAFE_NO_PAD.encode(h.finalize()));
        }
        Ok(out)
    }

    async fn get_policy(&self, policy_id: String) -> Result<String, PolicyError> {
        let policies = self.policies.read().await;
        let bytes = policies.get(&policy_id).ok_or_else(|| {
            PolicyError::ReadPolicyFileFailed(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("policy {policy_id} not found"),
            ))
        })?;
        Ok(URL_SAFE_NO_PAD.encode(bytes))
    }

    async fn delete_policy(&self, policy_id: String) -> Result<(), PolicyError> {
        if !super::is_valid_policy_id(&policy_id) {
            return Err(PolicyError::InvalidPolicyId);
        }
        if policy_id == "default" {
            return Err(PolicyError::CannotDeleteDefaultPolicy);
        }
        let mut policies = self.policies.write().await;
        policies.remove(&policy_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::config::DEFAULT_ARTIFACT_SERVER_ADDRESS;

    use super::*;

    const RAW_ALLOW_POLICY: &str = "package policy\ndefault allow = true";
    fn allow_policy() -> String {
        URL_SAFE_NO_PAD.encode(RAW_ALLOW_POLICY)
    }

    #[tokio::test]
    async fn set_get_list_delete_roundtrip() {
        let eng = OPAInMemory::with_raw_default_policy(
            RAW_ALLOW_POLICY,
            "test",
            DEFAULT_ARTIFACT_SERVER_ADDRESS,
        )
        .unwrap();
        assert_eq!(eng.list_policies().await.unwrap().len(), 1);
        assert_eq!(eng.get_policy("test".into()).await.unwrap(), allow_policy());
        eng.delete_policy("test".into()).await.unwrap();
        assert!(eng.list_policies().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn set_policy_then_get_roundtrip() {
        // Covers the set_policy -> get_policy path (the roundtrip above only
        // exercises with_default_policy). Verifies raw rego in == raw rego out.
        let eng = OPAInMemory::with_raw_default_policy(
            RAW_ALLOW_POLICY,
            "default",
            DEFAULT_ARTIFACT_SERVER_ADDRESS,
        )
        .unwrap();
        eng.set_policy("test".into(), allow_policy()).await.unwrap();
        let got = eng.get_policy("test".into()).await.unwrap();
        assert_eq!(got, allow_policy());
        // setting again overwrites cleanly
        eng.set_policy("test".into(), allow_policy()).await.unwrap();
        assert_eq!(eng.get_policy("test".into()).await.unwrap(), allow_policy());
    }

    #[tokio::test]
    async fn evaluate_uses_in_memory_policy() {
        let eng = OPAInMemory::with_raw_default_policy(
            RAW_ALLOW_POLICY,
            "test",
            DEFAULT_ARTIFACT_SERVER_ADDRESS,
        )
        .unwrap();
        eng.set_policy("p".into(), allow_policy()).await.unwrap();
        let res = eng
            .evaluate(
                "{}",
                "test",
                vec!["allow".into()],
                crate::rvps::test_resolver(HashMap::from([])),
            )
            .await
            .unwrap();
        assert!(res.rules_result.contains_key("allow"));
    }

    #[cfg(feature = "policy-rvps")]
    #[tokio::test]
    async fn evaluate_with_host_await_reference_value() {
        use crate::rvps::test_resolver;
        let eng = OPAInMemory::with_raw_default_policy(
            RAW_ALLOW_POLICY,
            "test",
            DEFAULT_ARTIFACT_SERVER_ADDRESS,
        )
        .unwrap();
        let policy = r#"package policy
import rego.v1
allow if {
  input.x == query_reference_value("k")
}
"#;
        eng.set_policy("p".into(), URL_SAFE_NO_PAD.encode(policy))
            .await
            .unwrap();
        let rvps = test_resolver(std::collections::HashMap::from([(
            "k".to_string(),
            serde_json::json!(1),
        )]));
        let res = eng
            .evaluate(r#"{"x":1}"#, "p", vec!["allow".into()], rvps)
            .await
            .unwrap();
        assert_eq!(
            res.rules_result.get("allow"),
            Some(&serde_json::Value::Bool(true))
        );
    }
}
