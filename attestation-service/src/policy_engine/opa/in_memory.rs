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
    /// Caller-injected functions exposed to rego policy. Generic injection
    /// point so a downstream crate can supply functions regorus does not ship
    /// built-in. Each entry's key becomes a rego-callable function name. `None`
    /// keeps the built-ins-only behaviour. See [`with_extra_extension_functions`].
    extra_extension_functions: Option<Vec<(String, super::ExtensionFunction)>>,
    /// Compiled-RVM-program cache shared across `evaluate` calls, keyed by
    /// `policy_id` with the content hash carried as a validation checksum. A
    /// repeated appraisal of the same policy skips `Engine` construction, policy
    /// parsing and compilation entirely and only runs the per-rule VM; a changed
    /// source invalidates just that entry. The affected entry is dropped on
    /// `set_policy`/`delete_policy`.
    #[cfg(feature = "regorus-regovm")]
    program_cache: Arc<super::ProgramCache>,
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
            extra_extension_functions: None,
            #[cfg(feature = "regorus-regovm")]
            program_cache: Arc::new(super::ProgramCache::default()),
        })
    }

    /// Inject additional functions callable from rego policy. Each `(key,
    /// function)` pair registers a rego function named `key` that policy can
    /// call to perform work regorus does not ship built-in. User functions are
    /// merged after the built-in `query_reference_value` /
    /// `query_artifact_server` extensions, so a colliding key is overridden by
    /// the caller's explicit choice.
    ///
    /// This is the generic extension point that lets a downstream crate supply
    /// host functions regorus omits by design.
    ///
    /// Both backends resolve dotted names (e.g. `crypto.sha256`): the
    /// `regorus-regovm` backend via generated function-rule wrappers, the
    /// `regorus-interpreter` backend via regorus's `add_extension` path
    /// resolution.
    pub fn with_extra_extension_functions(
        mut self,
        functions: Vec<(String, super::ExtensionFunction)>,
    ) -> Self {
        self.extra_extension_functions = Some(functions);
        self
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
            // The functions are `Arc` handles, so cloning the `Vec` is cheap and
            // lets `evaluate(&self)` hand the injected functions to
            // `common_evaluate` without moving out of `&self`.
            self.extra_extension_functions.clone(),
            // Shared program cache: the first appraisal of a policy pays the
            // compile; subsequent appraisals of the same content hit the cache.
            #[cfg(feature = "regorus-regovm")]
            &self.program_cache,
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
            // regorus 0.11 defaults to rego.v1; keep accepting legacy
            // `allow { ... }` (rego.v0) policies that were saved before the
            // rego.v1 migration. `import rego.v1` policies still work.
            engine.set_rego_v0(true);
            engine
                .add_policy(policy_id.clone(), src.to_string())
                .map_err(PolicyError::InvalidPolicy)?;
        }
        // Policy content changed (or was added): drop this policy_id's cached
        // programs so the next evaluation recompiles against the new source. The
        // hash-validation check would catch staleness anyway, but dropping the
        // slot here frees the memory eagerly instead of at the next lazy miss.
        #[cfg(feature = "regorus-regovm")]
        self.program_cache.write().await.remove(&policy_id);
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
        // A deleted policy's cached programs must not outlive it.
        #[cfg(feature = "regorus-regovm")]
        self.program_cache.write().await.remove(&policy_id);
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
    async fn evaluate_with_reference_value_extension() {
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

    // Injects an extension under the dotted key `crypto.sha256` and verifies a
    // rego policy can call `crypto.sha256("abc")` and receive the real sha256
    // hex. Runs on both backends: dotted keys resolve on the `regorus-regovm`
    // backend (via the `build_extensions` function-rule wrappers) AND on the
    // `regorus-interpreter` backend (regorus resolves a dotted `add_extension`
    // path to the matching policy call site).
    #[cfg(feature = "policy-rvps")]
    #[tokio::test]
    async fn evaluate_with_injected_dotted_extension() {
        use crate::policy_engine::opa::ExtensionFunction;
        use crate::rvps::test_resolver;
        use sha2::Digest;

        let sha256_fn: ExtensionFunction = Arc::new(|argument: regorus::Value| {
            Box::pin(async move {
                let s = argument.as_string().map_err(|e| {
                    PolicyError::EvalPolicyFailed(anyhow::anyhow!(
                        "crypto.sha256 arg not a string: {e}"
                    ))
                })?;
                let mut hasher = sha2::Sha256::new();
                hasher.update(s.as_bytes());
                Ok(regorus::Value::String(
                    hex::encode(hasher.finalize()).into(),
                ))
            })
        });
        let policy = r#"package policy
import rego.v1
test_hash := crypto.sha256("abc")
"#;
        let eng = OPAInMemory::with_raw_default_policy(
            policy,
            "default",
            DEFAULT_ARTIFACT_SERVER_ADDRESS,
        )
        .expect("build engine")
        .with_extra_extension_functions(vec![("crypto.sha256".to_string(), sha256_fn)]);

        let res = eng
            .evaluate(
                "{}",
                "default",
                vec!["test_hash".to_string()],
                test_resolver(HashMap::new()),
            )
            .await
            .expect("evaluate");
        let got = res.rules_result.get("test_hash").expect("test_hash result");
        assert_eq!(
            got.as_str(),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
    }

    // Regression for the per-rule program cache: a cache hit must not carry
    // over only the *first* request's compiled rule set. Two appraisals of the
    // same policy with different `evaluation_rules` must each return every
    // rule the policy defines — a rule absent from the first request must be
    // compiled on demand on the second, not skipped as "not defined". Exercises
    // the real `OPAInMemory::evaluate` -> `evaluate_with_regovm` path and the
    // real `ProgramCache`, both directions.
    #[cfg(all(feature = "policy-rvps", feature = "regorus-regovm"))]
    #[tokio::test]
    async fn evaluate_compiles_missing_rule_on_cached_policy() {
        use crate::rvps::test_resolver;
        let policy = r#"package policy
import rego.v1
first := 1
second := 2
"#;
        let eng = OPAInMemory::with_raw_default_policy(
            policy,
            "default",
            DEFAULT_ARTIFACT_SERVER_ADDRESS,
        )
        .unwrap();
        let rvps = test_resolver(HashMap::new());

        // First appraisal compiles only `first`; the cache entry then holds
        // just {first}. Requesting `second` next must compile and return it.
        let r1 = eng
            .evaluate("{}", "default", vec!["first".into()], rvps.clone())
            .await
            .unwrap();
        assert_eq!(r1.rules_result.get("first"), Some(&serde_json::json!(1)));
        let r2 = eng
            .evaluate("{}", "default", vec!["second".into()], rvps.clone())
            .await
            .unwrap();
        assert_eq!(r2.rules_result.get("second"), Some(&serde_json::json!(2)));

        // Reverse order on a fresh engine: `second` first, then `first`.
        let eng2 = OPAInMemory::with_raw_default_policy(
            policy,
            "default",
            DEFAULT_ARTIFACT_SERVER_ADDRESS,
        )
        .unwrap();
        let r3 = eng2
            .evaluate("{}", "default", vec!["second".into()], rvps.clone())
            .await
            .unwrap();
        assert_eq!(r3.rules_result.get("second"), Some(&serde_json::json!(2)));
        let r4 = eng2
            .evaluate("{}", "default", vec!["first".into()], rvps.clone())
            .await
            .unwrap();
        assert_eq!(r4.rules_result.get("first"), Some(&serde_json::json!(1)));
    }

    // Regression for the data dimension of the per-rule program cache: a cache
    // hit must not serve a stale data document from the first appraisal. The
    // compiled RVM program is data-independent (regorus lowers `data.x` to
    // `LoadData`, which reads the VM's runtime data store set per-evaluation
    // via `set_data`), so the second appraisal must observe its own `data`,
    // not the first's. Same policy_id (cache hit) with distinct reference
    // values (distinct `data`), same rule.
    #[cfg(all(feature = "policy-rvps", feature = "regorus-regovm"))]
    #[tokio::test]
    async fn evaluate_cache_hit_uses_request_data_not_stale() {
        use crate::rvps::test_resolver;

        // Legacy policy: `data.reference` is populated by `common_evaluate`
        // from the resolver, so each appraisal receives a distinct `data`.
        let policy = r#"package policy
import rego.v1
allow := data.reference.k == 1
"#;
        let eng = OPAInMemory::with_raw_default_policy(
            policy,
            "default",
            DEFAULT_ARTIFACT_SERVER_ADDRESS,
        )
        .unwrap();

        // First appraisal: k == 1 -> allow. Compiles and caches the program.
        let r1 = eng
            .evaluate(
                "{}",
                "default",
                vec!["allow".into()],
                test_resolver(HashMap::from([("k".to_string(), serde_json::json!(1))])),
            )
            .await
            .unwrap();
        assert_eq!(r1.rules_result.get("allow"), Some(&serde_json::json!(true)));

        // Second appraisal: same policy_id -> cache hit, but k == 2 -> allow
        // must be false. If the cached program had baked in the first `data`,
        // this would wrongly return true.
        let r2 = eng
            .evaluate(
                "{}",
                "default",
                vec!["allow".into()],
                test_resolver(HashMap::from([("k".to_string(), serde_json::json!(2))])),
            )
            .await
            .unwrap();
        assert_eq!(
            r2.rules_result.get("allow"),
            Some(&serde_json::json!(false))
        );
    }

    // Mirror of the injection test for the `regorus-interpreter` backend: a
    // plain (non-dotted) user function registered through the async->sync
    // `Extension` bridge, called from policy. Verifies `add_extension` wiring
    // and the `block_on` bridge for caller-injected functions on the legacy
    // path.
    #[cfg(all(feature = "policy-rvps", feature = "regorus-interpreter"))]
    #[tokio::test(flavor = "multi_thread")]
    async fn evaluate_with_injected_plain_extension_interpreter() {
        use crate::policy_engine::opa::ExtensionFunction;
        use crate::rvps::test_resolver;

        let upper_fn: ExtensionFunction = Arc::new(|argument: regorus::Value| {
            Box::pin(async move {
                let s = argument.as_string().map_err(|e| {
                    PolicyError::EvalPolicyFailed(anyhow::anyhow!("my_upper arg not a string: {e}"))
                })?;
                Ok(regorus::Value::String(s.to_uppercase().into()))
            })
        });
        let policy = r#"package policy
import rego.v1
test_upper := my_upper("abc")
"#;
        let eng = OPAInMemory::with_raw_default_policy(
            policy,
            "default",
            DEFAULT_ARTIFACT_SERVER_ADDRESS,
        )
        .expect("build engine")
        .with_extra_extension_functions(vec![("my_upper".to_string(), upper_fn)]);

        let res = eng
            .evaluate(
                "{}",
                "default",
                vec!["test_upper".to_string()],
                test_resolver(HashMap::new()),
            )
            .await
            .expect("evaluate");
        let got = res
            .rules_result
            .get("test_upper")
            .expect("test_upper result");
        assert_eq!(got.as_str(), Some("ABC"));
    }
}
