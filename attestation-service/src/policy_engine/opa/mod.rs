// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::rvps::ReferenceValueResolver;
#[cfg(feature = "policy-rvps")]
use anyhow::{anyhow, bail};
use anyhow::{Context, Result};
use async_trait::async_trait;
use base64::Engine;
use log::{debug, warn};
use regorus::Extension;
use sha2::{Digest, Sha384};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(feature = "policy-rvps")]
use std::time::Duration;

use super::{EvaluationResult, PolicyDigest, PolicyEngine, PolicyError};

#[cfg(all(feature = "policy-rvps", not(test)))]
const REFERENCE_QUERY_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(all(feature = "policy-rvps", test))]
const REFERENCE_QUERY_TIMEOUT: Duration = Duration::from_millis(100);

#[derive(Debug, Clone)]
pub struct OPA {
    policy_dir_path: PathBuf,
}

impl OPA {
    pub fn new(
        work_dir: PathBuf,
        default_policy: &str,
        default_policy_id: &str,
    ) -> Result<Self, PolicyError> {
        let mut policy_dir_path = work_dir;

        policy_dir_path.push("opa");
        if !policy_dir_path.as_path().exists() {
            fs::create_dir_all(&policy_dir_path).map_err(PolicyError::CreatePolicyDirFailed)?;
        }

        let mut default_policy_path = PathBuf::from(
            &policy_dir_path
                .to_str()
                .ok_or_else(|| PolicyError::PolicyDirPathToStringFailed)?,
        );
        default_policy_path.push(default_policy_id);
        if !default_policy_path.as_path().exists() {
            fs::write(&default_policy_path, default_policy)
                .map_err(PolicyError::WriteDefaultPolicyFailed)?;
        } else {
            warn!("Default policy file is already populated. Existing policy file will be used.");
        }

        Ok(Self { policy_dir_path })
    }

    fn is_valid_policy_id(policy_id: &str) -> bool {
        policy_id
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    }

    fn policy_uses_legacy_reference(policy: &str) -> Result<bool, PolicyError> {
        use regorus::unstable::{Lexer, Source, TokenKind};

        let source = Source::from_contents("policy.rego".to_string(), policy.to_string())
            .map_err(PolicyError::LoadPolicyFailed)?;
        let mut lexer = Lexer::new(&source);
        let mut tokens = Vec::new();

        loop {
            let token = lexer.next_token().map_err(PolicyError::LoadPolicyFailed)?;
            if token.0 == TokenKind::Eof {
                break;
            }
            tokens.push((token.0, token.1.text().to_string()));
        }

        let dotted = tokens.windows(3).any(|tokens| {
            tokens[0].0 == TokenKind::Ident
                && tokens[0].1 == "data"
                && tokens[1].0 == TokenKind::Symbol
                && tokens[1].1 == "."
                && tokens[2].0 == TokenKind::Ident
                && tokens[2].1 == "reference"
        });
        let indexed = tokens.windows(4).any(|tokens| {
            tokens[0].0 == TokenKind::Ident
                && tokens[0].1 == "data"
                && tokens[1].0 == TokenKind::Symbol
                && tokens[1].1 == "["
                && matches!(tokens[2].0, TokenKind::String | TokenKind::RawString)
                && tokens[2].1 == "reference"
                && tokens[3].0 == TokenKind::Symbol
                && tokens[3].1 == "]"
        });

        Ok(dotted || indexed)
    }

    #[cfg(feature = "policy-rvps")]
    fn query_reference_value_extension(
        reference_value_resolver: Arc<ReferenceValueResolver>,
        runtime_handle: tokio::runtime::Handle,
    ) -> Box<dyn Extension> {
        Box::new(move |params: Vec<regorus::Value>| {
            if params.len() != 1 {
                bail!("query_reference_value requires exactly one parameter");
            }
            let reference_value_id = params[0]
                .as_string()
                .context("query_reference_value parameter must be a string")?
                .to_string();
            debug!("query reference value from RVPS: {reference_value_id}");

            let value = runtime_handle
                .block_on(async {
                    tokio::time::timeout(
                        REFERENCE_QUERY_TIMEOUT,
                        reference_value_resolver.query_reference_value(&reference_value_id),
                    )
                    .await
                    .map_err(|_| {
                        anyhow!(
                            "query_reference_value({reference_value_id:?}) timed out after {:?}",
                            REFERENCE_QUERY_TIMEOUT
                        )
                    })?
                })
                .map_err(|e| {
                    anyhow!("query_reference_value({reference_value_id:?}) failed: {e}")
                })?;

            match value {
                Some(value) => Ok(regorus::Value::from(value)),
                None => {
                    warn!("No reference value found for id {reference_value_id:?}; returning null");
                    Ok(regorus::Value::Null)
                }
            }
        })
    }

    fn evaluate_sync(
        policy: String,
        input: String,
        policy_id: String,
        evaluation_rules: Vec<String>,
        data: String,
        query_extension: Option<Box<dyn Extension>>,
    ) -> Result<EvaluationResult, PolicyError> {
        let mut engine = regorus::Engine::new();

        let policy_hash = {
            let mut hasher = sha2::Sha384::new();
            hasher.update(&policy);
            hex::encode(hasher.finalize().to_vec())
        };

        engine
            .add_policy(policy_id.clone(), policy)
            .map_err(PolicyError::LoadPolicyFailed)?;

        let data =
            regorus::Value::from_json_str(&data).map_err(PolicyError::JsonSerializationFailed)?;
        engine
            .add_data(data)
            .map_err(PolicyError::LoadReferenceDataFailed)?;

        engine
            .set_input_json(&input)
            .context("set input")
            .map_err(PolicyError::SetInputDataFailed)?;

        if let Some(query_extension) = query_extension {
            engine
                .add_extension("query_reference_value".to_string(), 1, query_extension)
                .map_err(PolicyError::EvalPolicyFailed)?;
        }

        let mut rules_result = HashMap::new();
        for rule in evaluation_rules {
            let whole_rule = format!("data.policy.{rule}");
            let claim_value = match engine.eval_rule(whole_rule) {
                Ok(value) => value,
                Err(error) if error.to_string().contains("not a valid rule path") => {
                    debug!("Policy `{policy_id}` does not check {rule}");
                    continue;
                }
                Err(error) => return Err(PolicyError::EvalPolicyFailed(error)),
            };

            let claim_value = claim_value
                .to_json_str()
                .map_err(PolicyError::JsonSerializationFailed)?;
            let claim_value =
                serde_json::from_str(&claim_value).map_err(PolicyError::SerdeJsonError)?;
            rules_result.insert(rule, claim_value);
        }

        Ok(EvaluationResult {
            rules_result,
            policy_hash,
        })
    }
}

#[async_trait]
impl PolicyEngine for OPA {
    async fn evaluate(
        &self,
        input: &str,
        policy_id: &str,
        evaluation_rules: Vec<String>,
        reference_value_resolver: Arc<ReferenceValueResolver>,
    ) -> Result<EvaluationResult, PolicyError> {
        let policy_dir_path = self
            .policy_dir_path
            .to_str()
            .ok_or_else(|| PolicyError::PolicyDirPathToStringFailed)?;

        let policy_file_path = format!("{policy_dir_path}/{policy_id}.rego");

        let policy =
            fs::read_to_string(policy_file_path).map_err(PolicyError::ReadPolicyFileFailed)?;

        let data = if Self::policy_uses_legacy_reference(&policy)? {
            let reference_values = reference_value_resolver
                .get_reference_values()
                .await
                .map_err(|e| PolicyError::LoadReferenceDataFailed(e.into()))?;
            serde_json::json!({ "reference": reference_values }).to_string()
        } else {
            "{}".to_string()
        };

        #[cfg(feature = "policy-rvps")]
        {
            let runtime_handle = tokio::runtime::Handle::current();
            let query_extension = Some(Self::query_reference_value_extension(
                reference_value_resolver,
                runtime_handle,
            ));
            let policy_id = policy_id.to_string();
            let input = input.to_string();
            return tokio::task::spawn_blocking(move || {
                Self::evaluate_sync(
                    policy,
                    input,
                    policy_id,
                    evaluation_rules,
                    data,
                    query_extension,
                )
            })
            .await
            .map_err(|e| {
                PolicyError::EvalPolicyFailed(anyhow!(
                    "Regorus blocking evaluation task failed: {e}"
                ))
            })?;
        }

        #[cfg(not(feature = "policy-rvps"))]
        Self::evaluate_sync(
            policy,
            input.to_string(),
            policy_id.to_string(),
            evaluation_rules,
            data,
            None,
        )
    }

    async fn set_policy(&self, policy_id: String, policy: String) -> Result<(), PolicyError> {
        let policy_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(policy)?;

        if !Self::is_valid_policy_id(&policy_id) {
            return Err(PolicyError::InvalidPolicyId);
        }

        // Check if the policy is valid
        {
            let policy_content = String::from_utf8(policy_bytes.clone())
                .map_err(|e| PolicyError::InvalidPolicy(e.into()))?;
            let mut engine = regorus::Engine::new();
            engine
                .add_policy(policy_id.clone(), policy_content)
                .map_err(PolicyError::InvalidPolicy)?;
        }

        let mut policy_file_path = PathBuf::from(
            &self
                .policy_dir_path
                .to_str()
                .ok_or_else(|| PolicyError::PolicyDirPathToStringFailed)?,
        );

        policy_file_path.push(format!("{}.rego", policy_id));

        fs::write(&policy_file_path, policy_bytes).map_err(PolicyError::WritePolicyFileFailed)
    }

    async fn list_policies(&self) -> Result<HashMap<String, PolicyDigest>, PolicyError> {
        let mut policy_ids = Vec::new();
        let entries = fs::read_dir(&self.policy_dir_path)?;
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(std::ffi::OsStr::to_str) == Some("rego") {
                if let Some(filename) = path.file_stem() {
                    if let Some(filename_str) = filename.to_str() {
                        policy_ids.push(filename_str.to_owned());
                    }
                }
            }
        }

        let mut policy_list = HashMap::new();

        for id in policy_ids.iter() {
            let policy_file_path = self.policy_dir_path.join(format!("{id}.rego"));
            let policy = fs::read(policy_file_path).map_err(PolicyError::ReadPolicyFileFailed)?;

            let mut hasher = Sha384::new();
            hasher.update(policy);
            let digest = hasher.finalize().to_vec();
            policy_list.insert(
                id.to_string(),
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest),
            );
        }

        Ok(policy_list)
    }

    async fn get_policy(&self, policy_id: String) -> Result<String, PolicyError> {
        let policy_file_path = self.policy_dir_path.join(format!("{policy_id}.rego"));
        let policy = fs::read(policy_file_path).map_err(PolicyError::ReadPolicyFileFailed)?;
        let base64_policy = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(policy);
        Ok(base64_policy)
    }

    async fn delete_policy(&self, policy_id: String) -> Result<(), PolicyError> {
        if !Self::is_valid_policy_id(&policy_id) {
            return Err(PolicyError::InvalidPolicyId);
        }

        // Prevent deletion of default policy
        if policy_id == "default" {
            return Err(PolicyError::CannotDeleteDefaultPolicy);
        }

        let policy_file_path = self.policy_dir_path.join(format!("{policy_id}.rego"));

        if !policy_file_path.exists() {
            return Err(PolicyError::ReadPolicyFileFailed(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Policy {} not found", policy_id),
            )));
        }

        fs::remove_file(policy_file_path).map_err(PolicyError::IOError)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::rvps::{RvpsApi, RvpsError};
    use ear::TrustVector;
    use rstest::rstest;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn dummy_reference(svn: u64, launch_digest: String) -> Arc<ReferenceValueResolver> {
        crate::rvps::test_resolver(HashMap::from([
            ("svn".to_string(), json!([svn.to_string()])),
            ("launch_digest".to_string(), json!([launch_digest])),
        ]))
    }

    fn dummy_input(svn: u64, launch_digest: String) -> String {
        json!({
            "sample": {
                "svn": svn.to_string(),
                "launch_digest": launch_digest
            }
        })
        .to_string()
    }

    #[rstest]
    // #[case(1,1,"aac43bb3".to_string(),"aac43bb3".to_string(),3,2)]
    //#[case(2,1,"aac43bb3".to_string(),"aac43bb3".to_string(),3,97)]
    //#[case(1,1,"aac43bb4".to_string(),"aac43bb3".to_string(),33,2)]
    #[case(2,1,"aac43bb4".to_string(),"aac43bb3".to_string(),33,97)]
    #[tokio::test]
    async fn test_evaluate(
        #[case] svn_a: u64,
        #[case] svn_b: u64,
        #[case] digest_a: String,
        #[case] digest_b: String,
        #[case] ex_exp: i8,
        #[case] hw_exp: i8,
    ) {
        let opa = OPA {
            policy_dir_path: PathBuf::from("./src/token/"),
        };
        let default_policy_id = "ear_default_policy_cpu".to_string();

        let ear_rules = TrustVector::new()
            .into_iter()
            .map(|c| c.tag().to_string().replace("-", "_"))
            .collect();

        let output = opa
            .evaluate(
                &dummy_input(svn_b, digest_b),
                &default_policy_id,
                ear_rules,
                dummy_reference(svn_a, digest_a),
            )
            .await
            .unwrap();

        assert_eq!(
            hw_exp,
            output
                .rules_result
                .get("hardware")
                .unwrap()
                .as_i64()
                .unwrap() as i8
        );
        assert_eq!(
            ex_exp,
            output
                .rules_result
                .get("executables")
                .unwrap()
                .as_i64()
                .unwrap() as i8
        );
    }

    #[tokio::test]
    async fn test_policy_management() {
        let opa = OPA::new(PathBuf::from("tests/tmp"), "default", "default.rego").unwrap();
        let policy = "package policy
default allow = true"
            .to_string();

        let get_policy_output = "cGFja2FnZSBwb2xpY3kKZGVmYXVsdCBhbGxvdyA9IHRydWU".to_string();

        assert!(opa
            .set_policy(
                "test".to_string(),
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(policy)
            )
            .await
            .is_ok());
        let policy_list = opa.list_policies().await.unwrap();
        assert_eq!(policy_list.len(), 2);
        let test_policy = opa.get_policy("test".to_string()).await.unwrap();
        assert_eq!(test_policy, get_policy_output);
        assert!(opa.list_policies().await.is_ok());
    }

    #[test]
    fn detects_legacy_reference_without_comment_or_string_false_positives() {
        assert!(OPA::policy_uses_legacy_reference(
            "package policy\nallow { input.svn in data.reference.svn }"
        )
        .unwrap());
        assert!(OPA::policy_uses_legacy_reference(
            "package policy\nallow { input.svn in data[\"reference\"].svn }"
        )
        .unwrap());
        assert!(!OPA::policy_uses_legacy_reference(
            r#"package policy
               # data.reference.comment_only
               message := "data.reference.string_only"
               allow := true"#
        )
        .unwrap());
    }

    #[cfg(feature = "policy-rvps")]
    struct CountingRvps {
        keyed_queries: AtomicUsize,
        bulk_queries: AtomicUsize,
    }

    #[cfg(feature = "policy-rvps")]
    #[async_trait::async_trait]
    impl RvpsApi for CountingRvps {
        async fn verify_and_extract(&self, _message: &str) -> std::result::Result<(), RvpsError> {
            unreachable!()
        }

        async fn set_reference_value_list(
            &self,
            _payload: &str,
        ) -> std::result::Result<(), RvpsError> {
            unreachable!()
        }

        async fn query_reference_value(
            &self,
            reference_value_id: &str,
        ) -> std::result::Result<Option<serde_json::Value>, RvpsError> {
            self.keyed_queries.fetch_add(1, Ordering::SeqCst);
            Ok(match reference_value_id {
                "svn" => Some(json!([7])),
                "minimum" => Some(json!(3)),
                _ => None,
            })
        }

        async fn get_reference_values(
            &self,
        ) -> std::result::Result<HashMap<String, serde_json::Value>, RvpsError> {
            self.bulk_queries.fetch_add(1, Ordering::SeqCst);
            Ok(HashMap::new())
        }

        async fn delete_reference_value(
            &self,
            _name: &str,
        ) -> std::result::Result<bool, RvpsError> {
            unreachable!()
        }
    }

    #[cfg(feature = "policy-rvps")]
    #[tokio::test]
    async fn query_extension_is_keyed_cached_and_returns_null_for_missing() {
        let policy = r#"package policy
default allow = false
allow {
    query_reference_value("svn") == [7]
    query_reference_value("missing") == null
}
minimum = query_reference_value("minimum")
svn_again = query_reference_value("svn")
"#;
        let tmp = tempfile::tempdir().unwrap();
        let opa = OPA::new(tmp.path().to_path_buf(), policy, "query.rego").unwrap();
        let rvps = Arc::new(CountingRvps {
            keyed_queries: AtomicUsize::new(0),
            bulk_queries: AtomicUsize::new(0),
        });
        let resolver = Arc::new(ReferenceValueResolver::new(
            Arc::clone(&rvps) as Arc<dyn RvpsApi>
        ));

        let result = opa
            .evaluate(
                "{}",
                "query",
                vec![
                    "allow".to_string(),
                    "minimum".to_string(),
                    "svn_again".to_string(),
                ],
                resolver,
            )
            .await
            .unwrap();

        assert!(result.rules_result.get("allow").unwrap().as_bool().unwrap());
        assert_eq!(
            result
                .rules_result
                .get("minimum")
                .unwrap()
                .as_i64()
                .unwrap(),
            3
        );
        assert_eq!(result.rules_result.get("svn_again").unwrap(), &json!([7]));
        assert_eq!(rvps.keyed_queries.load(Ordering::SeqCst), 3);
        assert_eq!(rvps.bulk_queries.load(Ordering::SeqCst), 0);
    }

    #[cfg(feature = "policy-rvps")]
    struct UnavailableRvps {
        timeout: bool,
    }

    #[cfg(feature = "policy-rvps")]
    #[async_trait::async_trait]
    impl RvpsApi for UnavailableRvps {
        async fn verify_and_extract(&self, _message: &str) -> std::result::Result<(), RvpsError> {
            unreachable!()
        }

        async fn set_reference_value_list(
            &self,
            _payload: &str,
        ) -> std::result::Result<(), RvpsError> {
            unreachable!()
        }

        async fn query_reference_value(
            &self,
            _reference_value_id: &str,
        ) -> std::result::Result<Option<serde_json::Value>, RvpsError> {
            if self.timeout {
                std::future::pending::<()>().await;
                unreachable!()
            }
            Err(RvpsError::Anyhow(anyhow!("RVPS backend unavailable")))
        }

        async fn get_reference_values(
            &self,
        ) -> std::result::Result<HashMap<String, serde_json::Value>, RvpsError> {
            unreachable!()
        }

        async fn delete_reference_value(
            &self,
            _name: &str,
        ) -> std::result::Result<bool, RvpsError> {
            unreachable!()
        }
    }

    #[cfg(feature = "policy-rvps")]
    async fn evaluate_unavailable_rvps(timeout: bool) -> String {
        let policy = r#"package policy
allow = query_reference_value("svn") == [7]
"#;
        let tmp = tempfile::tempdir().unwrap();
        let opa = OPA::new(tmp.path().to_path_buf(), policy, "query.rego").unwrap();
        let resolver = Arc::new(ReferenceValueResolver::new(Arc::new(UnavailableRvps {
            timeout,
        })));

        opa.evaluate("{}", "query", vec!["allow".to_string()], resolver)
            .await
            .unwrap_err()
            .to_string()
    }

    #[cfg(feature = "policy-rvps")]
    #[tokio::test]
    async fn query_extension_preserves_backend_errors() {
        let error = evaluate_unavailable_rvps(false).await;
        assert!(error.contains("RVPS backend unavailable"), "{error}");
    }

    #[cfg(feature = "policy-rvps")]
    #[tokio::test]
    async fn query_extension_times_out() {
        let error = evaluate_unavailable_rvps(true).await;
        assert!(error.contains("timed out"), "{error}");
    }
}
