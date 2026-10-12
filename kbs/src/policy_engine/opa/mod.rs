// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::policy_engine::{KbsPolicyEngineError, PolicyEngineInterface};
use async_trait::async_trait;
use base64::Engine;
use key_value_storage::{PutCondition, PutOptions, Storage};
use std::fs;
use std::path::PathBuf;

const SHARED_POLICY_KEY: &str = "resource-policy";

fn validate_policy(policy_bytes: &[u8]) -> Result<(), KbsPolicyEngineError> {
    let policy_content = String::from_utf8(policy_bytes.to_vec())
        .map_err(|e| KbsPolicyEngineError::InvalidPolicy(e.into()))?;
    let mut engine = regorus::Engine::new();
    engine.set_rego_v0(true);
    engine
        .add_policy(String::from("default"), policy_content)
        .map_err(KbsPolicyEngineError::InvalidPolicy)?;
    Ok(())
}

fn evaluate_policy(
    policy_content: String,
    resource_path: &str,
    input_claims: &str,
) -> Result<bool, KbsPolicyEngineError> {
    let mut engine = regorus::Engine::new();
    engine.set_rego_v0(true);
    engine
        .add_policy(String::from("default"), policy_content)
        .map_err(|_| KbsPolicyEngineError::PolicyLoadError)?;

    let resource_path_object =
        regorus::Value::from_json_str(&format!("{{\"resource-path\":\"{resource_path}\"}}"))
            .map_err(|_| KbsPolicyEngineError::ResourcePathError)?;
    engine
        .add_data(resource_path_object)
        .map_err(|_| KbsPolicyEngineError::DataLoadError)?;
    engine
        .set_input_json(input_claims)
        .map_err(|_| KbsPolicyEngineError::InputError)?;
    engine
        .eval_bool_query("data.policy.allow".to_string(), false)
        .map_err(Into::into)
}

#[derive(Debug, Clone)]
pub struct Opa {
    policy_path: PathBuf,
}

impl Opa {
    pub fn new(policy_path: PathBuf) -> Result<Self, KbsPolicyEngineError> {
        std::fs::create_dir_all(policy_path.parent().unwrap())?;

        if !policy_path.as_path().exists() {
            let policy = std::include_str!("default_policy.rego").to_string();
            fs::write(&policy_path, policy)?;
        }

        Ok(Self { policy_path })
    }
}

#[async_trait]
impl PolicyEngineInterface for Opa {
    async fn evaluate(
        &self,
        resource_path: &str,
        input_claims: &str,
    ) -> Result<bool, KbsPolicyEngineError> {
        let policy_content = tokio::fs::read_to_string(&self.policy_path).await?;
        evaluate_policy(policy_content, resource_path, input_claims)
    }

    async fn set_policy(&mut self, policy: &str) -> Result<(), KbsPolicyEngineError> {
        let policy_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(policy)?;

        validate_policy(&policy_bytes)?;

        tokio::fs::write(&self.policy_path, policy_bytes).await?;

        Ok(())
    }

    async fn get_policy(&self) -> Result<String, KbsPolicyEngineError> {
        let policy = tokio::fs::read(&self.policy_path).await?;
        let policy = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(policy);
        Ok(policy)
    }
}

/// Resource policy backed by the unified store. Every evaluation reads the
/// authoritative value, so a policy written through any replica is visible to
/// the others without a restart or cache invalidation protocol.
pub struct OpaShared {
    storage: Storage,
}

impl OpaShared {
    pub async fn new(storage: Storage) -> Result<Self, KbsPolicyEngineError> {
        let default_policy = std::include_bytes!("default_policy.rego");
        storage
            .put(
                SHARED_POLICY_KEY,
                default_policy,
                PutOptions {
                    condition: PutCondition::IfAbsent,
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| KbsPolicyEngineError::EvaluationError(e.into()))?;
        Ok(Self { storage })
    }

    async fn policy_bytes(&self) -> Result<Vec<u8>, KbsPolicyEngineError> {
        self.storage
            .get(SHARED_POLICY_KEY)
            .await
            .map_err(|e| KbsPolicyEngineError::EvaluationError(e.into()))?
            .map(|entry| entry.value)
            .ok_or(KbsPolicyEngineError::PolicyLoadError)
    }
}

#[async_trait]
impl PolicyEngineInterface for OpaShared {
    async fn evaluate(
        &self,
        resource_path: &str,
        input_claims: &str,
    ) -> Result<bool, KbsPolicyEngineError> {
        let policy = String::from_utf8(self.policy_bytes().await?)
            .map_err(|_| KbsPolicyEngineError::PolicyLoadError)?;
        evaluate_policy(policy, resource_path, input_claims)
    }

    async fn set_policy(&mut self, policy: &str) -> Result<(), KbsPolicyEngineError> {
        let policy_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(policy)?;
        validate_policy(&policy_bytes)?;
        self.storage
            .put(SHARED_POLICY_KEY, &policy_bytes, PutOptions::default())
            .await
            .map_err(|e| KbsPolicyEngineError::EvaluationError(e.into()))?;
        Ok(())
    }

    async fn get_policy(&self) -> Result<String, KbsPolicyEngineError> {
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.policy_bytes().await?))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use key_value_storage::memory::MemoryStorage;
    use key_value_storage::mysql::{MysqlConfig, MysqlStorage};
    use rstest::rstest;
    use serde_json::json;
    use tempfile::{NamedTempFile, TempDir};

    fn compare_errors(a: KbsPolicyEngineError, b: KbsPolicyEngineError) -> bool {
        matches!(
            (a, b),
            (
                KbsPolicyEngineError::EvaluationError(_),
                KbsPolicyEngineError::EvaluationError(_)
            ) | (
                KbsPolicyEngineError::DataLoadError,
                KbsPolicyEngineError::DataLoadError
            ) | (
                KbsPolicyEngineError::ResourcePathError,
                KbsPolicyEngineError::ResourcePathError
            ) | (
                KbsPolicyEngineError::IOError(_),
                KbsPolicyEngineError::IOError(_)
            ) | (
                KbsPolicyEngineError::DecodeError(_),
                KbsPolicyEngineError::DecodeError(_)
            ) | (
                KbsPolicyEngineError::InputError,
                KbsPolicyEngineError::InputError
            ) | (
                KbsPolicyEngineError::PolicyLoadError,
                KbsPolicyEngineError::PolicyLoadError
            )
        )
    }

    fn dummy_input(product_id: &str, svn: u64, executables: u8, hardware: u8) -> String {
        json!({
            "submods": {
                "cpu0": {
                    "ear.trustworthiness-vector": {
                        "executables": executables,
                        "hardware": hardware,
                    },
                    "ear.veraison.annotated-evidence": {
                            "sample" : {
                                "productId": product_id,
                                "svn": svn
                            }
                        }
                    }
                }
            }
        )
        .to_string()
    }

    async fn set_policy_from_file(opa: &mut Opa, path: &str) -> Result<(), KbsPolicyEngineError> {
        let policy = std::fs::read(PathBuf::from(path.to_string())).unwrap();
        let policy = URL_SAFE_NO_PAD.encode(policy);

        opa.set_policy(&policy).await
    }

    #[tokio::test]
    async fn test_set_policy() {
        let tmp_dir = TempDir::new().unwrap();
        let tmp_file = tmp_dir.path().join("policy.rego");
        let mut opa = Opa::new(tmp_file).unwrap();

        set_policy_from_file(&mut opa, "test/data/policy_1.rego")
            .await
            .unwrap();

        // decode error
        let malformed_policy = "123";
        let res = opa.set_policy(malformed_policy).await;
        assert!(matches!(
            res.err().unwrap(),
            KbsPolicyEngineError::DecodeError(base64::DecodeError::InvalidLastSymbol(_, _))
        ));

        // IOError
        drop(tmp_dir);
        let res = set_policy_from_file(&mut opa, "test/data/policy_1.rego").await;
        assert!(matches!(
            res.err().unwrap(),
            KbsPolicyEngineError::IOError(_)
        ));

        // Illegal policy
        let res = set_policy_from_file(&mut opa, "test/data/policy_invalid_1.rego").await;
        assert!(matches!(
            res.err().unwrap(),
            KbsPolicyEngineError::InvalidPolicy(_)
        ));
    }

    #[tokio::test]
    async fn shared_policy_is_visible_and_not_clobbered_by_another_instance() {
        let storage: Storage = Arc::new(MemoryStorage::default());
        let mut first = OpaShared::new(storage.clone()).await.unwrap();
        let policy = std::fs::read("test/data/policy_1.rego").unwrap();
        let encoded = URL_SAFE_NO_PAD.encode(&policy);
        first.set_policy(&encoded).await.unwrap();

        let second = OpaShared::new(storage).await.unwrap();
        assert_eq!(second.get_policy().await.unwrap(), encoded);
        assert!(second
            .evaluate("my_repo/Alice/key", &dummy_input("Alice", 1, 2, 3))
            .await
            .unwrap());
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn shared_storage_mysql_policy_visibility() {
        let Ok(url) = std::env::var("MYSQL_TEST_URL") else {
            return;
        };
        let config = MysqlConfig {
            url,
            url_env: None,
            ..Default::default()
        };
        let first: Storage = Arc::new(
            MysqlStorage::connect(config.clone(), "kbs_policy_adapter_test")
                .await
                .unwrap(),
        );
        let second: Storage = Arc::new(
            MysqlStorage::connect(config, "kbs_policy_adapter_test")
                .await
                .unwrap(),
        );
        let mut first = OpaShared::new(first).await.unwrap();
        let second = OpaShared::new(second).await.unwrap();
        let policy = std::fs::read("test/data/policy_1.rego").unwrap();
        let encoded = URL_SAFE_NO_PAD.encode(policy);
        first.set_policy(&encoded).await.unwrap();
        assert_eq!(second.get_policy().await.unwrap(), encoded);
    }

    #[rstest]
    #[case("test/data/policy_1.rego", "my_repo/Alice/key", "Alice", 1, Ok(true))]
    #[case("test/data/policy_4.rego", "my_repo/Alice/key", "Alice", 1, Ok(true))]
    #[case("test/data/policy_1.rego", "my_repo/Alice/key", "Bob", 1, Ok(false))]
    #[case("test/data/policy_3.rego", "my_repo/Alice/key", "Alice", 1, Ok(false))]
    #[case(
        "test/data/policy_1.rego",
        "\"",
        "",
        1,
        Err(KbsPolicyEngineError::ResourcePathError)
    )]
    #[case(
        "test/data/policy_invalid_2.rego",
        "my_repo/Alice/key",
        "Alice",
        1,
        Err(KbsPolicyEngineError::EvaluationError(anyhow::anyhow!("test")))
    )]
    #[case("test/data/policy_5.rego", "myrepo/secret/secret1", "n", 2, Ok(true))]
    #[case("test/data/policy_5.rego", "myrepo/secret/secret1", "n", 1, Ok(false))]
    #[case("test/data/policy_5.rego", "myrepo/secret/secret2", "n", 3, Ok(true))]
    #[case("test/data/policy_5.rego", "myrepo/secret/secret2", "n", 2, Ok(false))]
    #[case("test/data/policy_5.rego", "myrepo/secret/secret3", "n", 3, Ok(false))]
    #[case("test/data/policy_5.rego", "a/b/secret2", "n", 3, Ok(false))]
    #[case("test/data/policy_5.rego", "abc", "n", 3, Ok(false))]
    #[tokio::test]
    async fn test_evaluate(
        #[case] policy_path: &str,
        #[case] resource_path: &str,
        #[case] input_name: &str,
        #[case] input_svn: u64,
        #[case] expected: Result<bool, KbsPolicyEngineError>,
    ) {
        let tmp_file = NamedTempFile::new().unwrap();
        let mut opa = Opa::new(tmp_file.path().to_path_buf()).unwrap();

        set_policy_from_file(&mut opa, policy_path).await.unwrap();

        let res = opa
            .evaluate(resource_path, &dummy_input(input_name, input_svn, 2, 3))
            .await;

        if let Ok(actual) = res {
            assert_eq!(
                actual,
                expected.expect("Result is Ok, but test expects Err")
            );
        } else if let Err(actual) = res {
            assert!(compare_errors(
                actual,
                expected.expect_err("Result is Err, but test expects Ok"),
            ));
        }
    }
}
