// Copyright (c) 2026 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, sync::Arc};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use key_value_storage::{DeleteOptions, DeleteOutcome, PutCondition, PutOptions, Storage};
use sha2::{Digest, Sha384};

use crate::{
    policy_engine::{EvaluationResult, PolicyDigest, PolicyEngine, PolicyError},
    rvps::ReferenceValueResolver,
};

pub const AS_POLICY_NAMESPACE: &str = "attestation_service_policy";

pub struct OPAShared {
    storage: Storage,
    #[cfg(feature = "policy-artifact-server")]
    artifact_server_client: Arc<artifact_resolve_sdk::Client>,
    #[cfg(feature = "regorus-regovm")]
    program_cache: Arc<super::ProgramCache>,
}

impl OPAShared {
    /// Initialize shared policy storage from a mounted policy file when one is
    /// present. The database write remains create-if-absent, so a ConfigMap or
    /// migrated file can seed the first replica without overwriting a policy
    /// that is already authoritative in shared storage.
    #[cfg(feature = "fs")]
    pub async fn new_with_policy_file(
        storage: Storage,
        policy_dir: &std::path::Path,
        default_policy: &str,
        default_policy_id: &str,
        artifact_server_address: &str,
    ) -> Result<Self, PolicyError> {
        let policy_path = policy_dir.join("opa").join(default_policy_id);
        let initial_policy = match tokio::fs::read_to_string(&policy_path).await {
            Ok(policy) => {
                log::info!(
                    "Seeding shared AS policy from {} when the namespace is empty",
                    policy_path.display()
                );
                policy
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                default_policy.to_string()
            }
            Err(error) => return Err(PolicyError::ReadPolicyFileFailed(error)),
        };
        Self::new(
            storage,
            &initial_policy,
            default_policy_id,
            artifact_server_address,
        )
        .await
    }

    pub async fn new(
        storage: Storage,
        default_policy: &str,
        default_policy_id: &str,
        #[cfg_attr(not(feature = "policy-artifact-server"), allow(unused_variables))]
        artifact_server_address: &str,
    ) -> Result<Self, PolicyError> {
        let default_policy_id = default_policy_id.trim_end_matches(".rego");
        let default_policy_key = Self::key(default_policy_id);
        storage
            .put(
                &default_policy_key,
                default_policy.as_bytes(),
                PutOptions {
                    condition: PutCondition::IfAbsent,
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| PolicyError::SharedStorage(e.into()))?;

        Ok(Self {
            storage,
            #[cfg(feature = "policy-artifact-server")]
            artifact_server_client: Arc::new(
                artifact_resolve_sdk::Client::new(artifact_server_address)
                    .map_err(PolicyError::ArtifactServerClientCreationFailed)?,
            ),
            #[cfg(feature = "regorus-regovm")]
            program_cache: Arc::new(super::ProgramCache::default()),
        })
    }

    async fn policy(&self, policy_id: &str) -> Result<Vec<u8>, PolicyError> {
        let key = Self::key(policy_id);
        self.storage
            .get(&key)
            .await
            .map_err(|e| PolicyError::SharedStorage(e.into()))?
            .map(|entry| entry.value)
            .ok_or_else(|| {
                PolicyError::ReadPolicyFileFailed(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("policy {policy_id} not found"),
                ))
            })
    }

    fn validate(policy_id: &str, policy: &[u8]) -> Result<(), PolicyError> {
        if !super::is_valid_policy_id(policy_id) {
            return Err(PolicyError::InvalidPolicyId);
        }
        let source =
            std::str::from_utf8(policy).map_err(|e| PolicyError::InvalidPolicy(e.into()))?;
        let mut engine = regorus::Engine::new();
        engine.set_rego_v0(true);
        engine
            .add_policy(policy_id.to_string(), source.to_string())
            .map_err(PolicyError::InvalidPolicy)?;
        Ok(())
    }

    fn key(policy_id: &str) -> String {
        URL_SAFE_NO_PAD.encode(policy_id.as_bytes())
    }

    fn policy_id(key: &str) -> Result<String, PolicyError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(key)
            .map_err(|e| PolicyError::SharedStorage(e.into()))?;
        String::from_utf8(bytes).map_err(|e| PolicyError::SharedStorage(e.into()))
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
impl PolicyEngine for OPAShared {
    async fn evaluate(
        &self,
        input: &str,
        policy_id: &str,
        evaluation_rules: Vec<String>,
        reference_value_resolver: Arc<ReferenceValueResolver>,
    ) -> Result<EvaluationResult, PolicyError> {
        let policy = String::from_utf8(self.policy(policy_id).await?)
            .map_err(|e| PolicyError::InvalidPolicy(e.into()))?;
        super::common_evaluate(
            policy,
            input.to_string(),
            policy_id.to_string(),
            evaluation_rules,
            reference_value_resolver,
            #[cfg(feature = "policy-artifact-server")]
            self.artifact_server_client.clone(),
            None,
            #[cfg(feature = "regorus-regovm")]
            &self.program_cache,
        )
        .await
    }

    async fn set_policy(&self, policy_id: String, policy: String) -> Result<(), PolicyError> {
        let bytes = URL_SAFE_NO_PAD.decode(policy)?;
        Self::validate(&policy_id, &bytes)?;
        #[cfg(feature = "regorus-regovm")]
        self.program_cache.write().await.remove(&policy_id);
        let key = Self::key(&policy_id);
        self.storage
            .put(&key, &bytes, PutOptions::default())
            .await
            .map_err(|e| PolicyError::SharedStorage(e.into()))?;
        Ok(())
    }

    async fn list_policies(&self) -> Result<HashMap<String, PolicyDigest>, PolicyError> {
        let mut policies = HashMap::new();
        for key in self
            .storage
            .list()
            .await
            .map_err(|e| PolicyError::SharedStorage(e.into()))?
        {
            let policy_id = Self::policy_id(&key)?;
            let bytes = self.policy(&policy_id).await?;
            let mut hasher = Sha384::new();
            hasher.update(bytes);
            policies.insert(policy_id, URL_SAFE_NO_PAD.encode(hasher.finalize()));
        }
        Ok(policies)
    }

    async fn get_policy(&self, policy_id: String) -> Result<String, PolicyError> {
        Ok(URL_SAFE_NO_PAD.encode(self.policy(&policy_id).await?))
    }

    async fn delete_policy(&self, policy_id: String) -> Result<(), PolicyError> {
        if !super::is_valid_policy_id(&policy_id) {
            return Err(PolicyError::InvalidPolicyId);
        }
        if policy_id == "default" {
            return Err(PolicyError::CannotDeleteDefaultPolicy);
        }
        #[cfg(feature = "regorus-regovm")]
        self.program_cache.write().await.remove(&policy_id);
        let key = Self::key(&policy_id);
        match self
            .storage
            .delete(&key, DeleteOptions::default())
            .await
            .map_err(|e| PolicyError::SharedStorage(e.into()))?
        {
            DeleteOutcome::Deleted => Ok(()),
            DeleteOutcome::NotFound => Err(PolicyError::ReadPolicyFileFailed(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("policy {policy_id} not found"),
            ))),
            DeleteOutcome::Conflict { .. } => Err(PolicyError::SharedStorage(anyhow::anyhow!(
                "policy changed while being deleted"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use key_value_storage::memory::MemoryStorage;
    #[cfg(feature = "shared-storage-mysql")]
    use key_value_storage::mysql::{MysqlConfig, MysqlStorage};

    use super::*;
    use crate::config::DEFAULT_ARTIFACT_SERVER_ADDRESS;

    const DEFAULT_POLICY: &str = "package policy\ndefault allow = true";

    #[tokio::test]
    async fn policy_updates_are_visible_across_instances() {
        let storage: Storage = Arc::new(MemoryStorage::default());
        let first = OPAShared::new(
            storage.clone(),
            DEFAULT_POLICY,
            "default.rego",
            DEFAULT_ARTIFACT_SERVER_ADDRESS,
        )
        .await
        .unwrap();
        let second = OPAShared::new(
            storage,
            "package policy\ndefault allow = false",
            "default.rego",
            DEFAULT_ARTIFACT_SERVER_ADDRESS,
        )
        .await
        .unwrap();

        assert_eq!(
            second.get_policy("default".into()).await.unwrap(),
            URL_SAFE_NO_PAD.encode(DEFAULT_POLICY)
        );
        first
            .set_policy(
                "custom".into(),
                URL_SAFE_NO_PAD.encode("package policy\ndefault allow = false"),
            )
            .await
            .unwrap();
        assert_eq!(
            second.get_policy("custom".into()).await.unwrap(),
            URL_SAFE_NO_PAD.encode("package policy\ndefault allow = false")
        );

        first
            .set_policy(
                "策略一".into(),
                URL_SAFE_NO_PAD.encode("package policy\ndefault allow = true"),
            )
            .await
            .unwrap();
        assert!(second.list_policies().await.unwrap().contains_key("策略一"));
    }

    #[cfg(feature = "fs")]
    #[tokio::test]
    async fn mounted_default_policy_seeds_an_empty_shared_namespace() {
        let storage: Storage = Arc::new(MemoryStorage::default());
        let policy_root = tempfile::tempdir().unwrap();
        let policy_dir = policy_root.path().join("opa");
        std::fs::create_dir_all(&policy_dir).unwrap();
        let mounted_policy = "package policy\ndefault allow = false";
        std::fs::write(policy_dir.join("default.rego"), mounted_policy).unwrap();

        let engine = OPAShared::new_with_policy_file(
            storage,
            policy_root.path(),
            DEFAULT_POLICY,
            "default.rego",
            DEFAULT_ARTIFACT_SERVER_ADDRESS,
        )
        .await
        .unwrap();

        assert_eq!(
            engine.get_policy("default".into()).await.unwrap(),
            URL_SAFE_NO_PAD.encode(mounted_policy)
        );
    }

    #[cfg(feature = "shared-storage-mysql")]
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
        let first_storage: Storage = Arc::new(
            MysqlStorage::connect(config.clone(), AS_POLICY_NAMESPACE)
                .await
                .unwrap(),
        );
        let second_storage: Storage = Arc::new(
            MysqlStorage::connect(config, AS_POLICY_NAMESPACE)
                .await
                .unwrap(),
        );
        let first = OPAShared::new(
            first_storage,
            DEFAULT_POLICY,
            "default.rego",
            DEFAULT_ARTIFACT_SERVER_ADDRESS,
        )
        .await
        .unwrap();
        let second = OPAShared::new(
            second_storage,
            DEFAULT_POLICY,
            "default.rego",
            DEFAULT_ARTIFACT_SERVER_ADDRESS,
        )
        .await
        .unwrap();
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let policy_id = format!("replica-{suffix}");
        let policy = "package policy\ndefault allow = false";

        first
            .set_policy(policy_id.clone(), URL_SAFE_NO_PAD.encode(policy))
            .await
            .unwrap();
        assert_eq!(
            second.get_policy(policy_id.clone()).await.unwrap(),
            URL_SAFE_NO_PAD.encode(policy)
        );
        second.delete_policy(policy_id).await.unwrap();
    }
}
