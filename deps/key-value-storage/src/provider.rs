// Copyright (c) 2026 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::{Result, Storage, StorageBackendConfig, StorageError, StorageType};

#[async_trait]
pub trait StorageProvider: Send + Sync {
    async fn get_or_register(&self, namespace: &str) -> Result<Storage>;

    async fn get_or_register_with_type(
        &self,
        namespace: &str,
        storage_type: StorageType,
    ) -> Result<Storage>;
}

pub struct KvStorageProvider {
    config: StorageBackendConfig,
    instances: RwLock<HashMap<(String, StorageType), Storage>>,
}

impl KvStorageProvider {
    pub fn new(config: StorageBackendConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            instances: RwLock::new(HashMap::new()),
        })
    }

    pub fn config(&self) -> &StorageBackendConfig {
        &self.config
    }

    fn validate_required_capabilities(&self, storage: &Storage) -> Result<()> {
        if !self.config.require_shared {
            return Ok(());
        }

        let capabilities = storage.capabilities();
        if !capabilities.shared {
            return Err(StorageError::UnsupportedCapability {
                capability: "shared storage",
            });
        }
        if !capabilities.compare_and_swap {
            return Err(StorageError::UnsupportedCapability {
                capability: "compare-and-swap",
            });
        }
        if !capabilities.ttl {
            return Err(StorageError::UnsupportedCapability { capability: "TTL" });
        }
        Ok(())
    }
}

#[async_trait]
impl StorageProvider for KvStorageProvider {
    async fn get_or_register(&self, namespace: &str) -> Result<Storage> {
        self.get_or_register_with_type(namespace, self.config.storage_type)
            .await
    }

    async fn get_or_register_with_type(
        &self,
        namespace: &str,
        storage_type: StorageType,
    ) -> Result<Storage> {
        let cache_key = (namespace.to_string(), storage_type);
        if let Some(storage) = self.instances.read().await.get(&cache_key) {
            return Ok(storage.clone());
        }

        let storage = self.config.backends.create(storage_type, namespace).await?;
        self.validate_required_capabilities(&storage)?;
        let mut instances = self.instances.write().await;
        Ok(instances.entry(cache_key).or_insert(storage).clone())
    }
}

#[cfg(test)]
mod tests {
    use crate::{PutOptions, PutOutcome};

    use super::*;

    #[tokio::test]
    async fn provider_reuses_a_namespaced_store() {
        let provider = KvStorageProvider::new(StorageBackendConfig::default());
        let first = provider.get_or_register("policy").await.unwrap();
        assert_eq!(
            first
                .put("default", b"allow", PutOptions::default())
                .await
                .unwrap(),
            PutOutcome::Created { revision: 1 }
        );

        let second = provider.get_or_register("policy").await.unwrap();
        assert_eq!(
            second.get("default").await.unwrap().unwrap().value,
            b"allow"
        );
    }

    #[tokio::test]
    async fn different_namespaces_are_isolated() {
        let provider = KvStorageProvider::new(StorageBackendConfig::default());
        provider
            .get_or_register("one")
            .await
            .unwrap()
            .put("key", b"value", PutOptions::default())
            .await
            .unwrap();
        assert!(provider
            .get_or_register("two")
            .await
            .unwrap()
            .get("key")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn require_shared_rejects_memory() {
        let provider = KvStorageProvider::new(StorageBackendConfig {
            require_shared: true,
            ..Default::default()
        });
        let error = match provider.get_or_register("policy").await {
            Err(error) => error,
            Ok(_) => panic!("memory storage must be rejected when shared storage is required"),
        };
        assert!(matches!(
            error,
            StorageError::UnsupportedCapability {
                capability: "shared storage"
            }
        ));
    }
}
