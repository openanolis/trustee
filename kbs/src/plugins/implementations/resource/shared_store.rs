// Copyright (c) 2026 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Context, Result};
use key_value_storage::{DeleteOptions, DeleteOutcome, PutOptions, Storage};

use super::{ResourceDesc, StorageBackend};

pub const RESOURCE_STORAGE_NAMESPACE: &str = "repository";

pub struct SharedStore {
    storage: Storage,
}

impl SharedStore {
    pub fn new(storage: Storage) -> Self {
        Self { storage }
    }
}

#[async_trait::async_trait]
impl StorageBackend for SharedStore {
    async fn read_secret_resource(&self, resource_desc: ResourceDesc) -> Result<Vec<u8>> {
        let key = resource_desc.to_string();
        self.storage
            .get(&key)
            .await
            .context("read resource from shared storage")?
            .map(|entry| entry.value)
            .ok_or_else(|| anyhow!("resource not found: {resource_desc}"))
    }

    async fn write_secret_resource(&self, resource_desc: ResourceDesc, data: &[u8]) -> Result<()> {
        self.storage
            .put(&resource_desc.to_string(), data, PutOptions::default())
            .await
            .context("write resource to shared storage")?;
        Ok(())
    }

    async fn delete_secret_resource(&self, resource_desc: ResourceDesc) -> Result<()> {
        match self
            .storage
            .delete(&resource_desc.to_string(), DeleteOptions::default())
            .await
            .context("delete resource from shared storage")?
        {
            DeleteOutcome::Deleted => Ok(()),
            DeleteOutcome::NotFound => Err(anyhow!("resource not found: {resource_desc}")),
            DeleteOutcome::Conflict { .. } => {
                Err(anyhow!("resource changed while it was being deleted"))
            }
        }
    }

    async fn list_secret_resources(&self) -> Result<Vec<ResourceDesc>> {
        self.storage
            .list()
            .await
            .context("list resources from shared storage")?
            .iter()
            .map(|key| ResourceDesc::try_from(key.as_str()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use key_value_storage::memory::MemoryStorage;

    use super::*;

    fn resource() -> ResourceDesc {
        ResourceDesc {
            repository_name: "default".into(),
            resource_type: "secret".into(),
            resource_tag: "database-password".into(),
        }
    }

    #[tokio::test]
    async fn resource_roundtrip() {
        let backend = SharedStore::new(Arc::new(MemoryStorage::default()));
        backend
            .write_secret_resource(resource(), b"value")
            .await
            .unwrap();
        assert_eq!(
            backend.read_secret_resource(resource()).await.unwrap(),
            b"value"
        );
        assert_eq!(backend.list_secret_resources().await.unwrap(), [resource()]);
        backend.delete_secret_resource(resource()).await.unwrap();
        assert!(backend.read_secret_resource(resource()).await.is_err());
    }
}
