// Copyright (c) 2026 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Context, Result};
use key_value_storage::{DeleteOptions, DeleteOutcome, PutOptions, Storage};
use sha2::{Digest, Sha256};

use super::{ResourceDesc, StorageBackend};

pub const RESOURCE_STORAGE_NAMESPACE: &str = "repository";
const RESOURCE_ENVELOPE_MAGIC: &[u8; 5] = b"TKVR\x01";

pub struct SharedStore {
    storage: Storage,
}

impl SharedStore {
    pub fn new(storage: Storage) -> Self {
        Self { storage }
    }

    fn key(resource_desc: &ResourceDesc) -> String {
        format!("{:x}", Sha256::digest(resource_desc.to_string().as_bytes()))
    }

    fn encode(resource_desc: &ResourceDesc, data: &[u8]) -> Result<Vec<u8>> {
        let descriptor = resource_desc.to_string();
        let descriptor_len =
            u32::try_from(descriptor.len()).context("resource descriptor is too large to store")?;
        let mut value =
            Vec::with_capacity(RESOURCE_ENVELOPE_MAGIC.len() + 4 + descriptor.len() + data.len());
        value.extend_from_slice(RESOURCE_ENVELOPE_MAGIC);
        value.extend_from_slice(&descriptor_len.to_be_bytes());
        value.extend_from_slice(descriptor.as_bytes());
        value.extend_from_slice(data);
        Ok(value)
    }

    fn decode(value: &[u8]) -> Result<(ResourceDesc, Vec<u8>)> {
        let remainder = value
            .strip_prefix(RESOURCE_ENVELOPE_MAGIC)
            .context("stored resource envelope has an unsupported format")?;
        let length_bytes: [u8; 4] = remainder
            .get(..4)
            .context("stored resource envelope is truncated")?
            .try_into()
            .expect("slice length was checked");
        let descriptor_len = u32::from_be_bytes(length_bytes) as usize;
        let descriptor_end = 4_usize
            .checked_add(descriptor_len)
            .context("stored resource descriptor length overflow")?;
        let descriptor = std::str::from_utf8(
            remainder
                .get(4..descriptor_end)
                .context("stored resource descriptor is truncated")?,
        )
        .context("stored resource descriptor is not UTF-8")?;
        let descriptor =
            ResourceDesc::try_from(descriptor).context("stored resource descriptor is invalid")?;
        let data = remainder
            .get(descriptor_end..)
            .expect("descriptor end was bounded by the value length")
            .to_vec();
        Ok((descriptor, data))
    }
}

#[async_trait::async_trait]
impl StorageBackend for SharedStore {
    async fn read_secret_resource(&self, resource_desc: ResourceDesc) -> Result<Vec<u8>> {
        let key = Self::key(&resource_desc);
        let entry = self
            .storage
            .get(&key)
            .await
            .context("read resource from shared storage")?
            .ok_or_else(|| anyhow!("resource not found: {resource_desc}"))?;
        let (stored_desc, data) = Self::decode(&entry.value)?;
        if stored_desc != resource_desc {
            return Err(anyhow!(
                "stored resource descriptor does not match requested resource"
            ));
        }
        Ok(data)
    }

    async fn write_secret_resource(&self, resource_desc: ResourceDesc, data: &[u8]) -> Result<()> {
        let key = Self::key(&resource_desc);
        let value = Self::encode(&resource_desc, data)?;
        self.storage
            .put(&key, &value, PutOptions::default())
            .await
            .context("write resource to shared storage")?;
        Ok(())
    }

    async fn delete_secret_resource(&self, resource_desc: ResourceDesc) -> Result<()> {
        let key = Self::key(&resource_desc);
        match self
            .storage
            .delete(&key, DeleteOptions::default())
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
        let mut resources = Vec::new();
        for key in self
            .storage
            .list()
            .await
            .context("list resources from shared storage")?
        {
            let Some(entry) = self
                .storage
                .get(&key)
                .await
                .context("read listed resource from shared storage")?
            else {
                continue;
            };
            resources.push(Self::decode(&entry.value)?.0);
        }
        resources.sort_by_key(ToString::to_string);
        Ok(resources)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use key_value_storage::{
        memory::MemoryStorage,
        mysql::{MysqlConfig, MysqlStorage},
    };

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

    #[tokio::test]
    async fn long_valid_resource_name_uses_fixed_length_storage_key() {
        let storage: Storage = Arc::new(MemoryStorage::default());
        let backend = SharedStore::new(storage.clone());
        let resource = ResourceDesc {
            repository_name: "repository".into(),
            resource_type: "secret".into(),
            resource_tag: "a".repeat(600),
        };

        backend
            .write_secret_resource(resource.clone(), b"long-name-value")
            .await
            .unwrap();

        let keys = storage.list().await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].len(), 64);
        assert_eq!(backend.list_secret_resources().await.unwrap(), [resource]);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn shared_storage_mysql_resource_visibility() {
        let Ok(url) = std::env::var("MYSQL_TEST_URL") else {
            return;
        };
        let config = MysqlConfig {
            url,
            url_env: None,
            ..Default::default()
        };
        let first_storage: Storage = Arc::new(
            MysqlStorage::connect(config.clone(), "kbs_resource_adapter_test")
                .await
                .unwrap(),
        );
        for key in first_storage.list().await.unwrap() {
            first_storage
                .delete(&key, DeleteOptions::default())
                .await
                .unwrap();
        }
        let second_storage: Storage = Arc::new(
            MysqlStorage::connect(config, "kbs_resource_adapter_test")
                .await
                .unwrap(),
        );
        let first = SharedStore::new(first_storage);
        let second = SharedStore::new(second_storage);

        first
            .write_secret_resource(resource(), b"mysql-value")
            .await
            .unwrap();
        assert_eq!(
            second.read_secret_resource(resource()).await.unwrap(),
            b"mysql-value"
        );
        assert_eq!(second.list_secret_resources().await.unwrap(), [resource()]);
    }
}
