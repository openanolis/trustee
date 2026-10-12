// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Store is responsible for storing verified Reference Values

use anyhow::Result;
use async_trait::async_trait;
use key_value_storage::StorageProvider;
use serde::Deserialize;
use std::sync::Arc;
use strum::Display;

#[cfg(feature = "fs")]
use self::local_fs::LocalFs;
#[cfg(feature = "fs")]
use self::local_json::LocalJson;

use super::ReferenceValue;

pub mod in_memory;
#[cfg(feature = "fs")]
pub mod local_fs;
#[cfg(feature = "fs")]
pub mod local_json;
pub mod shared_store;

#[derive(Clone, Debug, Deserialize, Display, PartialEq)]
#[serde(tag = "type")]
pub enum ReferenceValueStorageConfig {
    InMemory(in_memory::Config),
    SharedStore(shared_store::Config),
    #[cfg(feature = "fs")]
    LocalFs(local_fs::Config),
    #[cfg(feature = "fs")]
    LocalJson(local_json::Config),
}

impl Default for ReferenceValueStorageConfig {
    fn default() -> Self {
        #[cfg(feature = "fs")]
        {
            ReferenceValueStorageConfig::LocalFs(local_fs::Config::default())
        }
        #[cfg(not(feature = "fs"))]
        {
            ReferenceValueStorageConfig::InMemory(in_memory::Config::default())
        }
    }
}

impl ReferenceValueStorageConfig {
    pub fn to_storage(&self) -> Result<Box<dyn ReferenceValueStorage + Send + Sync>> {
        match self {
            ReferenceValueStorageConfig::InMemory(cfg) => {
                Ok(Box::new(in_memory::InMemory::new(cfg.clone())?)
                    as Box<dyn ReferenceValueStorage + Send + Sync>)
            }
            ReferenceValueStorageConfig::SharedStore(_) => Err(anyhow::anyhow!(
                "SharedStore RVPS backend requires async initialization with storage_backend"
            )),
            #[cfg(feature = "fs")]
            ReferenceValueStorageConfig::LocalFs(cfg) => Ok(Box::new(LocalFs::new(cfg.clone())?)
                as Box<dyn ReferenceValueStorage + Send + Sync>),
            #[cfg(feature = "fs")]
            ReferenceValueStorageConfig::LocalJson(cfg) => {
                Ok(Box::new(LocalJson::new(cfg.clone())?)
                    as Box<dyn ReferenceValueStorage + Send + Sync>)
            }
        }
    }

    pub async fn to_storage_with_provider(
        &self,
        storage_provider: Option<Arc<dyn StorageProvider>>,
    ) -> Result<Box<dyn ReferenceValueStorage + Send + Sync>> {
        match self {
            ReferenceValueStorageConfig::SharedStore(cfg) => {
                let provider = storage_provider.ok_or_else(|| {
                    anyhow::anyhow!(
                        "SharedStore RVPS backend requires a storage_backend configuration"
                    )
                })?;
                Ok(
                    Box::new(shared_store::SharedStore::new(cfg.clone(), provider).await?)
                        as Box<dyn ReferenceValueStorage + Send + Sync>,
                )
            }
            _ => self.to_storage(),
        }
    }
}

#[derive(Debug)]
pub struct VersionedReferenceValue {
    pub value: ReferenceValue,
    /// `None` denotes a legacy backend without cross-process revisions.
    pub revision: Option<u64>,
}

#[derive(Debug)]
pub enum ConditionalSetResult {
    Stored(Option<ReferenceValue>),
    Conflict,
}

#[derive(Debug)]
pub enum ConditionalDeleteResult {
    Deleted(Option<ReferenceValue>),
    NotFound,
    Conflict,
}

/// Interface for `ReferenceValueStorage`.
/// Reference value storage facilities should implement this trait.
#[async_trait]
pub trait ReferenceValueStorage {
    /// Store a reference value. If the given `name` exists,
    /// return the previous `Some<ReferenceValue>`, otherwise return `None`
    async fn set(&self, name: String, rv: ReferenceValue) -> Result<Option<ReferenceValue>>;

    // Retrieve reference value by name
    async fn get(&self, name: &str) -> Result<Option<ReferenceValue>>;

    // Retrieve reference values
    async fn get_values(&self) -> Result<Vec<ReferenceValue>>;

    // Delete reference value by name. Return the deleted value if exists
    async fn delete(&self, name: &str) -> Result<Option<ReferenceValue>>;

    async fn get_versioned(&self, name: &str) -> Result<Option<VersionedReferenceValue>> {
        Ok(self.get(name).await?.map(|value| VersionedReferenceValue {
            value,
            revision: None,
        }))
    }

    async fn set_if_unchanged(
        &self,
        name: String,
        rv: ReferenceValue,
        _expected_revision: Option<u64>,
    ) -> Result<ConditionalSetResult> {
        Ok(ConditionalSetResult::Stored(self.set(name, rv).await?))
    }

    async fn delete_if_unchanged(
        &self,
        name: &str,
        _expected_revision: Option<u64>,
    ) -> Result<ConditionalDeleteResult> {
        Ok(match self.delete(name).await? {
            Some(value) => ConditionalDeleteResult::Deleted(Some(value)),
            None => ConditionalDeleteResult::NotFound,
        })
    }
}
