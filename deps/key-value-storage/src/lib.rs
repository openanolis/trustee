// Copyright (c) 2026 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Shared, namespaced storage for Trustee's authoritative mutable state.
//!
//! Backends expose their consistency capabilities explicitly. Components that
//! require cross-replica compare-and-swap or expiry must reject an unsuitable
//! backend during startup rather than silently falling back to process memory.

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use serde::Deserialize;

pub mod error;
pub mod memory;
#[cfg(feature = "mysql")]
pub mod mysql;
pub mod provider;

pub use error::{Result, StorageError};
pub use provider::{KvStorageProvider, StorageProvider};

pub type Storage = Arc<dyn KeyValueStorage>;

/// Maximum key length. Together with the 191-byte ASCII namespace this keeps
/// the MySQL primary key below the 767-byte limit of older InnoDB deployments.
pub const MAX_KEY_LENGTH: usize = 512;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StorageCapabilities {
    /// State can be observed by other Trustee processes.
    pub shared: bool,
    /// Conditional updates are atomic across all clients.
    pub compare_and_swap: bool,
    /// Expired entries are hidden and can be purged by the backend.
    pub ttl: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredValue {
    pub value: Vec<u8>,
    pub revision: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PutCondition {
    #[default]
    Upsert,
    IfAbsent,
    IfRevision(u64),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PutOptions {
    pub condition: PutCondition,
    pub ttl: Option<Duration>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PutOutcome {
    Created { revision: u64 },
    Updated { revision: u64 },
    Conflict { current_revision: Option<u64> },
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DeleteOptions {
    pub expected_revision: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeleteOutcome {
    Deleted,
    NotFound,
    Conflict { current_revision: u64 },
}

#[async_trait]
pub trait KeyValueStorage: Send + Sync {
    fn capabilities(&self) -> StorageCapabilities;

    async fn put(&self, key: &str, value: &[u8], options: PutOptions) -> Result<PutOutcome>;

    async fn get(&self, key: &str) -> Result<Option<StoredValue>>;

    async fn list(&self) -> Result<Vec<String>>;

    async fn delete(&self, key: &str, options: DeleteOptions) -> Result<DeleteOutcome>;

    async fn purge_expired(&self) -> Result<u64>;
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum StorageType {
    #[default]
    Memory,
    Mysql,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct BackendConfigs {
    #[cfg(feature = "mysql")]
    pub mysql: Option<mysql::MysqlConfig>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct StorageBackendConfig {
    pub storage_type: StorageType,
    /// Reject process-local backends when components initialize HA state.
    pub require_shared: bool,
    pub backends: BackendConfigs,
}

impl BackendConfigs {
    pub async fn create(&self, storage_type: StorageType, namespace: &str) -> Result<Storage> {
        validate_namespace(namespace)?;
        match storage_type {
            StorageType::Memory => Ok(Arc::new(memory::MemoryStorage::default())),
            #[cfg(feature = "mysql")]
            StorageType::Mysql => {
                let config =
                    self.mysql
                        .as_ref()
                        .ok_or_else(|| StorageError::InvalidConfiguration {
                            message: "backends.mysql is required for storage_type=mysql".into(),
                        })?;
                Ok(Arc::new(
                    mysql::MysqlStorage::connect(config.clone(), namespace).await?,
                ))
            }
            #[cfg(not(feature = "mysql"))]
            StorageType::Mysql => Err(StorageError::InvalidConfiguration {
                message: "MySQL storage support is not enabled in this build".into(),
            }),
        }
    }
}

pub(crate) fn validate_namespace(namespace: &str) -> Result<()> {
    let valid = !namespace.is_empty()
        && namespace.len() <= 191
        && namespace
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if valid {
        Ok(())
    } else {
        Err(StorageError::InvalidNamespace {
            namespace: namespace.to_string(),
        })
    }
}

pub(crate) fn validate_key(key: &str) -> Result<()> {
    let valid = !key.is_empty()
        && key.len() <= MAX_KEY_LENGTH
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | ':'));
    if valid {
        Ok(())
    } else {
        Err(StorageError::InvalidKey {
            key: key.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_to_memory() {
        let config: StorageBackendConfig = toml::from_str("").unwrap();
        assert_eq!(config.storage_type, StorageType::Memory);
    }

    #[test]
    fn names_and_keys_are_validated() {
        assert!(validate_namespace("kbs_protocol_session").is_ok());
        assert!(validate_namespace("../escape").is_err());
        assert!(validate_key("default/key/tag").is_ok());
        assert!(validate_key("bad key").is_err());
        assert!(validate_key(&"a".repeat(MAX_KEY_LENGTH)).is_ok());
        assert!(validate_key(&"a".repeat(MAX_KEY_LENGTH + 1)).is_err());
    }
}
