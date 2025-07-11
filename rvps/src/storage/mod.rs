// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Store is responsible for storing verified Reference Values

use anyhow::Result;
use async_trait::async_trait;
use serde::Deserialize;
use strum::Display;

use self::local_fs::LocalFs;
use self::local_json::LocalJson;

use super::ReferenceValue;

pub mod local_fs;
pub mod local_json;

#[derive(Clone, Debug, Deserialize, Display, PartialEq)]
#[serde(tag = "type")]
pub enum ReferenceValueStorageConfig {
    LocalFs(local_fs::Config),
    LocalJson(local_json::Config),
}

impl Default for ReferenceValueStorageConfig {
    fn default() -> Self {
        ReferenceValueStorageConfig::LocalFs(local_fs::Config::default())
    }
}

impl ReferenceValueStorageConfig {
    pub fn to_storage(&self) -> Result<Box<dyn ReferenceValueStorage + Send + Sync>> {
        match self {
            ReferenceValueStorageConfig::LocalFs(cfg) => Ok(Box::new(LocalFs::new(cfg.clone())?)
                as Box<dyn ReferenceValueStorage + Send + Sync>),
            ReferenceValueStorageConfig::LocalJson(cfg) => {
                Ok(Box::new(LocalJson::new(cfg.clone())?)
                    as Box<dyn ReferenceValueStorage + Send + Sync>)
            }
        }
    }
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_reference_value_storage_config_default() {
        let config = ReferenceValueStorageConfig::default();
        assert!(matches!(config, ReferenceValueStorageConfig::LocalFs(_)));
    }

    #[test]
    fn test_reference_value_storage_config_display() {
        let fs_config = ReferenceValueStorageConfig::LocalFs(local_fs::Config::default());
        let json_config = ReferenceValueStorageConfig::LocalJson(local_json::Config::default());

        assert_eq!(format!("{}", fs_config), "LocalFs");
        assert_eq!(format!("{}", json_config), "LocalJson");
    }

    #[test]
    fn test_to_storage_local_fs() {
        // Create a temporary directory for storage
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let dir_path = temp_dir.path().to_string_lossy().to_string();

        // Create LocalFs config
        let fs_config = local_fs::Config {
            file_path: dir_path,
        };
        let config = ReferenceValueStorageConfig::LocalFs(fs_config);

        // Convert to storage
        let storage = config.to_storage();
        assert!(storage.is_ok(), "to_storage should succeed for LocalFs");
    }

    #[test]
    fn test_to_storage_local_json() {
        // Create a temporary directory for storage
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let dir_path = temp_dir
            .path()
            .join("test.json")
            .to_string_lossy()
            .to_string();

        // Create LocalJson config
        let json_config = local_json::Config {
            file_path: dir_path,
        };
        let config = ReferenceValueStorageConfig::LocalJson(json_config);

        // Convert to storage
        let storage = config.to_storage();
        assert!(storage.is_ok(), "to_storage should succeed for LocalJson");
    }
}
