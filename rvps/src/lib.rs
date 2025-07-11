// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod client;
pub mod config;
pub mod extractors;
pub mod pre_processor;
pub mod reference_value;
pub mod rvps_api;
pub mod server;
pub mod storage;

pub use config::Config;
pub use reference_value::{ReferenceValue, TrustedDigest};
pub use storage::ReferenceValueStorage;

use extractors::Extractors;
use pre_processor::{PreProcessor, PreProcessorAPI};

use anyhow::{bail, Context, Result};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Default version of Message
static MESSAGE_VERSION: &str = "0.1.0";

/// Message is an overall packet that Reference Value Provider Service
/// receives. It will contain payload (content of different provenance,
/// JSON format), provenance type (indicates the type of the payload)
/// and a version number (use to distinguish different version of
/// message, for extendability).
/// * `version`: version of this message.
/// * `payload`: content of the provenance, JSON encoded.
/// * `type`: provenance type of the payload.
#[derive(Serialize, Deserialize, Debug)]
pub struct Message {
    #[serde(default = "default_version")]
    version: String,
    payload: String,
    r#type: String,
}

/// Set the default version for Message
fn default_version() -> String {
    MESSAGE_VERSION.into()
}

/// The core of the RVPS, s.t. componants except communication componants.
pub struct Rvps {
    pre_processor: PreProcessor,
    extractors: Extractors,
    storage: Box<dyn ReferenceValueStorage + Send + Sync>,
}

impl Rvps {
    /// Instantiate a new RVPS
    pub fn new(config: Config) -> Result<Self> {
        let pre_processor = PreProcessor::default();
        let extractors = Extractors::default();
        let storage = config.storage.to_storage()?;

        Ok(Rvps {
            pre_processor,
            extractors,
            storage,
        })
    }

    /// Add Ware to the Core's Pre-Processor
    pub fn with_ware(&mut self, _ware: &str) -> &Self {
        // TODO: no wares implemented now.
        self
    }

    pub async fn verify_and_extract(&mut self, message: &str) -> Result<()> {
        let mut message: Message = serde_json::from_str(message).context("parse message")?;

        // Judge the version field
        if message.version != MESSAGE_VERSION {
            bail!(
                "Version unmatched! Need {}, given {}.",
                MESSAGE_VERSION,
                message.version
            );
        }

        self.pre_processor.process(&mut message)?;

        let rv = self.extractors.process(message)?;
        for v in rv.iter() {
            let old = self.storage.set(v.name().to_string(), v.clone()).await?;
            if let Some(old) = old {
                info!("Old Reference value of {} is replaced.", old.name());
            }
        }

        Ok(())
    }

    pub async fn get_digests(&self) -> Result<HashMap<String, Vec<String>>> {
        let mut rv_map = HashMap::new();
        let reference_values = self.storage.get_values().await?;

        for rv in reference_values {
            if rv.expired() {
                warn!("Reference value of {} is expired.", rv.name());
                continue;
            }

            let hash_values = rv
                .hash_values()
                .iter()
                .map(|pair| pair.value().to_owned())
                .collect();

            rv_map.insert(rv.name().to_string(), hash_values);
        }
        Ok(rv_map)
    }

    pub async fn delete_reference_value(&mut self, name: &str) -> Result<bool> {
        match self.storage.delete(name).await? {
            Some(deleted_rv) => {
                info!(
                    "Reference value {} deleted successfully.",
                    deleted_rv.name()
                );
                Ok(true)
            }
            None => {
                warn!("Reference value {} not found for deletion.", name);
                Ok(false)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use chrono::{Months, Utc};
    use serde_json::json;
    use tempfile::tempdir;

    // 创建一个有效的消息字符串用于测试
    fn create_valid_message() -> String {
        let payload = json!({
            "test_artifact": ["hash1", "hash2"]
        });

        let message = json!({
            "version": MESSAGE_VERSION,
            "payload": base64::engine::general_purpose::STANDARD.encode(payload.to_string()),
            "type": "sample"
        });

        message.to_string()
    }

    // 创建一个带有无效版本的消息字符串
    fn create_invalid_version_message() -> String {
        let payload = json!({
            "test_artifact": ["hash1", "hash2"]
        });

        let message = json!({
            "version": "999.999.999",
            "payload": base64::engine::general_purpose::STANDARD.encode(payload.to_string()),
            "type": "sample"
        });

        message.to_string()
    }

    // 创建一个带有无效类型的消息字符串
    fn create_invalid_type_message() -> String {
        let payload = json!({
            "test_artifact": ["hash1", "hash2"]
        });

        let message = json!({
            "version": MESSAGE_VERSION,
            "payload": base64::engine::general_purpose::STANDARD.encode(payload.to_string()),
            "type": "invalid_type"
        });

        message.to_string()
    }

    #[tokio::test]
    async fn test_rvps_new() {
        // 创建临时目录用于存储
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let dir_path = temp_dir.path().to_string_lossy().to_string();

        // 创建配置
        let storage_config = storage::local_fs::Config {
            file_path: dir_path,
        };
        let config = Config {
            storage: storage::ReferenceValueStorageConfig::LocalFs(storage_config),
        };

        // 测试创建 Rvps 实例
        let rvps = Rvps::new(config);
        assert!(rvps.is_ok(), "Failed to create Rvps instance");
    }

    #[tokio::test]
    async fn test_verify_and_extract() {
        // 创建临时目录用于存储
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let dir_path = temp_dir.path().to_string_lossy().to_string();

        // 创建配置
        let storage_config = storage::local_fs::Config {
            file_path: dir_path,
        };
        let config = Config {
            storage: storage::ReferenceValueStorageConfig::LocalFs(storage_config),
        };

        // 创建 Rvps 实例
        let mut rvps = Rvps::new(config).expect("Failed to create Rvps instance");

        // 测试有效消息
        let valid_message = create_valid_message();
        let result = rvps.verify_and_extract(&valid_message).await;
        assert!(result.is_ok(), "Failed to verify and extract valid message");

        // 测试无效版本消息
        let invalid_version = create_invalid_version_message();
        let result = rvps.verify_and_extract(&invalid_version).await;
        assert!(result.is_err(), "Should fail with invalid version");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Version unmatched"),
            "Error message should mention version mismatch"
        );

        // 测试无效类型消息
        let invalid_type = create_invalid_type_message();
        let result = rvps.verify_and_extract(&invalid_type).await;
        assert!(result.is_err(), "Should fail with invalid type");
    }

    #[tokio::test]
    async fn test_get_digests() {
        // 创建临时目录用于存储
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let dir_path = temp_dir.path().to_string_lossy().to_string();

        // 创建配置
        let storage_config = storage::local_fs::Config {
            file_path: dir_path,
        };
        let config = Config {
            storage: storage::ReferenceValueStorageConfig::LocalFs(storage_config),
        };

        // 创建 Rvps 实例
        let mut rvps = Rvps::new(config).expect("Failed to create Rvps instance");

        // 先添加一些引用值
        let valid_message = create_valid_message();
        rvps.verify_and_extract(&valid_message)
            .await
            .expect("Failed to add reference values");

        // 获取摘要
        let digests = rvps.get_digests().await.expect("Failed to get digests");
        assert!(!digests.is_empty(), "Digests should not be empty");
        assert!(
            digests.contains_key("test_artifact"),
            "Should contain test_artifact"
        );
        assert_eq!(
            digests["test_artifact"].len(),
            2,
            "Should have 2 hash values"
        );
        assert!(
            digests["test_artifact"].contains(&"hash1".to_string()),
            "Should contain hash1"
        );
        assert!(
            digests["test_artifact"].contains(&"hash2".to_string()),
            "Should contain hash2"
        );
    }

    #[tokio::test]
    async fn test_delete_reference_value() {
        // 创建临时目录用于存储
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let dir_path = temp_dir.path().to_string_lossy().to_string();

        // 创建配置
        let storage_config = storage::local_fs::Config {
            file_path: dir_path,
        };
        let config = Config {
            storage: storage::ReferenceValueStorageConfig::LocalFs(storage_config),
        };

        // 创建 Rvps 实例
        let mut rvps = Rvps::new(config).expect("Failed to create Rvps instance");

        // 先添加一些引用值
        let valid_message = create_valid_message();
        rvps.verify_and_extract(&valid_message)
            .await
            .expect("Failed to add reference values");

        // 确认引用值已添加
        let digests = rvps.get_digests().await.expect("Failed to get digests");
        assert!(
            digests.contains_key("test_artifact"),
            "Should contain test_artifact"
        );

        // 测试删除存在的引用值
        let result = rvps
            .delete_reference_value("test_artifact")
            .await
            .expect("Delete operation failed");
        assert!(
            result,
            "Should return true when deleting existing reference value"
        );

        // 确认引用值已删除
        let digests = rvps.get_digests().await.expect("Failed to get digests");
        assert!(
            !digests.contains_key("test_artifact"),
            "Should not contain test_artifact after deletion"
        );

        // 测试删除不存在的引用值
        let result = rvps
            .delete_reference_value("non_existent")
            .await
            .expect("Delete operation failed");
        assert!(
            !result,
            "Should return false when deleting non-existent reference value"
        );
    }

    #[tokio::test]
    async fn test_expired_reference_value() {
        // 创建临时目录用于存储
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let dir_path = temp_dir.path().to_string_lossy().to_string();

        // 创建配置
        let storage_config = storage::local_fs::Config {
            file_path: dir_path,
        };
        let config = Config {
            storage: storage::ReferenceValueStorageConfig::LocalFs(storage_config),
        };

        // 创建 Rvps 实例
        let rvps = Rvps::new(config).expect("Failed to create Rvps instance");

        // 创建一个过期的引用值并手动添加到存储中
        let expired_time = Utc::now().checked_sub_months(Months::new(1)).unwrap();
        let rv = ReferenceValue::new()
            .expect("Failed to create reference value")
            .set_name("expired_artifact")
            .set_expiration(expired_time)
            .add_hash_value("sha384".to_string(), "expired_hash".to_string());

        rvps.storage
            .set("expired_artifact".to_string(), rv)
            .await
            .expect("Failed to set reference value");

        // 获取摘要，过期的引用值不应该出现
        let digests = rvps.get_digests().await.expect("Failed to get digests");
        assert!(
            !digests.contains_key("expired_artifact"),
            "Expired reference value should not be included"
        );
    }
}
