use std::{fs, path::PathBuf};

use super::ReferenceValueStorage;
use crate::ReferenceValue;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use log::debug;
use serde::Deserialize;
use tokio::sync::RwLock;

const FILE_PATH: &str = "/opt/confidential-containers/attestation-service/reference_values.json";

#[derive(Debug)]
pub struct LocalJson {
    file_path: String,
    lock: RwLock<i32>,
}

fn default_file_path() -> String {
    FILE_PATH.to_string()
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Config {
    #[serde(default = "default_file_path")]
    pub file_path: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            file_path: default_file_path(),
        }
    }
}

impl LocalJson {
    pub fn new(config: Config) -> Result<Self> {
        let mut path = PathBuf::new();
        path.push(&config.file_path);

        let parent_dir = path.parent().ok_or_else(|| {
            anyhow!("Illegal `file_path` for LocalJson's config without a parent dir.")
        })?;
        debug!("create path for LocalJson: {:?}", parent_dir);
        fs::create_dir_all(parent_dir)?;

        if !path.exists() {
            debug!("Creating empty file for LocalJson reference values.");
            std::fs::write(&config.file_path, "[]")?;
        } else {
            // Verify if the file contains valid JSON array
            let content = fs::read_to_string(&config.file_path)?;
            if !content.is_empty() {
                serde_json::from_str::<Vec<ReferenceValue>>(&content).map_err(|e| {
                    anyhow!("Invalid JSON format in file {}: {}", config.file_path, e)
                })?;
            } else {
                // If file is empty, initialize with empty array
                std::fs::write(&config.file_path, "[]")?;
            }
        }

        Ok(Self {
            file_path: config.file_path,
            lock: RwLock::new(0),
        })
    }
}

#[async_trait]
impl ReferenceValueStorage for LocalJson {
    async fn set(&self, name: String, rv: ReferenceValue) -> Result<Option<ReferenceValue>> {
        let _ = self.lock.write().await;
        let file = tokio::fs::read(&self.file_path).await?;
        let mut rvs: Vec<ReferenceValue> = serde_json::from_slice(&file)?;
        let mut res = None;
        if let Some(item) = rvs.iter_mut().find(|it| it.name == name) {
            res = Some(item.to_owned());
            *item = rv;
        } else {
            rvs.push(rv);
        }

        let contents = serde_json::to_vec(&rvs)?;
        tokio::fs::write(&self.file_path, contents).await?;
        Ok(res)
    }

    async fn get(&self, name: &str) -> Result<Option<ReferenceValue>> {
        let _ = self.lock.read().await;
        let file = tokio::fs::read(&self.file_path).await?;
        let rvs: Vec<ReferenceValue> = serde_json::from_slice(&file)?;
        let rv = rvs.into_iter().find(|rv| rv.name == name);
        Ok(rv)
    }

    async fn get_values(&self) -> Result<Vec<ReferenceValue>> {
        let _ = self.lock.read().await;
        let file = tokio::fs::read(&self.file_path).await?;
        let rvs: Vec<ReferenceValue> = serde_json::from_slice(&file)?;
        Ok(rvs)
    }

    async fn delete(&self, name: &str) -> Result<Option<ReferenceValue>> {
        let _ = self.lock.write().await;
        let file = tokio::fs::read(&self.file_path).await?;
        let mut rvs: Vec<ReferenceValue> = serde_json::from_slice(&file)?;

        let mut deleted_rv = None;
        if let Some(pos) = rvs.iter().position(|rv| rv.name == name) {
            deleted_rv = Some(rvs.remove(pos));
        }

        let contents = serde_json::to_vec(&rvs)?;
        tokio::fs::write(&self.file_path, contents).await?;
        Ok(deleted_rv)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ReferenceValue;
    use serial_test::serial;
    use std::fs;
    use tempfile::tempdir;

    const KEY: &str = "test_key";

    #[tokio::test]
    #[serial]
    async fn test_set_and_get() {
        // Create a temporary directory for the test
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let file_path = temp_dir
            .path()
            .join("test.json")
            .to_string_lossy()
            .to_string();

        // Create LocalJson storage
        let storage =
            LocalJson::new(Config { file_path }).expect("Failed to create LocalJson storage");

        // Create a reference value
        let mut rv = ReferenceValue::new().expect("Failed to create reference value");
        // 设置一个名称，因为ReferenceValue可能使用name字段作为索引
        rv.name = KEY.to_owned();

        // Set the reference value
        let result = storage.set(KEY.to_owned(), rv.clone()).await;
        assert!(result.is_ok(), "Set operation should succeed");
        assert!(result.unwrap().is_none(), "No previous value should exist");

        // Get the reference value
        let result = storage.get(KEY).await;
        assert!(result.is_ok(), "Get operation should succeed");

        let got = result.unwrap();
        assert!(got.is_some(), "Reference value should exist");
        assert_eq!(
            got.unwrap(),
            rv,
            "Retrieved value should match the original"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_set_duplicated() {
        // Create a temporary directory for the test
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let file_path = temp_dir
            .path()
            .join("test.json")
            .to_string_lossy()
            .to_string();

        // Create LocalJson storage
        let storage =
            LocalJson::new(Config { file_path }).expect("Failed to create LocalJson storage");

        // Create first reference value
        let mut rv_old = ReferenceValue::new()
            .expect("Failed to create reference value")
            .set_name("old");
        // 确保引用值的name与存储中使用的键匹配
        rv_old.name = KEY.to_owned();

        // Create second reference value
        let mut rv_new = ReferenceValue::new()
            .expect("Failed to create reference value")
            .set_name("new");
        // 确保第二个引用值的name也与存储中使用的键匹配
        rv_new.name = KEY.to_owned();

        // Set the first reference value
        let result = storage.set(KEY.to_owned(), rv_old.clone()).await;
        assert!(result.is_ok(), "First set operation should succeed");
        assert!(result.unwrap().is_none(), "No previous value should exist");

        // Set the second reference value with the same key
        let result = storage.set(KEY.to_owned(), rv_new).await;
        assert!(result.is_ok(), "Second set operation should succeed");

        let old_value = result.unwrap();
        assert!(old_value.is_some(), "Previous value should exist");
        assert_eq!(
            old_value.unwrap(),
            rv_old,
            "Previous value should match the first reference value"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_get_nonexistent() {
        // Create a temporary directory for the test
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let file_path = temp_dir
            .path()
            .join("test.json")
            .to_string_lossy()
            .to_string();

        // Create LocalJson storage
        let storage =
            LocalJson::new(Config { file_path }).expect("Failed to create LocalJson storage");

        // Get a nonexistent reference value
        let result = storage.get("nonexistent").await;
        assert!(
            result.is_ok(),
            "Get operation should succeed even for nonexistent keys"
        );
        assert!(
            result.unwrap().is_none(),
            "Nonexistent key should return None"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_get_values() {
        // Create a temporary directory for the test
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let file_path = temp_dir
            .path()
            .join("test.json")
            .to_string_lossy()
            .to_string();

        // Create LocalJson storage
        let storage =
            LocalJson::new(Config { file_path }).expect("Failed to create LocalJson storage");

        // Create and set multiple reference values
        let rv1 = ReferenceValue::new()
            .expect("Failed to create reference value")
            .set_name("rv1");

        let rv2 = ReferenceValue::new()
            .expect("Failed to create reference value")
            .set_name("rv2");

        storage
            .set("key1".to_owned(), rv1.clone())
            .await
            .expect("Failed to set rv1");
        storage
            .set("key2".to_owned(), rv2.clone())
            .await
            .expect("Failed to set rv2");

        // Get all values
        let result = storage.get_values().await;
        assert!(result.is_ok(), "Get values operation should succeed");

        let values = result.unwrap();
        assert_eq!(values.len(), 2, "Should return two reference values");

        // Check that both reference values are in the result
        let has_rv1 = values.iter().any(|rv| rv.name() == "rv1");
        let has_rv2 = values.iter().any(|rv| rv.name() == "rv2");

        assert!(has_rv1, "Result should contain rv1");
        assert!(has_rv2, "Result should contain rv2");
    }

    #[tokio::test]
    #[serial]
    async fn test_delete_existing() {
        // Create a temporary directory for the test
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let file_path = temp_dir
            .path()
            .join("test.json")
            .to_string_lossy()
            .to_string();

        // Create LocalJson storage
        let storage =
            LocalJson::new(Config { file_path }).expect("Failed to create LocalJson storage");

        // Create and set a reference value
        let mut rv = ReferenceValue::new().expect("Failed to create reference value");
        rv.name = KEY.to_owned();

        storage
            .set(KEY.to_owned(), rv.clone())
            .await
            .expect("Failed to set reference value");

        let stored = storage
            .get(KEY)
            .await
            .expect("Failed to get reference value");
        assert!(
            stored.is_some(),
            "Reference value should be stored successfully"
        );
        assert_eq!(
            stored.unwrap(),
            rv,
            "Stored value should match the original"
        );

        // Delete the reference value
        let result = storage.delete(KEY).await;
        assert!(result.is_ok(), "Delete operation should succeed");

        let deleted = result.unwrap();
        assert!(deleted.is_some(), "Deleted value should be returned");
        assert_eq!(
            deleted.unwrap(),
            rv,
            "Deleted value should match the original"
        );

        // Verify the value is gone
        let result = storage.get(KEY).await;
        assert!(result.is_ok(), "Get operation should succeed");
        assert!(
            result.unwrap().is_none(),
            "Reference value should no longer exist"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_delete_nonexistent() {
        // Create a temporary directory for the test
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let file_path = temp_dir
            .path()
            .join("test.json")
            .to_string_lossy()
            .to_string();

        // Create LocalJson storage
        let storage =
            LocalJson::new(Config { file_path }).expect("Failed to create LocalJson storage");

        // Delete a nonexistent reference value
        let result = storage.delete("nonexistent").await;
        assert!(
            result.is_ok(),
            "Delete operation should succeed even for nonexistent keys"
        );
        assert!(
            result.unwrap().is_none(),
            "Nonexistent key should return None"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_persistence() {
        // Create a temporary directory for the test
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let file_path = temp_dir
            .path()
            .join("test.json")
            .to_string_lossy()
            .to_string();

        // Create a reference value
        let mut rv = ReferenceValue::new().expect("Failed to create reference value");

        rv.name = KEY.to_owned();

        // First instance: set the reference value
        {
            let storage = LocalJson::new(Config {
                file_path: file_path.clone(),
            })
            .expect("Failed to create LocalJson storage");

            storage
                .set(KEY.to_owned(), rv.clone())
                .await
                .expect("Failed to set reference value");

            let check = storage
                .get(KEY)
                .await
                .expect("Failed to get reference value");
            assert!(
                check.is_some(),
                "Reference value should be stored correctly"
            );
        }

        // Second instance: get the reference value
        {
            let storage =
                LocalJson::new(Config { file_path }).expect("Failed to create LocalJson storage");
            let result = storage.get(KEY).await;
            assert!(result.is_ok(), "Get operation should succeed");

            let got = result.unwrap();
            assert!(got.is_some(), "Reference value should exist");
            assert_eq!(
                got.unwrap(),
                rv,
                "Retrieved value should match the original"
            );
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_file_creation() {
        // Create a temporary directory for the test
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let file_path = temp_dir
            .path()
            .join("test.json")
            .to_string_lossy()
            .to_string();

        // Create LocalJson storage
        let _storage = LocalJson::new(Config {
            file_path: file_path.clone(),
        })
        .expect("Failed to create LocalJson storage");

        // Check that the file was created
        assert!(fs::metadata(&file_path).is_ok(), "File should be created");
    }

    #[tokio::test]
    #[serial]
    async fn test_invalid_json() {
        // Create a temporary directory for the test
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let file_path = temp_dir
            .path()
            .join("test.json")
            .to_string_lossy()
            .to_string();

        // Create an invalid JSON file
        fs::write(&file_path, "invalid json").expect("Failed to write file");

        // Try to create LocalJson storage
        let result = LocalJson::new(Config { file_path });
        assert!(result.is_err(), "Creation should fail with invalid JSON");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid JSON format"),
            "Error message should indicate invalid JSON format"
        );
    }
}
