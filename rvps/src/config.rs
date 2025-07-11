// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//
use anyhow::{Context, Result};
use serde::Deserialize;

use crate::storage::ReferenceValueStorageConfig;

#[derive(Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Config {
    #[serde(default)]
    pub storage: ReferenceValueStorageConfig,
}

impl Config {
    pub fn from_file(config_path: &str) -> Result<Self> {
        let c = config::Config::builder()
            .add_source(config::File::with_name(config_path))
            .build()?;

        let res = c.try_deserialize().context("invalid config")?;
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_config_default() {
        // Test that the default config uses LocalFs
        let config = Config::default();
        assert!(matches!(
            config.storage,
            crate::storage::ReferenceValueStorageConfig::LocalFs(_)
        ));
    }

    #[test]
    fn test_config_from_file_local_fs() {
        // Create a temporary directory for the config file
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let config_path = temp_dir.path().join("config.toml");

        // Create a config file with LocalFs configuration
        let config_content = r#"
        [storage]
        type = "LocalFs"
        file_path = "/tmp/test-path"
        "#;

        let mut file = File::create(&config_path).expect("Failed to create config file");
        file.write_all(config_content.as_bytes())
            .expect("Failed to write config file");

        // Read the config file
        let config =
            Config::from_file(config_path.to_str().unwrap()).expect("Failed to read config file");

        // Verify the config
        match config.storage {
            crate::storage::ReferenceValueStorageConfig::LocalFs(fs_config) => {
                assert_eq!(fs_config.file_path, "/tmp/test-path");
            }
            _ => panic!("Expected LocalFs config"),
        }
    }

    #[test]
    fn test_config_from_file_local_json() {
        // Create a temporary directory for the config file
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let config_path = temp_dir.path().join("config.toml");

        // Create a config file with LocalJson configuration
        let config_content = r#"
        [storage]
        type = "LocalJson"
        file_path = "/tmp/test-json"
        "#;

        let mut file = File::create(&config_path).expect("Failed to create config file");
        file.write_all(config_content.as_bytes())
            .expect("Failed to write config file");

        // Read the config file
        let config =
            Config::from_file(config_path.to_str().unwrap()).expect("Failed to read config file");

        // Verify the config
        match config.storage {
            crate::storage::ReferenceValueStorageConfig::LocalJson(json_config) => {
                assert_eq!(json_config.file_path, "/tmp/test-json");
            }
            _ => panic!("Expected LocalJson config"),
        }
    }

    #[test]
    fn test_config_from_file_invalid() {
        // Create a temporary directory for the config file
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let config_path = temp_dir.path().join("config.toml");

        // Create an invalid config file
        let config_content = r#"
        invalid-toml-content
        "#;

        let mut file = File::create(&config_path).expect("Failed to create config file");
        file.write_all(config_content.as_bytes())
            .expect("Failed to write config file");

        // Try to read the config file
        let result = Config::from_file(config_path.to_str().unwrap());
        assert!(result.is_err(), "Should fail with invalid config file");
    }

    #[test]
    fn test_config_from_file_nonexistent() {
        // Try to read a nonexistent config file
        let result = Config::from_file("/nonexistent/path/config.toml");
        assert!(result.is_err(), "Should fail with nonexistent config file");
    }
}
