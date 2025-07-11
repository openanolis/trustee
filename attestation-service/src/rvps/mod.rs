// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use log::info;
pub use reference_value_provider_service::config::Config as RvpsCrateConfig;
use serde::Deserialize;
use std::collections::HashMap;
use thiserror::Error;

#[cfg(feature = "rvps-grpc")]
pub mod grpc;

pub mod builtin;

#[derive(Error, Debug)]
pub enum RvpsError {
    #[error("Serde Json Error: {0}")]
    SerdeJson(#[from] serde_json::Error),

    #[cfg(feature = "rvps-grpc")]
    #[error("Returned status: {0}")]
    Status(#[from] tonic::Status),

    #[cfg(feature = "rvps-grpc")]
    #[error("tonic transport error: {0}")]
    TonicTransport(#[from] tonic::transport::Error),

    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

type Result<T> = std::result::Result<T, RvpsError>;

/// The interfaces of Reference Value Provider Service
/// * `verify_and_extract` is responsible for verify a message and
/// store reference values from it.
/// * `get_digests` gets trusted digests by the artifact's name.
/// * `delete_reference_value` is responsible for deleting a reference value.
#[async_trait::async_trait]
pub trait RvpsApi {
    /// Verify the given message and register the reference value included.
    async fn verify_and_extract(&mut self, message: &str) -> Result<()>;

    /// Get the reference values / golden values / expected digests in hex.
    async fn get_digests(&self) -> Result<HashMap<String, Vec<String>>>;

    /// Delete a reference value by name.
    async fn delete_reference_value(&mut self, name: &str) -> Result<bool>;
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type")]
pub enum RvpsConfig {
    BuiltIn(RvpsCrateConfig),
    #[cfg(feature = "rvps-grpc")]
    GrpcRemote(grpc::RvpsRemoteConfig),
}

impl Default for RvpsConfig {
    fn default() -> Self {
        Self::BuiltIn(RvpsCrateConfig::default())
    }
}

pub async fn initialize_rvps_client(config: &RvpsConfig) -> Result<Box<dyn RvpsApi + Send + Sync>> {
    match config {
        RvpsConfig::BuiltIn(config) => {
            info!("launch a built-in RVPS.");
            Ok(Box::new(builtin::BuiltinRvps::new(config.clone())?)
                as Box<dyn RvpsApi + Send + Sync>)
        }
        #[cfg(feature = "rvps-grpc")]
        RvpsConfig::GrpcRemote(config) => {
            info!("connect to remote RVPS: {}", config.address);
            Ok(Box::new(grpc::Agent::new(&config.address).await?)
                as Box<dyn RvpsApi + Send + Sync>)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;

    #[test]
    fn test_rvps_error_display() {
        // Test SerdeJson error
        let json_err = serde_json::from_str::<serde_json::Value>("invalid json").unwrap_err();
        let err = RvpsError::SerdeJson(json_err);
        assert!(format!("{}", err).contains("Serde Json Error"));

        // Test Anyhow error
        let anyhow_err = anyhow!("test error");
        let err = RvpsError::Anyhow(anyhow_err);
        assert!(format!("{}", err).contains("test error"));
    }

    #[test]
    fn test_rvps_config_default() {
        let config = RvpsConfig::default();
        match config {
            RvpsConfig::BuiltIn(_) => {} // Expected default
            #[cfg(feature = "rvps-grpc")]
            RvpsConfig::GrpcRemote(_) => panic!("Expected BuiltIn config"),
        }
    }

    #[test]
    fn test_rvps_config_equality() {
        let config1 = RvpsConfig::BuiltIn(RvpsCrateConfig::default());
        let config2 = RvpsConfig::BuiltIn(RvpsCrateConfig::default());
        let config3 = RvpsConfig::default();

        assert_eq!(config1, config2);
        assert_eq!(config1, config3);
    }

    // Mock implementation of RvpsApi for testing
    struct MockRvps {
        digests: HashMap<String, Vec<String>>,
    }

    #[async_trait::async_trait]
    impl RvpsApi for MockRvps {
        async fn verify_and_extract(&mut self, _message: &str) -> Result<()> {
            Ok(())
        }

        async fn get_digests(&self) -> Result<HashMap<String, Vec<String>>> {
            Ok(self.digests.clone())
        }

        async fn delete_reference_value(&mut self, name: &str) -> Result<bool> {
            Ok(self.digests.remove(name).is_some())
        }
    }

    impl MockRvps {
        fn new() -> Self {
            let mut digests = HashMap::new();
            digests.insert(
                "test".to_string(),
                vec!["digest1".to_string(), "digest2".to_string()],
            );
            Self { digests }
        }
    }

    #[tokio::test]
    async fn test_mock_rvps_api() {
        let mut mock = MockRvps::new();

        // Test get_digests
        let digests = mock.get_digests().await.unwrap();
        assert_eq!(digests.len(), 1);
        assert_eq!(digests.get("test").unwrap().len(), 2);

        // Test delete_reference_value
        let result = mock.delete_reference_value("test").await.unwrap();
        assert!(result);

        // Verify deletion
        let digests = mock.get_digests().await.unwrap();
        assert_eq!(digests.len(), 0);

        // Test delete non-existent value
        let result = mock.delete_reference_value("nonexistent").await.unwrap();
        assert!(!result);
    }
}
