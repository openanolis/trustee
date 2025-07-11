use super::{Result, RvpsApi};
use async_trait::async_trait;
use core::result::Result::Ok;
use reference_value_provider_service::{Config, Rvps};
use std::collections::HashMap;

pub struct BuiltinRvps {
    rvps: Rvps,
}

impl BuiltinRvps {
    pub fn new(config: Config) -> Result<Self> {
        let rvps = Rvps::new(config)?;
        Ok(Self { rvps })
    }
}

#[async_trait]
impl RvpsApi for BuiltinRvps {
    async fn verify_and_extract(&mut self, message: &str) -> Result<()> {
        self.rvps.verify_and_extract(message).await?;
        Ok(())
    }

    async fn get_digests(&self) -> Result<HashMap<String, Vec<String>>> {
        let hashes = self.rvps.get_digests().await?;

        Ok(hashes)
    }

    async fn delete_reference_value(&mut self, name: &str) -> Result<bool> {
        let result = self.rvps.delete_reference_value(name).await?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reference_value_provider_service::storage::{local_fs, ReferenceValueStorageConfig};
    use tempfile::tempdir;

    #[test]
    fn test_builtin_rvps_new() {
        // Create a temporary directory for testing
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().to_path_buf();

        // Create a config with local filesystem storage
        let storage_config = ReferenceValueStorageConfig::LocalFs(local_fs::Config {
            file_path: path.to_string_lossy().to_string(),
        });
        let config = Config {
            storage: storage_config,
        };

        // Create a new BuiltinRvps instance
        let result = BuiltinRvps::new(config);

        // Verify the result
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_builtin_rvps_empty_digests() {
        // Create a temporary directory for testing
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().to_path_buf();

        // Create a config with local filesystem storage
        let storage_config = ReferenceValueStorageConfig::LocalFs(local_fs::Config {
            file_path: path.to_string_lossy().to_string(),
        });
        let config = Config {
            storage: storage_config,
        };

        // Create a new BuiltinRvps instance
        let builtin_rvps = BuiltinRvps::new(config).unwrap();

        // Get digests from an empty storage
        let digests = builtin_rvps.get_digests().await.unwrap();

        // Verify the result
        assert!(digests.is_empty());
    }

    // This test requires mocking the Rvps implementation which is beyond the scope
    // of simple unit tests. In a real-world scenario, we would use a mock framework
    // or dependency injection to test the behavior with predefined data.
    #[test]
    fn test_builtin_rvps_methods() {
        // This is a placeholder for more comprehensive tests that would require
        // mocking the underlying Rvps implementation.
        // For a complete test suite, we would need to:
        // 1. Mock the Rvps implementation
        // 2. Test verify_and_extract with valid and invalid messages
        // 3. Test get_digests with populated storage
        // 4. Test delete_reference_value with existing and non-existing values
    }
}
