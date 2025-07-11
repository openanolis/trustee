// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use kbs_types::Tee;
use serde::Deserialize;
use shadow_rs::concatcp;
use std::collections::HashMap;
use strum::Display;
use verifier::TeeEvidenceParsedClaim;

use crate::config::DEFAULT_WORK_DIR;

pub mod ear_broker;
pub mod simple;

pub const DEFAULT_TOKEN_DURATION: i64 = 5;
pub const COCO_AS_ISSUER_NAME: &str = "CoCo-Attestation-Service";

const DEFAULT_TOKEN_WORK_DIR: &str = concatcp!(DEFAULT_WORK_DIR, "/token");

#[async_trait::async_trait]
pub trait AttestationTokenBroker: Send + Sync {
    /// Issue an signed attestation token with custom claims.
    /// Return base64 encoded Json Web Token.
    async fn issue(
        &self,
        tcb_claims: TeeEvidenceParsedClaim,
        policy_ids: Vec<String>,
        init_data_claims: serde_json::Value,
        runtime_data_claims: serde_json::Value,
        reference_data_map: HashMap<String, Vec<String>>,
        tee: Tee,
    ) -> Result<String>;

    async fn set_policy(&self, _policy_id: String, _policy: String) -> Result<()> {
        bail!("Set Policy not support")
    }

    async fn list_policies(&self) -> Result<HashMap<String, String>> {
        bail!("List Policies not support")
    }

    async fn get_policy(&self, _policy_id: String) -> Result<String> {
        bail!("Get Policy not support")
    }

    async fn delete_policy(&self, _policy_id: String) -> Result<()> {
        bail!("Delete Policy not support")
    }
}

#[derive(Deserialize, Debug, Clone, Display, PartialEq)]
#[serde(tag = "type")]
pub enum AttestationTokenConfig {
    Simple(simple::Configuration),
    Ear(ear_broker::Configuration),
}

impl Default for AttestationTokenConfig {
    fn default() -> Self {
        AttestationTokenConfig::Ear(ear_broker::Configuration::default())
    }
}

impl AttestationTokenConfig {
    pub fn to_token_broker(&self) -> Result<Box<dyn AttestationTokenBroker + Send + Sync>> {
        match self {
            AttestationTokenConfig::Simple(cfg) => Ok(Box::new(
                simple::SimpleAttestationTokenBroker::new(cfg.clone())?,
            )
                as Box<dyn AttestationTokenBroker + Send + Sync>),
            AttestationTokenConfig::Ear(cfg) => Ok(Box::new(
                ear_broker::EarAttestationTokenBroker::new(cfg.clone())?,
            )
                as Box<dyn AttestationTokenBroker + Send + Sync>),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_attestation_token_config_default() {
        let config = AttestationTokenConfig::default();
        match config {
            AttestationTokenConfig::Ear(_) => {} // Expected default
            _ => panic!("Expected Ear config as default"),
        }
    }

    #[test]
    fn test_attestation_token_config_display() {
        let simple_config = AttestationTokenConfig::Simple(simple::Configuration::default());
        let ear_config = AttestationTokenConfig::Ear(ear_broker::Configuration::default());

        assert_eq!(format!("{}", simple_config), "Simple");
        assert_eq!(format!("{}", ear_config), "Ear");
    }

    // Mock implementation of AttestationTokenBroker for testing
    struct MockTokenBroker;

    #[async_trait::async_trait]
    impl AttestationTokenBroker for MockTokenBroker {
        async fn issue(
            &self,
            _tcb_claims: TeeEvidenceParsedClaim,
            _policy_ids: Vec<String>,
            _init_data_claims: serde_json::Value,
            _runtime_data_claims: serde_json::Value,
            _reference_data_map: HashMap<String, Vec<String>>,
            _tee: Tee,
        ) -> Result<String> {
            Ok("mock_token".to_string())
        }
    }

    #[tokio::test]
    async fn test_default_policy_methods() {
        let broker = MockTokenBroker;

        // Test default set_policy implementation
        let result = broker
            .set_policy("policy_id".to_string(), "policy_content".to_string())
            .await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Set Policy not support");

        // Test default list_policies implementation
        let result = broker.list_policies().await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "List Policies not support");

        // Test default get_policy implementation
        let result = broker.get_policy("policy_id".to_string()).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Get Policy not support");

        // Test default delete_policy implementation
        let result = broker.delete_policy("policy_id".to_string()).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Delete Policy not support");
    }

    #[tokio::test]
    async fn test_mock_token_broker() {
        let broker = MockTokenBroker;

        // Test issue method
        let result = broker
            .issue(
                TeeEvidenceParsedClaim::default(),
                vec!["policy1".to_string()],
                json!({}),
                json!({}),
                HashMap::new(),
                Tee::Tdx,
            )
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "mock_token");
    }
}
