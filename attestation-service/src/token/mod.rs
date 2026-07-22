// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::rvps::ReferenceValueResolver;
use crate::TeeClaims;
use anyhow::*;
use const_format::concatcp;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use strum::Display;

use crate::config::DEFAULT_WORK_DIR;

pub mod ear_broker;
pub mod oidc;
pub mod signer_transparency;
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
        tee_claims: Vec<TeeClaims>,
        policy_ids: Vec<String>,
        reference_value_resolver: Arc<ReferenceValueResolver>,
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

    /// The signer's certificate-chain PEM bytes this broker already holds
    /// (loaded from an inline `cert_pem` or a `cert_path` at construction).
    /// `None` if the broker has no local signer cert. The service uses this to
    /// answer its "get token broker certificate" endpoint — it no longer holds
    /// a `Config` to read these from, so the broker self-reports. Default: none.
    async fn signer_cert_content(&self) -> Option<Result<Vec<u8>>> {
        None
    }

    /// The signer certificate URL (x5u) the broker publishes, if any. The
    /// service HTTP-fetches it when [`Self::signer_cert_content`] returns
    /// `None`. Default: none.
    fn signer_cert_url(&self) -> Option<&str> {
        None
    }

    /// The broker's public key set as a JWKS JSON string, for the service's
    /// "get token broker public key" endpoint. Default: not supported (the
    /// service returns `None`).
    async fn public_jwks(&self) -> Result<Option<String>> {
        Ok(None)
    }

    /// The broker's OIDC discovery configuration as a JSON string, for the
    /// service's "get token broker oid config" endpoint. Default: not supported.
    async fn oid_config_json(&self) -> Result<Option<String>> {
        Ok(None)
    }
}

#[derive(Deserialize, Debug, Clone, Display, PartialEq)]
#[serde(tag = "type")]
pub enum AttestationTokenConfig {
    Simple(simple::Configuration),
    Ear(ear_broker::Configuration),
    OIDC(oidc::Configuration),
}

impl Default for AttestationTokenConfig {
    fn default() -> Self {
        AttestationTokenConfig::Ear(ear_broker::Configuration::default())
    }
}

impl AttestationTokenConfig {
    #[cfg(feature = "fs")]
    pub fn to_token_broker(&self) -> Result<Box<dyn AttestationTokenBroker + Send + Sync>> {
        match self {
            AttestationTokenConfig::Simple(cfg) => Ok(Box::new(
                simple::SimpleAttestationTokenBroker::from_config(cfg.clone())?,
            )
                as Box<dyn AttestationTokenBroker + Send + Sync>),
            AttestationTokenConfig::Ear(cfg) => Ok(Box::new(
                ear_broker::EarAttestationTokenBroker::from_config(cfg.clone())?,
            )
                as Box<dyn AttestationTokenBroker + Send + Sync>),
            AttestationTokenConfig::OIDC(cfg) => Ok(Box::new(
                oidc::OIDCAttestationTokenBroker::from_config(cfg.clone())?,
            )
                as Box<dyn AttestationTokenBroker + Send + Sync>),
        }
    }
}
