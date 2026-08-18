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
pub mod signer;
pub mod signer_transparency;
pub mod simple;

pub const DEFAULT_TOKEN_DURATION: i64 = 5;
pub const COCO_AS_ISSUER_NAME: &str = "CoCo-Attestation-Service";

const DEFAULT_TOKEN_WORK_DIR: &str = concatcp!(DEFAULT_WORK_DIR, "/token");

#[cfg_attr(all(target_arch = "wasm32", target_vendor = "unknown", target_os = "unknown"), async_trait::async_trait(?Send))]
#[cfg_attr(
    not(all(
        target_arch = "wasm32",
        target_vendor = "unknown",
        target_os = "unknown"
    )),
    async_trait::async_trait
)]
pub trait AttestationTokenBroker: Send + Sync {
    /// Issue an signed attestation token with custom claims.
    /// Return base64 encoded Json Web Token.
    async fn issue(
        &self,
        tee_claims: Vec<TeeClaims>,
        policy_ids: Vec<String>,
        reference_value_resolver: Arc<ReferenceValueResolver>,
    ) -> Result<String>;

    /// Set a policy for the given `policy_id`.
    /// The `policy` string is encoded in URL-safe base64 (no padding, i.e. URL_SAFE_NO_PAD).
    async fn set_policy(&self, policy_id: String, policy: String) -> Result<()>;

    /// List all policies. The returned map's values are encoded in URL-safe base64 (no padding,
    /// i.e. URL_SAFE_NO_PAD).
    async fn list_policies(&self) -> Result<HashMap<String, String>>;

    /// Get the policy for the given `policy_id`.
    /// The returned string is encoded in URL-safe base64 (no padding, i.e. URL_SAFE_NO_PAD).
    async fn get_policy(&self, policy_id: String) -> Result<String>;

    /// Delete the policy for the given `policy_id`.
    async fn delete_policy(&self, policy_id: String) -> Result<()>;
    /// The signer's certificate-chain PEM bytes this broker already holds
    /// (loaded from an inline `cert_pem` or a `cert_path` at construction).
    /// `None` if the broker has no local signer cert. The service uses this to
    /// answer its "get token broker certificate" endpoint — it no longer holds
    /// a `Config` to read these from, so the broker self-reports. Default: none.
    async fn signer_cert_pem_live(&self) -> Option<Result<Vec<u8>>> {
        None
    }

    /// The signer certificate URL (x5u) the broker publishes, if any. The
    /// service HTTP-fetches it when [`Self::signer_cert_pem_live`] returns
    /// `None`. Default: none.
    fn signer_cert_url(&self) -> Option<&str> {
        None
    }

    /// The *configured* signer's public key set as a JWKS JSON string, for the
    /// service's "get token broker public key" (`/jwks`) endpoint.
    ///
    /// Publishes the JWKS only when a signer was explicitly configured; an
    /// ephemeral signer is intentionally **not** published (its key is freshly
    /// generated per process start, so clients cannot pin it), and the method
    /// returns `None` in that case — the service then answers `/jwks` with
    /// 404. This preserves the long-standing behavior of only publishing a
    /// JWKS for an explicitly configured signer. Default: not supported
    /// (`None`).
    ///
    /// The name emphasizes "configured" so callers don't assume a generic
    /// "any public key" contract. If a future use case needs to publish an
    /// ephemeral key too, add a separate method rather than loosening this one.
    async fn configured_signer_jwks(&self) -> Result<Option<String>> {
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
    pub fn to_token_broker(
        &self,
        artifact_server_address: &str,
    ) -> Result<Box<dyn AttestationTokenBroker + Send + Sync>> {
        match self {
            AttestationTokenConfig::Simple(cfg) => {
                Ok(Box::new(simple::SimpleAttestationTokenBroker::from_config(
                    cfg.clone(),
                    artifact_server_address,
                )?)
                    as Box<dyn AttestationTokenBroker + Send + Sync>)
            }
            AttestationTokenConfig::Ear(cfg) => {
                Ok(Box::new(ear_broker::EarAttestationTokenBroker::from_config(
                    cfg.clone(),
                    artifact_server_address,
                )?)
                    as Box<dyn AttestationTokenBroker + Send + Sync>)
            }
            AttestationTokenConfig::OIDC(cfg) => {
                Ok(Box::new(oidc::OIDCAttestationTokenBroker::from_config(
                    cfg.clone(),
                    artifact_server_address,
                )?)
                    as Box<dyn AttestationTokenBroker + Send + Sync>)
            }
        }
    }
}
