//! Configuration helpers for the IAM service.

use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

/// Full configuration structure loaded from `iam.toml`.
#[derive(Debug, Clone, Deserialize)]
pub struct IamConfig {
    /// HTTP server configuration.
    pub server: ServerConfig,
    /// Cryptography/signing related configuration.
    pub crypto: CryptoConfig,
}

/// HTTP server configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Bind address such as `0.0.0.0:8090`.
    #[serde(default = "default_bind_address")]
    pub bind_address: String,
}

/// Signing configuration for the STS token issuer.
#[derive(Debug, Clone, Deserialize)]
pub struct CryptoConfig {
    /// Issuer string embedded into every token.
    pub issuer: String,
    /// Shared secret for HMAC signing (replace with KMS/HSM in production).
    pub hmac_secret: String,
    /// Default TTL (seconds) for issued sessions.
    #[serde(default = "default_ttl_seconds")]
    pub default_ttl_seconds: u64,
}

impl IamConfig {
    /// Load configuration from a filesystem path.
    pub fn from_file(path: &Path) -> Result<Self> {
        let builder = config::Config::builder().add_source(config::File::from(path));
        let raw = builder.build().context("failed to build config loader")?;
        raw.try_deserialize().context("failed to parse IAM config")
    }
}

fn default_bind_address() -> String {
    "0.0.0.0:8090".to_string()
}

fn default_ttl_seconds() -> u64 {
    900
}
