// Copyright (c) 2026 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! `EncryptedDb` resource backend.
//!
//! Stores wrap keys and resource envelopes in a shared SQL database (MySQL or
//! SQLite) so multiple KBS replicas can share one set of managed keys. The
//! private keys are encrypted at rest with a deployment-level master secret
//! derived from a passphrase via Argon2id, so a database-only compromise does
//! not yield plaintext key material.
//!
//! See `kbs/docs/resource_storage_backend_encrypted_db.md` for the user-facing
//! documentation.

mod db;
mod key_store;
mod master_secret;
mod resource_store;
mod schema;

use anyhow::{bail, Result};
use serde::Deserialize;

use super::{ResourceDesc, RewrapReport, RotateReport, StorageBackend};

/// User-facing configuration for the `EncryptedDb` resource backend.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct EncryptedDbBackendConfig {
    /// Path to the file holding the master secret (passphrase). Defaults to
    /// `/run/trustee/master.passphrase` (typically a Kubernetes Secret mounted
    /// as a tmpfs file).
    #[serde(default = "default_master_secret_path")]
    pub master_secret_path: String,

    /// How often, in milliseconds, each replica polls the `bump` counter to
    /// detect that another replica has rotated the key. Defaults to 5000ms.
    #[serde(default = "default_bump_poll_interval_ms")]
    pub bump_poll_interval_ms: u64,

    /// Database connection settings.
    pub database: DatabaseConfig,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct DatabaseConfig {
    /// `"mysql"` or `"sqlite"`.
    #[serde(rename = "type")]
    pub kind: String,

    /// MySQL DSN, e.g. `mysql://user:pass@host:port/db?ssl-mode=PREFERRED`.
    /// Required when `kind == "mysql"`.
    #[serde(default)]
    pub dsn: String,

    /// SQLite database file path. Required when `kind == "sqlite"`.
    /// Use `":memory:"` for an ephemeral in-process database (tests only).
    #[serde(default)]
    pub path: String,

    /// MySQL connection pool tuning.
    #[serde(default)]
    pub max_open_conns: u32,
    #[serde(default)]
    pub max_idle_conns: u32,
    #[serde(default)]
    pub conn_max_lifetime: String,

    /// How long a retired key is kept in the database before it is physically
    /// purged. Accepts a humantime-style string (`"30d"`, `"168h"`); `"0"`
    /// disables purging entirely. The minimum non-zero value is `"1h"` to
    /// avoid accidentally orphaning resources uploaded with a stale public key
    /// during a rotation race.
    #[serde(default = "default_retired_key_purge_after")]
    pub retired_key_purge_after: String,
}

fn default_master_secret_path() -> String {
    "/run/trustee/master.passphrase".to_string()
}

fn default_bump_poll_interval_ms() -> u64 {
    5000
}

fn default_retired_key_purge_after() -> String {
    "30d".to_string()
}

/// Placeholder backend; real implementation lands in a follow-up commit. Kept
/// behind the `encrypted-db` feature so that scaffolding compiles before the
/// rest of the implementation is in place.
pub struct EncryptedDb {
    _config: EncryptedDbBackendConfig,
}

impl EncryptedDb {
    pub fn new(config: &EncryptedDbBackendConfig) -> Result<Self> {
        let _ = master_secret::FileMasterSecretProvider::new(&config.master_secret_path);
        bail!("EncryptedDb backend is not implemented yet (feature scaffold)")
    }
}

#[async_trait::async_trait]
impl StorageBackend for EncryptedDb {
    async fn read_secret_resource(&self, _resource_desc: ResourceDesc) -> Result<Vec<u8>> {
        bail!("EncryptedDb: read not implemented yet")
    }

    async fn write_secret_resource(
        &self,
        _resource_desc: ResourceDesc,
        _data: &[u8],
    ) -> Result<()> {
        bail!("EncryptedDb: write not implemented yet")
    }

    async fn delete_secret_resource(&self, _resource_desc: ResourceDesc) -> Result<()> {
        bail!("EncryptedDb: delete not implemented yet")
    }

    async fn list_secret_resources(&self) -> Result<Vec<ResourceDesc>> {
        bail!("EncryptedDb: list not implemented yet")
    }

    async fn reload_keys(&self) -> Result<usize> {
        bail!("EncryptedDb: reload_keys not implemented yet")
    }

    async fn rewrap_resources(&self) -> Result<RewrapReport> {
        bail!("EncryptedDb: rewrap_resources not implemented yet")
    }

    async fn current_public_key_pem(&self) -> Result<String> {
        bail!("EncryptedDb: current_public_key_pem not implemented yet")
    }

    async fn rotate_keys(&self) -> Result<RotateReport> {
        bail!("EncryptedDb: rotate_keys not implemented yet")
    }
}
