// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::{
    env,
    fmt::{self, Display},
    str::FromStr,
    sync::{Arc, OnceLock},
};

use anyhow::{anyhow, bail, Context, Error, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};

#[cfg(feature = "encrypted-local-fs")]
use super::encrypted_local_fs;
use super::local_fs;

type RepositoryInstance = Arc<dyn StorageBackend>;

const ENV_RESOURCE_STORAGE_TYPE: &str = "KBS_RESOURCE_STORAGE_TYPE";
const ENV_RESOURCE_STORAGE_DIR_PATH: &str = "KBS_RESOURCE_STORAGE_DIR_PATH";

#[cfg(feature = "encrypted-local-fs")]
const ENV_RESOURCE_STORAGE_PRIVATE_KEY_PATH: &str = "KBS_RESOURCE_STORAGE_PRIVATE_KEY_PATH";

const ENV_RESOURCE_STORAGE_LIBRARY_PATH: &str = "KBS_RESOURCE_STORAGE_LIBRARY_PATH";
const ENV_RESOURCE_STORAGE_INITIAL_BUFFER_SIZE: &str = "KBS_RESOURCE_STORAGE_INITIAL_BUFFER_SIZE";
const ENV_RESOURCE_STORAGE_MAX_BUFFER_SIZE: &str = "KBS_RESOURCE_STORAGE_MAX_BUFFER_SIZE";
const ENV_RESOURCE_STORAGE_ERROR_BUFFER_SIZE: &str = "KBS_RESOURCE_STORAGE_ERROR_BUFFER_SIZE";

#[cfg(feature = "encrypted-db")]
const ENV_RESOURCE_STORAGE_MASTER_SECRET_PATH: &str = "KBS_RESOURCE_STORAGE_MASTER_SECRET_PATH";
#[cfg(feature = "encrypted-db")]
const ENV_RESOURCE_STORAGE_BUMP_POLL_INTERVAL_MS: &str =
    "KBS_RESOURCE_STORAGE_BUMP_POLL_INTERVAL_MS";
#[cfg(feature = "encrypted-db")]
const ENV_RESOURCE_STORAGE_DB_TYPE: &str = "KBS_RESOURCE_STORAGE_DB_TYPE";
#[cfg(feature = "encrypted-db")]
const ENV_RESOURCE_STORAGE_DB_DSN: &str = "KBS_RESOURCE_STORAGE_DB_DSN";
#[cfg(feature = "encrypted-db")]
const ENV_RESOURCE_STORAGE_DB_PATH: &str = "KBS_RESOURCE_STORAGE_DB_PATH";
#[cfg(feature = "encrypted-db")]
const ENV_RESOURCE_STORAGE_DB_MAX_OPEN_CONNS: &str = "KBS_RESOURCE_STORAGE_DB_MAX_OPEN_CONNS";
#[cfg(feature = "encrypted-db")]
const ENV_RESOURCE_STORAGE_DB_MAX_IDLE_CONNS: &str = "KBS_RESOURCE_STORAGE_DB_MAX_IDLE_CONNS";
#[cfg(feature = "encrypted-db")]
const ENV_RESOURCE_STORAGE_DB_CONN_MAX_LIFETIME: &str = "KBS_RESOURCE_STORAGE_DB_CONN_MAX_LIFETIME";
#[cfg(feature = "encrypted-db")]
const ENV_RESOURCE_STORAGE_RETIRED_KEY_PURGE_AFTER: &str =
    "KBS_RESOURCE_STORAGE_RETIRED_KEY_PURGE_AFTER";

/// Interface of a `Repository`.
#[async_trait::async_trait]
pub trait StorageBackend: Send + Sync {
    /// Read secret resource from repository.
    async fn read_secret_resource(&self, resource_desc: ResourceDesc) -> Result<Vec<u8>>;

    /// Write secret resource into repository
    async fn write_secret_resource(&self, resource_desc: ResourceDesc, data: &[u8]) -> Result<()>;

    /// Delete secret resource from repository
    async fn delete_secret_resource(&self, resource_desc: ResourceDesc) -> Result<()>;

    /// List secret resources from repository
    async fn list_secret_resources(&self) -> Result<Vec<ResourceDesc>>;

    /// Reload key material from the backend's configured source without a
    /// restart. Returns the number of keys now active. Backends that do not
    /// manage keys return an error.
    async fn reload_keys(&self) -> Result<usize> {
        bail!("this storage backend does not support key reload")
    }

    /// Re-wrap all encrypted resources onto the backend's current primary key,
    /// so that a rotated-out key can be retired. Backends that do not encrypt
    /// resources return an error.
    async fn rewrap_resources(&self) -> Result<RewrapReport> {
        bail!("this storage backend does not support resource re-wrapping")
    }

    /// Return the backend's current primary public key, PEM-encoded, for clients
    /// that encrypt resources. Backends that do not manage keys return an error.
    async fn current_public_key_pem(&self) -> Result<String> {
        bail!("this storage backend does not expose a public key")
    }

    /// Rotate keys in one shot: generate a new key pair, re-wrap all resources
    /// onto it, and retire the old keys. Backends that do not self-manage keys
    /// return an error.
    async fn rotate_keys(&self) -> Result<RotateReport> {
        bail!("this storage backend does not support key rotation")
    }
}

/// Outcome of a re-wrap (key rotation migration) pass over the repository.
#[derive(Debug, Default, Serialize)]
pub struct RewrapReport {
    /// Total number of resources scanned.
    pub total: usize,
    /// Resources re-wrapped onto the primary key.
    pub rewrapped: usize,
    /// Resources left untouched (plaintext, or already on the primary key).
    pub skipped: usize,
    /// Resources that could not be re-wrapped (e.g. no configured key decrypts
    /// them).
    pub failed: usize,
}

/// Outcome of a one-shot `rotate` operation.
#[derive(Debug, Default, Serialize)]
pub struct RotateReport {
    /// The new primary public key (PEM), ready for clients to encrypt with.
    pub public_key: String,
    /// Resources re-wrapped onto the new key.
    pub rewrapped: usize,
    /// Resources left untouched (plaintext, or already on the new key).
    pub skipped: usize,
    /// Resources that could not be re-wrapped; when non-zero the old keys are
    /// kept (not retired) so those resources stay decryptable.
    pub failed: usize,
    /// Number of old managed keys retired after a clean migration.
    pub retired_keys: usize,
    /// Number of retired keys physically purged from persistent storage
    /// after their grace period (`retired_key_purge_after`) expired. Always
    /// 0 for backends that do not implement deferred purging
    /// (`EncryptedLocalFs` deletes immediately on retire).
    #[serde(default)]
    pub purged_keys: usize,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ResourceDesc {
    pub repository_name: String,
    pub resource_type: String,
    pub resource_tag: String,
}

static CELL: OnceLock<Regex> = OnceLock::new();

impl TryFrom<&str> for ResourceDesc {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        let regex = CELL.get_or_init(|| {
            Regex::new(
                r"^(?<repo>[a-zA-Z0-9_\-]+[a-zA-Z0-9_\-\.]*)\/(?<type>[a-zA-Z0-9_\-]+[a-zA-Z0-9_\-\.]*)\/(?<tag>[a-zA-Z0-9_\-]+[a-zA-Z0-9_\-\.]*)$",
            )
            .unwrap()
        });
        let Some(captures) = regex.captures(value) else {
            bail!("illegal ResourceDesc format.");
        };

        Ok(Self {
            repository_name: captures["repo"].into(),
            resource_type: captures["type"].into(),
            resource_tag: captures["tag"].into(),
        })
    }
}

impl fmt::Display for ResourceDesc {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}/{}/{}",
            self.repository_name, self.resource_type, self.resource_tag
        )
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum RepositoryConfig {
    LocalFs(local_fs::LocalFsRepoDesc),

    #[cfg(feature = "encrypted-local-fs")]
    #[serde(alias = "encrypted_local_fs", alias = "encrypted-local-fs")]
    EncryptedLocalFs(encrypted_local_fs::EncryptedLocalFsRepoDesc),

    #[cfg(feature = "encrypted-db")]
    #[serde(alias = "encrypted_db", alias = "encrypted-db")]
    EncryptedDb(super::encrypted_db::EncryptedDbBackendConfig),

    #[cfg(feature = "aliyun")]
    #[serde(alias = "aliyun")]
    Aliyun(super::aliyun_kms::AliyunKmsBackendConfig),

    #[serde(alias = "external_kms", alias = "external-kms", alias = "ExternalKms")]
    ExternalKms(super::external_kms::ExternalKmsBackendConfig),
}

impl Default for RepositoryConfig {
    fn default() -> Self {
        Self::LocalFs(local_fs::LocalFsRepoDesc::default())
    }
}

impl RepositoryConfig {
    pub(crate) fn env_overrides_present() -> bool {
        let core_present = [
            ENV_RESOURCE_STORAGE_TYPE,
            ENV_RESOURCE_STORAGE_DIR_PATH,
            ENV_RESOURCE_STORAGE_LIBRARY_PATH,
            ENV_RESOURCE_STORAGE_INITIAL_BUFFER_SIZE,
            ENV_RESOURCE_STORAGE_MAX_BUFFER_SIZE,
            ENV_RESOURCE_STORAGE_ERROR_BUFFER_SIZE,
        ]
        .into_iter()
        .any(|name| env::var_os(name).is_some());

        if core_present {
            return true;
        }

        #[cfg(feature = "encrypted-local-fs")]
        if env::var_os(ENV_RESOURCE_STORAGE_PRIVATE_KEY_PATH).is_some() {
            return true;
        }

        #[cfg(feature = "encrypted-db")]
        {
            let encrypted_db_present = [
                ENV_RESOURCE_STORAGE_MASTER_SECRET_PATH,
                ENV_RESOURCE_STORAGE_BUMP_POLL_INTERVAL_MS,
                ENV_RESOURCE_STORAGE_DB_TYPE,
                ENV_RESOURCE_STORAGE_DB_DSN,
                ENV_RESOURCE_STORAGE_DB_PATH,
                ENV_RESOURCE_STORAGE_DB_MAX_OPEN_CONNS,
                ENV_RESOURCE_STORAGE_DB_MAX_IDLE_CONNS,
                ENV_RESOURCE_STORAGE_DB_CONN_MAX_LIFETIME,
                ENV_RESOURCE_STORAGE_RETIRED_KEY_PURGE_AFTER,
            ]
            .into_iter()
            .any(|name| env::var_os(name).is_some());

            if encrypted_db_present {
                return true;
            }
        }

        #[cfg(feature = "aliyun")]
        if super::aliyun_kms::AliyunKmsBackendConfig::env_overrides_present() {
            return true;
        }

        false
    }

    pub(crate) fn from_env_overrides() -> Result<Self> {
        let backend_type = env_string(ENV_RESOURCE_STORAGE_TYPE)?.ok_or_else(|| {
            anyhow!(
                "{ENV_RESOURCE_STORAGE_TYPE} is required when configuring the resource plugin only from environment variables"
            )
        })?;

        let mut config = Self::from_env_type(&backend_type)?;
        config.apply_field_env_overrides()?;
        Ok(config)
    }

    pub(crate) fn apply_env_overrides(&mut self) -> Result<()> {
        if let Some(backend_type) = env_string(ENV_RESOURCE_STORAGE_TYPE)? {
            *self = Self::from_env_type(&backend_type)?;
        }

        self.apply_field_env_overrides()
    }

    fn from_env_type(backend_type: &str) -> Result<Self> {
        let normalized = backend_type
            .trim()
            .to_ascii_lowercase()
            .replace(['_', '-'], "");

        match normalized.as_str() {
            "localfs" => Ok(Self::LocalFs(local_fs::LocalFsRepoDesc::default())),
            "encryptedlocalfs" => {
                #[cfg(feature = "encrypted-local-fs")]
                {
                    Ok(Self::EncryptedLocalFs(
                        encrypted_local_fs::EncryptedLocalFsRepoDesc::default(),
                    ))
                }

                #[cfg(not(feature = "encrypted-local-fs"))]
                {
                    bail!(
                        "{ENV_RESOURCE_STORAGE_TYPE}=EncryptedLocalFs requires the encrypted-local-fs feature"
                    )
                }
            }
            "aliyun" => {
                #[cfg(feature = "aliyun")]
                {
                    Ok(Self::Aliyun(
                        super::aliyun_kms::AliyunKmsBackendConfig::default(),
                    ))
                }

                #[cfg(not(feature = "aliyun"))]
                {
                    bail!("{ENV_RESOURCE_STORAGE_TYPE}=Aliyun requires the aliyun feature")
                }
            }
            "externalkms" => Ok(Self::ExternalKms(
                super::external_kms::ExternalKmsBackendConfig::default(),
            )),
            "encrypteddb" => {
                #[cfg(feature = "encrypted-db")]
                {
                    Ok(Self::EncryptedDb(
                        super::encrypted_db::EncryptedDbBackendConfig::default(),
                    ))
                }
                #[cfg(not(feature = "encrypted-db"))]
                {
                    bail!(
                        "{ENV_RESOURCE_STORAGE_TYPE}=EncryptedDb requires the encrypted-db feature"
                    )
                }
            }
            _ => bail!("unsupported {ENV_RESOURCE_STORAGE_TYPE} value `{backend_type}`"),
        }
    }

    fn apply_field_env_overrides(&mut self) -> Result<()> {
        match self {
            Self::LocalFs(desc) => {
                if let Some(dir_path) = env_string(ENV_RESOURCE_STORAGE_DIR_PATH)? {
                    desc.dir_path = dir_path;
                }
            }
            #[cfg(feature = "encrypted-local-fs")]
            Self::EncryptedLocalFs(desc) => {
                if let Some(dir_path) = env_string(ENV_RESOURCE_STORAGE_DIR_PATH)? {
                    desc.dir_path = dir_path;
                }
                if let Some(private_key_path) = env_string(ENV_RESOURCE_STORAGE_PRIVATE_KEY_PATH)? {
                    desc.private_key_path = private_key_path;
                }
            }
            #[cfg(feature = "encrypted-db")]
            Self::EncryptedDb(config) => {
                if let Some(master_secret_path) =
                    env_string(ENV_RESOURCE_STORAGE_MASTER_SECRET_PATH)?
                {
                    config.master_secret_path = master_secret_path;
                }
                if let Some(bump_poll_interval_ms) =
                    env_parse(ENV_RESOURCE_STORAGE_BUMP_POLL_INTERVAL_MS)?
                {
                    config.bump_poll_interval_ms = bump_poll_interval_ms;
                }
                if let Some(db_type) = env_string(ENV_RESOURCE_STORAGE_DB_TYPE)? {
                    config.database.kind = db_type;
                }
                if let Some(db_dsn) = env_string(ENV_RESOURCE_STORAGE_DB_DSN)? {
                    config.database.dsn = db_dsn;
                }
                if let Some(db_path) = env_string(ENV_RESOURCE_STORAGE_DB_PATH)? {
                    config.database.path = db_path;
                }
                if let Some(max_open_conns) = env_parse(ENV_RESOURCE_STORAGE_DB_MAX_OPEN_CONNS)? {
                    config.database.max_open_conns = max_open_conns;
                }
                if let Some(max_idle_conns) = env_parse(ENV_RESOURCE_STORAGE_DB_MAX_IDLE_CONNS)? {
                    config.database.max_idle_conns = max_idle_conns;
                }
                if let Some(conn_max_lifetime) =
                    env_string(ENV_RESOURCE_STORAGE_DB_CONN_MAX_LIFETIME)?
                {
                    config.database.conn_max_lifetime = conn_max_lifetime;
                }
                if let Some(retired_key_purge_after) =
                    env_string(ENV_RESOURCE_STORAGE_RETIRED_KEY_PURGE_AFTER)?
                {
                    config.database.retired_key_purge_after = retired_key_purge_after;
                }
            }
            #[cfg(feature = "aliyun")]
            Self::Aliyun(config) => {
                config.apply_env_overrides()?;
            }
            Self::ExternalKms(config) => {
                if let Some(library_path) = env_string(ENV_RESOURCE_STORAGE_LIBRARY_PATH)? {
                    config.library_path = library_path;
                }
                if let Some(initial_buffer_size) =
                    env_parse(ENV_RESOURCE_STORAGE_INITIAL_BUFFER_SIZE)?
                {
                    config.initial_buffer_size = initial_buffer_size;
                }
                if let Some(max_buffer_size) = env_parse(ENV_RESOURCE_STORAGE_MAX_BUFFER_SIZE)? {
                    config.max_buffer_size = max_buffer_size;
                }
                if let Some(error_buffer_size) = env_parse(ENV_RESOURCE_STORAGE_ERROR_BUFFER_SIZE)?
                {
                    config.error_buffer_size = error_buffer_size;
                }
            }
        }

        Ok(())
    }
}

fn env_string(name: &str) -> Result<Option<String>> {
    match env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(err) => Err(anyhow!("read environment variable {name}: {err}")),
    }
}

fn env_parse<T>(name: &str) -> Result<Option<T>>
where
    T: FromStr,
    T::Err: Display,
{
    env_string(name)?
        .map(|value| {
            value
                .parse::<T>()
                .map_err(|err| anyhow!("parse environment variable {name}: {err}"))
        })
        .transpose()
}

#[derive(Clone)]
pub struct ResourceStorage {
    backend: RepositoryInstance,
}

impl TryFrom<RepositoryConfig> for ResourceStorage {
    type Error = Error;

    fn try_from(value: RepositoryConfig) -> Result<Self> {
        match value {
            RepositoryConfig::LocalFs(desc) => {
                let backend = local_fs::LocalFs::new(&desc)
                    .context("Failed to initialize Resource Storage")?;
                Ok(Self {
                    backend: Arc::new(backend),
                })
            }
            #[cfg(feature = "encrypted-local-fs")]
            RepositoryConfig::EncryptedLocalFs(desc) => {
                let backend = encrypted_local_fs::EncryptedLocalFs::new(&desc)
                    .context("Failed to initialize encrypted local Resource Storage")?;
                Ok(Self {
                    backend: Arc::new(backend),
                })
            }
            #[cfg(feature = "encrypted-db")]
            RepositoryConfig::EncryptedDb(config) => {
                let backend = super::encrypted_db::EncryptedDb::new(&config)
                    .context("Failed to initialize encrypted DB Resource Storage")?;
                Ok(Self {
                    backend: Arc::new(backend),
                })
            }
            #[cfg(feature = "aliyun")]
            RepositoryConfig::Aliyun(config) => {
                let client = super::aliyun_kms::AliyunKmsBackend::new(&config)?;
                Ok(Self {
                    backend: Arc::new(client),
                })
            }
            RepositoryConfig::ExternalKms(config) => {
                let backend = super::external_kms::ExternalKmsBackend::new(&config)?;
                Ok(Self {
                    backend: Arc::new(backend),
                })
            }
        }
    }
}

impl ResourceStorage {
    pub(crate) async fn set_secret_resource(
        &self,
        resource_desc: ResourceDesc,
        data: &[u8],
    ) -> Result<()> {
        self.backend
            .write_secret_resource(resource_desc, data)
            .await
    }

    pub(crate) async fn get_secret_resource(&self, resource_desc: ResourceDesc) -> Result<Vec<u8>> {
        self.backend.read_secret_resource(resource_desc).await
    }

    pub(crate) async fn delete_secret_resource(&self, resource_desc: ResourceDesc) -> Result<()> {
        self.backend.delete_secret_resource(resource_desc).await
    }

    pub(crate) async fn list_secret_resources(&self) -> Result<Vec<ResourceDesc>> {
        self.backend.list_secret_resources().await
    }

    pub(crate) async fn reload_keys(&self) -> Result<usize> {
        self.backend.reload_keys().await
    }

    pub(crate) async fn rewrap_resources(&self) -> Result<RewrapReport> {
        self.backend.rewrap_resources().await
    }

    pub(crate) async fn current_public_key_pem(&self) -> Result<String> {
        self.backend.current_public_key_pem().await
    }

    pub(crate) async fn rotate_keys(&self) -> Result<RotateReport> {
        self.backend.rotate_keys().await
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::ResourceDesc;

    #[rstest]
    #[case("default/1/2", Some(ResourceDesc {
        repository_name: "default".into(),
        resource_type: "1".into(),
        resource_tag: "2".into(),
    }))]
    #[case("/1/2", None)]
    #[case("/repo/type/tag", None)]
    #[case("repo/type/tag", Some(ResourceDesc {
        repository_name: "repo".into(),
        resource_type: "type".into(),
        resource_tag: "tag".into(),
    }))]
    #[case("1/2", None)]
    #[case("123--_default/1Abff-_/___-afds44BC", Some(ResourceDesc {
        repository_name: "123--_default".into(),
        resource_type: "1Abff-_".into(),
        resource_tag: "___-afds44BC".into(),
    }))]
    #[case("1.ok/2ok./3...", Some(ResourceDesc {
        repository_name: "1.ok".into(),
        resource_type: "2ok.".into(),
        resource_tag: "3...".into(),
    }))]
    #[case(".1.ok/2ok./3...", None)]
    #[case("1.ok/.2ok./3...", None)]
    #[case("1.ok/2ok./.3...", None)]
    fn parse_resource_desc(#[case] desc: &str, #[case] expected: Option<ResourceDesc>) {
        let parsed = ResourceDesc::try_from(desc);
        if expected.is_none() {
            assert!(parsed.is_err());
        } else {
            assert_eq!(parsed.unwrap(), expected.unwrap());
        }
    }
}
