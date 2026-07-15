// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::admin::config::{AdminConfig, DEFAULT_INSECURE_API};
use crate::plugins::{PluginsConfig, RepositoryConfig};
use crate::policy_engine::PolicyEngineConfig;
use crate::token::AttestationTokenVerifierConfig;
use anyhow::anyhow;
use clap::Parser;
use config::{Config, File};
use const_format::concatcp;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

const DEFAULT_INSECURE_HTTP: bool = false;
const DEFAULT_SOCKET: &str = "127.0.0.1:8080";
const DEFAULT_PAYLOAD_REQUEST_SIZE: u32 = 2;

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct HttpServerConfig {
    /// Socket addresses (IP:port) to listen on, e.g. 127.0.0.1:8080.
    pub sockets: Vec<SocketAddr>,

    /// HTTPS private key.
    pub private_key: Option<PathBuf>,

    /// HTTPS Certificate.
    pub certificate: Option<PathBuf>,

    /// Insecure HTTP.
    /// WARNING: Using this option makes the HTTP connection insecure.
    pub insecure_http: bool,

    /// Request payload size in MB
    pub payload_request_size: u32,
}

impl Default for HttpServerConfig {
    fn default() -> Self {
        Self {
            sockets: vec![DEFAULT_SOCKET.parse().expect("unexpected parse error")],
            private_key: None,
            certificate: None,
            insecure_http: DEFAULT_INSECURE_HTTP,
            payload_request_size: DEFAULT_PAYLOAD_REQUEST_SIZE,
        }
    }
}

/// Contains all configurable KBS properties.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct KbsConfig {
    /// Attestation token result broker config.
    #[serde(default)]
    pub attestation_token: AttestationTokenVerifierConfig,

    /// Configuration for the Attestation Service.
    #[cfg(feature = "as")]
    #[serde(default)]
    pub attestation_service: crate::attestation::config::AttestationConfig,

    /// Configuration for the KBS Http Server
    pub http_server: HttpServerConfig,

    /// Configuration for the KBS admin API
    pub admin: AdminConfig,

    /// Policy engine configuration used for evaluating whether the TCB status has access to
    /// specific resources.
    #[serde(default)]
    pub policy_engine: PolicyEngineConfig,

    #[serde(default)]
    pub plugins: Vec<PluginsConfig>,
}

/// The commit ref of the config documentation in the openanolis/trustee repository.
const DOC_COMMIT_REF: &str = "6cae09a2";

const CONFIG_DOC: &str = concatcp!(
    "https://github.com/openanolis/trustee/blob/",
    DOC_COMMIT_REF,
    "/kbs/docs/config.md"
);

/// Best-effort mapping from a config error string to the relevant section anchor
/// in the KBS configuration documentation.
fn config_section_hint(err: &str) -> Option<&'static str> {
    if err.contains("admin") {
        return Some(concatcp!(CONFIG_DOC, "#admin-api-configuration"));
    }
    if err.contains("attestation_service") {
        return Some(concatcp!(CONFIG_DOC, "#attestation-configuration"));
    }
    if err.contains("attestation_token") {
        return Some(concatcp!(CONFIG_DOC, "#attestation-token-configuration"));
    }
    if err.contains("http_server") {
        return Some(concatcp!(CONFIG_DOC, "#http-server-configuration"));
    }
    if err.contains("policy_engine") {
        return Some(concatcp!(CONFIG_DOC, "#policy-engine-configuration"));
    }
    if err.contains("plugins") {
        return Some(concatcp!(CONFIG_DOC, "#plugins-configuration"));
    }
    None
}

fn format_config_load_error(config_path: &Path, err: impl std::fmt::Display) -> anyhow::Error {
    let err_str = err.to_string();
    let mut message = format!(
        "failed to load configuration file {}: {err_str}",
        config_path.display()
    );
    if let Some(doc) = config_section_hint(&err_str) {
        message.push_str("\nSee ");
        message.push_str(doc);
        message.push('.');
    }
    anyhow!(message)
}

impl KbsConfig {
    fn apply_resource_plugin_env_overrides(&mut self) -> anyhow::Result<()> {
        if !RepositoryConfig::env_overrides_present() {
            return Ok(());
        }

        let mut found_resource_plugin = false;
        for plugin in &mut self.plugins {
            if let PluginsConfig::ResourceStorage(repository_config) = plugin {
                repository_config.apply_env_overrides()?;
                found_resource_plugin = true;
            }
        }

        if !found_resource_plugin {
            let repository_config = RepositoryConfig::from_env_overrides()?;
            self.plugins
                .push(PluginsConfig::ResourceStorage(repository_config));
        }

        Ok(())
    }
}

impl TryFrom<&Path> for KbsConfig {
    type Error = anyhow::Error;

    /// Load `Config` from a configuration file. Supported formats are all formats supported by the
    /// `config` crate. See `KbsConfig` for schema information.
    fn try_from(config_path: &Path) -> Result<Self, Self::Error> {
        let c = Config::builder()
            .set_default("admin.insecure_api", DEFAULT_INSECURE_API)?
            .set_default("http_server.insecure_http", DEFAULT_INSECURE_HTTP)?
            .set_default("http_server.sockets", vec![DEFAULT_SOCKET])?
            .set_default(
                "http_server.payload_request_size",
                DEFAULT_PAYLOAD_REQUEST_SIZE,
            )?
            .set_default("attestation_service.policy_ids", Vec::<&str>::new())?
            .add_source(File::with_name(config_path.to_str().unwrap()))
            .build()
            .map_err(|e| format_config_load_error(config_path, e))?;

        let mut kbs_config: Self = c
            .try_deserialize()
            .map_err(|e| format_config_load_error(config_path, e))?;
        kbs_config.apply_resource_plugin_env_overrides()?;
        Ok(kbs_config)
    }
}

/// KBS command-line arguments.
#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Path to a KBS config file. Supported formats: TOML, YAML, JSON and possibly other formats
    /// supported by the `config` crate.
    #[arg(short, long, env = "KBS_CONFIG_FILE")]
    pub config_file: String,
}

#[cfg(test)]
mod tests {
    use std::{
        env,
        ffi::OsString,
        path::{Path, PathBuf},
    };

    use crate::{
        admin::config::AdminConfig,
        config::{
            HttpServerConfig, DEFAULT_INSECURE_API, DEFAULT_INSECURE_HTTP,
            DEFAULT_PAYLOAD_REQUEST_SIZE, DEFAULT_SOCKET,
        },
        plugins::{
            implementations::{
                resource::{external_kms::ExternalKmsBackendConfig, local_fs::LocalFsRepoDesc},
                RepositoryConfig, SampleConfig,
            },
            PluginsConfig,
        },
        policy_engine::{PolicyEngineConfig, DEFAULT_POLICY_PATH},
        token::AttestationTokenVerifierConfig,
    };

    use super::KbsConfig;

    #[cfg(feature = "coco-as-builtin")]
    use attestation_service::{
        rvps::{grpc::RvpsRemoteConfig, RvpsConfig, RvpsCrateConfig},
        token::{simple, AttestationTokenConfig, COCO_AS_ISSUER_NAME, DEFAULT_TOKEN_DURATION},
    };

    use reference_value_provider_service::storage::{local_fs, ReferenceValueStorageConfig};

    use rstest::rstest;
    use serial_test::serial;

    const RESOURCE_STORAGE_ENV_VARS: &[&str] = &[
        "KBS_RESOURCE_STORAGE_TYPE",
        "KBS_RESOURCE_STORAGE_DIR_PATH",
        "KBS_RESOURCE_STORAGE_PRIVATE_KEY_PATH",
        "KBS_RESOURCE_STORAGE_LIBRARY_PATH",
        "KBS_RESOURCE_STORAGE_INITIAL_BUFFER_SIZE",
        "KBS_RESOURCE_STORAGE_MAX_BUFFER_SIZE",
        "KBS_RESOURCE_STORAGE_ERROR_BUFFER_SIZE",
        "KBS_RESOURCE_STORAGE_MASTER_SECRET_PATH",
        "KBS_RESOURCE_STORAGE_BUMP_POLL_INTERVAL_MS",
        "KBS_RESOURCE_STORAGE_DB_TYPE",
        "KBS_RESOURCE_STORAGE_DB_DSN",
        "KBS_RESOURCE_STORAGE_DB_PATH",
        "KBS_RESOURCE_STORAGE_DB_MAX_OPEN_CONNS",
        "KBS_RESOURCE_STORAGE_DB_MAX_IDLE_CONNS",
        "KBS_RESOURCE_STORAGE_DB_CONN_MAX_LIFETIME",
        "KBS_RESOURCE_STORAGE_RETIRED_KEY_PURGE_AFTER",
        "KBS_RESOURCE_STORAGE_ALIYUN_CLIENT_KEY",
        "KBS_RESOURCE_STORAGE_ALIYUN_KMS_INSTANCE_ID",
        "KBS_RESOURCE_STORAGE_ALIYUN_PASSWORD",
        "KBS_RESOURCE_STORAGE_ALIYUN_CERT_PEM",
        "KBS_RESOURCE_STORAGE_ALIYUN_ACCESS_KEY_ID",
        "KBS_RESOURCE_STORAGE_ALIYUN_ACCESS_KEY_SECRET",
        "KBS_RESOURCE_STORAGE_ALIYUN_REGION_ID",
        "KBS_RESOURCE_STORAGE_ALIYUN_ENDPOINT",
        "KBS_RESOURCE_STORAGE_ALIYUN_INSECURE_SKIP_TLS_VERIFY",
    ];

    struct EnvGuard {
        saved: Vec<(&'static str, Option<OsString>)>,
    }

    impl EnvGuard {
        fn clear() -> Self {
            let saved = RESOURCE_STORAGE_ENV_VARS
                .iter()
                .map(|name| {
                    let value = env::var_os(name);
                    env::remove_var(name);
                    (*name, value)
                })
                .collect();

            Self { saved }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (name, value) in &self.saved {
                match value {
                    Some(value) => env::set_var(name, value),
                    None => env::remove_var(name),
                }
            }
        }
    }

    #[rstest]
    #[case("test_data/configs/coco-as-grpc-1.toml",         KbsConfig {
        attestation_token: AttestationTokenVerifierConfig {
            trusted_certs_paths: vec!["/etc/ca".into(), "/etc/ca2".into()],
            insecure_key: false,
            trusted_jwk_sets: vec![],
            extra_teekey_paths: vec![],
        },
        #[cfg(feature = "coco-as-grpc")]
        attestation_service: crate::attestation::config::AttestationConfig {
            attestation_service:
                crate::attestation::config::AttestationServiceConfig::CoCoASGrpc(
                    crate::attestation::coco::grpc::GrpcConfig {
                        as_addr: "http://127.0.0.1:50001".into(),
                        pool_size: 100,
                    },
                ),
            timeout: 600,
        },
        http_server: HttpServerConfig {
            sockets: vec!["0.0.0.0:8080".parse().unwrap()],
            private_key: Some("/etc/kbs-private.key".into()),
            certificate: Some("/etc/kbs-cert.pem".into()),
            insecure_http: false,
            payload_request_size: DEFAULT_PAYLOAD_REQUEST_SIZE,
        },
        admin: AdminConfig {
            auth_public_key: Some(PathBuf::from("/etc/kbs-admin.pub")),
            insecure_api: false,
        },
        policy_engine: PolicyEngineConfig {
            policy_path: PathBuf::from("/etc/kbs-policy.rego"),
        },
        plugins: vec![PluginsConfig::Sample(SampleConfig {
            item: "value1".into(),
        }),
        PluginsConfig::ResourceStorage(RepositoryConfig::LocalFs(
            LocalFsRepoDesc {
                dir_path: "/tmp/kbs-resource".into(),
            },
        ))],
    })]
    #[case("test_data/configs/coco-as-builtin-1.toml",         KbsConfig {
        attestation_token: AttestationTokenVerifierConfig {
            trusted_certs_paths: vec![],
            insecure_key: false,
            trusted_jwk_sets: vec![],
            extra_teekey_paths: vec![],
        },
        #[cfg(feature = "coco-as-builtin")]
        attestation_service: crate::attestation::config::AttestationConfig {
            attestation_service:
                crate::attestation::config::AttestationServiceConfig::CoCoASBuiltIn(
                    attestation_service::config::Config {
                        work_dir: "/opt/coco/attestation-service".into(),
                        rvps_config: RvpsConfig::GrpcRemote(RvpsRemoteConfig {
                            address: "http://127.0.0.1:50003".into(),
                        }),
                        attestation_token_broker: AttestationTokenConfig::Simple(simple::Configuration {
                            duration_min: DEFAULT_TOKEN_DURATION,
                            issuer_name: COCO_AS_ISSUER_NAME.into(),
                            signer: None,
                            ..Default::default()
                        }),
                        challenge_key_path: None,
                    }
                ),
            timeout: crate::attestation::config::DEFAULT_TIMEOUT,
        },
        http_server: HttpServerConfig {
            sockets: vec![DEFAULT_SOCKET.parse().unwrap()],
            private_key: None,
            certificate: None,
            insecure_http: DEFAULT_INSECURE_HTTP,
            payload_request_size: DEFAULT_PAYLOAD_REQUEST_SIZE,
        },
        admin: AdminConfig {
            auth_public_key: None,
            insecure_api: DEFAULT_INSECURE_API,
        },
        policy_engine: PolicyEngineConfig {
            policy_path: DEFAULT_POLICY_PATH.into(),
        },
        plugins: Vec::new(),
    })]
    #[case("test_data/configs/coco-as-grpc-2.toml",         KbsConfig {
        attestation_token: AttestationTokenVerifierConfig {
            ..Default::default()
        },
        #[cfg(feature = "coco-as-grpc")]
        attestation_service: crate::attestation::config::AttestationConfig {
            attestation_service:
                crate::attestation::config::AttestationServiceConfig::CoCoASGrpc(
                    crate::attestation::coco::grpc::GrpcConfig {
                        as_addr: "http://as:50004".into(),
                        pool_size: crate::attestation::coco::grpc::DEFAULT_POOL_SIZE,
                    },
                ),
            timeout: crate::attestation::config::DEFAULT_TIMEOUT,
        },
        http_server: HttpServerConfig {
            sockets: vec!["0.0.0.0:8080".parse().unwrap()],
            private_key: None,
            certificate: None,
            insecure_http: true,
            payload_request_size: DEFAULT_PAYLOAD_REQUEST_SIZE,
        },
        admin: AdminConfig {
            auth_public_key: Some(PathBuf::from("/opt/confidential-containers/kbs/user-keys/public.pub")),
            insecure_api: DEFAULT_INSECURE_API,
        },
        policy_engine: PolicyEngineConfig::default(),
        plugins: Vec::new(),
    })]
    #[case("test_data/configs/coco-as-builtin-2.toml",         KbsConfig {
        attestation_token: AttestationTokenVerifierConfig {
            trusted_certs_paths: vec![],
            insecure_key: false,
            trusted_jwk_sets: vec![],
            extra_teekey_paths: vec![],
        },
        #[cfg(feature = "coco-as-builtin")]
        attestation_service: crate::attestation::config::AttestationConfig {
            attestation_service:
                crate::attestation::config::AttestationServiceConfig::CoCoASBuiltIn(
                    attestation_service::config::Config {
                        work_dir: "/opt/confidential-containers/attestation-service".into(),
                        rvps_config: RvpsConfig::BuiltIn(RvpsCrateConfig{
                            storage: ReferenceValueStorageConfig::LocalFs(local_fs::Config{
                                file_path: "/opt/confidential-containers/attestation-service/reference_values".into(),
                            }),
                        }),
                        attestation_token_broker: AttestationTokenConfig::Simple(simple::Configuration{
                            duration_min: 5,
                            ..Default::default()
                        }),
                        challenge_key_path: None,
                    }
                ),
            timeout: crate::attestation::config::DEFAULT_TIMEOUT,
        },
        http_server: HttpServerConfig {
            sockets: vec!["0.0.0.0:8080".parse().unwrap()],
            private_key: None,
            certificate: None,
            insecure_http: true,
            payload_request_size: DEFAULT_PAYLOAD_REQUEST_SIZE,
        },
        admin: AdminConfig {
            auth_public_key: Some("/kbs/kbs.pem".into()),
            insecure_api: DEFAULT_INSECURE_API,
        },
        policy_engine: PolicyEngineConfig::default(),
        plugins: Vec::new(),
    })]
    #[case("test_data/configs/coco-as-grpc-3.toml",         KbsConfig {
        attestation_token: AttestationTokenVerifierConfig {
            ..Default::default()
        },
        #[cfg(feature = "coco-as-grpc")]
        attestation_service: crate::attestation::config::AttestationConfig {
            attestation_service:
                crate::attestation::config::AttestationServiceConfig::CoCoASGrpc(
                    crate::attestation::coco::grpc::GrpcConfig {
                        as_addr: "http://127.0.0.1:50004".into(),
                        pool_size: 100,
                    },
                ),
            timeout: crate::attestation::config::DEFAULT_TIMEOUT,
        },
        http_server: HttpServerConfig {
            insecure_http: true,
            ..Default::default()
        },
        admin: AdminConfig {
            insecure_api: true,
            ..Default::default()
        },
        policy_engine: PolicyEngineConfig::default(),
        plugins: Vec::new(),
    })]
    #[case("test_data/configs/coco-as-builtin-3.toml",         KbsConfig {
        attestation_token: AttestationTokenVerifierConfig {
            trusted_certs_paths: vec![],
            insecure_key: false,
            trusted_jwk_sets: vec![],
            extra_teekey_paths: vec![],
        },
        #[cfg(feature = "coco-as-builtin")]
        attestation_service: crate::attestation::config::AttestationConfig {
            attestation_service:
                crate::attestation::config::AttestationServiceConfig::CoCoASBuiltIn(
                    attestation_service::config::Config {
                        work_dir: "/opt/confidential-containers/attestation-service".into(),
                        rvps_config: RvpsConfig::BuiltIn(RvpsCrateConfig::default()),
                        attestation_token_broker: AttestationTokenConfig::Simple(simple::Configuration {
                            duration_min: 5,
                            policy_dir: "/opt/confidential-containers/attestation-service/simple-policies".into(),
                            ..Default::default()
                        }),
                        challenge_key_path: None,
                    }
                ),
            timeout: crate::attestation::config::DEFAULT_TIMEOUT,
        },
        http_server: HttpServerConfig {
            insecure_http: true,
            ..Default::default()
        },
        admin: AdminConfig {
            insecure_api: true,
            ..Default::default()
        },
        policy_engine: PolicyEngineConfig {
            policy_path: "/opa/confidential-containers/kbs/policy.rego".into(),
        },
        plugins: vec![
        PluginsConfig::ResourceStorage(RepositoryConfig::LocalFs(
            LocalFsRepoDesc {
                dir_path: "/opt/confidential-containers/kbs/repository".into(),
            },
        ))],
    })]
    #[serial]
    fn read_config(#[case] config_path: &str, #[case] expected: KbsConfig) {
        let _env = EnvGuard::clear();
        let config = KbsConfig::try_from(Path::new(config_path)).unwrap();
        assert_eq!(config, expected, "case {config_path}");
    }

    #[test]
    #[serial]
    fn resource_storage_env_overrides_existing_local_fs() {
        let _env = EnvGuard::clear();
        env::set_var("KBS_RESOURCE_STORAGE_DIR_PATH", "/env/kbs-resource");

        let config =
            KbsConfig::try_from(Path::new("test_data/configs/coco-as-grpc-1.toml")).unwrap();

        assert_eq!(
            config.plugins[1],
            PluginsConfig::ResourceStorage(RepositoryConfig::LocalFs(LocalFsRepoDesc {
                dir_path: "/env/kbs-resource".into(),
            }))
        );
    }

    #[test]
    #[serial]
    fn resource_storage_env_replaces_existing_backend_type() {
        let _env = EnvGuard::clear();
        env::set_var("KBS_RESOURCE_STORAGE_TYPE", "ExternalKms");
        env::set_var("KBS_RESOURCE_STORAGE_LIBRARY_PATH", "/opt/kms/libcustom.so");
        env::set_var("KBS_RESOURCE_STORAGE_INITIAL_BUFFER_SIZE", "128");
        env::set_var("KBS_RESOURCE_STORAGE_MAX_BUFFER_SIZE", "8192");
        env::set_var("KBS_RESOURCE_STORAGE_ERROR_BUFFER_SIZE", "256");

        let config =
            KbsConfig::try_from(Path::new("test_data/configs/coco-as-grpc-1.toml")).unwrap();

        assert_eq!(
            config.plugins[1],
            PluginsConfig::ResourceStorage(RepositoryConfig::ExternalKms(
                ExternalKmsBackendConfig {
                    library_path: "/opt/kms/libcustom.so".into(),
                    initial_buffer_size: 128,
                    max_buffer_size: 8192,
                    error_buffer_size: 256,
                }
            ))
        );
    }

    #[test]
    #[serial]
    fn resource_storage_env_adds_resource_plugin() {
        let _env = EnvGuard::clear();
        env::set_var("KBS_RESOURCE_STORAGE_TYPE", "LocalFs");
        env::set_var("KBS_RESOURCE_STORAGE_DIR_PATH", "/env/kbs-resource");

        let config =
            KbsConfig::try_from(Path::new("test_data/configs/coco-as-grpc-3.toml")).unwrap();

        assert_eq!(
            config.plugins,
            vec![PluginsConfig::ResourceStorage(RepositoryConfig::LocalFs(
                LocalFsRepoDesc {
                    dir_path: "/env/kbs-resource".into(),
                }
            ))]
        );
    }

    #[test]
    #[serial]
    fn resource_storage_env_requires_type_when_adding_plugin() {
        let _env = EnvGuard::clear();
        env::set_var("KBS_RESOURCE_STORAGE_DIR_PATH", "/env/kbs-resource");

        let err = KbsConfig::try_from(Path::new("test_data/configs/coco-as-grpc-3.toml"))
            .expect_err("resource storage type should be required");

        assert!(err
            .to_string()
            .contains("KBS_RESOURCE_STORAGE_TYPE is required"));
    }

    #[cfg(feature = "encrypted-db")]
    #[test]
    #[serial]
    fn resource_storage_env_overrides_existing_encrypted_db() {
        use crate::plugins::implementations::resource::encrypted_db::{
            DatabaseConfig, EncryptedDbBackendConfig,
        };

        let _env = EnvGuard::clear();
        env::set_var(
            "KBS_RESOURCE_STORAGE_DB_DSN",
            "mysql://kbs:env-pass@db.env:3306/trustee_kbs",
        );
        env::set_var(
            "KBS_RESOURCE_STORAGE_MASTER_SECRET_PATH",
            "/env/master.passphrase",
        );
        env::set_var("KBS_RESOURCE_STORAGE_BUMP_POLL_INTERVAL_MS", "1234");
        env::set_var("KBS_RESOURCE_STORAGE_DB_MAX_OPEN_CONNS", "42");
        env::set_var("KBS_RESOURCE_STORAGE_DB_CONN_MAX_LIFETIME", "30m");
        env::set_var("KBS_RESOURCE_STORAGE_RETIRED_KEY_PURGE_AFTER", "7d");

        let config = KbsConfig::try_from(Path::new(
            "test_data/configs/coco-as-grpc-encrypted-db.toml",
        ))
        .unwrap();

        assert_eq!(
            config.plugins[0],
            PluginsConfig::ResourceStorage(RepositoryConfig::EncryptedDb(
                EncryptedDbBackendConfig {
                    master_secret_path: "/env/master.passphrase".into(),
                    bump_poll_interval_ms: 1234,
                    database: DatabaseConfig {
                        kind: "mysql".into(),
                        dsn: "mysql://kbs:env-pass@db.env:3306/trustee_kbs".into(),
                        path: "".into(),
                        max_open_conns: 42,
                        max_idle_conns: 5,
                        conn_max_lifetime: "30m".into(),
                        retired_key_purge_after: "7d".into(),
                    },
                }
            ))
        );
    }

    #[cfg(feature = "encrypted-db")]
    #[test]
    #[serial]
    fn resource_storage_env_adds_encrypted_db_plugin() {
        use crate::plugins::implementations::resource::encrypted_db::{
            DatabaseConfig, EncryptedDbBackendConfig,
        };

        let _env = EnvGuard::clear();
        env::set_var("KBS_RESOURCE_STORAGE_TYPE", "EncryptedDb");
        env::set_var("KBS_RESOURCE_STORAGE_DB_TYPE", "mysql");
        env::set_var(
            "KBS_RESOURCE_STORAGE_DB_DSN",
            "mysql://kbs:env-pass@db.env:3306/trustee_kbs",
        );
        env::set_var(
            "KBS_RESOURCE_STORAGE_MASTER_SECRET_PATH",
            "/env/master.passphrase",
        );

        let config =
            KbsConfig::try_from(Path::new("test_data/configs/coco-as-grpc-3.toml")).unwrap();

        assert_eq!(
            config.plugins,
            vec![PluginsConfig::ResourceStorage(
                RepositoryConfig::EncryptedDb(EncryptedDbBackendConfig {
                    master_secret_path: "/env/master.passphrase".into(),
                    bump_poll_interval_ms: 0,
                    database: DatabaseConfig {
                        kind: "mysql".into(),
                        dsn: "mysql://kbs:env-pass@db.env:3306/trustee_kbs".into(),
                        path: "".into(),
                        max_open_conns: 0,
                        max_idle_conns: 0,
                        conn_max_lifetime: "".into(),
                        retired_key_purge_after: "".into(),
                    },
                })
            )]
        );
    }
}
