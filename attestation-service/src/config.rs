use crate::rvps::RvpsConfig;
use crate::token::AttestationTokenConfig;

use serde::Deserialize;
use std::fs::File;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Environment macro for Attestation Service work dir.
const AS_WORK_DIR: &str = "AS_WORK_DIR";
pub const DEFAULT_WORK_DIR: &str = "/opt/confidential-containers/attestation-service";
pub const DEFAULT_ARTIFACT_SERVER_ADDRESS: &str = "https://attest-pre.aliyuncs.com";

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Config {
    /// The location for Attestation Service to store data.
    #[serde(default = "default_work_dir")]
    pub work_dir: PathBuf,

    /// Configurations for RVPS.
    #[serde(default)]
    pub rvps_config: RvpsConfig,

    /// Artifact Server address used by policy `query_artifact_server`.
    #[serde(default = "default_artifact_server_address")]
    pub artifact_server_address: String,

    /// The Attestation Result Token Broker Config
    #[serde(default)]
    pub attestation_token_broker: AttestationTokenConfig,

    /// Optional path to the RSA private key used to sign and verify
    /// attestation challenge (nonce) tokens. When unset, a built-in default
    /// path (`/etc/trustee/attestation-service/nonce_token_issuer/key.pem`)
    /// is used, and the key is generated on first use if it does not exist.
    #[serde(default)]
    pub challenge_key_path: Option<PathBuf>,
}

fn default_work_dir() -> PathBuf {
    PathBuf::from(std::env::var(AS_WORK_DIR).unwrap_or_else(|_| DEFAULT_WORK_DIR.to_string()))
}

fn default_artifact_server_address() -> String {
    DEFAULT_ARTIFACT_SERVER_ADDRESS.to_string()
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("io error: {0}")]
    IO(#[from] std::io::Error),
    #[error("failed to parse AS config file: {0}")]
    FileParse(#[source] std::io::Error),
    #[error("failed to parse AS config file: {0}")]
    JsonFileParse(#[source] serde_json::Error),
    #[error("Illegal format of the content of the configuration file: {0}")]
    SerdeJson(#[from] serde_json::Error),
}

impl Default for Config {
    // Construct a default instance of `Config`
    fn default() -> Config {
        Config {
            work_dir: default_work_dir(),
            rvps_config: RvpsConfig::default(),
            artifact_server_address: default_artifact_server_address(),
            attestation_token_broker: AttestationTokenConfig::default(),
            challenge_key_path: None,
        }
    }
}

impl TryFrom<&Path> for Config {
    /// Load `Config` from a configuration file like:
    ///    {
    ///        "work_dir": "/var/lib/attestation-service/",
    ///        "policy_engine": "opa",
    ///        "rvps_config": {
    ///            "storage": {
    ///                "type": "LocalFs"
    ///            }
    ///            "store_config": {},
    ///        },
    ///        "artifact_server_address": "https://attest-pre.aliyuncs.com",
    ///        "attestation_token_broker": {
    ///            "type": "Ear",
    ///            "duration_min": 5
    ///        }
    ///    }
    type Error = ConfigError;
    fn try_from(config_path: &Path) -> Result<Self, ConfigError> {
        let file = File::open(config_path)?;
        serde_json::from_reader::<File, Config>(file).map_err(ConfigError::JsonFileParse)
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use std::path::PathBuf;

    use super::{Config, DEFAULT_ARTIFACT_SERVER_ADDRESS};
    use crate::rvps::RvpsCrateConfig;
    use crate::{
        rvps::RvpsConfig,
        token::{ear_broker, oidc, simple, AttestationTokenConfig},
    };
    use reference_value_provider_service::storage::{local_fs, ReferenceValueStorageConfig};

    #[rstest]
    #[case("./tests/configs/example1.json", Config {
        work_dir: PathBuf::from("/var/lib/attestation-service/"),
        rvps_config: RvpsConfig::BuiltIn(RvpsCrateConfig {
            storage: ReferenceValueStorageConfig::LocalFs(local_fs::Config::default()),
        }),
        attestation_token_broker: AttestationTokenConfig::Simple(simple::Configuration {
            settings: simple::TokenBrokerSettings {
                duration_min: 5,
                issuer_name: "test".into(),
            },
            signer: None,
            policy_dir: "/var/lib/attestation-service/policies".into(),
        }),
        challenge_key_path: None,
        artifact_server_address: DEFAULT_ARTIFACT_SERVER_ADDRESS.to_string(),
    })]
    #[case("./tests/configs/example2.json", Config {
        work_dir: PathBuf::from("/var/lib/attestation-service/"),
        rvps_config: RvpsConfig::BuiltIn(RvpsCrateConfig {
            storage: ReferenceValueStorageConfig::LocalFs(local_fs::Config::default()),
        }),
        attestation_token_broker: AttestationTokenConfig::Simple(simple::Configuration {
            settings: simple::TokenBrokerSettings {
                duration_min: 5,
                issuer_name: "test".into(),
            },
            policy_dir: "/var/lib/attestation-service/policies".into(),
            signer: Some(simple::SignerConfig {
                key_path: "/etc/key".into(),
                cert_url: Some("https://example.io".into()),
                cert_path: Some("/etc/cert.pem".into())
            }),
        }),
        challenge_key_path: None,
        artifact_server_address: DEFAULT_ARTIFACT_SERVER_ADDRESS.to_string(),
    })]
    #[case("./tests/configs/example3.json", Config {
        work_dir: PathBuf::from("/var/lib/attestation-service/"),
        rvps_config: RvpsConfig::BuiltIn(RvpsCrateConfig {
            storage: ReferenceValueStorageConfig::LocalFs(local_fs::Config::default()),
        }),
        attestation_token_broker: AttestationTokenConfig::Ear(ear_broker::Configuration {
            settings: ear_broker::TokenBrokerSettings {
                duration_min: 5,
                issuer_name: "test".into(),
                developer_name: "someone".into(),
                build_name: "0.1.0".into(),
                profile_name: "tag:github.com,2024:confidential-containers/Trustee".into(),
            },
            signer: None,
            policy_dir: "/var/lib/attestation-service/policies".into(),
        }),
        challenge_key_path: None,
        artifact_server_address: DEFAULT_ARTIFACT_SERVER_ADDRESS.to_string(),
    })]
    #[case("./tests/configs/example4.json", Config {
        work_dir: PathBuf::from("/var/lib/attestation-service/"),
        rvps_config: RvpsConfig::BuiltIn(RvpsCrateConfig {
            storage: ReferenceValueStorageConfig::LocalFs(local_fs::Config::default()),
        }),
        attestation_token_broker: AttestationTokenConfig::Ear(ear_broker::Configuration {
            settings: ear_broker::TokenBrokerSettings {
                duration_min: 5,
                issuer_name: "test".into(),
                developer_name: "someone".into(),
                build_name: "0.1.0".into(),
                profile_name: "tag:github.com,2024:confidential-containers/Trustee".into(),
            },
            policy_dir: "/var/lib/attestation-service/policies".into(),
            signer: Some(ear_broker::SignerConfig {
                key_path: "/etc/key".into(),
                cert_url: Some("https://example.io".into()),
                cert_path: Some("/etc/cert.pem".into())
            }),
        }),
        challenge_key_path: None,
        artifact_server_address: DEFAULT_ARTIFACT_SERVER_ADDRESS.to_string(),
    })]
    #[case("./tests/configs/example5.json", Config {
        work_dir: PathBuf::from("/var/lib/attestation-service/"),
        rvps_config: RvpsConfig::BuiltIn(RvpsCrateConfig {
            storage: ReferenceValueStorageConfig::LocalFs(local_fs::Config::default()),
        }),
        attestation_token_broker: AttestationTokenConfig::OIDC(oidc::Configuration {
            settings: oidc::TokenBrokerSettings {
                duration_min: 5,
                issuer_name: "test".into(),
                oid_config: Some(oidc::OpenIDConfig {
                    issuer: "https://example.com".into(),
                    jwks_uri: "https://example.com/jwks".into(),
                    id_token_signing_alg_values_supported: vec!["RS256".into()],
                    audience: "sigstore".into(),
                    sub_claims: Some(vec!["sub1".into()]),
                    additional_claims: Some(vec!["extra1".into()]),
                }),
            },
            signer: Some(oidc::SignerConfig {
                key_path: "/etc/key".into(),
                cert_url: Some("https://example.io".into()),
                cert_path: Some("/etc/cert.pem".into()),
            }),
            policy_dir: "/var/lib/attestation-service/policies".into(),
        }),
        challenge_key_path: None,
        artifact_server_address: DEFAULT_ARTIFACT_SERVER_ADDRESS.to_string(),
    })]
    fn read_config(#[case] config: &str, #[case] expected: Config) {
        let config = std::fs::read_to_string(config).unwrap();
        let config: Config = serde_json::from_str(&config).unwrap();
        assert_eq!(config, expected);
    }

    // Backward compatibility: the refactor moved `duration_min` / `issuer_name`
    // (and ear's `developer_name` / `build_name` / `profile_name`, oidc's
    // `oid_config`) into a nested `settings: TokenBrokerSettings` sub-struct.
    // `#[serde(flatten)]` on `settings` must keep the *pre-refactor* flat
    // JSON/TOML config format working. These inline cases assert that a flat
    // broker config still deserializes into the nested struct for every broker
    // variant, without relying on the on-disk example fixtures.
    #[test]
    fn backward_compat_flat_broker_json_deserializes_into_nested_settings() {
        // Simple: flat `duration_min` / `issuer_name` → `settings.*`.
        let json = r#"{
            "type": "Simple",
            "duration_min": 9,
            "issuer_name": "flat-issuer",
            "policy_dir": "/p"
        }"#;
        let cfg: AttestationTokenConfig = serde_json::from_str(json).unwrap();
        let simple::Configuration {
            settings,
            signer,
            policy_dir,
            ..
        } = match cfg {
            AttestationTokenConfig::Simple(c) => c,
            _ => unreachable!(),
        };
        assert_eq!(settings.duration_min, 9);
        assert_eq!(settings.issuer_name, "flat-issuer");
        assert_eq!(policy_dir, "/p");
        assert!(signer.is_none());

        // Ear: flat `developer_name` / `build_name` / `profile_name` → `settings.*`.
        let json = r#"{
            "type": "Ear",
            "duration_min": 9,
            "issuer_name": "flat-issuer",
            "developer_name": "dev",
            "build_name": "build",
            "profile_name": "prof",
            "policy_dir": "/p"
        }"#;
        let cfg: AttestationTokenConfig = serde_json::from_str(json).unwrap();
        let ear_broker::Configuration {
            settings,
            signer,
            policy_dir,
            ..
        } = match cfg {
            AttestationTokenConfig::Ear(c) => c,
            _ => unreachable!(),
        };
        assert_eq!(settings.developer_name, "dev");
        assert_eq!(settings.build_name, "build");
        assert_eq!(settings.profile_name, "prof");
        assert_eq!(policy_dir, "/p");
        assert!(signer.is_none());

        // OIDC: flat `oid_config` → `settings.oid_config`.
        let json = r#"{
            "type": "OIDC",
            "duration_min": 9,
            "issuer_name": "flat-issuer",
            "policy_dir": "/p",
            "oid_config": {
                "issuer": "https://example.com",
                "jwks_uri": "https://example.com/jwks"
            }
        }"#;
        let cfg: AttestationTokenConfig = serde_json::from_str(json).unwrap();
        let oidc::Configuration {
            settings,
            signer,
            policy_dir,
            ..
        } = match cfg {
            AttestationTokenConfig::OIDC(c) => c,
            _ => unreachable!(),
        };
        let oid = settings.oid_config.expect("oid_config deserialized");
        assert_eq!(oid.issuer, "https://example.com");
        assert_eq!(oid.jwks_uri, "https://example.com/jwks");
        assert_eq!(policy_dir, "/p");
        assert!(signer.is_none());
    }

    // Backward-compat / relaxation: the shared `SignerConfig` makes `cert_url`
    // and `cert_path` `#[serde(default)]` (absent → `None`). The pre-refactor
    // simple/oidc `TokenSignerConfig` rejected a signer missing `cert_url`; the
    // new shared config must accept a minimal `{key_path}` signer for every
    // broker.
    #[test]
    fn signer_config_accepts_minimal_key_path_only() {
        let json = r#"{
            "type": "Simple",
            "signer": { "key_path": "/etc/key" },
            "policy_dir": "/p"
        }"#;
        let cfg: AttestationTokenConfig = serde_json::from_str(json).unwrap();
        let simple::Configuration { signer, .. } = match cfg {
            AttestationTokenConfig::Simple(c) => c,
            _ => unreachable!(),
        };
        let signer = signer.expect("signer present");
        assert_eq!(signer.key_path, "/etc/key");
        assert!(signer.cert_url.is_none());
        assert!(signer.cert_path.is_none());
    }
}
