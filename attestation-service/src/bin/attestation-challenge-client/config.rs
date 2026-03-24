use anyhow::{Context, Result};
use attestation_service::config::Config;
use attestation_service::rvps::{RvpsConfig, RvpsCrateConfig};
use attestation_service::token::{ear_broker, AttestationTokenConfig};
use reference_value_provider_service::storage::{local_json, ReferenceValueStorageConfig};
use std::fs;
use std::path::{Path, PathBuf};

pub const DEFAULT_WORK_DIR: &str = "/var/lib/attestation";

/// Work directory for RVPS storage and policies. Override with env
/// `ATTESTATION_CHALLENGE_CLIENT_WORK_DIR` (e.g. for tests without `/var/lib/attestation`).
pub fn resolve_work_dir() -> PathBuf {
    std::env::var_os("ATTESTATION_CHALLENGE_CLIENT_WORK_DIR")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from(DEFAULT_WORK_DIR))
}

pub fn build_default_config(work_dir: &Path) -> Result<Config> {
    let rvps_config = RvpsConfig::BuiltIn(RvpsCrateConfig {
        storage: ReferenceValueStorageConfig::LocalJson(local_json::Config {
            file_path: work_dir
                .join("reference_values.json")
                .to_string_lossy()
                .to_string(),
        }),
    });

    let policy_dir = work_dir.join("token/ear/policies");
    fs::create_dir_all(&policy_dir)
        .with_context(|| format!("create policy dir {}", policy_dir.display()))?;

    let ear_cfg = ear_broker::Configuration {
        policy_dir: policy_dir.to_string_lossy().to_string(),
        ..ear_broker::Configuration::default()
    };

    Ok(Config {
        work_dir: work_dir.to_path_buf(),
        rvps_config,
        attestation_token_broker: AttestationTokenConfig::Ear(ear_cfg),
    })
}

pub fn init_logger() {
    let env = env_logger::Env::default().default_filter_or("info");
    let _ = env_logger::Builder::from_env(env).try_init();
}
