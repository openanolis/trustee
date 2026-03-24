use crate::config::{build_default_config, resolve_work_dir};
use anyhow::{Context, Result};
use attestation_service::AttestationService;
use std::fs;
use std::path::PathBuf;

pub async fn run(rv_list: PathBuf) -> Result<()> {
    let payload = fs::read_to_string(&rv_list)
        .with_context(|| format!("read rv-list file {}", rv_list.display()))?;
    serde_json::from_str::<serde_json::Value>(&payload).context("parse rv-list JSON")?;

    let work_dir = resolve_work_dir();
    let config = build_default_config(&work_dir)?;
    let mut attestation_service = AttestationService::new(config)
        .await
        .context("initialize attestation service")?;

    attestation_service
        .set_reference_value_list(&payload)
        .await
        .context("set reference value list via RVPS")?;

    println!("Reference value list applied from `{}`", rv_list.display());
    Ok(())
}
