use crate::cli::{ProvenanceType, SetReferenceValueArgs};
use crate::config::{build_default_config, resolve_work_dir};
use crate::rekor::RekorClient;
use crate::rvps_message::{build_rvps_message, build_rvps_message_with_payload_string};
use anyhow::{anyhow, bail, Context, Result};
use attestation_service::AttestationService;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use serde_json::json;
use serde_json::Value;
use std::fs;

pub async fn run(args: SetReferenceValueArgs) -> Result<()> {
    match args.provenance_type {
        ProvenanceType::Slsa => handle_slsa(args).await,
        ProvenanceType::Sample => handle_sample(args).await,
    }
}

async fn handle_slsa(args: SetReferenceValueArgs) -> Result<()> {
    let artifact_type = args
        .artifact_type
        .ok_or_else(|| anyhow!("--artifact-type is required when --provenance-type is slsa"))?;
    let artifact_name = args
        .artifact_name
        .ok_or_else(|| anyhow!("--artifact-name is required when --provenance-type is slsa"))?;

    let rekor_client = RekorClient::new(&args.rekor_url)?;
    let slsa_provenance = rekor_client
        .fetch_slsa_provenance(&artifact_name)
        .await
        .context("fetch SLSA provenance from Rekor")?;

    if slsa_provenance.is_empty() {
        bail!("No SLSA provenance found on Rekor for artifact `{artifact_name}`");
    }

    let work_dir = resolve_work_dir();
    let config = build_default_config(&work_dir)?;
    let mut attestation_service = AttestationService::new(config)
        .await
        .context("initialize attestation service")?;

    let payload = json!({
        "artifact_type": artifact_type,
        "slsa_provenance": slsa_provenance,
        "artifacts_download_url": Vec::<String>::new(),
    });

    let message = build_rvps_message("slsa", &payload)?;

    attestation_service
        .register_reference_value(&message)
        .await
        .context("register reference values to RVPS")?;

    println!("Reference values registered, artifact: `{artifact_name}`");

    Ok(())
}

async fn handle_sample(args: SetReferenceValueArgs) -> Result<()> {
    let payload_path = args
        .payload
        .ok_or_else(|| anyhow!("--payload is required when --provenance-type is sample"))?;

    let payload_raw = fs::read_to_string(&payload_path)
        .with_context(|| format!("read payload from {}", payload_path.display()))?;
    let payload: Value =
        serde_json::from_str(&payload_raw).context("parse payload JSON for sample provenance")?;
    let payload_b64 = encode_sample_payload(&payload)?;

    let work_dir = resolve_work_dir();
    let config = build_default_config(&work_dir)?;
    let mut attestation_service = AttestationService::new(config)
        .await
        .context("initialize attestation service")?;

    let message = build_rvps_message_with_payload_string("sample", payload_b64)?;

    attestation_service
        .register_reference_value(&message)
        .await
        .context("register reference values to RVPS")?;

    println!(
        "Reference values registered for sample payload: {}",
        payload_path.display()
    );

    Ok(())
}

fn encode_sample_payload(payload: &Value) -> Result<String> {
    if let Some(obj) = payload.as_object() {
        // Compatibility path: accept a full RVPS message and reuse its payload field.
        if let Some(embedded_payload) = obj.get("payload") {
            return Ok(match embedded_payload {
                Value::String(s) => {
                    if BASE64_STANDARD.decode(s).is_ok() {
                        s.clone()
                    } else {
                        BASE64_STANDARD.encode(s.as_bytes())
                    }
                }
                other => BASE64_STANDARD
                    .encode(serde_json::to_vec(other).context("serialize embedded payload JSON")?),
            });
        }
    }

    Ok(BASE64_STANDARD
        .encode(serde_json::to_vec(payload).context("serialize sample payload JSON")?))
}
