use crate::cli::{ProvenanceType, RekorApiVersion, SetReferenceValueArgs};
use crate::config::{build_default_config, DEFAULT_WORK_DIR};
use crate::rekor::RekorClient;
use crate::rvps_message::build_rvps_message;
use anyhow::{anyhow, bail, Context, Result};
use attestation_service::AttestationService;
use serde_json::json;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

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

    let work_dir = PathBuf::from(DEFAULT_WORK_DIR);
    let config = build_default_config(&work_dir)?;
    let mut attestation_service = AttestationService::new(config)
        .await
        .context("initialize attestation service")?;

    let source_protocol = args.provenance_source_protocol.as_deref();
    let source_uri = args.provenance_source_uri.as_deref();

    if source_protocol.is_some()
        || source_uri.is_some()
        || args.rekor_api_version == RekorApiVersion::V2
    {
        let protocol = source_protocol
            .ok_or_else(|| anyhow!("--provenance-source-protocol is required when provenance source mode is used or rekor-api-version=2"))?;
        let uri = source_uri
            .ok_or_else(|| anyhow!("--provenance-source-uri is required when provenance source mode is used or rekor-api-version=2"))?;

        let payload = json!({
            "rv_list": [
                {
                    "id": &artifact_name,
                    "version": "cli",
                    "type": &artifact_type,
                    "provenance_info": {
                        "type": "slsa-intoto-statements",
                        "rekor_url": args.rekor_url,
                        "rekor_api_version": rekor_api_version_to_u8(args.rekor_api_version),
                    },
                    "provenance_source": {
                        "protocol": protocol,
                        "uri": uri,
                        "artifact": args.provenance_source_artifact,
                    },
                    "operation_type": "refresh"
                }
            ]
        });

        attestation_service
            .set_reference_value_list(&payload.to_string())
            .await
            .context("set reference value list to RVPS")?;
        println!("Reference values registered via provenance source, artifact: `{artifact_name}`");
    } else {
        let rekor_client = RekorClient::new(&args.rekor_url)?;
        let slsa_provenance = rekor_client
            .fetch_slsa_provenance(&artifact_name)
            .await
            .context("fetch SLSA provenance from Rekor")?;

        if slsa_provenance.is_empty() {
            bail!("No SLSA provenance found on Rekor for artifact `{artifact_name}`");
        }

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
    }

    Ok(())
}

fn rekor_api_version_to_u8(v: RekorApiVersion) -> Option<u8> {
    match v {
        RekorApiVersion::Auto => None,
        RekorApiVersion::V1 => Some(1),
        RekorApiVersion::V2 => Some(2),
    }
}

async fn handle_sample(args: SetReferenceValueArgs) -> Result<()> {
    let payload_path = args
        .payload
        .ok_or_else(|| anyhow!("--payload is required when --provenance-type is sample"))?;

    let payload_raw = fs::read_to_string(&payload_path)
        .with_context(|| format!("read payload from {}", payload_path.display()))?;
    let payload: Value =
        serde_json::from_str(&payload_raw).context("parse payload JSON for sample provenance")?;

    let work_dir = PathBuf::from(DEFAULT_WORK_DIR);
    let config = build_default_config(&work_dir)?;
    let mut attestation_service = AttestationService::new(config)
        .await
        .context("initialize attestation service")?;

    let message = build_rvps_message("sample", &payload)?;

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
