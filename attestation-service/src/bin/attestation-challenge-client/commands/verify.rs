use crate::config::{build_default_config, DEFAULT_WORK_DIR};
use crate::data::{
    decode_jwt_payload, load_init_data, load_runtime_data_for_verify, parse_runtime_hash_alg,
    parse_tee, read_evidence,
};
use anyhow::{Context, Result};
use attestation_service::{AttestationService, VerificationRequest};
use std::path::PathBuf;

#[allow(clippy::too_many_arguments)]
pub async fn run(
    evidence_path: PathBuf,
    tee_text: String,
    runtime_raw: Option<String>,
    runtime_raw_file: Option<PathBuf>,
    runtime_json: Option<String>,
    runtime_json_file: Option<PathBuf>,
    runtime_hash_alg: String,
    init_data_digest: Option<String>,
    init_data_toml: Option<PathBuf>,
    policies: Vec<String>,
    claims: bool,
) -> Result<()> {
    let work_dir = PathBuf::from(DEFAULT_WORK_DIR);
    let config = build_default_config(&work_dir)?;

    let attestation_service = AttestationService::new(config)
        .await
        .context("initialize attestation service")?;

    let evidence = read_evidence(&evidence_path)?;
    let tee = parse_tee(&tee_text)?;
    let runtime_hash_algorithm = parse_runtime_hash_alg(&runtime_hash_alg)?;
    let runtime_data = load_runtime_data_for_verify(
        runtime_raw,
        runtime_raw_file,
        runtime_json,
        runtime_json_file,
    )?;
    let init_data = load_init_data(init_data_digest, init_data_toml)?;
    let policy_ids = if policies.is_empty() {
        vec!["default".into()]
    } else {
        policies
    };

    let request = VerificationRequest {
        evidence,
        tee,
        runtime_data,
        runtime_data_hash_algorithm: runtime_hash_algorithm,
        init_data,
        additional_data: None,
    };

    let token = attestation_service
        .evaluate(vec![request], policy_ids)
        .await
        .context("verify evidence")?;

    println!("{token}");

    if claims {
        let payload = decode_jwt_payload(&token).context("decode token payload")?;
        let pretty = serde_json::to_string_pretty(&payload)?;
        println!("{pretty}");
    }

    Ok(())
}
