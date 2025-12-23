use anyhow::{anyhow, bail, Context, Result};
use attestation_service::{InitDataInput, RuntimeData};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use kbs_types::Tee;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

pub fn load_runtime_data_for_fetch(
    runtime_data: Option<String>,
    runtime_data_file: Option<PathBuf>,
) -> Result<String> {
    if let Some(path) = runtime_data_file {
        let content = fs::read_to_string(&path)
            .with_context(|| format!("read runtime data file {}", path.display()))?;
        return Ok(content);
    }

    Ok(runtime_data.unwrap_or_default())
}

pub fn load_runtime_data_for_verify(
    runtime_raw: Option<String>,
    runtime_raw_file: Option<PathBuf>,
    runtime_json: Option<String>,
    runtime_json_file: Option<PathBuf>,
) -> Result<Option<RuntimeData>> {
    if let Some(raw) = runtime_raw {
        return Ok(Some(RuntimeData::Raw(raw.into_bytes())));
    }

    if let Some(path) = runtime_raw_file {
        let bytes = fs::read(&path)
            .with_context(|| format!("read runtime data file {}", path.display()))?;
        return Ok(Some(RuntimeData::Raw(bytes)));
    }

    if let Some(json_str) = runtime_json {
        let value: Value =
            serde_json::from_str(&json_str).context("parse runtime data JSON from string")?;
        return Ok(Some(RuntimeData::Structured(value)));
    }

    if let Some(path) = runtime_json_file {
        let content = fs::read_to_string(&path)
            .with_context(|| format!("read runtime data JSON file {}", path.display()))?;
        let value: Value =
            serde_json::from_str(&content).context("parse runtime data JSON from file")?;
        return Ok(Some(RuntimeData::Structured(value)));
    }

    Ok(None)
}

pub fn load_init_data(
    init_data_digest: Option<String>,
    init_data_toml: Option<PathBuf>,
) -> Result<Option<InitDataInput>> {
    if let Some(digest_hex) = init_data_digest {
        let bytes = hex::decode(&digest_hex)
            .with_context(|| format!("decode init data digest hex from `{digest_hex}`"))?;
        return Ok(Some(InitDataInput::Digest(bytes)));
    }

    if let Some(path) = init_data_toml {
        let content = fs::read_to_string(&path)
            .with_context(|| format!("read init data toml {}", path.display()))?;
        return Ok(Some(InitDataInput::Toml(content)));
    }

    Ok(None)
}

pub fn read_evidence(path: &Path) -> Result<Value> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("read evidence file {}", path.display()))?;
    let evidence: Value = serde_json::from_str(&content).context("parse evidence as JSON value")?;
    Ok(evidence)
}

pub fn parse_tee(text: &str) -> Result<Tee> {
    match text.to_lowercase().as_str() {
        "azsnpvtpm" => Ok(Tee::AzSnpVtpm),
        "sev" => Ok(Tee::Sev),
        "sgx" => Ok(Tee::Sgx),
        "snp" => Ok(Tee::Snp),
        "tdx" => Ok(Tee::Tdx),
        "csv" => Ok(Tee::Csv),
        "sample" => Ok(Tee::Sample),
        "sampledevice" => Ok(Tee::SampleDevice),
        "aztdxvtpm" => Ok(Tee::AzTdxVtpm),
        "system" => Ok(Tee::System),
        "se" => Ok(Tee::Se),
        "tpm" => Ok(Tee::Tpm),
        "hygondcu" => Ok(Tee::HygonDcu),
        other => bail!("unsupported tee `{other}`"),
    }
}

pub fn decode_jwt_payload(token: &str) -> Result<Value> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 {
        bail!("invalid JWT format");
    }

    let payload_b64 = parts[1];
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(payload_b64))
        .context("decode jwt payload base64")?;
    let payload: Value =
        serde_json::from_slice(&payload_bytes).context("parse jwt payload json")?;
    Ok(payload)
}

pub fn parse_runtime_hash_alg(text: &str) -> Result<attestation_service::HashAlgorithm> {
    attestation_service::HashAlgorithm::from_str(text)
        .map_err(|e| anyhow!("invalid runtime hash algorithm: {e}"))
}
