//! A lightweight CLI for challenge-mode remote attestation.
//! It talks to the guest `api-server-rest` to fetch evidence, and
//! then verifies it locally with the attestation-service library.

use anyhow::{anyhow, bail, Context, Result};
use attestation_service::config::Config;
use attestation_service::rvps::{RvpsConfig, RvpsCrateConfig};
use attestation_service::token::{ear_broker, AttestationTokenConfig};
use attestation_service::{
    AttestationService, HashAlgorithm, InitDataInput, RuntimeData, VerificationRequest,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use clap::{ArgGroup, Parser, Subcommand};
use kbs_types::Tee;
use reference_value_provider_service::storage::{local_json, ReferenceValueStorageConfig};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

const DEFAULT_WORK_DIR: &str = "/var/lib/attestation";

#[derive(Parser, Debug)]
#[command(
    name = "attestation-challenge-client",
    about = "Fetch attestation evidence and verify it locally."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(
        about = "Call guest api-server-rest /aa/evidence to fetch hardware evidence",
        group(
            ArgGroup::new("runtime_source")
                .args(["runtime_data", "runtime_data_file"])
                .multiple(false)
        )
    )]
    GetEvidence {
        /// Base URL of the guest api-server-rest, for example https://host:8006
        #[arg(long = "aa-url")]
        aa_url: String,
        /// Runtime data string passed to attestation-agent (defaults to empty)
        #[arg(long)]
        runtime_data: Option<String>,
        /// Read runtime data from file (must be UTF-8)
        #[arg(long)]
        runtime_data_file: Option<PathBuf>,
        /// Write evidence to file instead of stdout
        #[arg(long)]
        output: Option<PathBuf>,
    },

    #[command(
        about = "Verify evidence and print an EAR token or its payload",
        group(
            ArgGroup::new("runtime_input")
                .args(["runtime_raw", "runtime_raw_file", "runtime_json", "runtime_json_file"])
                .multiple(false)
        ),
        group(
            ArgGroup::new("init_input")
                .args(["init_data_digest", "init_data_toml"])
                .multiple(false)
        )
    )]
    Verify {
        /// Path to evidence file produced by get-evidence
        #[arg(long)]
        evidence: PathBuf,
        /// TEE type (e.g. tdx, sgx, snp, csv, azsnpvtpm, sample, system)
        #[arg(long)]
        tee: String,
        /// Use raw runtime data bytes from this string (UTF-8)
        #[arg(long)]
        runtime_raw: Option<String>,
        /// Use raw runtime data bytes from file
        #[arg(long)]
        runtime_raw_file: Option<PathBuf>,
        /// Use structured runtime data from JSON string
        #[arg(long)]
        runtime_json: Option<String>,
        /// Use structured runtime data from JSON file
        #[arg(long)]
        runtime_json_file: Option<PathBuf>,
        /// Hash algorithm for runtime data binding
        #[arg(long, default_value = "sha384")]
        runtime_hash_alg: String,
        /// Hex-encoded init data digest
        #[arg(long)]
        init_data_digest: Option<String>,
        /// Path to init data TOML file
        #[arg(long)]
        init_data_toml: Option<PathBuf>,
        /// Policy IDs to use (default: default)
        #[arg(long = "policy")]
        policies: Vec<String>,
        /// Print token payload as formatted JSON
        #[arg(long)]
        claims: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logger();
    let cli = Cli::parse();

    match cli.command {
        Commands::GetEvidence {
            aa_url,
            runtime_data,
            runtime_data_file,
            output,
        } => handle_get_evidence(&aa_url, runtime_data, runtime_data_file, output).await?,
        Commands::Verify {
            evidence,
            tee,
            runtime_raw,
            runtime_raw_file,
            runtime_json,
            runtime_json_file,
            runtime_hash_alg,
            init_data_digest,
            init_data_toml,
            policies,
            claims,
        } => {
            handle_verify(
                evidence,
                tee,
                runtime_raw,
                runtime_raw_file,
                runtime_json,
                runtime_json_file,
                runtime_hash_alg,
                init_data_digest,
                init_data_toml,
                policies,
                claims,
            )
            .await?
        }
    }

    Ok(())
}

async fn handle_get_evidence(
    aa_url: &str,
    runtime_data: Option<String>,
    runtime_data_file: Option<PathBuf>,
    output: Option<PathBuf>,
) -> Result<()> {
    let runtime_data = load_runtime_data_for_fetch(runtime_data, runtime_data_file)?;
    let base = aa_url.trim_end_matches('/');
    let url = format!("{}/aa/evidence", base);

    // The api-server-rest only accepts GET with runtime_data as query parameter.
    let client = reqwest::Client::new();
    let resp = client
        .get(url)
        .query(&[("runtime_data", runtime_data)])
        .send()
        .await
        .context("send request to api-server-rest")?;

    if !resp.status().is_success() {
        bail!("request failed with status {}", resp.status());
    }

    let body = resp.text().await.context("read evidence body")?;

    if let Some(path) = output {
        fs::write(&path, &body).with_context(|| format!("write evidence to {}", path.display()))?;
        println!("evidence saved to {}", path.display());
    } else {
        println!("{body}");
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_verify(
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

    // Initialize service with the enforced defaults.
    let attestation_service = AttestationService::new(config)
        .await
        .context("initialize attestation service")?;

    let evidence = read_evidence(&evidence_path)?;
    let tee = parse_tee(&tee_text)?;
    let runtime_hash_algorithm = HashAlgorithm::from_str(&runtime_hash_alg)
        .map_err(|e| anyhow!("invalid runtime hash algorithm: {e}"))?;
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

fn build_default_config(work_dir: &Path) -> Result<Config> {
    // Keep everything under the given work dir as requested.
    let rvps_config = RvpsConfig::BuiltIn(RvpsCrateConfig {
        storage: ReferenceValueStorageConfig::LocalJson(local_json::Config {
            file_path: work_dir
                .join("reference_values.json")
                .to_string_lossy()
                .to_string(),
        }),
    });

    let policy_dir = work_dir.join("token/ear/policies");
    // Ensure the policy directory exists before OPA loads the default rego.
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

fn load_runtime_data_for_fetch(
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

fn load_runtime_data_for_verify(
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

fn load_init_data(
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

fn read_evidence(path: &Path) -> Result<Value> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("read evidence file {}", path.display()))?;
    let evidence: Value = serde_json::from_str(&content).context("parse evidence as JSON value")?;
    Ok(evidence)
}

fn parse_tee(text: &str) -> Result<Tee> {
    // Follow the same mapping used by the RESTful service.
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

fn decode_jwt_payload(token: &str) -> Result<Value> {
    // Manual, signature-agnostic decode for display only.
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

fn init_logger() {
    // Prefer user-provided RUST_LOG, otherwise keep info noise low.
    let env = env_logger::Env::default().default_filter_or("info");
    let _ = env_logger::Builder::from_env(env).try_init();
}
