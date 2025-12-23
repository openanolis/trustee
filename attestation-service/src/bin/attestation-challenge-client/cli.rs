use crate::rekor::DEFAULT_REKOR_URL;
use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "attestation-challenge-client",
    about = "Fetch attestation evidence and verify it locally."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
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

    #[command(
        about = "Set reference values into RVPS using provenance documents",
        group(
            ArgGroup::new("slsa_args")
                .args(["artifact_type", "artifact_name", "rekor_url"])
                .requires_all(&["artifact_type", "artifact_name"])
        ),
        group(ArgGroup::new("sample_args").args(["payload"]).requires_all(&["payload"]))
    )]
    SetReferenceValue(SetReferenceValueArgs),
}

#[derive(Args, Debug)]
pub struct SetReferenceValueArgs {
    /// Provenance type to ingest (currently supports: slsa)
    #[arg(long = "provenance-type", value_enum)]
    pub provenance_type: ProvenanceType,

    /// Artifact type recorded in RVPS (required for SLSA)
    #[arg(long = "artifact-type")]
    pub artifact_type: Option<String>,

    /// Artifact name used to locate provenance in Rekor (required for SLSA)
    #[arg(long = "artifact-name")]
    pub artifact_name: Option<String>,

    /// Rekor base URL (defaults to the public Rekor)
    #[arg(long = "rekor-url", default_value = DEFAULT_REKOR_URL)]
    pub rekor_url: String,

    /// Path to the provenance payload JSON (required for sample)
    #[arg(long = "payload")]
    pub payload: Option<PathBuf>,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvenanceType {
    #[value(name = "slsa")]
    Slsa,
    #[value(name = "sample")]
    Sample,
}
