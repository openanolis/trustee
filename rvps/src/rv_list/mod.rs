use anyhow::{bail, Context, Result};
use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct ReferenceValueListPayload {
    pub rv_list: Vec<ReferenceValueListItem>,
}

#[derive(Deserialize, Debug)]
pub struct ReferenceValueListItem {
    pub id: String,
    pub version: String,
    #[serde(rename = "type")]
    pub rv_type: String,
    pub provenance_info: ReferenceValueProvenanceInfo,
    #[serde(default)]
    pub provenance_source: Option<ReferenceValueProvenanceSource>,
    pub operation_type: String,
    /// When set, use this as the RVPS reference value name instead of
    /// `measurement.{type}.{id}`.
    #[serde(default)]
    pub rv_name: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct ReferenceValueProvenanceInfo {
    #[serde(rename = "type")]
    pub provenance_type: String,
    pub rekor_url: String,
    #[serde(default)]
    pub rekor_api_version: Option<u8>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ReferenceValueProvenanceSource {
    pub protocol: String,
    pub uri: String,
    #[serde(default)]
    pub artifact: Option<String>,
}

pub enum ReferenceValueOperation {
    Add,
    Refresh,
}

impl ReferenceValueOperation {
    pub fn parse(op: &str) -> Result<Self> {
        match op.to_ascii_lowercase().as_str() {
            "add" => Ok(Self::Add),
            "refresh" => Ok(Self::Refresh),
            other => bail!("unsupported operation_type `{other}`"),
        }
    }
}

pub fn parse_reference_value_list(payload: &str) -> Result<ReferenceValueListPayload> {
    serde_json::from_str(payload).context("parse reference value list payload")
}

mod slsa_parse;

pub use slsa_parse::extract_slsa_digests;
