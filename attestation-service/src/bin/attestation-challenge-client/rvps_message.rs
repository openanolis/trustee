use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;

#[derive(Serialize)]
struct RvpsMessage<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<&'a str>,
    #[serde(rename = "type")]
    provenance_type: &'a str,
    payload: String,
}

pub fn build_rvps_message(provenance_type: &str, payload: &Value) -> Result<String> {
    let payload_str = serde_json::to_string(payload).context("serialize RVPS payload to string")?;
    let message = RvpsMessage {
        version: Some("0.1.0"),
        provenance_type,
        payload: payload_str,
    };

    serde_json::to_string(&message).context("serialize RVPS message")
}
