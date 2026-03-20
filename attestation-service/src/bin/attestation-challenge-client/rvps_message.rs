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
    build_rvps_message_with_payload_string(provenance_type, payload_str)
}

pub fn build_rvps_message_with_payload_string(
    provenance_type: &str,
    payload: String,
) -> Result<String> {
    let message = RvpsMessage {
        version: Some("0.1.0"),
        provenance_type,
        payload,
    };

    serde_json::to_string(&message).context("serialize RVPS message")
}
