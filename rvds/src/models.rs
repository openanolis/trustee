use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

/// Generic audit proof that can point to different ledger backends.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuditProof {
    pub backend: String,
    pub handle: String,
    pub event_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_b64: Option<String>,
}

/// Register trustee subscription request body.
#[derive(Debug, Deserialize)]
pub struct SubscribeRequest {
    pub trustee_url: Vec<String>,
}

impl SubscribeRequest {
    /// Validate basic constraints for subscription input.
    pub fn validate(&self) -> Result<()> {
        if self.trustee_url.is_empty() {
            return Err(anyhow!("trustee_url cannot be empty"));
        }
        Ok(())
    }
}

/// Publish event payload coming from CI workflows.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PublishEventRequest {
    pub artifact_type: String,
    /// A list of SLSA provenance documents (raw JSON or base64-encoded JSON).
    pub slsa_provenance: Vec<String>,
    pub artifacts_download_url: Vec<String>,
    /// Optional audit proof (ledger) attached by RVDS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_proof: Option<AuditProof>,
}

impl PublishEventRequest {
    /// Validate allowed artifact type and required fields.
    pub fn validate(&self) -> Result<()> {
        if self.artifact_type.is_empty() {
            return Err(anyhow!("artifact_type cannot be empty"));
        }
        if self.slsa_provenance.is_empty() {
            return Err(anyhow!("slsa_provenance cannot be empty"));
        }
        if self.artifacts_download_url.is_empty() {
            return Err(anyhow!("artifacts_download_url cannot be empty"));
        }
        Ok(())
    }
}

/// Wrapper sent to RVPS register API through trustee gateway.
#[derive(Debug, Clone, Serialize)]
pub struct RvpsRegisterRequest {
    pub message: String,
}

/// Envelope expected by RVPS core.
#[derive(Debug, Clone, Serialize)]
pub struct RvpsMessageEnvelope {
    pub version: String,
    #[serde(rename = "type")]
    pub typ: String,
    pub payload: String,
}

/// Result for each forwarding attempt.
#[derive(Debug, Serialize)]
pub struct ForwardResult {
    pub target: String,
    pub delivered: bool,
    pub error: Option<String>,
}

/// Response shape for subscription endpoint.
#[derive(Debug, Serialize)]
pub struct SubscribeResponse {
    pub registered: Vec<String>,
}

/// Response shape for publish endpoint.
#[derive(Debug, Serialize)]
pub struct PublishResponse {
    pub forwarded: Vec<ForwardResult>,
    pub ledger_receipt: Option<crate::ledger::LedgerReceipt>,
}
