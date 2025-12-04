//! Minimal attestation token parsing helpers (Base64 JSON -> env map).

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{Map, Value};

use crate::error::IamError;

/// Parsed attestation claims kept in a structured map.
#[derive(Debug, Clone, Default)]
pub struct AttestationContext {
    pub claims: Map<String, Value>,
}

impl AttestationContext {
    /// Convert claims into the env map stored within session tokens.
    pub fn to_env(&self) -> Map<String, Value> {
        self.claims.clone()
    }
}

/// Verify (decode + JSON parse) the optional attestation token.
pub fn verify_attestation(token: Option<&str>) -> Result<AttestationContext, IamError> {
    match token {
        None => Ok(AttestationContext::default()),
        Some(raw) => {
            let bytes = STANDARD.decode(raw).map_err(|err| {
                IamError::InvalidRequest(format!("invalid attestation token: {err}"))
            })?;
            let claims: Value = serde_json::from_slice(&bytes).map_err(|err| {
                IamError::InvalidRequest(format!("invalid attestation payload: {err}"))
            })?;
            match claims {
                Value::Object(map) => Ok(AttestationContext { claims: map }),
                _ => Err(IamError::InvalidRequest(
                    "attestation payload must be a JSON object".to_string(),
                )),
            }
        }
    }
}
