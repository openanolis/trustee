use anyhow::Result;
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use sha2::{Digest, Sha256};

use crate::models::PublishEventRequest;

use super::{LedgerAdapter, LedgerReceipt};

/// No-op ledger used by default; returns a synthetic receipt.
pub struct NoopLedger;

#[async_trait]
impl LedgerAdapter for NoopLedger {
    async fn record_event(
        &self,
        _event: &PublishEventRequest,
        canonical_payload: &str,
    ) -> Result<LedgerReceipt> {
        let event_hash = hex::encode(Sha256::digest(canonical_payload.as_bytes()));
        Ok(LedgerReceipt {
            backend: "none".to_string(),
            handle: "noop".to_string(),
            event_hash,
            payload_hash: Some(hex::encode(Sha256::digest(canonical_payload.as_bytes()))),
            payload_b64: Some(B64.encode(canonical_payload.as_bytes())),
        })
    }
}
