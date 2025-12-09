use anyhow::{Context, Result};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::LedgerConfig;
use crate::models::PublishEventRequest;

use super::{LedgerAdapter, LedgerReceipt};

/// Simple HTTP ledger: POST canonical payload hash to an external service that acts
/// as a gateway to a public immutable log (e.g., blockchain/transparent log).
pub struct HttpLedger {
    client: Client,
    endpoint: String,
    api_key: Option<String>,
}

impl HttpLedger {
    pub fn new(cfg: &LedgerConfig, client: Client) -> Result<Self> {
        let endpoint = cfg
            .http_endpoint
            .clone()
            .context("RVDS_LEDGER_HTTP_ENDPOINT required for http ledger")?;
        Ok(Self {
            client,
            endpoint,
            api_key: cfg.http_api_key.clone(),
        })
    }
}

#[derive(Serialize)]
struct HttpLedgerRequest<'a> {
    event_hash: &'a str,
    payload: &'a str,
}

#[derive(Deserialize)]
struct HttpLedgerResponse {
    handle: String,
}

#[async_trait]
impl LedgerAdapter for HttpLedger {
    async fn record_event(
        &self,
        _event: &PublishEventRequest,
        canonical_payload: &str,
    ) -> Result<LedgerReceipt> {
        let event_hash = hex::encode(Sha256::digest(canonical_payload.as_bytes()));
        let payload_hash = hex::encode(Sha256::digest(canonical_payload.as_bytes()));
        let payload_b64 = B64.encode(canonical_payload.as_bytes());
        let req_body = HttpLedgerRequest {
            event_hash: &event_hash,
            payload: canonical_payload,
        };

        let mut req = self.client.post(&self.endpoint).json(&req_body);
        if let Some(key) = &self.api_key {
            req = req.header("Authorization", format!("Bearer {key}"));
        }

        let resp = req
            .send()
            .await
            .context("send ledger http request")?
            .error_for_status()
            .context("ledger http status")?;

        let parsed: HttpLedgerResponse = resp.json().await.context("parse ledger response")?;

        Ok(LedgerReceipt {
            backend: "http".to_string(),
            handle: parsed.handle,
            event_hash: event_hash.clone(),
            payload_hash: Some(payload_hash),
            payload_b64: Some(payload_b64),
        })
    }
}
