use anyhow::{Context, Result};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;

use crate::config::LedgerConfig;
use crate::models::PublishEventRequest;

use super::{LedgerAdapter, LedgerReceipt};

pub struct EthGatewayLedger {
    client: Client,
    endpoint: String,
    api_key: Option<String>,
    timeout: Duration,
}

impl EthGatewayLedger {
    pub fn new(cfg: &LedgerConfig, client: Client) -> Result<Self> {
        let endpoint = cfg
            .eth_gateway_endpoint
            .clone()
            .context("RVDS_LEDGER_ETH_GATEWAY required for eth ledger")?;
        Ok(Self {
            client,
            endpoint,
            api_key: cfg.eth_gateway_api_key.clone(),
            timeout: Duration::from_secs(60),
        })
    }
}

#[derive(Serialize)]
struct EthGatewayRequest<'a> {
    event_hash: &'a str,
    payload: &'a str,
}

#[derive(Deserialize)]
struct EthGatewayResponse {
    tx_hash: String,
}

#[async_trait]
impl LedgerAdapter for EthGatewayLedger {
    async fn record_event(
        &self,
        _event: &PublishEventRequest,
        canonical_payload: &str,
    ) -> Result<LedgerReceipt> {
        let event_hash = hex::encode(Sha256::digest(canonical_payload.as_bytes()));
        let payload_hash = hex::encode(Sha256::digest(canonical_payload.as_bytes()));
        let payload_b64 = B64.encode(canonical_payload.as_bytes());
        let req_body = EthGatewayRequest {
            event_hash: &event_hash,
            payload: canonical_payload,
        };

        let mut req = self.client.post(&self.endpoint).json(&req_body);
        if let Some(key) = &self.api_key {
            req = req.header("Authorization", format!("Bearer {key}"));
        }

        let resp = tokio::time::timeout(self.timeout, req.send())
            .await
            .context("eth gateway timeout")?
            .context("eth gateway request error")?
            .error_for_status()
            .context("eth gateway status")?;

        let parsed: EthGatewayResponse = resp.json().await.context("parse eth gateway response")?;

        Ok(LedgerReceipt {
            backend: "ethereum-gateway".to_string(),
            handle: parsed.tx_hash,
            event_hash,
            payload_hash: Some(payload_hash),
            payload_b64: Some(payload_b64),
        })
    }
}
