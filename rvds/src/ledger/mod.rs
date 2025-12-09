mod eth_gateway;
mod http;
mod noop;

use anyhow::Result;
use log::warn;
use reqwest::Client;
use std::sync::Arc;

use crate::config::LedgerConfig;
use crate::models::PublishEventRequest;

pub use eth_gateway::EthGatewayLedger;
pub use http::HttpLedger;
pub use noop::NoopLedger;

/// Receipt returned after persisting an event into an external immutable ledger.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LedgerReceipt {
    pub backend: String,
    pub handle: String,
    pub event_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_b64: Option<String>,
}

/// Ledger adapter trait to allow swapping implementations (none/http/eth...).
#[async_trait::async_trait]
pub trait LedgerAdapter: Send + Sync {
    async fn record_event(
        &self,
        event: &PublishEventRequest,
        canonical_payload: &str,
    ) -> Result<LedgerReceipt>;
}

/// Factory to build ledger adapter based on configuration.
pub fn build_ledger(cfg: &LedgerConfig, client: Client) -> Arc<dyn LedgerAdapter> {
    match cfg.backend.as_str() {
        "http" => match HttpLedger::new(cfg, client) {
            Ok(adp) => Arc::new(adp),
            Err(e) => {
                warn!("Http ledger init failed ({e:?}), falling back to noop.");
                Arc::new(NoopLedger)
            }
        },
        "eth" => match EthGatewayLedger::new(cfg, client) {
            Ok(adp) => Arc::new(adp),
            Err(e) => {
                warn!("Ethereum ledger init failed ({e:?}), falling back to noop.");
                Arc::new(NoopLedger)
            }
        },
        "none" | _ => Arc::new(NoopLedger),
    }
}
