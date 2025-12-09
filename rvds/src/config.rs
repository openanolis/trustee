use std::env;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};

#[derive(Clone, Debug)]
pub struct LedgerConfig {
    /// Backend type: "none" (default) or "http" (external ledger gateway).
    pub backend: String,
    /// HTTP endpoint for the ledger gateway.
    pub http_endpoint: Option<String>,
    /// Optional API key for the ledger gateway.
    pub http_api_key: Option<String>,
    /// Ethereum gateway endpoint that relays tx to chain.
    pub eth_gateway_endpoint: Option<String>,
    /// Optional API key for the ethereum gateway.
    pub eth_gateway_api_key: Option<String>,
}

/// Application level configuration loaded from environment variables.
#[derive(Clone, Debug)]
pub struct AppConfig {
    pub listen_addr: String,
    pub data_dir: PathBuf,
    pub request_timeout: Duration,
    pub ledger: LedgerConfig,
}

impl AppConfig {
    /// Build configuration from environment variables with safe defaults.
    pub fn from_env() -> Result<Self> {
        // Listen address for the HTTP server.
        let listen_addr =
            env::var("RVDS_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8090".to_string());

        // Directory used to persist subscriber registry.
        let data_dir = env::var("RVDS_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("data/rvds"));

        // Timeout for outbound webhook requests.
        let request_timeout_secs: u64 = env::var("RVDS_FORWARD_TIMEOUT_SECS")
            .unwrap_or_else(|_| "10".to_string())
            .parse()
            .context("parse RVDS_FORWARD_TIMEOUT_SECS")?;

        if request_timeout_secs == 0 {
            return Err(anyhow!(
                "RVDS_FORWARD_TIMEOUT_SECS must be greater than zero"
            ));
        }

        let ledger_backend = env::var("RVDS_LEDGER_BACKEND").unwrap_or_else(|_| "none".to_string());
        let ledger_http_endpoint = env::var("RVDS_LEDGER_HTTP_ENDPOINT").ok();
        let ledger_http_api_key = env::var("RVDS_LEDGER_HTTP_API_KEY").ok();
        let eth_gateway_endpoint = env::var("RVDS_LEDGER_ETH_GATEWAY").ok();
        let eth_gateway_api_key = env::var("RVDS_LEDGER_ETH_GATEWAY_API_KEY").ok();

        Ok(Self {
            listen_addr,
            data_dir,
            request_timeout: Duration::from_secs(request_timeout_secs),
            ledger: LedgerConfig {
                backend: ledger_backend,
                http_endpoint: ledger_http_endpoint,
                http_api_key: ledger_http_api_key,
                eth_gateway_endpoint,
                eth_gateway_api_key,
            },
        })
    }
}
