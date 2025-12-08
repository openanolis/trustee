use std::env;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};

/// Application level configuration loaded from environment variables.
#[derive(Clone, Debug)]
pub struct AppConfig {
    pub listen_addr: String,
    pub data_dir: PathBuf,
    pub request_timeout: Duration,
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

        Ok(Self {
            listen_addr,
            data_dir,
            request_timeout: Duration::from_secs(request_timeout_secs),
        })
    }
}
