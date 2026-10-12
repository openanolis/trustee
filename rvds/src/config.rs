use std::env;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use key_value_storage::{mysql::MysqlConfig, BackendConfigs, StorageBackendConfig, StorageType};

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
    /// Optional shared subscriber registry. When omitted, RVDS keeps the
    /// legacy subscribers.json behavior for backward compatibility.
    pub storage_backend: Option<StorageBackendConfig>,
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
        let storage_backend = Self::storage_backend_from_env()?;

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
            storage_backend,
        })
    }

    fn storage_backend_from_env() -> Result<Option<StorageBackendConfig>> {
        let Some(storage_type) = env::var("RVDS_STORAGE_TYPE")
            .ok()
            .filter(|value| !value.trim().is_empty())
        else {
            return Ok(None);
        };
        let storage_type = match storage_type.to_ascii_lowercase().as_str() {
            "memory" => StorageType::Memory,
            "mysql" => StorageType::Mysql,
            other => return Err(anyhow!("unsupported RVDS_STORAGE_TYPE `{other}`")),
        };
        let require_shared = match env::var("RVDS_REQUIRE_SHARED") {
            Ok(value) => value
                .parse::<bool>()
                .context("parse RVDS_REQUIRE_SHARED as true or false")?,
            Err(env::VarError::NotPresent) => false,
            Err(error) => return Err(error.into()),
        };

        Ok(Some(StorageBackendConfig {
            storage_type,
            require_shared,
            backends: BackendConfigs {
                mysql: (storage_type == StorageType::Mysql).then(MysqlConfig::default),
            },
        }))
    }
}

#[cfg(test)]
mod tests {
    use serial_test::serial;

    use super::*;

    #[test]
    #[serial]
    fn shared_storage_config_uses_common_mysql_secret() {
        env::set_var("RVDS_STORAGE_TYPE", "mysql");
        env::set_var("RVDS_REQUIRE_SHARED", "true");
        let config = AppConfig::from_env().unwrap();
        let storage = config.storage_backend.unwrap();
        assert_eq!(storage.storage_type, StorageType::Mysql);
        assert!(storage.require_shared);
        assert_eq!(
            storage.backends.mysql.unwrap().url_env.as_deref(),
            Some("TRUSTEE_STORAGE_MYSQL_URL")
        );
        env::remove_var("RVDS_STORAGE_TYPE");
        env::remove_var("RVDS_REQUIRE_SHARED");
    }
}
