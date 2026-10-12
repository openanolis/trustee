use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use futures::future::join_all;
use key_value_storage::{
    KvStorageProvider, PutCondition, PutOptions, PutOutcome, Storage, StorageProvider,
};
use log::{debug, info, warn};
use reqwest::Client;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use url::Url;

use crate::config::AppConfig;
use crate::error::ApiError;
use crate::ledger::{build_ledger, LedgerAdapter, LedgerReceipt};
use crate::models::{
    ForwardResult, PublishEventRequest, RvpsMessageEnvelope, RvpsRegisterRequest, SubscribeRequest,
};

#[derive(Clone)]
pub struct AppState {
    subscribers: SubscriberRegistry,
    http_client: Client,
    request_timeout: Duration,
    ledger: std::sync::Arc<dyn LedgerAdapter>,
}

const SUBSCRIBER_NAMESPACE: &str = "rvds_subscriber";

#[derive(Clone)]
enum SubscriberRegistry {
    File {
        entries: std::sync::Arc<RwLock<HashSet<String>>>,
        path: PathBuf,
    },
    Shared(Storage),
}

impl SubscriberRegistry {
    fn key(url: &str) -> String {
        format!("{:x}", Sha256::digest(url.as_bytes()))
    }

    async fn add(&self, urls: &[String]) -> Result<Vec<String>> {
        match self {
            Self::File { entries, path } => {
                let mut guard = entries.write().await;
                let mut newly_added = Vec::new();
                for url in urls {
                    if guard.insert(url.clone()) {
                        newly_added.push(url.clone());
                    }
                }
                Self::persist_file(path, &guard)?;
                Ok(newly_added)
            }
            Self::Shared(storage) => {
                let mut newly_added = Vec::new();
                for url in urls {
                    let outcome = storage
                        .put(
                            &Self::key(url),
                            url.as_bytes(),
                            PutOptions {
                                condition: PutCondition::IfAbsent,
                                ..Default::default()
                            },
                        )
                        .await
                        .context("store RVDS subscriber")?;
                    if matches!(outcome, PutOutcome::Created { .. }) {
                        newly_added.push(url.clone());
                    }
                }
                Ok(newly_added)
            }
        }
    }

    async fn list(&self) -> Result<Vec<String>> {
        match self {
            Self::File { entries, .. } => Ok(entries.read().await.iter().cloned().collect()),
            Self::Shared(storage) => {
                let mut subscribers = Vec::new();
                for key in storage.list().await.context("list RVDS subscribers")? {
                    if let Some(entry) = storage.get(&key).await.context("read RVDS subscriber")? {
                        subscribers.push(
                            String::from_utf8(entry.value)
                                .context("stored RVDS subscriber is not UTF-8")?,
                        );
                    }
                }
                Ok(subscribers)
            }
        }
    }

    fn persist_file(path: &Path, data: &HashSet<String>) -> Result<()> {
        let serialized = serde_json::to_string_pretty(data).context("serialize subscribers")?;
        fs::write(path, serialized).context("write subscribers registry")
    }

    fn load_file(path: &Path) -> Result<HashSet<String>> {
        if !path.exists() {
            return Ok(HashSet::new());
        }
        let raw = fs::read_to_string(path).context("read subscribers registry")?;
        serde_json::from_str(&raw).context("parse subscribers registry")
    }
}

impl AppState {
    /// Build initial state and reload persisted subscriber registry.
    pub async fn initialize(cfg: &AppConfig) -> Result<Self> {
        let storage_path = cfg.data_dir.join("subscribers.json");
        let subscribers = if let Some(storage_config) = cfg.storage_backend.clone() {
            let provider = KvStorageProvider::new(storage_config);
            let storage = provider
                .get_or_register(SUBSCRIBER_NAMESPACE)
                .await
                .context("initialize shared RVDS subscriber storage")?;
            let registry = SubscriberRegistry::Shared(storage);
            let legacy = SubscriberRegistry::load_file(&storage_path)?;
            if !legacy.is_empty() {
                let values: Vec<_> = legacy.into_iter().collect();
                let imported = registry.add(&values).await?;
                info!(
                    "Imported {} legacy RVDS subscribers into shared storage",
                    imported.len()
                );
            }
            registry
        } else {
            if let Some(parent) = storage_path.parent() {
                fs::create_dir_all(parent).context("create data directory")?;
            }
            SubscriberRegistry::File {
                entries: std::sync::Arc::new(RwLock::new(SubscriberRegistry::load_file(
                    &storage_path,
                )?)),
                path: storage_path,
            }
        };
        let http_client = Client::builder()
            .timeout(cfg.request_timeout)
            .build()
            .context("build reqwest client")?;
        let ledger = build_ledger(&cfg.ledger, http_client.clone());

        Ok(Self {
            subscribers,
            http_client,
            request_timeout: cfg.request_timeout,
            ledger,
        })
    }

    /// Register trustee endpoints and persist them.
    pub async fn add_trustees(&self, req: &SubscribeRequest) -> Result<Vec<String>, ApiError> {
        req.validate()
            .map_err(|e| ApiError::Validation(e.to_string()))?;

        let mut normalized = Vec::new();
        for raw in &req.trustee_url {
            // Normalize URLs to avoid duplicated entries that only differ in trailing slash.
            let mut url = Url::parse(raw)
                .map_err(|e| ApiError::Validation(format!("invalid url {raw}: {e}")))?;
            let trimmed_path = url.path().trim_end_matches('/').to_string();
            url.set_path(&trimmed_path);
            normalized.push(url.to_string());
        }

        self.subscribers
            .add(&normalized)
            .await
            .map_err(|e| ApiError::Storage(e.to_string()))
    }

    /// Forward publish events to every registered trustee.
    pub async fn forward_publish_event(
        &self,
        mut event: PublishEventRequest,
    ) -> Result<(Vec<ForwardResult>, Option<LedgerReceipt>), ApiError> {
        event
            .validate()
            .map_err(|e| ApiError::Validation(e.to_string()))?;

        // Build the RVPS envelope once and reuse it for every subscriber.
        let payload_json = serde_json::to_string(&event)
            .map_err(|e| ApiError::Internal(format!("serialize event: {e}")))?;
        let message_envelope = RvpsMessageEnvelope {
            version: "0.1.0".to_string(),
            typ: "slsa".to_string(),
            payload: payload_json.clone(),
        };
        let envelope_str = serde_json::to_string(&message_envelope)
            .map_err(|e| ApiError::Internal(format!("serialize envelope: {e}")))?;
        let register_request = RvpsRegisterRequest {
            message: envelope_str,
        };

        let subscribers = self
            .subscribers
            .list()
            .await
            .map_err(|e| ApiError::Storage(e.to_string()))?;

        if subscribers.is_empty() {
            warn!("No trustee subscribers registered; skipping forward.");
        }

        // Record in external ledger (if enabled).
        let ledger_receipt = match self.ledger.record_event(&event, &payload_json).await {
            Ok(r) => {
                info!(
                    "Ledger recorded event_hash={} via {}",
                    r.event_hash, r.backend
                );
                event.audit_proof = Some(crate::models::AuditProof {
                    backend: r.backend.clone(),
                    handle: r.handle.clone(),
                    event_hash: r.event_hash.clone(),
                    payload_hash: r.payload_hash.clone(),
                    payload_b64: r.payload_b64.clone(),
                });
                Some(r)
            }
            Err(e) => {
                warn!("Ledger recording failed: {e}");
                None
            }
        };

        // Dispatch webhooks concurrently to reduce tail latency.
        let futs = subscribers
            .into_iter()
            .map(|target| self.send_to_trustee(target, register_request.clone()));

        let results = join_all(futs).await;
        Ok((results, ledger_receipt))
    }

    async fn send_to_trustee(&self, target: String, req: RvpsRegisterRequest) -> ForwardResult {
        let endpoint = format!("{}/api/rvps/register", target.trim_end_matches('/'));
        info!("Forwarding release event to {endpoint}");

        // Clone client and request to move into async block cleanly.
        let client = self.http_client.clone();
        let timeout = self.request_timeout;

        // Use explicit timeout guard to surface slow downstreams.
        let response =
            tokio::time::timeout(timeout, client.post(endpoint.clone()).json(&req).send()).await;

        match response {
            Err(_) => ForwardResult {
                target,
                delivered: false,
                error: Some(format!("timeout after {timeout:?}")),
            },
            Ok(Err(err)) => ForwardResult {
                target,
                delivered: false,
                error: Some(format!("request error: {err}")),
            },
            Ok(Ok(resp)) => {
                let status = resp.status();
                if status.is_success() {
                    ForwardResult {
                        target,
                        delivered: true,
                        error: None,
                    }
                } else {
                    // Log body for easier diagnostics without failing the loop.
                    let body = resp.text().await.unwrap_or_default();
                    debug!("Non-2xx from {endpoint}: {status} - {body}");
                    ForwardResult {
                        target,
                        delivered: false,
                        error: Some(format!("status {status}")),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use key_value_storage::{
        memory::MemoryStorage,
        mysql::{MysqlConfig, MysqlStorage},
        DeleteOptions,
    };
    use serial_test::serial;

    use super::*;

    #[tokio::test]
    async fn shared_registry_is_visible_across_instances() {
        let storage: Storage = Arc::new(MemoryStorage::default());
        let first = SubscriberRegistry::Shared(storage.clone());
        let second = SubscriberRegistry::Shared(storage);
        let subscriber = "https://trustee.example/".to_string();

        let added = first.add(std::slice::from_ref(&subscriber)).await.unwrap();
        assert_eq!(added.as_slice(), std::slice::from_ref(&subscriber));
        assert!(first
            .add(std::slice::from_ref(&subscriber))
            .await
            .unwrap()
            .is_empty());
        assert_eq!(second.list().await.unwrap(), [subscriber]);
    }

    #[tokio::test]
    #[serial]
    async fn shared_storage_mysql_registry_visibility() {
        let Ok(url) = std::env::var("MYSQL_TEST_URL") else {
            return;
        };
        let config = MysqlConfig {
            url,
            url_env: None,
            ..Default::default()
        };
        let first_storage: Storage = Arc::new(
            MysqlStorage::connect(config.clone(), SUBSCRIBER_NAMESPACE)
                .await
                .unwrap(),
        );
        for key in first_storage.list().await.unwrap() {
            first_storage
                .delete(&key, DeleteOptions::default())
                .await
                .unwrap();
        }
        let second_storage: Storage = Arc::new(
            MysqlStorage::connect(config, SUBSCRIBER_NAMESPACE)
                .await
                .unwrap(),
        );
        let first = SubscriberRegistry::Shared(first_storage);
        let second = SubscriberRegistry::Shared(second_storage);
        let subscriber = "https://trustee.example/".to_string();

        let added = first.add(std::slice::from_ref(&subscriber)).await.unwrap();
        assert_eq!(added.as_slice(), std::slice::from_ref(&subscriber));
        assert_eq!(second.list().await.unwrap(), [subscriber]);
    }
}
