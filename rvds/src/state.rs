use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use futures::future::join_all;
use log::{debug, info, warn};
use reqwest::Client;
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
    subscribers: std::sync::Arc<RwLock<HashSet<String>>>,
    storage_path: PathBuf,
    http_client: Client,
    request_timeout: Duration,
    ledger: std::sync::Arc<dyn LedgerAdapter>,
}

impl AppState {
    /// Build initial state and reload persisted subscriber registry.
    pub async fn initialize(cfg: &AppConfig) -> Result<Self> {
        let storage_path = cfg.data_dir.join("subscribers.json");
        // Ensure data directory exists before writing registry file.
        if let Some(parent) = storage_path.parent() {
            fs::create_dir_all(parent).context("create data directory")?;
        }

        let subscribers = Self::load_registry(&storage_path)?;
        let http_client = Client::builder()
            .timeout(cfg.request_timeout)
            .build()
            .context("build reqwest client")?;
        let ledger = build_ledger(&cfg.ledger, http_client.clone());

        Ok(Self {
            subscribers: std::sync::Arc::new(RwLock::new(subscribers)),
            storage_path,
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

        let mut guard = self.subscribers.write().await;
        let mut newly_added = Vec::new();
        for url in normalized {
            if guard.insert(url.clone()) {
                newly_added.push(url);
            }
        }

        self.persist_registry(&guard)
            .map_err(|e| ApiError::Storage(e.to_string()))?;

        Ok(newly_added)
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

        let subscribers = {
            let guard = self.subscribers.read().await;
            guard.iter().cloned().collect::<Vec<_>>()
        };

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

    /// Persist subscriber registry to disk.
    fn persist_registry(&self, data: &HashSet<String>) -> Result<()> {
        let serialized = serde_json::to_string_pretty(data).context("serialize subscribers")?;
        fs::write(&self.storage_path, serialized).context("write subscribers registry")
    }

    /// Load registry from disk if the file exists.
    fn load_registry(path: &Path) -> Result<HashSet<String>> {
        if !path.exists() {
            return Ok(HashSet::new());
        }

        let raw = fs::read_to_string(path).context("read subscribers registry")?;
        let parsed: HashSet<String> =
            serde_json::from_str(&raw).context("parse subscribers registry")?;
        Ok(parsed)
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
                error: Some(format!("timeout after {:?}", timeout)),
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
