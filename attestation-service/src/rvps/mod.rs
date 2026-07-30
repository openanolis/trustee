// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use log::info;
pub use reference_value_provider_service::config::Config as RvpsCrateConfig;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;

#[cfg(feature = "rvps-grpc")]
pub mod grpc;

pub mod builtin;

#[derive(Error, Debug)]
pub enum RvpsError {
    #[error("Serde Json Error: {0}")]
    SerdeJson(#[from] serde_json::Error),

    #[cfg(feature = "rvps-grpc")]
    #[error("Returned status: {0}")]
    Status(#[from] tonic::Status),

    #[cfg(feature = "rvps-grpc")]
    #[error("tonic transport error: {0}")]
    TonicTransport(#[from] tonic::transport::Error),

    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

type Result<T> = std::result::Result<T, RvpsError>;

/// The interfaces of Reference Value Provider Service
/// * `verify_and_extract` is responsible for verify a message and
/// store reference values from it.
/// * `query_reference_value` gets one policy-facing value by its identifier.
/// * `get_reference_values` keeps the legacy bulk-query API available.
/// * `delete_reference_value` is responsible for deleting a reference value.
#[async_trait::async_trait]
pub trait RvpsApi: Send + Sync {
    /// Verify the given message and register the reference value included.
    async fn verify_and_extract(&self, message: &str) -> Result<()>;

    /// Set reference values list via RVPS.
    async fn set_reference_value_list(&self, payload: &str) -> Result<()>;

    /// Get one policy-facing reference value.
    async fn query_reference_value(&self, reference_value_id: &str) -> Result<Option<Value>>;

    /// Get all policy-facing reference values.
    async fn get_reference_values(&self) -> Result<HashMap<String, Value>>;

    /// Delete a reference value by name.
    async fn delete_reference_value(&self, name: &str) -> Result<bool>;
}

/// A per-attestation view of RVPS.
///
/// Both values and misses are cached so multiple policies or repeated policy
/// calls observe one consistent value and do not generate duplicate RPCs.
pub struct ReferenceValueResolver {
    rvps: Arc<dyn RvpsApi>,
    keyed_cache: Mutex<HashMap<String, Option<Value>>>,
    bulk_cache: Mutex<Option<HashMap<String, Value>>>,
}

impl ReferenceValueResolver {
    pub fn new(rvps: Arc<dyn RvpsApi>) -> Self {
        Self {
            rvps,
            keyed_cache: Mutex::new(HashMap::new()),
            bulk_cache: Mutex::new(None),
        }
    }

    pub async fn query_reference_value(&self, reference_value_id: &str) -> Result<Option<Value>> {
        {
            let bulk_cache = self.bulk_cache.lock().await;
            if let Some(values) = bulk_cache.as_ref() {
                return Ok(values.get(reference_value_id).cloned());
            }
        }

        let mut keyed_cache = self.keyed_cache.lock().await;
        if let Some(value) = keyed_cache.get(reference_value_id) {
            return Ok(value.clone());
        }

        let value = self.rvps.query_reference_value(reference_value_id).await?;
        keyed_cache.insert(reference_value_id.to_string(), value.clone());
        Ok(value)
    }

    pub async fn get_reference_values(&self) -> Result<HashMap<String, Value>> {
        let mut bulk_cache = self.bulk_cache.lock().await;
        if let Some(values) = bulk_cache.as_ref() {
            return Ok(values.clone());
        }

        let mut values = self.rvps.get_reference_values().await?;
        let mut keyed_cache = self.keyed_cache.lock().await;
        // Preserve the first value observed during this attestation if a
        // legacy policy triggers a bulk query after keyed queries.
        for (key, value) in keyed_cache.iter() {
            match value {
                Some(value) => {
                    values.insert(key.clone(), value.clone());
                }
                None => {
                    values.remove(key);
                }
            }
        }
        for (key, value) in &values {
            keyed_cache
                .entry(key.clone())
                .or_insert_with(|| Some(value.clone()));
        }
        *bulk_cache = Some(values.clone());
        Ok(values)
    }
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type")]
pub enum RvpsConfig {
    BuiltIn(RvpsCrateConfig),
    #[cfg(feature = "rvps-grpc")]
    GrpcRemote(grpc::RvpsRemoteConfig),
}

impl Default for RvpsConfig {
    fn default() -> Self {
        Self::BuiltIn(RvpsCrateConfig::default())
    }
}

pub async fn initialize_rvps_client(config: &RvpsConfig) -> Result<Arc<dyn RvpsApi>> {
    match config {
        RvpsConfig::BuiltIn(config) => {
            info!("launch a built-in RVPS.");
            Ok(Arc::new(builtin::BuiltinRvps::new(config.clone())?) as Arc<dyn RvpsApi>)
        }
        #[cfg(feature = "rvps-grpc")]
        RvpsConfig::GrpcRemote(config) => {
            info!("connect to remote RVPS: {}", config.address);
            Ok(Arc::new(grpc::Agent::new(&config.address).await?) as Arc<dyn RvpsApi>)
        }
    }
}

#[cfg(test)]
struct StaticTestRvps {
    values: HashMap<String, Value>,
}

#[cfg(test)]
#[async_trait::async_trait]
impl RvpsApi for StaticTestRvps {
    async fn verify_and_extract(&self, _message: &str) -> Result<()> {
        unreachable!()
    }

    async fn set_reference_value_list(&self, _payload: &str) -> Result<()> {
        unreachable!()
    }

    async fn query_reference_value(&self, reference_value_id: &str) -> Result<Option<Value>> {
        Ok(self.values.get(reference_value_id).cloned())
    }

    async fn get_reference_values(&self) -> Result<HashMap<String, Value>> {
        Ok(self.values.clone())
    }

    async fn delete_reference_value(&self, _name: &str) -> Result<bool> {
        unreachable!()
    }
}

#[cfg(test)]
pub(crate) fn test_resolver(values: HashMap<String, Value>) -> Arc<ReferenceValueResolver> {
    let rvps = Arc::new(StaticTestRvps { values }) as Arc<dyn RvpsApi>;
    Arc::new(ReferenceValueResolver::new(rvps))
}

#[cfg(test)]
pub(crate) fn empty_test_resolver() -> Arc<ReferenceValueResolver> {
    test_resolver(HashMap::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingRvps {
        values: HashMap<String, Value>,
        keyed_queries: AtomicUsize,
        bulk_queries: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl RvpsApi for CountingRvps {
        async fn verify_and_extract(&self, _message: &str) -> Result<()> {
            unreachable!()
        }

        async fn set_reference_value_list(&self, _payload: &str) -> Result<()> {
            unreachable!()
        }

        async fn query_reference_value(&self, reference_value_id: &str) -> Result<Option<Value>> {
            self.keyed_queries.fetch_add(1, Ordering::SeqCst);
            Ok(self.values.get(reference_value_id).cloned())
        }

        async fn get_reference_values(&self) -> Result<HashMap<String, Value>> {
            self.bulk_queries.fetch_add(1, Ordering::SeqCst);
            Ok(self.values.clone())
        }

        async fn delete_reference_value(&self, _name: &str) -> Result<bool> {
            unreachable!()
        }
    }

    fn counting_rvps() -> Arc<CountingRvps> {
        Arc::new(CountingRvps {
            values: HashMap::from([("svn".to_string(), serde_json::json!([1, 2]))]),
            keyed_queries: AtomicUsize::new(0),
            bulk_queries: AtomicUsize::new(0),
        })
    }

    #[tokio::test]
    async fn keyed_values_and_misses_are_cached() {
        let rvps = counting_rvps();
        let resolver = ReferenceValueResolver::new(Arc::clone(&rvps) as Arc<dyn RvpsApi>);

        assert_eq!(
            resolver.query_reference_value("svn").await.unwrap(),
            Some(serde_json::json!([1, 2]))
        );
        assert_eq!(
            resolver.query_reference_value("svn").await.unwrap(),
            Some(serde_json::json!([1, 2]))
        );
        assert_eq!(
            resolver.query_reference_value("missing").await.unwrap(),
            None
        );
        assert_eq!(
            resolver.query_reference_value("missing").await.unwrap(),
            None
        );
        assert_eq!(rvps.keyed_queries.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn bulk_snapshot_is_cached_and_serves_keyed_queries() {
        let rvps = counting_rvps();
        let resolver = ReferenceValueResolver::new(Arc::clone(&rvps) as Arc<dyn RvpsApi>);

        assert_eq!(resolver.get_reference_values().await.unwrap().len(), 1);
        assert_eq!(resolver.get_reference_values().await.unwrap().len(), 1);
        assert_eq!(
            resolver.query_reference_value("svn").await.unwrap(),
            Some(serde_json::json!([1, 2]))
        );
        assert_eq!(
            resolver.query_reference_value("missing").await.unwrap(),
            None
        );
        assert_eq!(rvps.bulk_queries.load(Ordering::SeqCst), 1);
        assert_eq!(rvps.keyed_queries.load(Ordering::SeqCst), 0);
    }
}
