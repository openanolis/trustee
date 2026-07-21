use super::{Result, RvpsApi};
use async_trait::async_trait;
use core::result::Result::Ok;
use reference_value_provider_service::{Config, Rvps};
use std::collections::HashMap;
use tokio::sync::RwLock;

pub struct BuiltinRvps {
    rvps: RwLock<Rvps>,
}

impl BuiltinRvps {
    pub fn new(config: Config) -> Result<Self> {
        let rvps = Rvps::new(config)?;
        Ok(Self {
            rvps: RwLock::new(rvps),
        })
    }
}

#[cfg_attr(all(target_arch = "wasm32", target_vendor = "unknown", target_os = "unknown"), async_trait(?Send))]
#[cfg_attr(not(all(target_arch = "wasm32", target_vendor = "unknown", target_os = "unknown")), async_trait)]
impl RvpsApi for BuiltinRvps {
    async fn verify_and_extract(&self, message: &str) -> Result<()> {
        self.rvps.write().await.verify_and_extract(message).await?;
        Ok(())
    }

    async fn set_reference_value_list(&self, payload: &str) -> Result<()> {
        self.rvps
            .write()
            .await
            .set_reference_value_list(payload)
            .await?;
        Ok(())
    }

    async fn query_reference_value(
        &self,
        reference_value_id: &str,
    ) -> Result<Option<serde_json::Value>> {
        let value = self
            .rvps
            .read()
            .await
            .query_reference_value(reference_value_id)
            .await?;
        Ok(value)
    }

    async fn get_reference_values(&self) -> Result<HashMap<String, serde_json::Value>> {
        let values = self.rvps.read().await.get_reference_values().await?;
        Ok(values)
    }

    async fn delete_reference_value(&self, name: &str) -> Result<bool> {
        let result = self.rvps.write().await.delete_reference_value(name).await?;
        Ok(result)
    }
}
