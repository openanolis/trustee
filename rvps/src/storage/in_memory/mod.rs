// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! fs-free `ReferenceValueStorage`: keeps reference values in a `HashMap`
//! behind a `tokio::sync::RwLock`. For pure-lib / wasm consumers that preload
//! reference values in-process (no on-disk DB).

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use serde::Deserialize;
use tokio::sync::RwLock;

use super::ReferenceValueStorage;
use crate::ReferenceValue;

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct Config {}

pub struct InMemory {
    map: Arc<RwLock<HashMap<String, ReferenceValue>>>,
}

impl InMemory {
    pub fn new(_config: Config) -> Result<Self> {
        Ok(Self {
            map: Arc::new(RwLock::new(HashMap::new())),
        })
    }
}

#[async_trait]
impl ReferenceValueStorage for InMemory {
    async fn set(&self, name: String, rv: ReferenceValue) -> Result<Option<ReferenceValue>> {
        let mut m = self.map.write().await;
        Ok(m.insert(name, rv))
    }

    async fn get(&self, name: &str) -> Result<Option<ReferenceValue>> {
        let m = self.map.read().await;
        Ok(m.get(name).cloned())
    }

    async fn get_values(&self) -> Result<Vec<ReferenceValue>> {
        let m = self.map.read().await;
        Ok(m.values().cloned().collect())
    }

    async fn delete(&self, name: &str) -> Result<Option<ReferenceValue>> {
        let mut m = self.map.write().await;
        Ok(m.remove(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn dummy_rv(name: &str) -> ReferenceValue {
        ReferenceValue {
            version: "0.1.0".to_string(),
            name: name.to_string(),
            expiration: chrono::Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap(),
            hash_value: vec![],
            audit_proof: None,
        }
    }

    #[tokio::test]
    async fn set_get_delete() {
        let s = InMemory::new(Config {}).unwrap();
        s.set("a".into(), dummy_rv("a")).await.unwrap();
        assert!(s.get("a").await.unwrap().is_some());
        assert_eq!(s.get_values().await.unwrap().len(), 1);
        s.delete("a").await.unwrap();
        assert!(s.get("a").await.unwrap().is_none());
    }
}
