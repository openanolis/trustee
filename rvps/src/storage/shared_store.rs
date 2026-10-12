// Copyright (c) 2026 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use key_value_storage::{
    DeleteOptions, DeleteOutcome, PutCondition, PutOptions, PutOutcome, Storage, StorageProvider,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::{
    ConditionalDeleteResult, ConditionalSetResult, ReferenceValueStorage, VersionedReferenceValue,
};
use crate::ReferenceValue;

pub const REFERENCE_VALUE_NAMESPACE: &str = "reference_value";

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct Config {}

pub struct SharedStore {
    storage: Storage,
}

impl SharedStore {
    pub async fn new(_config: Config, provider: Arc<dyn StorageProvider>) -> Result<Self> {
        let storage = provider
            .get_or_register(REFERENCE_VALUE_NAMESPACE)
            .await
            .context("initialize shared reference-value storage")?;
        Ok(Self { storage })
    }

    fn decode(bytes: &[u8]) -> Result<ReferenceValue> {
        serde_json::from_slice(bytes).context("deserialize reference value")
    }

    fn key(name: &str) -> String {
        format!("{:x}", Sha256::digest(name.as_bytes()))
    }
}

#[async_trait]
impl ReferenceValueStorage for SharedStore {
    async fn set(&self, name: String, rv: ReferenceValue) -> Result<Option<ReferenceValue>> {
        let previous = self.get(&name).await?;
        let key = Self::key(&name);
        self.storage
            .put(&key, &serde_json::to_vec(&rv)?, PutOptions::default())
            .await
            .context("write reference value")?;
        Ok(previous)
    }

    async fn get(&self, name: &str) -> Result<Option<ReferenceValue>> {
        let key = Self::key(name);
        self.storage
            .get(&key)
            .await
            .context("read reference value")?
            .map(|entry| Self::decode(&entry.value))
            .transpose()
    }

    async fn get_values(&self) -> Result<Vec<ReferenceValue>> {
        let mut values = Vec::new();
        for key in self.storage.list().await.context("list reference values")? {
            if let Some(entry) = self
                .storage
                .get(&key)
                .await
                .context("read listed reference value")?
            {
                values.push(Self::decode(&entry.value)?);
            }
        }
        Ok(values)
    }

    async fn delete(&self, name: &str) -> Result<Option<ReferenceValue>> {
        let previous = self.get(name).await?;
        let key = Self::key(name);
        self.storage
            .delete(&key, DeleteOptions::default())
            .await
            .context("delete reference value")?;
        Ok(previous)
    }

    async fn get_versioned(&self, name: &str) -> Result<Option<VersionedReferenceValue>> {
        let key = Self::key(name);
        self.storage
            .get(&key)
            .await
            .context("read versioned reference value")?
            .map(|entry| {
                Ok(VersionedReferenceValue {
                    value: Self::decode(&entry.value)?,
                    revision: Some(entry.revision),
                })
            })
            .transpose()
    }

    async fn set_if_unchanged(
        &self,
        name: String,
        rv: ReferenceValue,
        expected_revision: Option<u64>,
    ) -> Result<ConditionalSetResult> {
        let condition = expected_revision
            .map(PutCondition::IfRevision)
            .unwrap_or(PutCondition::IfAbsent);
        let key = Self::key(&name);
        let outcome = self
            .storage
            .put(
                &key,
                &serde_json::to_vec(&rv)?,
                PutOptions {
                    condition,
                    ..Default::default()
                },
            )
            .await
            .context("conditionally write reference value")?;
        Ok(match outcome {
            PutOutcome::Created { .. } | PutOutcome::Updated { .. } => {
                ConditionalSetResult::Stored(None)
            }
            PutOutcome::Conflict { .. } => ConditionalSetResult::Conflict,
        })
    }

    async fn delete_if_unchanged(
        &self,
        name: &str,
        expected_revision: Option<u64>,
    ) -> Result<ConditionalDeleteResult> {
        let key = Self::key(name);
        let outcome = self
            .storage
            .delete(&key, DeleteOptions { expected_revision })
            .await
            .context("conditionally delete reference value")?;
        Ok(match outcome {
            DeleteOutcome::Deleted => ConditionalDeleteResult::Deleted(None),
            DeleteOutcome::NotFound => ConditionalDeleteResult::NotFound,
            DeleteOutcome::Conflict { .. } => ConditionalDeleteResult::Conflict,
        })
    }
}
