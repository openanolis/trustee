// Copyright (c) 2026 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, time::Instant};

use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::{
    validate_key, DeleteOptions, DeleteOutcome, KeyValueStorage, PutCondition, PutOptions,
    PutOutcome, Result, StorageCapabilities, StoredValue,
};

struct Record {
    value: Vec<u8>,
    revision: u64,
    expires_at: Option<Instant>,
}

impl Record {
    fn is_expired(&self, now: Instant) -> bool {
        self.expires_at.is_some_and(|expires_at| expires_at <= now)
    }
}

#[derive(Default)]
pub struct MemoryStorage {
    values: RwLock<HashMap<String, Record>>,
}

#[async_trait]
impl KeyValueStorage for MemoryStorage {
    fn capabilities(&self) -> StorageCapabilities {
        StorageCapabilities {
            shared: false,
            compare_and_swap: true,
            ttl: true,
        }
    }

    async fn put(&self, key: &str, value: &[u8], options: PutOptions) -> Result<PutOutcome> {
        validate_key(key)?;
        let now = Instant::now();
        let mut values = self.values.write().await;
        if values.get(key).is_some_and(|record| record.is_expired(now)) {
            values.remove(key);
        }

        let current = values.get(key);
        let allowed = match options.condition {
            PutCondition::Upsert => true,
            PutCondition::IfAbsent => current.is_none(),
            PutCondition::IfRevision(expected) => {
                current.is_some_and(|record| record.revision == expected)
            }
        };
        if !allowed {
            return Ok(PutOutcome::Conflict {
                current_revision: current.map(|record| record.revision),
            });
        }

        let revision = current.map_or(1, |record| record.revision + 1);
        let created = current.is_none();
        values.insert(
            key.to_string(),
            Record {
                value: value.to_vec(),
                revision,
                expires_at: options.ttl.map(|ttl| now + ttl),
            },
        );
        Ok(if created {
            PutOutcome::Created { revision }
        } else {
            PutOutcome::Updated { revision }
        })
    }

    async fn get(&self, key: &str) -> Result<Option<StoredValue>> {
        validate_key(key)?;
        let now = Instant::now();
        let mut values = self.values.write().await;
        if values.get(key).is_some_and(|record| record.is_expired(now)) {
            values.remove(key);
            return Ok(None);
        }
        Ok(values.get(key).map(|record| StoredValue {
            value: record.value.clone(),
            revision: record.revision,
        }))
    }

    async fn list(&self) -> Result<Vec<String>> {
        self.purge_expired().await?;
        let mut keys = self.values.read().await.keys().cloned().collect::<Vec<_>>();
        keys.sort();
        Ok(keys)
    }

    async fn delete(&self, key: &str, options: DeleteOptions) -> Result<DeleteOutcome> {
        validate_key(key)?;
        let now = Instant::now();
        let mut values = self.values.write().await;
        if values.get(key).is_some_and(|record| record.is_expired(now)) {
            values.remove(key);
            return Ok(DeleteOutcome::NotFound);
        }
        let Some(record) = values.get(key) else {
            return Ok(DeleteOutcome::NotFound);
        };
        if let Some(expected) = options.expected_revision {
            if record.revision != expected {
                return Ok(DeleteOutcome::Conflict {
                    current_revision: record.revision,
                });
            }
        }
        values.remove(key);
        Ok(DeleteOutcome::Deleted)
    }

    async fn purge_expired(&self) -> Result<u64> {
        let now = Instant::now();
        let mut values = self.values.write().await;
        let before = values.len();
        values.retain(|_, record| !record.is_expired(now));
        Ok((before - values.len()) as u64)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn compare_and_swap_rejects_stale_revision() {
        let storage = MemoryStorage::default();
        storage
            .put("key", b"v1", PutOptions::default())
            .await
            .unwrap();
        assert_eq!(
            storage
                .put(
                    "key",
                    b"v2",
                    PutOptions {
                        condition: PutCondition::IfRevision(7),
                        ttl: None,
                    },
                )
                .await
                .unwrap(),
            PutOutcome::Conflict {
                current_revision: Some(1)
            }
        );
        assert_eq!(storage.get("key").await.unwrap().unwrap().value, b"v1");
    }

    #[tokio::test]
    async fn ttl_hides_expired_values() {
        let storage = MemoryStorage::default();
        storage
            .put(
                "key",
                b"value",
                PutOptions {
                    condition: PutCondition::Upsert,
                    ttl: Some(Duration::ZERO),
                },
            )
            .await
            .unwrap();
        assert!(storage.get("key").await.unwrap().is_none());
    }
}
