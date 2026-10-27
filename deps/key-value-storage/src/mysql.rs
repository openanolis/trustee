// Copyright (c) 2026 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use derivative::Derivative;
use serde::Deserialize;
use sqlx::{mysql::MySqlPoolOptions, MySql, MySqlPool, Row, Transaction};

use crate::{
    validate_key, validate_namespace, DeleteOptions, DeleteOutcome, KeyValueStorage, PutCondition,
    PutOptions, PutOutcome, Result, StorageCapabilities, StorageError, StoredValue,
};

const CREATE_TABLE: &str = r#"
CREATE TABLE IF NOT EXISTS trustee_kv_entries (
    namespace VARCHAR(191) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    entry_key VARBINARY(512) NOT NULL,
    entry_value LONGBLOB NOT NULL,
    revision BIGINT UNSIGNED NOT NULL,
    expires_at TIMESTAMP(6) NULL,
    PRIMARY KEY (namespace, entry_key),
    INDEX trustee_kv_expiry (expires_at)
) ENGINE=InnoDB
"#;
const MAX_TRANSACTION_RETRIES: usize = 16;

fn transaction_retry_backoff(attempt: usize) -> Duration {
    // Missing-row gap locks can deadlock even when writers use distinct keys.
    // Yielding immediately lets the same contenders repeatedly collide and
    // exhaust retries before a peer commits. Cap the delay and add inexpensive
    // cross-process jitter; this is scheduling, not cryptographic randomness.
    let base_ms = 1_u64 << attempt.min(6);
    let jitter = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::from(elapsed.subsec_nanos()) % (base_ms + 1))
        .unwrap_or_default();
    Duration::from_millis(base_ms + jitter)
}

pub const DEFAULT_MYSQL_URL_ENV: &str = "TRUSTEE_STORAGE_MYSQL_URL";

#[derive(Clone, Derivative, Deserialize, PartialEq)]
#[derivative(Debug)]
#[serde(default)]
pub struct MysqlConfig {
    #[derivative(Debug = "ignore")]
    pub url: String,
    /// Environment variable that overrides `url`, suitable for a Secret.
    pub url_env: Option<String>,
    pub max_connections: u32,
    pub min_connections: u32,
    pub acquire_timeout_seconds: u64,
}

impl Default for MysqlConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            url_env: Some(DEFAULT_MYSQL_URL_ENV.into()),
            max_connections: 10,
            min_connections: 0,
            acquire_timeout_seconds: 10,
        }
    }
}

pub struct MysqlStorage {
    pool: MySqlPool,
    namespace: String,
}

impl MysqlStorage {
    pub async fn connect(config: MysqlConfig, namespace: &str) -> Result<Self> {
        validate_namespace(namespace)?;
        let url = config.database_url()?;
        if config.max_connections == 0 || config.min_connections > config.max_connections {
            return Err(StorageError::InvalidConfiguration {
                message: "invalid MySQL connection pool limits".into(),
            });
        }

        let pool = MySqlPoolOptions::new()
            .max_connections(config.max_connections)
            .min_connections(config.min_connections)
            .acquire_timeout(Duration::from_secs(config.acquire_timeout_seconds))
            .connect(&url)
            .await
            .map_err(|error| StorageError::Backend {
                message: format!("connect to MySQL: {error}"),
            })?;
        sqlx::query(CREATE_TABLE).execute(&pool).await?;

        Ok(Self {
            pool,
            namespace: namespace.to_string(),
        })
    }

    fn ttl_micros(ttl: Option<Duration>) -> Result<Option<i64>> {
        ttl.map(|ttl| {
            i64::try_from(ttl.as_micros()).map_err(|_| StorageError::InvalidConfiguration {
                message: "TTL is too large".into(),
            })
        })
        .transpose()
    }

    async fn delete_expired_key(
        &self,
        transaction: &mut Transaction<'_, MySql>,
        key: &str,
    ) -> Result<()> {
        sqlx::query(
            "DELETE FROM trustee_kv_entries \
             WHERE namespace = ? AND entry_key = ? \
             AND expires_at IS NOT NULL AND expires_at <= UTC_TIMESTAMP(6)",
        )
        .bind(&self.namespace)
        .bind(key.as_bytes())
        .execute(&mut **transaction)
        .await?;
        Ok(())
    }

    async fn current_revision(
        &self,
        transaction: &mut Transaction<'_, MySql>,
        key: &str,
    ) -> Result<Option<u64>> {
        let row = sqlx::query(
            "SELECT revision FROM trustee_kv_entries \
             WHERE namespace = ? AND entry_key = ? FOR UPDATE",
        )
        .bind(&self.namespace)
        .bind(key.as_bytes())
        .fetch_optional(&mut **transaction)
        .await?;
        row.map(|row| row.try_get("revision"))
            .transpose()
            .map_err(Into::into)
    }

    async fn put_transaction(
        &self,
        key: &str,
        value: &[u8],
        options: PutOptions,
    ) -> Result<PutOutcome> {
        let ttl_micros = Self::ttl_micros(options.ttl)?;
        let mut transaction = self.pool.begin().await?;
        self.delete_expired_key(&mut transaction, key).await?;

        let outcome = match options.condition {
            PutCondition::Upsert => {
                let existed = self
                    .current_revision(&mut transaction, key)
                    .await?
                    .is_some();
                sqlx::query(
                    "INSERT INTO trustee_kv_entries \
                     (namespace, entry_key, entry_value, revision, expires_at) \
                     VALUES (?, ?, ?, 1, TIMESTAMPADD(MICROSECOND, ?, UTC_TIMESTAMP(6))) \
                     ON DUPLICATE KEY UPDATE entry_value = VALUES(entry_value), \
                     revision = revision + 1, expires_at = VALUES(expires_at)",
                )
                .bind(&self.namespace)
                .bind(key.as_bytes())
                .bind(value)
                .bind(ttl_micros)
                .execute(&mut *transaction)
                .await?;
                let revision = self
                    .current_revision(&mut transaction, key)
                    .await?
                    .ok_or_else(|| StorageError::Backend {
                        message: "MySQL upsert completed without a visible record".into(),
                    })?;
                if existed {
                    PutOutcome::Updated { revision }
                } else {
                    PutOutcome::Created { revision }
                }
            }
            PutCondition::IfAbsent => {
                let result = sqlx::query(
                    "INSERT IGNORE INTO trustee_kv_entries \
                     (namespace, entry_key, entry_value, revision, expires_at) \
                     VALUES (?, ?, ?, 1, TIMESTAMPADD(MICROSECOND, ?, UTC_TIMESTAMP(6)))",
                )
                .bind(&self.namespace)
                .bind(key.as_bytes())
                .bind(value)
                .bind(ttl_micros)
                .execute(&mut *transaction)
                .await?;
                if result.rows_affected() == 1 {
                    PutOutcome::Created { revision: 1 }
                } else {
                    PutOutcome::Conflict {
                        current_revision: self.current_revision(&mut transaction, key).await?,
                    }
                }
            }
            PutCondition::IfRevision(expected) => {
                let result = sqlx::query(
                    "UPDATE trustee_kv_entries SET entry_value = ?, \
                     revision = revision + 1, \
                     expires_at = TIMESTAMPADD(MICROSECOND, ?, UTC_TIMESTAMP(6)) \
                     WHERE namespace = ? AND entry_key = ? AND revision = ?",
                )
                .bind(value)
                .bind(ttl_micros)
                .bind(&self.namespace)
                .bind(key.as_bytes())
                .bind(expected)
                .execute(&mut *transaction)
                .await?;
                if result.rows_affected() == 1 {
                    PutOutcome::Updated {
                        revision: expected + 1,
                    }
                } else {
                    PutOutcome::Conflict {
                        current_revision: self.current_revision(&mut transaction, key).await?,
                    }
                }
            }
        };
        transaction.commit().await?;
        Ok(outcome)
    }

    async fn delete_transaction(&self, key: &str, options: DeleteOptions) -> Result<DeleteOutcome> {
        let mut transaction = self.pool.begin().await?;
        self.delete_expired_key(&mut transaction, key).await?;
        let current = self.current_revision(&mut transaction, key).await?;
        let Some(current_revision) = current else {
            transaction.commit().await?;
            return Ok(DeleteOutcome::NotFound);
        };
        if options
            .expected_revision
            .is_some_and(|expected| expected != current_revision)
        {
            transaction.commit().await?;
            return Ok(DeleteOutcome::Conflict { current_revision });
        }
        sqlx::query("DELETE FROM trustee_kv_entries WHERE namespace = ? AND entry_key = ?")
            .bind(&self.namespace)
            .bind(key.as_bytes())
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(DeleteOutcome::Deleted)
    }
}

impl MysqlConfig {
    fn database_url(&self) -> Result<String> {
        let url = self
            .url_env
            .as_deref()
            .and_then(|name| std::env::var(name).ok())
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| self.url.clone());
        if url.trim().is_empty() {
            return Err(StorageError::InvalidConfiguration {
                message: format!(
                    "MySQL URL must be set in backends.mysql.url or {}",
                    self.url_env.as_deref().unwrap_or(DEFAULT_MYSQL_URL_ENV)
                ),
            });
        }
        Ok(url)
    }
}

#[async_trait]
impl KeyValueStorage for MysqlStorage {
    fn capabilities(&self) -> StorageCapabilities {
        StorageCapabilities {
            shared: true,
            compare_and_swap: true,
            ttl: true,
        }
    }

    async fn put(&self, key: &str, value: &[u8], options: PutOptions) -> Result<PutOutcome> {
        validate_key(key)?;
        for attempt in 0..MAX_TRANSACTION_RETRIES {
            match self.put_transaction(key, value, options).await {
                Err(error)
                    if error.is_retryable_mysql_transaction()
                        && attempt + 1 < MAX_TRANSACTION_RETRIES =>
                {
                    tokio::time::sleep(transaction_retry_backoff(attempt)).await;
                }
                result => return result,
            }
        }
        unreachable!("bounded transaction retry loop always returns")
    }

    async fn get(&self, key: &str) -> Result<Option<StoredValue>> {
        validate_key(key)?;
        let row = sqlx::query(
            "SELECT entry_value, revision FROM trustee_kv_entries \
             WHERE namespace = ? AND entry_key = ? \
             AND (expires_at IS NULL OR expires_at > UTC_TIMESTAMP(6))",
        )
        .bind(&self.namespace)
        .bind(key.as_bytes())
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            Ok(StoredValue {
                value: row.try_get("entry_value")?,
                revision: row.try_get("revision")?,
            })
        })
        .transpose()
    }

    async fn list(&self) -> Result<Vec<String>> {
        let rows = sqlx::query(
            "SELECT entry_key FROM trustee_kv_entries \
             WHERE namespace = ? AND (expires_at IS NULL OR expires_at > UTC_TIMESTAMP(6)) \
             ORDER BY entry_key",
        )
        .bind(&self.namespace)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| {
                let key: Vec<u8> = row.try_get("entry_key")?;
                String::from_utf8(key).map_err(|error| StorageError::Backend {
                    message: format!("stored key is not UTF-8: {error}"),
                })
            })
            .collect()
    }

    async fn delete(&self, key: &str, options: DeleteOptions) -> Result<DeleteOutcome> {
        validate_key(key)?;
        for attempt in 0..MAX_TRANSACTION_RETRIES {
            match self.delete_transaction(key, options).await {
                Err(error)
                    if error.is_retryable_mysql_transaction()
                        && attempt + 1 < MAX_TRANSACTION_RETRIES =>
                {
                    tokio::time::sleep(transaction_retry_backoff(attempt)).await;
                }
                result => return result,
            }
        }
        unreachable!("bounded transaction retry loop always returns")
    }

    async fn purge_expired(&self) -> Result<u64> {
        let result = sqlx::query(
            "DELETE FROM trustee_kv_entries \
             WHERE namespace = ? AND expires_at IS NOT NULL \
             AND expires_at <= UTC_TIMESTAMP(6)",
        )
        .bind(&self.namespace)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use std::{env, sync::Arc};

    use serial_test::serial;

    use super::*;

    async fn storage(namespace: &str) -> Option<MysqlStorage> {
        let url = env::var("MYSQL_TEST_URL").ok()?;
        Some(
            MysqlStorage::connect(
                MysqlConfig {
                    url,
                    ..Default::default()
                },
                namespace,
            )
            .await
            .unwrap(),
        )
    }

    #[tokio::test]
    #[serial]
    async fn mysql_supports_shared_cas_and_ttl() {
        let Some(first) = storage("kv_mysql_test").await else {
            return;
        };
        first.purge_expired().await.unwrap();
        for key in first.list().await.unwrap() {
            first.delete(&key, DeleteOptions::default()).await.unwrap();
        }
        let second = storage("kv_mysql_test").await.unwrap();

        assert_eq!(
            first
                .put("session", b"authed", PutOptions::default())
                .await
                .unwrap(),
            PutOutcome::Created { revision: 1 }
        );
        assert_eq!(
            second.get("session").await.unwrap().unwrap().value,
            b"authed"
        );
        assert_eq!(
            second
                .put(
                    "session",
                    b"attested",
                    PutOptions {
                        condition: PutCondition::IfRevision(1),
                        ttl: Some(Duration::ZERO),
                    },
                )
                .await
                .unwrap(),
            PutOutcome::Updated { revision: 2 }
        );
        assert!(first.get("session").await.unwrap().is_none());
    }

    #[tokio::test]
    #[serial]
    async fn only_one_concurrent_compare_and_swap_succeeds() {
        let Some(storage) = storage("kv_mysql_cas_test").await.map(Arc::new) else {
            return;
        };
        for key in storage.list().await.unwrap() {
            storage
                .delete(&key, DeleteOptions::default())
                .await
                .unwrap();
        }
        storage
            .put("session", b"authed", PutOptions::default())
            .await
            .unwrap();

        let mut tasks = Vec::new();
        for candidate in 0..16_u8 {
            let storage = storage.clone();
            tasks.push(tokio::spawn(async move {
                storage
                    .put(
                        "session",
                        &[candidate],
                        PutOptions {
                            condition: PutCondition::IfRevision(1),
                            ttl: None,
                        },
                    )
                    .await
                    .unwrap()
            }));
        }

        let mut updated = 0;
        for task in tasks {
            if matches!(task.await.unwrap(), PutOutcome::Updated { revision: 2 }) {
                updated += 1;
            }
        }
        assert_eq!(updated, 1);
        assert_eq!(storage.get("session").await.unwrap().unwrap().revision, 2);
    }

    #[tokio::test]
    #[serial]
    async fn concurrent_first_writes_retry_mysql_deadlocks() {
        let Some(first) = storage("kv_mysql_first_write_test").await.map(Arc::new) else {
            return;
        };
        for key in first.list().await.unwrap() {
            first.delete(&key, DeleteOptions::default()).await.unwrap();
        }
        let second = Arc::new(storage("kv_mysql_first_write_test").await.unwrap());

        let mut tasks = Vec::new();
        for candidate in 0..16_u8 {
            let storage = if candidate % 2 == 0 {
                first.clone()
            } else {
                second.clone()
            };
            tasks.push(tokio::spawn(async move {
                storage
                    .put(
                        "new-session",
                        &[candidate],
                        PutOptions {
                            condition: PutCondition::IfAbsent,
                            ttl: None,
                        },
                    )
                    .await
                    .unwrap()
            }));
        }

        let mut created = 0;
        for task in tasks {
            if matches!(task.await.unwrap(), PutOutcome::Created { revision: 1 }) {
                created += 1;
            }
        }
        assert_eq!(created, 1);
    }

    #[test]
    fn debug_output_redacts_database_url() {
        let config = MysqlConfig {
            url: "mysql://user:password@example.invalid/trustee".into(),
            ..Default::default()
        };
        let debug = format!("{config:?}");
        assert!(!debug.contains("password"));
        assert!(!debug.contains("example.invalid"));
    }

    #[test]
    fn transaction_retry_backoff_is_bounded() {
        for attempt in 0..32 {
            let base = Duration::from_millis(1_u64 << attempt.min(6));
            let delay = transaction_retry_backoff(attempt);
            assert!(delay >= base);
            assert!(delay <= base * 2);
            assert!(delay <= Duration::from_millis(128));
        }
    }

    #[tokio::test]
    #[serial]
    async fn concurrent_distinct_resource_upserts_preserve_every_value() {
        let Some(first) = storage("kv_mysql_distinct_upserts").await.map(Arc::new) else {
            return;
        };
        for key in first.list().await.unwrap() {
            first.delete(&key, DeleteOptions::default()).await.unwrap();
        }
        let second = Arc::new(storage("kv_mysql_distinct_upserts").await.unwrap());
        let barrier = Arc::new(tokio::sync::Barrier::new(32));
        let mut tasks = Vec::new();
        for candidate in 0..32_u8 {
            let storage = if candidate % 2 == 0 {
                first.clone()
            } else {
                second.clone()
            };
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                let key = format!("resource-{candidate:02}");
                storage
                    .put(&key, &[candidate], PutOptions::default())
                    .await
                    .unwrap();
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(second.list().await.unwrap().len(), 32);
        for candidate in 0..32_u8 {
            let key = format!("resource-{candidate:02}");
            assert_eq!(
                second.get(&key).await.unwrap().unwrap().value,
                vec![candidate]
            );
        }
    }

    #[test]
    #[serial]
    fn configured_environment_variable_overrides_inline_url() {
        const URL_ENV: &str = "TRUSTEE_STORAGE_TEST_MYSQL_URL";
        env::set_var(URL_ENV, "mysql://env.invalid/trustee");
        let config = MysqlConfig {
            url: "mysql://fallback.invalid/trustee".into(),
            url_env: Some(URL_ENV.into()),
            ..Default::default()
        };
        assert_eq!(
            config.database_url().unwrap(),
            "mysql://env.invalid/trustee"
        );
        env::remove_var(URL_ENV);
    }
}
