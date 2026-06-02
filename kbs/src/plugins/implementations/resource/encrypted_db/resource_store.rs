// Copyright (c) 2026 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Resource envelope persistence (`kbs_resources`).
//!
//! Resources are pre-encrypted by the client with the current primary public
//! key, serialized into the JSON envelope format defined by
//! `EncryptedLocalFs` (alg / enc_key / iv / ciphertext / tag, all base64),
//! and POSTed to KBS as the request body. KBS stores them verbatim — it
//! does not parse or re-encrypt on write — so the wire format is the same
//! as the EncryptedLocalFs backend and clients keep working unchanged.
//!
//! On read the parent `EncryptedDb` module fetches the JSON, picks the
//! envelope apart, and trial-decrypts with each loaded key in
//! newest-first order (mirroring the EncryptedLocalFs decrypt path).

use anyhow::{Context, Result};
use std::time::{SystemTime, UNIX_EPOCH};

use super::db::DbPool;
use super::key_store::Generation;
use super::ResourceDesc;

/// One resource row read from `kbs_resources`.
#[derive(Debug, Clone)]
pub struct ResourceRow {
    pub repository_name: String,
    pub resource_type: String,
    pub resource_tag: String,
    pub envelope: String,
    pub generation: Generation,
}

/// UPSERT a resource: insert if new, replace envelope+generation+updated_at
/// if the (repo, type, tag) already exists.
pub async fn upsert_envelope(
    pool: &DbPool,
    desc: &ResourceDesc,
    envelope: &[u8],
    generation: Generation,
) -> Result<()> {
    let envelope_str = std::str::from_utf8(envelope)
        .context("EncryptedDb only stores valid UTF-8 JSON envelopes; got non-UTF-8 bytes")?;
    let now = current_iso_timestamp()?;
    match pool {
        DbPool::MySql(p) => {
            sqlx::query(
                "INSERT INTO kbs_resources
                    (repository_name, resource_type, resource_tag,
                     envelope, generation, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?)
                 ON DUPLICATE KEY UPDATE
                    envelope   = VALUES(envelope),
                    generation = VALUES(generation),
                    updated_at = VALUES(updated_at)",
            )
            .bind(&desc.repository_name)
            .bind(&desc.resource_type)
            .bind(&desc.resource_tag)
            .bind(envelope_str)
            .bind(generation)
            .bind(&now)
            .execute(p)
            .await
            .context("upsert resource (mysql)")?;
        }
        DbPool::Sqlite(p) => {
            sqlx::query(
                "INSERT INTO kbs_resources
                    (repository_name, resource_type, resource_tag,
                     envelope, generation, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?)
                 ON CONFLICT(repository_name, resource_type, resource_tag) DO UPDATE SET
                    envelope   = excluded.envelope,
                    generation = excluded.generation,
                    updated_at = excluded.updated_at",
            )
            .bind(&desc.repository_name)
            .bind(&desc.resource_type)
            .bind(&desc.resource_tag)
            .bind(envelope_str)
            .bind(generation)
            .bind(&now)
            .execute(p)
            .await
            .context("upsert resource (sqlite)")?;
        }
    }
    Ok(())
}

/// Read a single envelope's bytes for the given resource. Returns `None`
/// when the resource does not exist.
pub async fn read_envelope(pool: &DbPool, desc: &ResourceDesc) -> Result<Option<Vec<u8>>> {
    let row: Option<(String,)> = match pool {
        DbPool::MySql(p) => sqlx::query_as(
            "SELECT envelope FROM kbs_resources
             WHERE repository_name = ? AND resource_type = ? AND resource_tag = ?",
        )
        .bind(&desc.repository_name)
        .bind(&desc.resource_type)
        .bind(&desc.resource_tag)
        .fetch_optional(p)
        .await
        .context("read resource (mysql)")?,
        DbPool::Sqlite(p) => sqlx::query_as(
            "SELECT envelope FROM kbs_resources
             WHERE repository_name = ? AND resource_type = ? AND resource_tag = ?",
        )
        .bind(&desc.repository_name)
        .bind(&desc.resource_type)
        .bind(&desc.resource_tag)
        .fetch_optional(p)
        .await
        .context("read resource (sqlite)")?,
    };
    Ok(row.map(|(v,)| v.into_bytes()))
}

/// Delete a single resource. No-op if the row is already gone.
pub async fn delete_resource(pool: &DbPool, desc: &ResourceDesc) -> Result<()> {
    match pool {
        DbPool::MySql(p) => {
            sqlx::query(
                "DELETE FROM kbs_resources
                 WHERE repository_name = ? AND resource_type = ? AND resource_tag = ?",
            )
            .bind(&desc.repository_name)
            .bind(&desc.resource_type)
            .bind(&desc.resource_tag)
            .execute(p)
            .await
            .context("delete resource (mysql)")?;
        }
        DbPool::Sqlite(p) => {
            sqlx::query(
                "DELETE FROM kbs_resources
                 WHERE repository_name = ? AND resource_type = ? AND resource_tag = ?",
            )
            .bind(&desc.repository_name)
            .bind(&desc.resource_type)
            .bind(&desc.resource_tag)
            .execute(p)
            .await
            .context("delete resource (sqlite)")?;
        }
    }
    Ok(())
}

/// List every resource (repo, type, tag triple), name-sorted for
/// determinism. The envelope payload is intentionally not returned here —
/// listing is used by rewrap and admin endpoints, both of which fetch
/// payloads on demand.
pub async fn list_resources(pool: &DbPool) -> Result<Vec<ResourceDesc>> {
    let rows: Vec<(String, String, String)> = match pool {
        DbPool::MySql(p) => sqlx::query_as(
            "SELECT repository_name, resource_type, resource_tag
             FROM kbs_resources
             ORDER BY repository_name, resource_type, resource_tag",
        )
        .fetch_all(p)
        .await
        .context("list resources (mysql)")?,
        DbPool::Sqlite(p) => sqlx::query_as(
            "SELECT repository_name, resource_type, resource_tag
             FROM kbs_resources
             ORDER BY repository_name, resource_type, resource_tag",
        )
        .fetch_all(p)
        .await
        .context("list resources (sqlite)")?,
    };
    Ok(rows
        .into_iter()
        .map(|(r, t, g)| ResourceDesc {
            repository_name: r,
            resource_type: t,
            resource_tag: g,
        })
        .collect())
}

/// Fetch a batch of resources strictly older than `cutoff_generation`
/// (i.e. wrapped under a key that pre-dates the new primary). Used by
/// the rewrap pass.
pub async fn fetch_batch_older_than(
    pool: &DbPool,
    cutoff_generation: Generation,
    limit: i64,
) -> Result<Vec<ResourceRow>> {
    let rows: Vec<(String, String, String, String, Generation)> = match pool {
        DbPool::MySql(p) => sqlx::query_as(
            "SELECT repository_name, resource_type, resource_tag, envelope, generation
             FROM kbs_resources
             WHERE generation < ?
             ORDER BY repository_name, resource_type, resource_tag
             LIMIT ?",
        )
        .bind(cutoff_generation)
        .bind(limit)
        .fetch_all(p)
        .await
        .context("fetch batch (mysql)")?,
        DbPool::Sqlite(p) => sqlx::query_as(
            "SELECT repository_name, resource_type, resource_tag, envelope, generation
             FROM kbs_resources
             WHERE generation < ?
             ORDER BY repository_name, resource_type, resource_tag
             LIMIT ?",
        )
        .bind(cutoff_generation)
        .bind(limit)
        .fetch_all(p)
        .await
        .context("fetch batch (sqlite)")?,
    };
    Ok(rows
        .into_iter()
        .map(|(r, t, g, e, gen)| ResourceRow {
            repository_name: r,
            resource_type: t,
            resource_tag: g,
            envelope: e,
            generation: gen,
        })
        .collect())
}

/// Fetch every resource (no generation filter). Used by the purge pass to
/// catch stragglers a prior rewrap missed.
pub async fn fetch_all(pool: &DbPool) -> Result<Vec<ResourceRow>> {
    let rows: Vec<(String, String, String, String, Generation)> = match pool {
        DbPool::MySql(p) => sqlx::query_as(
            "SELECT repository_name, resource_type, resource_tag, envelope, generation
             FROM kbs_resources
             ORDER BY repository_name, resource_type, resource_tag",
        )
        .fetch_all(p)
        .await
        .context("fetch all (mysql)")?,
        DbPool::Sqlite(p) => sqlx::query_as(
            "SELECT repository_name, resource_type, resource_tag, envelope, generation
             FROM kbs_resources
             ORDER BY repository_name, resource_type, resource_tag",
        )
        .fetch_all(p)
        .await
        .context("fetch all (sqlite)")?,
    };
    Ok(rows
        .into_iter()
        .map(|(r, t, g, e, gen)| ResourceRow {
            repository_name: r,
            resource_type: t,
            resource_tag: g,
            envelope: e,
            generation: gen,
        })
        .collect())
}

/// Update a single envelope's payload + generation (used by rewrap).
pub async fn update_envelope(
    pool: &DbPool,
    desc: &ResourceDesc,
    envelope: &[u8],
    generation: Generation,
) -> Result<()> {
    let envelope_str =
        std::str::from_utf8(envelope).context("re-wrapped envelope is not valid UTF-8 JSON")?;
    let now = current_iso_timestamp()?;
    match pool {
        DbPool::MySql(p) => {
            sqlx::query(
                "UPDATE kbs_resources
                 SET envelope = ?, generation = ?, updated_at = ?
                 WHERE repository_name = ? AND resource_type = ? AND resource_tag = ?",
            )
            .bind(envelope_str)
            .bind(generation)
            .bind(&now)
            .bind(&desc.repository_name)
            .bind(&desc.resource_type)
            .bind(&desc.resource_tag)
            .execute(p)
            .await
            .context("update envelope (mysql)")?;
        }
        DbPool::Sqlite(p) => {
            sqlx::query(
                "UPDATE kbs_resources
                 SET envelope = ?, generation = ?, updated_at = ?
                 WHERE repository_name = ? AND resource_type = ? AND resource_tag = ?",
            )
            .bind(envelope_str)
            .bind(generation)
            .bind(&now)
            .bind(&desc.repository_name)
            .bind(&desc.resource_type)
            .bind(&desc.resource_tag)
            .execute(p)
            .await
            .context("update envelope (sqlite)")?;
        }
    }
    Ok(())
}

fn current_iso_timestamp() -> Result<String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?;
    let secs = now.as_secs() as i64;
    let micros = now.subsec_micros();
    let datetime = chrono::DateTime::<chrono::Utc>::from_timestamp(secs, micros * 1_000)
        .ok_or_else(|| anyhow::anyhow!("convert system time to chrono"))?;
    Ok(datetime.format("%Y-%m-%d %H:%M:%S%.6f").to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::implementations::resource::encrypted_db::schema::{
        ensure_meta_defaults, migrate_schema,
    };

    async fn fresh_pool() -> DbPool {
        let pool = DbPool::connect_sqlite_memory().await.unwrap();
        migrate_schema(&pool).await.unwrap();
        ensure_meta_defaults(&pool, None).await.unwrap();
        pool
    }

    fn desc(r: &str, t: &str, g: &str) -> ResourceDesc {
        ResourceDesc {
            repository_name: r.into(),
            resource_type: t.into(),
            resource_tag: g.into(),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn upsert_then_read() {
        let pool = fresh_pool().await;
        let d = desc("repo", "secret", "r1");
        upsert_envelope(&pool, &d, b"{\"alg\":\"X\"}", 100)
            .await
            .unwrap();
        let got = read_envelope(&pool, &d).await.unwrap();
        assert_eq!(got.as_deref(), Some(b"{\"alg\":\"X\"}".as_slice()));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn upsert_replaces_on_conflict() {
        let pool = fresh_pool().await;
        let d = desc("repo", "secret", "r1");
        upsert_envelope(&pool, &d, b"v1", 100).await.unwrap();
        upsert_envelope(&pool, &d, b"v2", 200).await.unwrap();
        let got = read_envelope(&pool, &d).await.unwrap();
        assert_eq!(got.as_deref(), Some(b"v2".as_slice()));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn read_missing_returns_none() {
        let pool = fresh_pool().await;
        let got = read_envelope(&pool, &desc("repo", "secret", "missing"))
            .await
            .unwrap();
        assert!(got.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn delete_then_read_returns_none() {
        let pool = fresh_pool().await;
        let d = desc("repo", "secret", "r1");
        upsert_envelope(&pool, &d, b"v1", 100).await.unwrap();
        delete_resource(&pool, &d).await.unwrap();
        assert!(read_envelope(&pool, &d).await.unwrap().is_none());
        // Idempotent: re-deleting is fine.
        delete_resource(&pool, &d).await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn list_is_sorted() {
        let pool = fresh_pool().await;
        upsert_envelope(&pool, &desc("repo", "secret", "b"), b"x", 1)
            .await
            .unwrap();
        upsert_envelope(&pool, &desc("repo", "secret", "a"), b"x", 1)
            .await
            .unwrap();
        upsert_envelope(&pool, &desc("repo", "key", "a"), b"x", 1)
            .await
            .unwrap();
        let lst = list_resources(&pool).await.unwrap();
        let tags: Vec<String> = lst
            .iter()
            .map(|d| {
                format!(
                    "{}/{}/{}",
                    d.repository_name, d.resource_type, d.resource_tag
                )
            })
            .collect();
        assert_eq!(
            tags,
            vec![
                "repo/key/a".to_string(),
                "repo/secret/a".into(),
                "repo/secret/b".into()
            ]
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fetch_batch_filters_by_generation() {
        let pool = fresh_pool().await;
        upsert_envelope(&pool, &desc("repo", "secret", "old"), b"x", 100)
            .await
            .unwrap();
        upsert_envelope(&pool, &desc("repo", "secret", "new"), b"x", 200)
            .await
            .unwrap();
        let batch = fetch_batch_older_than(&pool, 200, 10).await.unwrap();
        let tags: Vec<String> = batch.iter().map(|r| r.resource_tag.clone()).collect();
        assert_eq!(tags, vec!["old".to_string()]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn update_envelope_writes_back() {
        let pool = fresh_pool().await;
        let d = desc("repo", "secret", "r1");
        upsert_envelope(&pool, &d, b"v1", 100).await.unwrap();
        update_envelope(&pool, &d, b"v2", 200).await.unwrap();
        let got = read_envelope(&pool, &d).await.unwrap();
        assert_eq!(got.as_deref(), Some(b"v2".as_slice()));
    }
}
