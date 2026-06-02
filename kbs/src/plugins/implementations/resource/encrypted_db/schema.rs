// Copyright (c) 2026 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Schema bootstrap for the `EncryptedDb` backend.
//!
//! The schema is created with `CREATE TABLE IF NOT EXISTS` (idempotent) so
//! every replica can run the same code on startup. On MySQL we additionally
//! take a named server-side advisory lock (`GET_LOCK`) for the duration of
//! the migration, so two replicas booting at once cannot race; on SQLite the
//! lock is a no-op (single-writer file or in-memory database).
//!
//! The metadata table seeds default rows on first start, including a fresh
//! random salt and the canary ciphertext used to verify the master secret.

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};

use super::db::DbPool;
use super::master_secret::{
    encrypt_canary, generate_salt, Argon2Params, MasterKey, DEFAULT_ARGON2_M_COST,
    DEFAULT_ARGON2_P_COST, DEFAULT_ARGON2_T_COST,
};

/// Schema version. Bump when introducing breaking changes.
pub const SCHEMA_VERSION: i64 = 1;

/// Name of the MySQL advisory lock taken during schema migration.
const MIGRATION_LOCK_NAME: &str = "trustee_kbs_encrypted_db_migrate";

/// Lock timeout in seconds (`GET_LOCK` second argument).
const MIGRATION_LOCK_TIMEOUT_SECS: i64 = 30;

/// `kbs_meta` keys.
pub mod meta {
    pub const SCHEMA_VERSION: &str = "schema_version";
    pub const KDF_ALGO: &str = "kdf.algo";
    pub const KDF_SALT: &str = "kdf.salt_b64";
    pub const KDF_M_COST: &str = "kdf.m_cost";
    pub const KDF_T_COST: &str = "kdf.t_cost";
    pub const KDF_P_COST: &str = "kdf.p_cost";
    pub const CANARY_NONCE: &str = "canary.iv_b64";
    pub const CANARY_TAG: &str = "canary.tag_b64";
    pub const CANARY_CIPHERTEXT: &str = "canary.ciphertext_b64";
    pub const PRIMARY_GENERATION: &str = "primary_generation";
}

/// Run all CREATE TABLE statements (idempotent).
pub async fn migrate_schema(pool: &DbPool) -> Result<()> {
    match pool {
        DbPool::MySql(p) => {
            let row: (Option<i64>,) = sqlx::query_as("SELECT GET_LOCK(?, ?)")
                .bind(MIGRATION_LOCK_NAME)
                .bind(MIGRATION_LOCK_TIMEOUT_SECS)
                .fetch_one(p)
                .await
                .context("acquire migration lock")?;
            if row.0 != Some(1) {
                return Err(anyhow!(
                    "failed to acquire MySQL advisory lock `{MIGRATION_LOCK_NAME}` within {MIGRATION_LOCK_TIMEOUT_SECS}s"
                ));
            }
            let result = create_tables_mysql(p).await;
            // Best-effort release.
            let _ = sqlx::query("SELECT RELEASE_LOCK(?)")
                .bind(MIGRATION_LOCK_NAME)
                .execute(p)
                .await;
            result
        }
        DbPool::Sqlite(p) => create_tables_sqlite(p).await,
    }
}

const MYSQL_CREATE_KEYS: &str = r#"
CREATE TABLE IF NOT EXISTS kbs_managed_keys (
    generation       BIGINT          NOT NULL PRIMARY KEY,
    public_key_pem   TEXT            NOT NULL,
    enc_private_key  VARBINARY(8192) NOT NULL,
    iv               VARBINARY(12)   NOT NULL,
    tag              VARBINARY(16)   NOT NULL,
    created_at       DATETIME(6)     NOT NULL,
    retired_at       DATETIME(6)     NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
"#;

const MYSQL_CREATE_RESOURCES: &str = r#"
CREATE TABLE IF NOT EXISTS kbs_resources (
    repository_name  VARCHAR(255)    NOT NULL,
    resource_type    VARCHAR(255)    NOT NULL,
    resource_tag     VARCHAR(255)    NOT NULL,
    envelope         MEDIUMTEXT      NOT NULL,
    generation       BIGINT          NOT NULL,
    updated_at       DATETIME(6)     NOT NULL,
    PRIMARY KEY (repository_name, resource_type, resource_tag),
    KEY idx_generation (generation)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
"#;

const MYSQL_CREATE_META: &str = r#"
CREATE TABLE IF NOT EXISTS kbs_meta (
    k     VARCHAR(64) NOT NULL PRIMARY KEY,
    v     TEXT        NOT NULL,
    bump  BIGINT      NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
"#;

const SQLITE_CREATE_KEYS: &str = r#"
CREATE TABLE IF NOT EXISTS kbs_managed_keys (
    generation       INTEGER NOT NULL PRIMARY KEY,
    public_key_pem   TEXT    NOT NULL,
    enc_private_key  BLOB    NOT NULL,
    iv               BLOB    NOT NULL,
    tag              BLOB    NOT NULL,
    created_at       TEXT    NOT NULL,
    retired_at       TEXT    NULL
)
"#;

const SQLITE_CREATE_RESOURCES: &str = r#"
CREATE TABLE IF NOT EXISTS kbs_resources (
    repository_name  TEXT    NOT NULL,
    resource_type    TEXT    NOT NULL,
    resource_tag     TEXT    NOT NULL,
    envelope         TEXT    NOT NULL,
    generation       INTEGER NOT NULL,
    updated_at       TEXT    NOT NULL,
    PRIMARY KEY (repository_name, resource_type, resource_tag)
)
"#;

const SQLITE_CREATE_RESOURCES_INDEX: &str =
    "CREATE INDEX IF NOT EXISTS idx_kbs_resources_generation ON kbs_resources(generation)";

const SQLITE_CREATE_META: &str = r#"
CREATE TABLE IF NOT EXISTS kbs_meta (
    k     TEXT    NOT NULL PRIMARY KEY,
    v     TEXT    NOT NULL,
    bump  INTEGER NOT NULL DEFAULT 0
)
"#;

async fn create_tables_mysql(pool: &sqlx::MySqlPool) -> Result<()> {
    for stmt in [MYSQL_CREATE_KEYS, MYSQL_CREATE_RESOURCES, MYSQL_CREATE_META] {
        sqlx::query(stmt)
            .execute(pool)
            .await
            .with_context(|| format!("execute mysql schema: {}", first_line(stmt)))?;
    }
    Ok(())
}

async fn create_tables_sqlite(pool: &sqlx::SqlitePool) -> Result<()> {
    for stmt in [
        SQLITE_CREATE_KEYS,
        SQLITE_CREATE_RESOURCES,
        SQLITE_CREATE_RESOURCES_INDEX,
        SQLITE_CREATE_META,
    ] {
        sqlx::query(stmt)
            .execute(pool)
            .await
            .with_context(|| format!("execute sqlite schema: {}", first_line(stmt)))?;
    }
    Ok(())
}

fn first_line(s: &str) -> &str {
    s.lines().find(|l| !l.trim().is_empty()).unwrap_or(s).trim()
}

/// Insert default rows in `kbs_meta` (no-ops if already present). Generates a
/// fresh salt the first time, and a canary ciphertext the first time a
/// master key is supplied.
pub async fn ensure_meta_defaults(pool: &DbPool, master_key: Option<&MasterKey>) -> Result<()> {
    insert_meta_if_absent(pool, meta::SCHEMA_VERSION, &SCHEMA_VERSION.to_string()).await?;
    insert_meta_if_absent(pool, meta::KDF_ALGO, "argon2id").await?;
    insert_meta_if_absent(
        pool,
        meta::KDF_M_COST,
        &DEFAULT_ARGON2_M_COST.to_string(),
    )
    .await?;
    insert_meta_if_absent(
        pool,
        meta::KDF_T_COST,
        &DEFAULT_ARGON2_T_COST.to_string(),
    )
    .await?;
    insert_meta_if_absent(
        pool,
        meta::KDF_P_COST,
        &DEFAULT_ARGON2_P_COST.to_string(),
    )
    .await?;

    if read_meta_string(pool, meta::KDF_SALT).await?.is_none() {
        let salt = generate_salt();
        let salt_b64 = STANDARD.encode(salt);
        // INSERT IGNORE so a peer replica that beat us leaves theirs intact.
        insert_meta_if_absent(pool, meta::KDF_SALT, &salt_b64).await?;
    }

    if let Some(key) = master_key {
        if read_meta_string(pool, meta::CANARY_CIPHERTEXT).await?.is_none() {
            let (nonce, tag, ct) = encrypt_canary(key)?;
            insert_meta_if_absent(pool, meta::CANARY_NONCE, &STANDARD.encode(&nonce)).await?;
            insert_meta_if_absent(pool, meta::CANARY_TAG, &STANDARD.encode(&tag)).await?;
            insert_meta_if_absent(pool, meta::CANARY_CIPHERTEXT, &STANDARD.encode(&ct)).await?;
        }
    }

    Ok(())
}

/// Idempotent `INSERT IGNORE` (or `INSERT OR IGNORE`) into `kbs_meta`.
pub async fn insert_meta_if_absent(pool: &DbPool, key: &str, value: &str) -> Result<()> {
    match pool {
        DbPool::MySql(p) => {
            sqlx::query("INSERT IGNORE INTO kbs_meta (k, v, bump) VALUES (?, ?, 0)")
                .bind(key)
                .bind(value)
                .execute(p)
                .await
                .with_context(|| format!("insert {key} (mysql)"))?;
        }
        DbPool::Sqlite(p) => {
            sqlx::query("INSERT OR IGNORE INTO kbs_meta (k, v, bump) VALUES (?, ?, 0)")
                .bind(key)
                .bind(value)
                .execute(p)
                .await
                .with_context(|| format!("insert {key} (sqlite)"))?;
        }
    }
    Ok(())
}

/// Read a single `kbs_meta.v` value as a UTF-8 string.
pub async fn read_meta_string(pool: &DbPool, key: &str) -> Result<Option<String>> {
    let row: Option<(String,)> = match pool {
        DbPool::MySql(p) => sqlx::query_as("SELECT v FROM kbs_meta WHERE k = ?")
            .bind(key)
            .fetch_optional(p)
            .await
            .with_context(|| format!("read meta {key}"))?,
        DbPool::Sqlite(p) => sqlx::query_as("SELECT v FROM kbs_meta WHERE k = ?")
            .bind(key)
            .fetch_optional(p)
            .await
            .with_context(|| format!("read meta {key}"))?,
    };
    Ok(row.map(|(v,)| v))
}

/// Read the persisted Argon2id parameters. Falls back to defaults if any are
/// missing (should not happen after `ensure_meta_defaults`).
pub async fn read_argon2_params(pool: &DbPool) -> Result<Argon2Params> {
    let m_cost = parse_or_default(
        read_meta_string(pool, meta::KDF_M_COST).await?,
        DEFAULT_ARGON2_M_COST,
        "m_cost",
    )?;
    let t_cost = parse_or_default(
        read_meta_string(pool, meta::KDF_T_COST).await?,
        DEFAULT_ARGON2_T_COST,
        "t_cost",
    )?;
    let p_cost = parse_or_default(
        read_meta_string(pool, meta::KDF_P_COST).await?,
        DEFAULT_ARGON2_P_COST,
        "p_cost",
    )?;
    Ok(Argon2Params {
        m_cost,
        t_cost,
        p_cost,
    })
}

fn parse_or_default(v: Option<String>, default: u32, name: &str) -> Result<u32> {
    match v {
        None => Ok(default),
        Some(s) => s
            .parse::<u32>()
            .map_err(|e| anyhow!("parse argon2 {name}: {e}")),
    }
}

/// Read the persisted KDF salt (decoded bytes).
pub async fn read_salt(pool: &DbPool) -> Result<Vec<u8>> {
    let v = read_meta_string(pool, meta::KDF_SALT)
        .await?
        .ok_or_else(|| anyhow!("kbs_meta.kdf.salt_b64 missing (run schema migration first)"))?;
    STANDARD.decode(v).map_err(|e| anyhow!("decode salt: {e}"))
}

/// Read the persisted canary parts as `(nonce, tag, ciphertext)` if present.
pub async fn read_canary(pool: &DbPool) -> Result<Option<(Vec<u8>, Vec<u8>, Vec<u8>)>> {
    let nonce = read_meta_string(pool, meta::CANARY_NONCE).await?;
    let tag = read_meta_string(pool, meta::CANARY_TAG).await?;
    let ct = read_meta_string(pool, meta::CANARY_CIPHERTEXT).await?;
    let (Some(n), Some(t), Some(c)) = (nonce, tag, ct) else {
        return Ok(None);
    };
    let n = STANDARD
        .decode(n)
        .map_err(|e| anyhow!("decode canary nonce: {e}"))?;
    let t = STANDARD
        .decode(t)
        .map_err(|e| anyhow!("decode canary tag: {e}"))?;
    let c = STANDARD
        .decode(c)
        .map_err(|e| anyhow!("decode canary ciphertext: {e}"))?;
    Ok(Some((n, t, c)))
}
