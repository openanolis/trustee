// Copyright (c) 2026 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Wrap-key persistence and lifecycle (`kbs_managed_keys` + parts of
//! `kbs_meta`).
//!
//! Each generation is identified by a 64-bit integer (nanoseconds since
//! UNIX_EPOCH) used as primary key — this gives a strict ordering matching
//! the wall clock and dovetails with the `mkey-<nanos>.pem` filename
//! convention used by `EncryptedLocalFs`.
//!
//! Private keys are stored encrypted under the master key using AES-256-GCM
//! with a fresh per-key nonce. The key generation is bound as AAD so a
//! ciphertext copy-pasted to a different generation row would fail
//! authentication.
//!
//! Higher-level rotate/rewrap orchestration lives in the parent module; this
//! file is the storage layer only.

use anyhow::{anyhow, bail, Context, Result};
use rsa::pkcs8::{
    DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding,
};
use rsa::{RsaPrivateKey, RsaPublicKey};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

use super::db::DbPool;
use super::master_secret::{aes_gcm_decrypt, aes_gcm_encrypt, MasterKey};
use super::schema::{insert_meta_if_absent, meta, read_meta_string};

/// Generation number used as the primary key for wrap keys. Nanoseconds since
/// UNIX_EPOCH; monotonically increasing within one host clock.
pub type Generation = i64;

/// One persisted wrap key, decrypted into memory.
#[allow(dead_code)] // Some fields read by future commits (rotate / decrypt path).
pub struct LoadedKey {
    pub generation: Generation,
    pub public_key: RsaPublicKey,
    pub private_key: RsaPrivateKey,
    pub retired: bool,
}

/// Generate a fresh `Generation` value from the system clock.
pub fn next_generation() -> Result<Generation> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_nanos();
    if nanos > i64::MAX as u128 {
        bail!("nanosecond timestamp overflow");
    }
    Ok(nanos as i64)
}

/// Generate a fresh RSA-3072 key pair.
pub fn generate_rsa_key_pair() -> Result<RsaPrivateKey> {
    let mut rng = rand::thread_rng();
    RsaPrivateKey::new(&mut rng, 3072).context("generate RSA-3072 key pair")
}

/// Encrypt and persist a freshly generated key as a new generation.
pub async fn insert_new_generation(
    pool: &DbPool,
    master_key: &MasterKey,
    generation: Generation,
    private_key: &RsaPrivateKey,
) -> Result<RsaPublicKey> {
    let public_key = private_key.to_public_key();
    let public_pem = public_key
        .to_public_key_pem(LineEnding::LF)
        .context("encode public key as PEM")?;
    let private_pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .context("encode private key as PKCS#8 PEM")?;
    let aad = aad_for_generation(generation);
    let (nonce, tag, ciphertext) = aes_gcm_encrypt(master_key, private_pem.as_bytes(), &aad)
        .context("encrypt private key under master key")?;
    let now = current_iso_timestamp()?;
    match pool {
        DbPool::MySql(p) => {
            sqlx::query(
                "INSERT INTO kbs_managed_keys
                    (generation, public_key_pem, enc_private_key, iv, tag, created_at)
                 VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(generation)
            .bind(&public_pem)
            .bind(&ciphertext)
            .bind(&nonce)
            .bind(&tag)
            .bind(&now)
            .execute(p)
            .await
            .context("insert wrap key (mysql)")?;
        }
        DbPool::Sqlite(p) => {
            sqlx::query(
                "INSERT INTO kbs_managed_keys
                    (generation, public_key_pem, enc_private_key, iv, tag, created_at)
                 VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(generation)
            .bind(&public_pem)
            .bind(&ciphertext)
            .bind(&nonce)
            .bind(&tag)
            .bind(&now)
            .execute(p)
            .await
            .context("insert wrap key (sqlite)")?;
        }
    }
    Ok(public_key)
}

/// Load all generations (retired + unretired) and decrypt private keys with
/// the master key. Returned newest-first so callers can pick the primary as
/// the first non-retired entry.
pub async fn load_all_keys(pool: &DbPool, master_key: &MasterKey) -> Result<Vec<LoadedKey>> {
    let rows: Vec<KeyRow> = match pool {
        DbPool::MySql(p) => sqlx::query_as::<_, KeyRow>(
            "SELECT generation, public_key_pem, enc_private_key, iv, tag,
                    CASE WHEN retired_at IS NULL THEN 0 ELSE 1 END AS retired
             FROM kbs_managed_keys
             ORDER BY generation DESC",
        )
        .fetch_all(p)
        .await
        .context("load wrap keys (mysql)")?,
        DbPool::Sqlite(p) => sqlx::query_as::<_, KeyRow>(
            "SELECT generation, public_key_pem, enc_private_key, iv, tag,
                    CASE WHEN retired_at IS NULL THEN 0 ELSE 1 END AS retired
             FROM kbs_managed_keys
             ORDER BY generation DESC",
        )
        .fetch_all(p)
        .await
        .context("load wrap keys (sqlite)")?,
    };

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let aad = aad_for_generation(row.generation);
        let private_pem = aes_gcm_decrypt(
            master_key,
            &row.iv,
            &row.tag,
            &row.enc_private_key,
            &aad,
        )
        .with_context(|| format!("decrypt private key for generation {}", row.generation))?;
        let private_key = pkcs8_decode_zeroizing(&private_pem)
            .with_context(|| format!("parse private key for generation {}", row.generation))?;
        let public_key = RsaPublicKey::from_public_key_pem(&row.public_key_pem)
            .map_err(|e| anyhow!("parse public key for generation {}: {e}", row.generation))?;
        out.push(LoadedKey {
            generation: row.generation,
            public_key,
            private_key,
            retired: row.retired != 0,
        });
    }
    Ok(out)
}

#[derive(sqlx::FromRow)]
struct KeyRow {
    generation: i64,
    public_key_pem: String,
    enc_private_key: Vec<u8>,
    iv: Vec<u8>,
    tag: Vec<u8>,
    retired: i64,
}

fn pkcs8_decode_zeroizing(pem: &Zeroizing<Vec<u8>>) -> Result<RsaPrivateKey> {
    let pem_str = std::str::from_utf8(pem).map_err(|e| anyhow!("private key PEM utf8: {e}"))?;
    RsaPrivateKey::from_pkcs8_pem(pem_str).map_err(|e| anyhow!("decode pkcs8: {e}"))
}

/// Return the generations of every key that has been retired for at least
/// `min_age`. Used by the purge sweep at the end of `/rotate`.
pub async fn list_retired_older_than(
    pool: &DbPool,
    min_age: std::time::Duration,
) -> Result<Vec<Generation>> {
    let cutoff_iso = current_iso_minus(min_age)?;
    let rows: Vec<(Generation,)> = match pool {
        DbPool::MySql(p) => sqlx::query_as(
            "SELECT generation FROM kbs_managed_keys
             WHERE retired_at IS NOT NULL AND retired_at < ?",
        )
        .bind(cutoff_iso)
        .fetch_all(p)
        .await
        .context("list retired keys (mysql)")?,
        DbPool::Sqlite(p) => sqlx::query_as(
            "SELECT generation FROM kbs_managed_keys
             WHERE retired_at IS NOT NULL AND retired_at < ?",
        )
        .bind(cutoff_iso)
        .fetch_all(p)
        .await
        .context("list retired keys (sqlite)")?,
    };
    Ok(rows.into_iter().map(|(g,)| g).collect())
}

/// Physically delete a retired key. The caller must have first verified
/// (via a fresh rewrap pass) that no resource is wrapped with this
/// generation; otherwise readers can be permanently broken.
pub async fn delete_key_row(pool: &DbPool, generation: Generation) -> Result<()> {
    match pool {
        DbPool::MySql(p) => {
            sqlx::query(
                "DELETE FROM kbs_managed_keys
                 WHERE generation = ? AND retired_at IS NOT NULL",
            )
            .bind(generation)
            .execute(p)
            .await
            .context("delete retired key (mysql)")?;
        }
        DbPool::Sqlite(p) => {
            sqlx::query(
                "DELETE FROM kbs_managed_keys
                 WHERE generation = ? AND retired_at IS NOT NULL",
            )
            .bind(generation)
            .execute(p)
            .await
            .context("delete retired key (sqlite)")?;
        }
    }
    Ok(())
}

fn current_iso_minus(d: std::time::Duration) -> Result<String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?;
    let cutoff = now.checked_sub(d).unwrap_or(std::time::Duration::ZERO);
    let secs = cutoff.as_secs() as i64;
    let micros = cutoff.subsec_micros();
    let datetime = chrono::DateTime::<chrono::Utc>::from_timestamp(secs, micros * 1_000)
        .ok_or_else(|| anyhow!("convert system time to chrono"))?;
    Ok(datetime.format("%Y-%m-%d %H:%M:%S%.6f").to_string())
}

/// Mark every generation older than `cutoff` as retired (idempotent).
/// Returns the number of rows newly marked.
pub async fn mark_older_retired(pool: &DbPool, cutoff: Generation) -> Result<u64> {
    let now = current_iso_timestamp()?;
    let rows_affected = match pool {
        DbPool::MySql(p) => sqlx::query(
            "UPDATE kbs_managed_keys
             SET retired_at = ?
             WHERE generation < ? AND retired_at IS NULL",
        )
        .bind(&now)
        .bind(cutoff)
        .execute(p)
        .await
        .context("retire older generations (mysql)")?
        .rows_affected(),
        DbPool::Sqlite(p) => sqlx::query(
            "UPDATE kbs_managed_keys
             SET retired_at = ?
             WHERE generation < ? AND retired_at IS NULL",
        )
        .bind(&now)
        .bind(cutoff)
        .execute(p)
        .await
        .context("retire older generations (sqlite)")?
        .rows_affected(),
    };
    Ok(rows_affected)
}

/// Read the current `primary_generation` pointer.
pub async fn read_primary_generation(pool: &DbPool) -> Result<Option<Generation>> {
    let v = read_meta_string(pool, meta::PRIMARY_GENERATION).await?;
    match v {
        None => Ok(None),
        Some(s) => Ok(Some(
            s.parse::<i64>()
                .map_err(|e| anyhow!("parse primary_generation: {e}"))?,
        )),
    }
}

/// Read `(primary_generation, bump)` together so callers can detect that
/// another replica advanced the pointer since their last poll.
pub async fn read_primary_generation_and_bump(pool: &DbPool) -> Result<Option<(Generation, i64)>> {
    let row: Option<(String, i64)> = match pool {
        DbPool::MySql(p) => sqlx::query_as("SELECT v, bump FROM kbs_meta WHERE k = ?")
            .bind(meta::PRIMARY_GENERATION)
            .fetch_optional(p)
            .await
            .context("read primary_generation + bump (mysql)")?,
        DbPool::Sqlite(p) => sqlx::query_as("SELECT v, bump FROM kbs_meta WHERE k = ?")
            .bind(meta::PRIMARY_GENERATION)
            .fetch_optional(p)
            .await
            .context("read primary_generation + bump (sqlite)")?,
    };
    let Some((v, bump)) = row else {
        return Ok(None);
    };
    let gen: i64 = v
        .parse()
        .map_err(|e| anyhow!("parse primary_generation: {e}"))?;
    Ok(Some((gen, bump)))
}

/// Insert the very first `primary_generation` row. Idempotent.
pub async fn set_primary_generation_initial(
    pool: &DbPool,
    generation: Generation,
) -> Result<()> {
    insert_meta_if_absent(pool, meta::PRIMARY_GENERATION, &generation.to_string()).await
}

/// Advance `primary_generation` and bump the counter atomically. The caller
/// is expected to have first taken the row's exclusive lock via
/// `lock_primary_generation_for_update` (or to be inside a SQLite-style
/// serialized transaction).
pub async fn advance_primary_generation(pool: &DbPool, generation: Generation) -> Result<()> {
    let new_v = generation.to_string();
    match pool {
        DbPool::MySql(p) => {
            sqlx::query("UPDATE kbs_meta SET v = ?, bump = bump + 1 WHERE k = ?")
                .bind(&new_v)
                .bind(meta::PRIMARY_GENERATION)
                .execute(p)
                .await
                .context("advance primary_generation (mysql)")?;
        }
        DbPool::Sqlite(p) => {
            sqlx::query("UPDATE kbs_meta SET v = ?, bump = bump + 1 WHERE k = ?")
                .bind(&new_v)
                .bind(meta::PRIMARY_GENERATION)
                .execute(p)
                .await
                .context("advance primary_generation (sqlite)")?;
        }
    }
    Ok(())
}

/// AAD format used for AES-GCM-encrypting a private key, binding it to its
/// generation.
pub fn aad_for_generation(generation: Generation) -> Vec<u8> {
    format!("trustee-mkey-{generation}").into_bytes()
}

/// Format the current wall-clock as ISO8601 with microsecond precision; the
/// `DATETIME(6)` columns on MySQL accept this directly, and SQLite stores it
/// as TEXT.
fn current_iso_timestamp() -> Result<String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?;
    let secs = now.as_secs() as i64;
    let micros = now.subsec_micros();
    let datetime = chrono::DateTime::<chrono::Utc>::from_timestamp(secs, micros * 1_000)
        .ok_or_else(|| anyhow!("convert system time to chrono"))?;
    Ok(datetime.format("%Y-%m-%d %H:%M:%S%.6f").to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::implementations::resource::encrypted_db::master_secret::{
        derive_master_key, generate_salt, Argon2Params, MASTER_KEY_LEN,
    };
    use crate::plugins::implementations::resource::encrypted_db::schema::{
        ensure_meta_defaults, migrate_schema,
    };
    use zeroize::Zeroizing;

    fn fast_key() -> MasterKey {
        let salt = generate_salt();
        let p = Argon2Params {
            m_cost: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
        };
        derive_master_key(b"unit-test", &salt, p).unwrap()
    }

    async fn fresh_pool() -> DbPool {
        let pool = DbPool::connect_sqlite_memory().await.unwrap();
        migrate_schema(&pool).await.unwrap();
        ensure_meta_defaults(&pool, None).await.unwrap();
        pool
    }

    #[tokio::test(flavor = "current_thread")]
    async fn insert_and_load_round_trip() {
        let pool = fresh_pool().await;
        let master = fast_key();

        let priv1 = generate_rsa_key_pair().unwrap();
        let gen1 = next_generation().unwrap();
        let pub1 = insert_new_generation(&pool, &master, gen1, &priv1)
            .await
            .expect("insert");

        let keys = load_all_keys(&pool, &master).await.expect("load");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].generation, gen1);
        assert!(!keys[0].retired);
        assert_eq!(
            keys[0].public_key.to_public_key_pem(LineEnding::LF).unwrap(),
            pub1.to_public_key_pem(LineEnding::LF).unwrap()
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn duplicate_generation_insert_rejected() {
        let pool = fresh_pool().await;
        let master = fast_key();
        let priv1 = generate_rsa_key_pair().unwrap();
        let gen1 = 12345i64;
        insert_new_generation(&pool, &master, gen1, &priv1).await.unwrap();
        let priv2 = generate_rsa_key_pair().unwrap();
        let err = insert_new_generation(&pool, &master, gen1, &priv2)
            .await
            .expect_err("PK conflict");
        let s = format!("{err:#}");
        assert!(
            s.contains("UNIQUE")
                || s.contains("constraint")
                || s.contains("Duplicate")
                || s.contains("PRIMARY"),
            "expected uniqueness error, got {s}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn aad_binding_prevents_swap() {
        let pool = fresh_pool().await;
        let master = fast_key();
        let priv1 = generate_rsa_key_pair().unwrap();
        let priv2 = generate_rsa_key_pair().unwrap();
        let gen1 = 100i64;
        let gen2 = 200i64;
        insert_new_generation(&pool, &master, gen1, &priv1).await.unwrap();
        insert_new_generation(&pool, &master, gen2, &priv2).await.unwrap();

        // Manually swap the encrypted bytes between rows and confirm that
        // load_all_keys rejects the result (AAD mismatch).
        let DbPool::Sqlite(p) = &pool else { unreachable!() };
        let row1: (Vec<u8>, Vec<u8>, Vec<u8>) = sqlx::query_as(
            "SELECT enc_private_key, iv, tag FROM kbs_managed_keys WHERE generation = ?",
        )
        .bind(gen1)
        .fetch_one(p)
        .await
        .unwrap();
        sqlx::query("UPDATE kbs_managed_keys SET enc_private_key = ?, iv = ?, tag = ? WHERE generation = ?")
            .bind(&row1.0).bind(&row1.1).bind(&row1.2).bind(gen2)
            .execute(p).await.unwrap();

        let err = match load_all_keys(&pool, &master).await {
            Ok(_) => panic!("AAD mismatch: load should have failed"),
            Err(e) => e,
        };
        assert!(format!("{err:#}").contains("decrypt"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wrong_master_key_fails_load() {
        let pool = fresh_pool().await;
        let master_a = fast_key();
        let master_b: MasterKey = Zeroizing::new([0xAA; MASTER_KEY_LEN]);
        let priv1 = generate_rsa_key_pair().unwrap();
        insert_new_generation(&pool, &master_a, 1, &priv1).await.unwrap();
        let err = match load_all_keys(&pool, &master_b).await {
            Ok(_) => panic!("wrong master key: load should have failed"),
            Err(e) => e,
        };
        assert!(format!("{err:#}").contains("decrypt"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn primary_generation_seed_and_advance() {
        let pool = fresh_pool().await;
        let master = fast_key();

        assert!(read_primary_generation(&pool).await.unwrap().is_none());

        let priv1 = generate_rsa_key_pair().unwrap();
        let gen1 = 100i64;
        insert_new_generation(&pool, &master, gen1, &priv1).await.unwrap();
        set_primary_generation_initial(&pool, gen1).await.unwrap();

        // Idempotent: seeding twice does not change the value.
        set_primary_generation_initial(&pool, gen1 + 999).await.unwrap();
        let (cur, bump_before) = read_primary_generation_and_bump(&pool)
            .await
            .unwrap()
            .expect("primary set");
        assert_eq!(cur, gen1);

        // Advance bumps both pointer and counter.
        let priv2 = generate_rsa_key_pair().unwrap();
        let gen2 = 200i64;
        insert_new_generation(&pool, &master, gen2, &priv2).await.unwrap();
        advance_primary_generation(&pool, gen2).await.unwrap();

        let (cur, bump_after) = read_primary_generation_and_bump(&pool)
            .await
            .unwrap()
            .expect("primary set");
        assert_eq!(cur, gen2);
        assert_eq!(bump_after, bump_before + 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retire_marks_generation_without_deletion() {
        let pool = fresh_pool().await;
        let master = fast_key();
        let priv1 = generate_rsa_key_pair().unwrap();
        let priv2 = generate_rsa_key_pair().unwrap();
        insert_new_generation(&pool, &master, 100, &priv1).await.unwrap();
        insert_new_generation(&pool, &master, 200, &priv2).await.unwrap();

        let n = mark_older_retired(&pool, 200).await.unwrap();
        assert_eq!(n, 1);

        let keys = load_all_keys(&pool, &master).await.unwrap();
        assert_eq!(keys.len(), 2, "row stays for decryption use");
        let retired: Vec<bool> = keys.iter().map(|k| k.retired).collect();
        assert_eq!(retired, vec![false, true]); // newest first
    }
}
