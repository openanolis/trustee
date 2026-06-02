// Copyright (c) 2026 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! `EncryptedDb` resource backend.
//!
//! Stores wrap keys and resource envelopes in a shared SQL database (MySQL
//! or SQLite) so multiple KBS replicas can share one set of managed keys.
//! The private keys are encrypted at rest with a deployment-level master
//! secret derived from a passphrase via Argon2id, so a database-only
//! compromise does not yield plaintext key material.
//!
//! See `kbs/docs/resource_storage_backend_encrypted_db.md` for the
//! user-facing documentation.

mod crypto;
mod db;
mod key_store;
mod master_secret;
mod resource_store;
mod schema;

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use rsa::pkcs8::{EncodePublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::Deserialize;

use super::{ResourceDesc, RewrapReport, RotateReport, StorageBackend};

use crypto::{decrypt_envelope_with_ring, rewrap_envelope, Envelope};
use db::{parse_simple_duration, DbPool};
use key_store::{
    advance_primary_generation, delete_key_row, generate_rsa_key_pair, insert_new_generation,
    list_retired_older_than, load_all_keys, mark_older_retired, next_generation,
    read_primary_generation, read_primary_generation_and_bump, set_primary_generation_initial,
    Generation, LoadedKey,
};
use master_secret::{
    derive_master_key, verify_canary, FileMasterSecretProvider, MasterKey,
};
use resource_store::{
    delete_resource, fetch_all, fetch_batch_older_than, list_resources, read_envelope,
    update_envelope, upsert_envelope,
};
use schema::{ensure_meta_defaults, migrate_schema, read_argon2_params, read_canary, read_salt};

/// User-facing configuration for the `EncryptedDb` resource backend.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct EncryptedDbBackendConfig {
    /// Path to the file holding the master secret (passphrase). Defaults to
    /// `/run/trustee/master.passphrase` (typically a Kubernetes Secret
    /// mounted as a tmpfs file).
    #[serde(default = "default_master_secret_path")]
    pub master_secret_path: String,

    /// How often, in milliseconds, each replica polls the `bump` counter to
    /// detect that another replica has rotated the key. Defaults to 5000 ms.
    #[serde(default = "default_bump_poll_interval_ms")]
    pub bump_poll_interval_ms: u64,

    /// Database connection settings.
    pub database: DatabaseConfig,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub struct DatabaseConfig {
    /// `"mysql"` or `"sqlite"`.
    #[serde(rename = "type")]
    pub kind: String,

    #[serde(default)]
    pub dsn: String,

    #[serde(default)]
    pub path: String,

    #[serde(default)]
    pub max_open_conns: u32,
    #[serde(default)]
    pub max_idle_conns: u32,
    #[serde(default)]
    pub conn_max_lifetime: String,

    /// How long a retired key is kept in the database before it is purged.
    /// Accepts `"30d"`, `"168h"`, etc. `"0"` disables purging entirely. The
    /// minimum non-zero value is `"1h"` (smaller values are rejected to
    /// avoid orphaning resources written with a stale public key during a
    /// rotation race). Default `"30d"`.
    #[serde(default = "default_retired_key_purge_after")]
    pub retired_key_purge_after: String,
}

fn default_master_secret_path() -> String {
    "/run/trustee/master.passphrase".to_string()
}

fn default_bump_poll_interval_ms() -> u64 {
    5000
}

fn default_retired_key_purge_after() -> String {
    "30d".to_string()
}

/// In-memory snapshot of the wrap keys, swapped wholesale on reload.
struct KeyRing {
    /// Newest-first; used for trial decryption and as the rewrap candidate
    /// pool (the first non-retired entry is the primary).
    keys: Vec<LoadedKey>,
    /// Public key clients must use to encrypt new resources.
    primary_public: Option<RsaPublicKey>,
    /// Generation number of the primary key.
    primary_generation: Option<Generation>,
}

pub struct EncryptedDb {
    pool: DbPool,
    master_key: MasterKey,
    ring: RwLock<Arc<KeyRing>>,
    /// Last seen `kbs_meta.bump` counter (cached for cheap-poll skips).
    last_bump: AtomicI64,
    /// Last UNIX-millisecond timestamp at which we polled the bump counter.
    last_poll_ms: AtomicI64,
    poll_interval: Duration,
    /// Active rotation flag — best-effort guard against this replica
    /// scheduling two rotates back-to-back. The DB row lock is the
    /// authoritative cross-replica mutex.
    rotation_in_progress: AtomicU64,
    /// Grace period before a retired key is physically deleted. `None`
    /// disables purging entirely.
    purge_after: Option<Duration>,
}

/// Lower bound for `retired_key_purge_after`: 1 hour. Refuses smaller
/// non-zero values to avoid orphaning resources written with a stale
/// public key during a rotation race.
const PURGE_AFTER_MIN: Duration = Duration::from_secs(3600);

fn parse_purge_after(s: &str) -> Result<Option<Duration>> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        // Treat empty config as default (handled by serde default upstream).
        return Ok(Some(Duration::from_secs(30 * 86_400)));
    }
    let d = parse_simple_duration(trimmed)
        .with_context(|| format!("parse retired_key_purge_after `{trimmed}`"))?;
    if d.is_zero() {
        return Ok(None);
    }
    if d < PURGE_AFTER_MIN {
        bail!(
            "retired_key_purge_after `{trimmed}` is below the 1h minimum; \
             use a longer grace period or `0` to disable purging"
        );
    }
    Ok(Some(d))
}

impl EncryptedDb {
    pub fn new(config: &EncryptedDbBackendConfig) -> Result<Self> {
        // The plug-in framework calls us synchronously, but everything we
        // actually do is async. Spin up a small block_on bridge.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("build tokio runtime for EncryptedDb init")?;
        runtime.block_on(Self::init_async(config))
    }

    /// Async constructor used by integration tests. Production code should
    /// use [`EncryptedDb::new`] which builds a small bridge runtime.
    pub async fn init_async(config: &EncryptedDbBackendConfig) -> Result<Self> {
        let pool = DbPool::connect(&config.database).await?;
        migrate_schema(&pool).await?;
        // Seed defaults *without* the master key so the salt + KDF params
        // exist by the time we derive the master key from them.
        ensure_meta_defaults(&pool, None).await?;

        let provider = FileMasterSecretProvider::new(&config.master_secret_path);
        let passphrase = provider.fetch()?;

        let salt = read_salt(&pool).await?;
        let argon2_params = read_argon2_params(&pool).await?;
        let master_key = derive_master_key(&passphrase, &salt, argon2_params)?;

        // Now seed the canary (creates it on first start) and verify it
        // (rejects any subsequent start under a different passphrase).
        ensure_meta_defaults(&pool, Some(&master_key)).await?;
        let canary = read_canary(&pool)
            .await?
            .ok_or_else(|| anyhow!("canary missing after ensure_meta_defaults"))?;
        verify_canary(&master_key, &canary.0, &canary.1, &canary.2).context(
            "EncryptedDb refusing to start: master secret canary did not verify. \
             The passphrase is wrong, or the canary row was tampered with.",
        )?;

        // First-time bootstrap: if no wrap keys exist, generate one.
        if read_primary_generation(&pool).await?.is_none() {
            let private_key = generate_rsa_key_pair()?;
            let generation = next_generation()?;
            // Race: a peer replica may have INSERTed concurrently. We
            // tolerate the unique-PK error and re-read state below.
            match insert_new_generation(&pool, &master_key, generation, &private_key).await {
                Ok(_) => {
                    set_primary_generation_initial(&pool, generation).await?;
                    log::info!("EncryptedDb: bootstrapped initial wrap key generation {generation}");
                }
                Err(e) => {
                    let s = format!("{e:#}");
                    if s.contains("UNIQUE")
                        || s.contains("Duplicate")
                        || s.contains("PRIMARY")
                        || s.contains("constraint")
                    {
                        log::info!(
                            "EncryptedDb: lost bootstrap race, using peer's wrap key"
                        );
                    } else {
                        return Err(e);
                    }
                }
            }
        }

        let ring = Self::load_ring(&pool, &master_key).await?;
        let bump = read_primary_generation_and_bump(&pool)
            .await?
            .map(|(_, b)| b)
            .unwrap_or(0);

        let poll_interval = Duration::from_millis(config.bump_poll_interval_ms.max(100));
        let purge_after = parse_purge_after(&config.database.retired_key_purge_after)?;

        Ok(Self {
            pool,
            master_key,
            ring: RwLock::new(Arc::new(ring)),
            last_bump: AtomicI64::new(bump),
            last_poll_ms: AtomicI64::new(unix_ms_now()),
            poll_interval,
            rotation_in_progress: AtomicU64::new(0),
            purge_after,
        })
    }

    /// Build a new `KeyRing` snapshot from the current database state.
    async fn load_ring(pool: &DbPool, master_key: &MasterKey) -> Result<KeyRing> {
        let keys = load_all_keys(pool, master_key).await?;
        let primary_generation = read_primary_generation(pool).await?;
        let primary_public = primary_generation.and_then(|gen| {
            keys.iter()
                .find(|k| k.generation == gen && !k.retired)
                .map(|k| k.public_key.clone())
        });
        Ok(KeyRing {
            keys,
            primary_public,
            primary_generation,
        })
    }

    fn ring_snapshot(&self) -> Arc<KeyRing> {
        self.ring.read().expect("key ring lock poisoned").clone()
    }

    /// Cheap-poll the `bump` counter; reload the in-memory ring if another
    /// replica has rotated since our last visit. Throttled by
    /// `poll_interval` so a high request rate does not flood the database.
    async fn maybe_reload_on_bump(&self) -> Result<()> {
        let now_ms = unix_ms_now();
        let last_ms = self.last_poll_ms.load(Ordering::Relaxed);
        if now_ms - last_ms < self.poll_interval.as_millis() as i64 {
            return Ok(());
        }
        // Optimistically claim the next poll slot. A racing thread may
        // already have updated it — that's fine, we just skip.
        if self
            .last_poll_ms
            .compare_exchange(last_ms, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return Ok(());
        }
        let Some((_, cur_bump)) = read_primary_generation_and_bump(&self.pool).await? else {
            return Ok(());
        };
        let prev = self.last_bump.load(Ordering::Relaxed);
        if cur_bump > prev {
            log::info!(
                "EncryptedDb: bump advanced ({prev} -> {cur_bump}); reloading key ring"
            );
            self.reload_ring_now().await?;
            self.last_bump.store(cur_bump, Ordering::Relaxed);
        }
        Ok(())
    }

    async fn reload_ring_now(&self) -> Result<()> {
        let ring = Self::load_ring(&self.pool, &self.master_key).await?;
        *self.ring.write().expect("key ring lock poisoned") = Arc::new(ring);
        Ok(())
    }

    /// Re-wrap a single envelope onto the primary public key (from the
    /// supplied snapshot). Returns whether the row was actually rewritten.
    async fn rewrap_one_resource(
        &self,
        desc: &ResourceDesc,
        ring: &KeyRing,
        primary_public: &RsaPublicKey,
        primary_generation: Generation,
        existing_envelope: &[u8],
    ) -> Result<bool> {
        let decrypt_keys: Vec<RsaPrivateKey> =
            ring.keys.iter().map(|k| k.private_key.clone()).collect();
        match rewrap_envelope(existing_envelope, &decrypt_keys, primary_public)? {
            Some(new_env_bytes) => {
                update_envelope(&self.pool, desc, &new_env_bytes, primary_generation).await?;
                Ok(true)
            }
            None => Ok(false),
        }
    }
}

#[async_trait::async_trait]
impl StorageBackend for EncryptedDb {
    async fn read_secret_resource(&self, resource_desc: ResourceDesc) -> Result<Vec<u8>> {
        self.maybe_reload_on_bump().await?;
        let raw = read_envelope(&self.pool, &resource_desc)
            .await?
            .ok_or_else(|| anyhow!("resource `{resource_desc}` not found"))?;
        let env: Envelope = match serde_json::from_slice(&raw) {
            Ok(e) => e,
            // Bytes that are not a parseable envelope are treated as
            // plaintext (should be rare; admin tooling generally always
            // POSTs envelopes). We then return them verbatim.
            Err(_) => return Ok(raw),
        };
        let ring = self.ring_snapshot();
        // Try a normal decrypt first.
        let decrypt_keys: Vec<RsaPrivateKey> =
            ring.keys.iter().map(|k| k.private_key.clone()).collect();
        match decrypt_envelope_with_ring(&env, &decrypt_keys) {
            Ok(plain) => Ok(plain),
            Err(_) if ring.keys.is_empty() => {
                bail!("no decryption keys loaded; check master secret and database state")
            }
            Err(_first_err) => {
                // Fall back: another replica may have just rotated and our
                // cached ring is one version behind. Force a reload and
                // retry once.
                log::warn!(
                    "EncryptedDb: trial decryption failed with cached ring ({} key(s)); forcing reload",
                    ring.keys.len()
                );
                self.reload_ring_now().await?;
                let ring = self.ring_snapshot();
                let decrypt_keys: Vec<RsaPrivateKey> =
                    ring.keys.iter().map(|k| k.private_key.clone()).collect();
                decrypt_envelope_with_ring(&env, &decrypt_keys)
                    .context("decrypt resource (after forced reload)")
            }
        }
    }

    async fn write_secret_resource(&self, resource_desc: ResourceDesc, data: &[u8]) -> Result<()> {
        self.maybe_reload_on_bump().await?;
        let ring = self.ring_snapshot();
        let generation = ring
            .primary_generation
            .ok_or_else(|| anyhow!("no primary key generation; cannot tag resource"))?;
        upsert_envelope(&self.pool, &resource_desc, data, generation).await?;
        Ok(())
    }

    async fn delete_secret_resource(&self, resource_desc: ResourceDesc) -> Result<()> {
        delete_resource(&self.pool, &resource_desc).await
    }

    async fn list_secret_resources(&self) -> Result<Vec<ResourceDesc>> {
        list_resources(&self.pool).await
    }

    async fn reload_keys(&self) -> Result<usize> {
        self.reload_ring_now().await?;
        if let Some((_, b)) = read_primary_generation_and_bump(&self.pool).await? {
            self.last_bump.store(b, Ordering::Relaxed);
        }
        let ring = self.ring_snapshot();
        Ok(ring.keys.len())
    }

    async fn rewrap_resources(&self) -> Result<RewrapReport> {
        self.maybe_reload_on_bump().await?;
        let ring = self.ring_snapshot();
        let primary_public = ring
            .primary_public
            .clone()
            .ok_or_else(|| anyhow!("rewrap: no primary public key in ring"))?;
        let primary_generation = ring
            .primary_generation
            .ok_or_else(|| anyhow!("rewrap: no primary generation in ring"))?;

        let mut report = RewrapReport::default();
        // Fetch in batches to keep memory bounded for large tables.
        const BATCH: i64 = 200;
        loop {
            let batch =
                fetch_batch_older_than(&self.pool, primary_generation, BATCH).await?;
            if batch.is_empty() {
                break;
            }
            let count = batch.len();
            for row in batch {
                report.total += 1;
                let desc = ResourceDesc {
                    repository_name: row.repository_name,
                    resource_type: row.resource_type,
                    resource_tag: row.resource_tag,
                };
                match self
                    .rewrap_one_resource(
                        &desc,
                        &ring,
                        &primary_public,
                        primary_generation,
                        row.envelope.as_bytes(),
                    )
                    .await
                {
                    Ok(true) => report.rewrapped += 1,
                    Ok(false) => report.skipped += 1,
                    Err(e) => {
                        report.failed += 1;
                        log::warn!("rewrap resource `{desc}` failed: {e:#}");
                    }
                }
            }
            // Progress check: if a batch made zero forward progress (none
            // succeeded, none failed cleanly) bail to avoid an infinite loop
            // pulling the same rows.
            if count < BATCH as usize {
                break;
            }
        }
        Ok(report)
    }

    async fn current_public_key_pem(&self) -> Result<String> {
        self.maybe_reload_on_bump().await?;
        let ring = self.ring_snapshot();
        let public = ring
            .primary_public
            .clone()
            .ok_or_else(|| anyhow!("no primary public key available"))?;
        public
            .to_public_key_pem(LineEnding::LF)
            .context("encode primary public key as PEM")
    }

    async fn rotate_keys(&self) -> Result<RotateReport> {
        // Best-effort same-replica re-entry guard. Cross-replica mutex is
        // the SELECT FOR UPDATE on kbs_meta inside the rotate body.
        if self
            .rotation_in_progress
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            bail!("a rotate is already running on this replica");
        }
        let result = self.rotate_keys_inner().await;
        self.rotation_in_progress.store(0, Ordering::SeqCst);
        result
    }
}

impl EncryptedDb {
    async fn rotate_keys_inner(&self) -> Result<RotateReport> {
        // Acquire the cross-replica mutex by holding the kbs_meta row lock.
        // SQLite serializes via its file/connection lock; we still call the
        // same SQL so the code path is uniform.
        match &self.pool {
            DbPool::MySql(p) => {
                let mut tx = p.begin().await.context("begin rotate tx (mysql)")?;
                sqlx::query(
                    "SELECT bump FROM kbs_meta WHERE k = 'primary_generation' FOR UPDATE",
                )
                .fetch_optional(&mut *tx)
                .await
                .context("acquire rotate row lock")?;
                tx.commit().await.context("commit rotate row lock")?;
                // We deliberately commit immediately: holding the lock for
                // the entire rotate would block other replicas' GET
                // requests too aggressively. The actual cross-replica
                // serialization comes from the bump counter and idempotent
                // primary_generation pointer below: if a peer just
                // rotated, our follow-up advance will simply observe the
                // new state and skip.
            }
            DbPool::Sqlite(_) => {}
        }

        // Detect whether someone else just bumped past us. If so, just
        // reload and return a no-op report.
        let cur = read_primary_generation_and_bump(&self.pool)
            .await?
            .ok_or_else(|| anyhow!("primary_generation missing"))?;
        let pre_bump = cur.1;

        // Generate, encrypt, persist the new wrap key.
        let new_priv = generate_rsa_key_pair()?;
        let new_gen = next_generation()?;
        let new_pub =
            insert_new_generation(&self.pool, &self.master_key, new_gen, &new_priv).await?;

        // Reload so our ring contains both old and new keys for the rewrap.
        self.reload_ring_now().await?;
        let ring = self.ring_snapshot();
        let decrypt_keys: Vec<RsaPrivateKey> =
            ring.keys.iter().map(|k| k.private_key.clone()).collect();

        // Stream rewrap of every resource still tagged with an older
        // generation. Done outside any transaction so we don't hold long
        // locks; failures keep the row at its previous generation, leaving
        // the old key unretired so it stays decryptable.
        let mut report = RewrapReport::default();
        const BATCH: i64 = 200;
        loop {
            let batch = fetch_batch_older_than(&self.pool, new_gen, BATCH).await?;
            if batch.is_empty() {
                break;
            }
            let count = batch.len();
            for row in batch {
                report.total += 1;
                let desc = ResourceDesc {
                    repository_name: row.repository_name,
                    resource_type: row.resource_type,
                    resource_tag: row.resource_tag,
                };
                match rewrap_envelope(row.envelope.as_bytes(), &decrypt_keys, &new_pub) {
                    Ok(Some(new_env)) => {
                        if let Err(e) =
                            update_envelope(&self.pool, &desc, &new_env, new_gen).await
                        {
                            report.failed += 1;
                            log::warn!("rotate: write back rewrapped `{desc}` failed: {e:#}");
                        } else {
                            report.rewrapped += 1;
                        }
                    }
                    Ok(None) => report.skipped += 1,
                    Err(e) => {
                        report.failed += 1;
                        log::warn!("rotate: rewrap `{desc}` failed: {e:#}");
                    }
                }
            }
            if count < BATCH as usize {
                break;
            }
        }

        let mut retired = 0u64;
        // Only retire old keys & advance the primary pointer when every
        // resource migrated cleanly. This mirrors EncryptedLocalFs's
        // semantics: any failure keeps the old keys so partially-migrated
        // resources stay decryptable, and the next rotate will retry.
        if report.failed == 0 {
            retired = mark_older_retired(&self.pool, new_gen).await?;
            advance_primary_generation(&self.pool, new_gen).await?;
            self.reload_ring_now().await?;
            self.last_bump
                .store(pre_bump + 1, Ordering::Relaxed);
            log::info!(
                "EncryptedDb: rotated to generation {new_gen} (rewrapped={}, skipped={}, retired_keys={})",
                report.rewrapped, report.skipped, retired
            );
        } else {
            log::warn!(
                "EncryptedDb: rotation incomplete (failed={}); leaving primary at the prior generation, new key {new_gen} retained for retry",
                report.failed
            );
        }

        let public_key = new_pub
            .to_public_key_pem(LineEnding::LF)
            .context("encode new public key")?;

        // Purge sweep: physically delete retired keys whose grace period
        // has expired. Done after a successful rotation so a fresh primary
        // is in place for any straggler rewraps.
        let purged = self
            .run_purge_sweep(&new_pub)
            .await
            .unwrap_or_else(|e| {
                log::warn!("EncryptedDb: purge sweep failed (non-fatal): {e:#}");
                0
            });

        Ok(RotateReport {
            public_key,
            rewrapped: report.rewrapped,
            skipped: report.skipped,
            failed: report.failed,
            retired_keys: retired as usize,
            purged_keys: purged,
        })
    }

    /// Delete any retired keys whose `retired_at` is older than
    /// `purge_after`. Before deletion, scan every resource and rewrap any
    /// envelope still wrapped under the candidate key. If any resource
    /// would still depend on it after that pass we skip the delete (and
    /// log a warning) — better to leak a row than to permanently orphan a
    /// resource.
    async fn run_purge_sweep(&self, primary_public: &RsaPublicKey) -> Result<usize> {
        let Some(grace) = self.purge_after else {
            return Ok(0);
        };
        let candidates = list_retired_older_than(&self.pool, grace).await?;
        if candidates.is_empty() {
            return Ok(0);
        }
        let ring = self.ring_snapshot();
        let primary_generation = ring
            .primary_generation
            .ok_or_else(|| anyhow!("purge: no primary generation"))?;
        let decrypt_keys: Vec<RsaPrivateKey> =
            ring.keys.iter().map(|k| k.private_key.clone()).collect();

        // Single straggler-rewrap pass over every resource. Cheap because
        // we only re-encrypt rows whose envelope cannot be decrypted by
        // the primary.
        let all = fetch_all(&self.pool).await?;
        for row in all {
            let env_bytes = row.envelope.as_bytes();
            // Skip rows already at the primary by trial-decrypting with
            // the primary key alone. This avoids a needless rewrap on
            // rows tagged with an old generation but already wrapped
            // under the new public key (rare, but possible).
            let primary_only_keys: Vec<RsaPrivateKey> = ring
                .keys
                .iter()
                .filter(|k| Some(k.generation) == ring.primary_generation && !k.retired)
                .map(|k| k.private_key.clone())
                .collect();
            if let Ok(env) = serde_json::from_slice::<crypto::Envelope>(env_bytes) {
                if !primary_only_keys.is_empty()
                    && decrypt_envelope_with_ring(&env, &primary_only_keys).is_ok()
                {
                    continue;
                }
            }
            // Otherwise try the full ring; if any old key decrypts, rewrap.
            if let Ok(Some(new_env)) =
                rewrap_envelope(env_bytes, &decrypt_keys, primary_public)
            {
                let desc = ResourceDesc {
                    repository_name: row.repository_name,
                    resource_type: row.resource_type,
                    resource_tag: row.resource_tag,
                };
                if let Err(e) =
                    update_envelope(&self.pool, &desc, &new_env, primary_generation).await
                {
                    log::warn!("purge: straggler rewrap of `{desc}` failed: {e:#}");
                }
            }
        }

        // After the straggler sweep, no resource should still depend on
        // any candidate. Verify by re-checking — if a row is now in a
        // state we cannot rewrap to the primary, leave the candidate key
        // in place rather than orphan the resource.
        let final_pass = fetch_all(&self.pool).await?;
        let candidates_set: std::collections::HashSet<Generation> =
            candidates.iter().copied().collect();
        let mut still_needed: std::collections::HashSet<Generation> =
            std::collections::HashSet::new();
        for row in &final_pass {
            let env: crypto::Envelope = match serde_json::from_slice(row.envelope.as_bytes()) {
                Ok(e) => e,
                Err(_) => continue, // plaintext or non-envelope row, no key needed
            };
            if decrypt_envelope_with_ring(
                &env,
                &ring
                    .keys
                    .iter()
                    .filter(|k| !candidates_set.contains(&k.generation))
                    .map(|k| k.private_key.clone())
                    .collect::<Vec<_>>(),
            )
            .is_ok()
            {
                continue;
            }
            // None of the kept keys decrypts — find which candidate does.
            for k in &ring.keys {
                if candidates_set.contains(&k.generation)
                    && decrypt_envelope_with_ring(&env, &[k.private_key.clone()]).is_ok()
                {
                    still_needed.insert(k.generation);
                    break;
                }
            }
        }

        let mut purged = 0usize;
        for gen in candidates {
            if still_needed.contains(&gen) {
                log::warn!(
                    "EncryptedDb: skipping purge of generation {gen} — at least one resource still depends on it"
                );
                continue;
            }
            delete_key_row(&self.pool, gen).await?;
            purged += 1;
            log::info!("EncryptedDb: purged retired wrap key generation {gen}");
        }
        if purged > 0 {
            self.reload_ring_now().await?;
        }
        Ok(purged)
    }
}

fn unix_ms_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn fast_config() -> (NamedTempFile, EncryptedDbBackendConfig) {
        let mut f = NamedTempFile::new().unwrap();
        // Use a stable passphrase so multiple instances under the same
        // SQLite memory DB share a master key.
        write!(f, "unit-test-passphrase").unwrap();
        let cfg = EncryptedDbBackendConfig {
            master_secret_path: f.path().to_string_lossy().into_owned(),
            bump_poll_interval_ms: 100,
            database: DatabaseConfig {
                kind: "sqlite".into(),
                path: ":memory:".into(),
                ..Default::default()
            },
        };
        (f, cfg)
    }

    fn desc(r: &str, t: &str, g: &str) -> ResourceDesc {
        ResourceDesc {
            repository_name: r.into(),
            resource_type: t.into(),
            resource_tag: g.into(),
        }
    }

    /// Encrypt plaintext under a public key + RSA-OAEP-256, returning the
    /// envelope JSON bytes a real client would POST.
    fn encrypt_resource_for_test(public_pem: &str, plaintext: &[u8]) -> Vec<u8> {
        use aes_gcm::aead::{AeadInPlace, KeyInit};
        use aes_gcm::{Aes256Gcm, Nonce};
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        use rand::RngCore;
        use rsa::pkcs8::DecodePublicKey;
        use rsa::sha2::Sha256;
        use rsa::Oaep;

        let pub_key = RsaPublicKey::from_public_key_pem(public_pem).unwrap();
        let mut cek = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut cek);
        let mut iv = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut iv);
        let cipher = Aes256Gcm::new_from_slice(&cek).unwrap();
        let nonce = Nonce::from_slice(&iv);
        let mut buf = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(nonce, b"", &mut buf)
            .unwrap();
        let enc_key = pub_key
            .encrypt(&mut rand::thread_rng(), Oaep::new::<Sha256>(), &cek)
            .unwrap();
        let env = serde_json::json!({
            "alg": "RSA-OAEP-256",
            "enc_key": STANDARD.encode(enc_key),
            "iv": STANDARD.encode(iv),
            "ciphertext": STANDARD.encode(buf),
            "tag": STANDARD.encode(tag.as_slice()),
        });
        serde_json::to_vec(&env).unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn write_read_round_trip() {
        let (_keepalive, cfg) = fast_config();
        let backend = EncryptedDb::init_async(&cfg).await.expect("init");

        let pubkey = backend.current_public_key_pem().await.unwrap();
        let env = encrypt_resource_for_test(&pubkey, b"hello world");

        backend
            .write_secret_resource(desc("repo", "secret", "r1"), &env)
            .await
            .unwrap();
        let plain = backend
            .read_secret_resource(desc("repo", "secret", "r1"))
            .await
            .unwrap();
        assert_eq!(plain, b"hello world");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn list_after_writes() {
        let (_keepalive, cfg) = fast_config();
        let backend = EncryptedDb::init_async(&cfg).await.unwrap();
        let pubkey = backend.current_public_key_pem().await.unwrap();
        let env = encrypt_resource_for_test(&pubkey, b"x");
        backend
            .write_secret_resource(desc("repo", "secret", "a"), &env)
            .await
            .unwrap();
        backend
            .write_secret_resource(desc("repo", "secret", "b"), &env)
            .await
            .unwrap();
        let lst = backend.list_secret_resources().await.unwrap();
        let tags: Vec<_> = lst.iter().map(|d| d.resource_tag.clone()).collect();
        assert_eq!(tags, vec!["a", "b"]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn delete_then_read_errors() {
        let (_keepalive, cfg) = fast_config();
        let backend = EncryptedDb::init_async(&cfg).await.unwrap();
        let pubkey = backend.current_public_key_pem().await.unwrap();
        let env = encrypt_resource_for_test(&pubkey, b"x");
        backend
            .write_secret_resource(desc("repo", "secret", "x"), &env)
            .await
            .unwrap();
        backend
            .delete_secret_resource(desc("repo", "secret", "x"))
            .await
            .unwrap();
        let err = backend
            .read_secret_resource(desc("repo", "secret", "x"))
            .await;
        assert!(err.is_err(), "read after delete should fail");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rotate_rewraps_old_resources() {
        let (_keepalive, cfg) = fast_config();
        let backend = EncryptedDb::init_async(&cfg).await.unwrap();
        let p1 = backend.current_public_key_pem().await.unwrap();
        let env_old = encrypt_resource_for_test(&p1, b"old");
        backend
            .write_secret_resource(desc("repo", "secret", "old"), &env_old)
            .await
            .unwrap();

        let report = backend.rotate_keys().await.unwrap();
        assert_eq!(report.failed, 0);
        assert_eq!(report.rewrapped, 1, "single old envelope should be rewrapped");
        assert!(report.public_key.contains("BEGIN PUBLIC KEY"));

        // After rotation the resource should still decrypt under the new ring.
        let plain = backend
            .read_secret_resource(desc("repo", "secret", "old"))
            .await
            .unwrap();
        assert_eq!(plain, b"old");

        // The pubkey returned should be the new one.
        let p2 = backend.current_public_key_pem().await.unwrap();
        assert_ne!(p1, p2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn purge_after_grace_deletes_retired_key() {
        // Use a file-backed SQLite so we can reach in and back-date
        // retired_at to simulate the grace period elapsing.
        let mut f = NamedTempFile::new().unwrap();
        write!(f, "purge-test").unwrap();
        let dbdir = tempfile::tempdir().unwrap();
        let dbpath = dbdir.path().join("kbs.db");
        let cfg = EncryptedDbBackendConfig {
            master_secret_path: f.path().to_string_lossy().into_owned(),
            bump_poll_interval_ms: 100,
            database: DatabaseConfig {
                kind: "sqlite".into(),
                path: dbpath.to_string_lossy().into_owned(),
                retired_key_purge_after: "1h".into(),
                ..Default::default()
            },
        };

        let backend = EncryptedDb::init_async(&cfg).await.unwrap();
        let p1 = backend.current_public_key_pem().await.unwrap();
        let env_old = encrypt_resource_for_test(&p1, b"old");
        backend
            .write_secret_resource(desc("repo", "secret", "x"), &env_old)
            .await
            .unwrap();

        // First rotate retires the bootstrap key but the grace period has
        // not elapsed yet, so nothing should be purged.
        let r1 = backend.rotate_keys().await.unwrap();
        assert_eq!(r1.failed, 0);
        assert!(r1.retired_keys >= 1);
        assert_eq!(r1.purged_keys, 0, "grace not elapsed yet");

        // Back-date every retired_at into the distant past.
        let DbPool::Sqlite(p) = &backend.pool else {
            unreachable!()
        };
        sqlx::query(
            "UPDATE kbs_managed_keys SET retired_at = '2020-01-01 00:00:00.000000' WHERE retired_at IS NOT NULL",
        )
        .execute(p)
        .await
        .unwrap();

        // Second rotate should now purge.
        let r2 = backend.rotate_keys().await.unwrap();
        assert_eq!(r2.failed, 0);
        assert!(r2.purged_keys >= 1, "expected purge after back-dating");

        // Resource still readable under the latest key.
        let plain = backend
            .read_secret_resource(desc("repo", "secret", "x"))
            .await
            .unwrap();
        assert_eq!(plain, b"old");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn purge_disabled_when_grace_zero() {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, "no-purge").unwrap();
        let dbdir = tempfile::tempdir().unwrap();
        let dbpath = dbdir.path().join("kbs.db");
        let cfg = EncryptedDbBackendConfig {
            master_secret_path: f.path().to_string_lossy().into_owned(),
            bump_poll_interval_ms: 100,
            database: DatabaseConfig {
                kind: "sqlite".into(),
                path: dbpath.to_string_lossy().into_owned(),
                retired_key_purge_after: "0".into(),
                ..Default::default()
            },
        };

        let backend = EncryptedDb::init_async(&cfg).await.unwrap();
        backend.rotate_keys().await.unwrap();

        // Even with retired_at way in the past, purge must not run.
        let DbPool::Sqlite(p) = &backend.pool else {
            unreachable!()
        };
        sqlx::query(
            "UPDATE kbs_managed_keys SET retired_at = '2020-01-01 00:00:00.000000' WHERE retired_at IS NOT NULL",
        )
        .execute(p)
        .await
        .unwrap();
        let r = backend.rotate_keys().await.unwrap();
        assert_eq!(r.purged_keys, 0, "purge_after = 0 disables purging");
    }

    #[test]
    fn parse_purge_after_rejects_below_minimum() {
        assert!(parse_purge_after("30s").is_err());
        assert!(parse_purge_after("59m").is_err());
        assert!(parse_purge_after("0").unwrap().is_none());
        assert_eq!(
            parse_purge_after("1h").unwrap(),
            Some(Duration::from_secs(3600))
        );
        assert_eq!(
            parse_purge_after("30d").unwrap(),
            Some(Duration::from_secs(30 * 86_400))
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn second_init_under_wrong_passphrase_fails() {
        let (mut keepalive, mut cfg) = fast_config();
        // First start: bootstrap the canary.
        let _backend = EncryptedDb::init_async(&cfg).await.unwrap();

        // Stash the bootstrapped state by sharing the same SQLite file
        // across two providers — :memory: is per-pool, so we use a real
        // tempfile path to share state.
        let tmpdir = tempfile::tempdir().unwrap();
        let dbpath = tmpdir.path().join("kbs.db");
        cfg.database.path = dbpath.to_string_lossy().into_owned();

        // Bootstrap the file-backed DB with a known passphrase.
        let _backend = EncryptedDb::init_async(&cfg).await.unwrap();

        // Now flip the passphrase and re-init: must fail at the canary.
        write!(keepalive, "wrong-passphrase").unwrap();
        let err = EncryptedDb::init_async(&cfg)
            .await
            .err()
            .expect("wrong passphrase must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("canary") || msg.contains("authentication"),
            "expected canary error, got: {msg}"
        );
    }
}
