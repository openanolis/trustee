// Copyright (c) 2026 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
//! End-to-end test for the EncryptedDb backend against a real MySQL.
//!
//! Skipped unless `MYSQL_TEST_URL` is set (typical local invocation:
//!
//! ```bash
//! docker run -d --name kbs-mysql-test \
//!   -e MYSQL_ROOT_PASSWORD=test-root \
//!   -e MYSQL_DATABASE=trustee_kbs_test \
//!   -p 33307:3306 mysql:8.0
//!
//! MYSQL_TEST_URL=mysql://root:test-root@127.0.0.1:33307/trustee_kbs_test \
//!   cargo test -p kbs --features encrypted-db --test encrypted_db_mysql_e2e -- --nocapture
//! ```
//!
//! The test mirrors the multi-replica deployment scenario from the plan
//! (`/home/xinjian.zjl/.claude/plans/glittery-wishing-wilkes.md`):
//!
//!   1. Replica A returns a public key P1.
//!   2. A client encrypts a resource r1 with P1 and POSTs to A.
//!   3. Replica B reads r1 — must succeed (multi-replica path).
//!   4. POST /rotate to B → returns a new public key P2.
//!   5. A picks up the new pubkey within poll_interval.
//!   6. Client uses P2 to upload r2 → A reads it.
//!   7. Old r1 is rewrapped to P2 and still readable.
//!   8. A reinitialized replica still uses P2.
//!   9. A new replica started under a wrong passphrase fails canary check.
//!  10. DELETE r1 — invisible from both replicas.
//!  11. Backdate retired_at to simulate the grace period elapsing, run
//!      another rotate, and observe purged_keys > 0 + the row gone.

#![cfg(feature = "encrypted-db")]

use std::env;
use std::io::Write;
use std::time::Duration;

use aes_gcm::aead::{generic_array::GenericArray, AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::RngCore;
use rsa::pkcs8::DecodePublicKey;
use rsa::sha2::Sha256;
use rsa::{Oaep, RsaPublicKey};
use tempfile::NamedTempFile;

use kbs::plugins::implementations::resource::encrypted_db::{
    DatabaseConfig, EncryptedDb, EncryptedDbBackendConfig,
};
use kbs::plugins::implementations::resource::{ResourceDesc, StorageBackend};

const PASSPHRASE: &[u8] = b"e2e-master-secret-pls-change";

/// Prepare a fresh schema by dropping the tables EncryptedDb owns. We do
/// this via a side-channel sqlx connection so the per-test state is
/// deterministic.
async fn reset_mysql_schema(dsn: &str) {
    let pool = sqlx::MySqlPool::connect(dsn).await.expect("connect mysql");
    for stmt in [
        "DROP TABLE IF EXISTS kbs_resources",
        "DROP TABLE IF EXISTS kbs_managed_keys",
        "DROP TABLE IF EXISTS kbs_meta",
    ] {
        sqlx::query(stmt).execute(&pool).await.unwrap();
    }
    pool.close().await;
}

fn write_passphrase(bytes: &[u8]) -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(bytes).unwrap();
    f.flush().unwrap();
    f
}

fn cfg(dsn: &str, secret_path: &str) -> EncryptedDbBackendConfig {
    EncryptedDbBackendConfig {
        master_secret_path: secret_path.to_string(),
        bump_poll_interval_ms: 250, // short so tests don't drag
        database: DatabaseConfig {
            kind: "mysql".to_string(),
            dsn: dsn.to_string(),
            ..Default::default()
        },
    }
}

fn desc(r: &str, t: &str, g: &str) -> ResourceDesc {
    ResourceDesc {
        repository_name: r.into(),
        resource_type: t.into(),
        resource_tag: g.into(),
    }
}

/// Encrypt `plaintext` for the given PEM public key using the same
/// envelope schema KBS expects (RSA-OAEP-256 wraps a 32-byte CEK that
/// AES-256-GCM encrypts the body). Returns the JSON envelope a client
/// would POST to `/repo/secret/<tag>`.
fn encrypt_for_pubkey(public_pem: &str, plaintext: &[u8]) -> Vec<u8> {
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
        "tag": STANDARD.encode(GenericArray::from(tag).as_slice()),
    });
    serde_json::to_vec(&env).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn end_to_end_two_replicas() {
    let Ok(dsn) = env::var("MYSQL_TEST_URL") else {
        eprintln!("MYSQL_TEST_URL not set — skipping MySQL e2e test");
        return;
    };
    reset_mysql_schema(&dsn).await;

    let secret = write_passphrase(PASSPHRASE);
    let secret_path = secret.path().to_string_lossy().into_owned();

    // Replica A: bootstraps the schema, the canary, and the first wrap key.
    let replica_a = EncryptedDb::init_async(&cfg(&dsn, &secret_path))
        .await
        .expect("replica A init");
    // Replica B: same DSN, same passphrase, same shared state.
    let replica_b = EncryptedDb::init_async(&cfg(&dsn, &secret_path))
        .await
        .expect("replica B init");

    // 1+2. A returns P1, client wraps r1 with P1, POSTs to A.
    let p1 = replica_a.current_public_key_pem().await.unwrap();
    let env_r1 = encrypt_for_pubkey(&p1, b"r1-payload");
    replica_a
        .write_secret_resource(desc("repo", "secret", "r1"), &env_r1)
        .await
        .unwrap();

    // 3. B reads r1 — the critical multi-replica path.
    let plain = replica_b
        .read_secret_resource(desc("repo", "secret", "r1"))
        .await
        .unwrap();
    assert_eq!(plain, b"r1-payload", "B must decrypt what A wrote");

    // 4. POST /rotate to B.
    let rotate = replica_b.rotate_keys().await.unwrap();
    assert_eq!(rotate.failed, 0, "rotate must not fail");
    assert!(
        rotate.rewrapped >= 1,
        "r1 should have been rewrapped during rotate, got {}",
        rotate.rewrapped
    );
    assert!(rotate.public_key.contains("BEGIN PUBLIC KEY"));
    assert!(
        rotate.retired_keys >= 1,
        "old generation should be retired"
    );
    let p2 = rotate.public_key.clone();

    // 5. A picks up the new pubkey within poll_interval. We wait a beat
    //    longer than the configured 250ms throttle, then read /pubkey.
    tokio::time::sleep(Duration::from_millis(400)).await;
    let p_seen_by_a = replica_a.current_public_key_pem().await.unwrap();
    assert_eq!(p_seen_by_a, p2, "A must observe the rotated pubkey");

    // 6. Client uses P2 to upload r2 → A reads it.
    let env_r2 = encrypt_for_pubkey(&p2, b"r2-payload");
    replica_b
        .write_secret_resource(desc("repo", "secret", "r2"), &env_r2)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    let plain = replica_a
        .read_secret_resource(desc("repo", "secret", "r2"))
        .await
        .unwrap();
    assert_eq!(plain, b"r2-payload");

    // 7. Old r1 still readable from both replicas (was rewrapped to P2).
    for replica in [&replica_a, &replica_b] {
        let plain = replica
            .read_secret_resource(desc("repo", "secret", "r1"))
            .await
            .unwrap();
        assert_eq!(plain, b"r1-payload");
    }

    // 8. A "fresh" replica (init from scratch) ends up with P2 as primary.
    drop(replica_a);
    let replica_c = EncryptedDb::init_async(&cfg(&dsn, &secret_path))
        .await
        .unwrap();
    let p_c = replica_c.current_public_key_pem().await.unwrap();
    assert_eq!(p_c, p2);

    // 9. Wrong passphrase ⇒ canary refuses to start.
    let wrong = write_passphrase(b"WRONG-passphrase");
    let err = EncryptedDb::init_async(&cfg(
        &dsn,
        &wrong.path().to_string_lossy(),
    ))
    .await
    .err()
    .expect("wrong passphrase must fail");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("canary") || msg.contains("authentication"),
        "expected canary error, got: {msg}"
    );

    // 10. DELETE r1 — invisible from any replica.
    replica_b
        .delete_secret_resource(desc("repo", "secret", "r1"))
        .await
        .unwrap();
    for replica in [&replica_b, &replica_c] {
        let res = replica
            .read_secret_resource(desc("repo", "secret", "r1"))
            .await;
        assert!(res.is_err(), "deleted r1 must not be readable");
    }

    // 11. Back-date retired_at to simulate the grace period elapsing, then
    //     rotate one more time and observe purged_keys > 0.
    let pool = sqlx::MySqlPool::connect(&dsn).await.unwrap();
    let pre_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM kbs_managed_keys WHERE retired_at IS NOT NULL")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(pre_count.0 >= 1, "must have at least one retired key");
    sqlx::query(
        "UPDATE kbs_managed_keys SET retired_at = '2020-01-01 00:00:00.000000' WHERE retired_at IS NOT NULL",
    )
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;

    let rotate2 = replica_b.rotate_keys().await.unwrap();
    assert_eq!(rotate2.failed, 0);
    assert!(
        rotate2.purged_keys >= pre_count.0 as usize,
        "expected purge to remove the back-dated retired keys, got {}",
        rotate2.purged_keys
    );

    let pool = sqlx::MySqlPool::connect(&dsn).await.unwrap();
    let post_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM kbs_managed_keys WHERE retired_at IS NOT NULL AND retired_at < '2021-01-01'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        post_count.0, 0,
        "back-dated retired keys must be physically deleted"
    );
    pool.close().await;
}
