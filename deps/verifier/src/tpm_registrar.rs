// Copyright (c) 2026 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

//! Shared keylime registrar client for the TPM-family verifiers.
//!
//! The registrar binding check (confirming that the EK/AK carried in the
//! evidence matches what the keylime registrar recorded for a given agent UUID)
//! used to build a brand-new HTTP client and perform two *blocking, serial*
//! HTTPS round-trips to the registrar on **every** attestation. Under load this
//! turned attestation throughput into a hostage of the registrar (a low-concurrency,
//! DB-backed service) while leaving the AS itself idle on CPU.
//!
//! This module removes that per-request cost by:
//!   * reusing a single process-wide [`reqwest::Client`] so TCP connections and
//!     TLS sessions are pooled instead of re-established on every call,
//!   * caching the registrar API version per registrar URL, and
//!   * caching the per-UUID registrar `results` object with a TTL,
//!   * canonicalizing UUIDs before building the registrar request path,
//!
//! so repeated attestations for the same agent no longer touch the registrar.
//!
//! Caching the registrar data does **not** weaken the binding check: each
//! verifier still compares the returned EK/AK material against the evidence it
//! is validating. The TTL (overridable via `KEYLIME_REGISTRAR_CACHE_TTL_SECS`,
//! default 120s) bounds how long a stale registration can be trusted after an
//! agent re-registers.

use anyhow::{anyhow, Result};
use reqwest::Client;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use uuid::Uuid;

pub const DEFAULT_KEYLIME_REGISTRAR_URL: &str = "https://127.0.0.1:8991";
const DEFAULT_CACHE_TTL_SECS: u64 = 120;
const CACHE_TTL_ENV: &str = "KEYLIME_REGISTRAR_CACHE_TTL_SECS";

/// Resolve the registrar base URL from `KEYLIME_REGISTRAR_URL`, falling back to
/// the default local address.
pub fn registrar_url() -> String {
    std::env::var("KEYLIME_REGISTRAR_URL")
        .unwrap_or_else(|_| DEFAULT_KEYLIME_REGISTRAR_URL.to_string())
}

fn canonical_agent_id(agent_id: &str) -> String {
    Uuid::parse_str(agent_id)
        .map(|uuid| uuid.to_string())
        .unwrap_or_else(|_| agent_id.to_string())
}

fn cache_ttl() -> Duration {
    let secs = std::env::var(CACHE_TTL_ENV)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_CACHE_TTL_SECS);
    Duration::from_secs(secs)
}

/// Process-wide HTTP client with connection pooling / TLS reuse.
fn http_client() -> &'static Client {
    static CLIENT: OnceLock<Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        Client::builder()
            .danger_accept_invalid_certs(true)
            .pool_idle_timeout(Duration::from_secs(90))
            .build()
            .expect("build keylime registrar HTTP client")
    })
}

struct Timed<T> {
    value: T,
    at: Instant,
}

fn version_cache() -> &'static Mutex<HashMap<String, Timed<String>>> {
    static C: OnceLock<Mutex<HashMap<String, Timed<String>>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

fn results_cache() -> &'static Mutex<HashMap<String, Timed<Value>>> {
    static C: OnceLock<Mutex<HashMap<String, Timed<Value>>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

fn cached<T: Clone>(
    cache: &Mutex<HashMap<String, Timed<T>>>,
    key: &str,
    ttl: Duration,
) -> Option<T> {
    let map = cache.lock().expect("registrar cache poisoned");
    map.get(key)
        .filter(|e| e.at.elapsed() < ttl)
        .map(|e| e.value.clone())
}

fn store<T>(cache: &Mutex<HashMap<String, Timed<T>>>, key: String, value: T) {
    cache.lock().expect("registrar cache poisoned").insert(
        key,
        Timed {
            value,
            at: Instant::now(),
        },
    );
}

/// Fetch (with caching) the keylime registrar `results` object for `uuid`.
///
/// On a cache hit no HTTPS request is made. On a miss the registrar API version
/// and the agent record are fetched over the shared client and both are cached.
/// The caller must still compare the EK/AK material in the returned object
/// against the evidence being verified.
pub async fn get_agent_results(registrar: &str, uuid: &str) -> Result<Value> {
    let ttl = cache_ttl();
    // Keylime canonicalizes configured UUIDs with `Uuid::to_string()` before
    // registration. Match that behavior so uppercase UUIDs from older evidence
    // do not query a different, non-existent registrar path.
    let uuid = canonical_agent_id(uuid);
    let key = format!("{registrar}|{uuid}");

    if let Some(results) = cached(results_cache(), &key, ttl) {
        return Ok(results);
    }

    let version = get_version(registrar, ttl).await?;
    let agent = http_client()
        .get(format!("{registrar}/v{version}/agents/{uuid}"))
        .send()
        .await
        .map_err(|e| anyhow!("fetch agent info: {e}"))?
        .error_for_status()
        .map_err(|e| anyhow!("fetch agent info: {e}"))?
        .json::<Value>()
        .await
        .map_err(|e| anyhow!("parse agent json: {e}"))?;

    let results = agent
        .get("results")
        .ok_or_else(|| anyhow!("Invalid agent results"))?
        .clone();

    store(results_cache(), key, results.clone());
    Ok(results)
}

async fn get_version(registrar: &str, ttl: Duration) -> Result<String> {
    if let Some(version) = cached(version_cache(), registrar, ttl) {
        return Ok(version);
    }

    let ver_resp = http_client()
        .get(format!("{registrar}/version"))
        .send()
        .await
        .map_err(|e| anyhow!("fetch registrar version: {e}"))?
        .error_for_status()
        .map_err(|e| anyhow!("fetch registrar version: {e}"))?
        .json::<Value>()
        .await
        .map_err(|e| anyhow!("parse registrar version json: {e}"))?;

    let version = ver_resp
        .get("results")
        .and_then(|v| v.get("current_version"))
        .and_then(|v| {
            v.as_str()
                .map(|s| s.to_string())
                .or_else(|| v.as_u64().map(|n| n.to_string()))
        })
        .ok_or_else(|| anyhow!("Invalid registrar version response"))?;

    store(version_cache(), registrar.to_string(), version.clone());
    Ok(version)
}

#[cfg(test)]
mod tests {
    use super::canonical_agent_id;

    #[test]
    fn canonical_agent_id_normalizes_uuid_case() {
        assert_eq!(
            canonical_agent_id("D432FBB3-D2F1-4A97-9EF7-75BD81C00000"),
            "d432fbb3-d2f1-4a97-9ef7-75bd81c00000"
        );
    }

    #[test]
    fn canonical_agent_id_preserves_non_uuid_ids() {
        assert_eq!(canonical_agent_id("custom-agent"), "custom-agent");
    }
}
