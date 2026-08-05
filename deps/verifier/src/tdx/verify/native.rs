//! TDX quote verification backend that needs no external DCAP shared library.
//! Selected by the `tdx-dcap-rust` feature.
//!
//! This backend removes the dependency on the Intel DCAP shared library
//! (`libsgx_dcap_quoteverify`) and its dynamically loaded quote provider. The
//! ECDSA quote signature, PCK certificate chain, TCB info and QE identity are
//! all verified via the [`dcap_qvl`] crate; verification collateral is fetched
//! over HTTPS from a PCCS using the verifier's own `reqwest` stack (we
//! deliberately do *not* enable `dcap-qvl`'s `report` feature, which would pull
//! in `reqwest` 0.13 / `aws-lc-sys`).
//!
//! Crypto backend: `dcap-qvl` is used with its `ring` crypto backend. `ring`
//! statically links its own crypto (no external shared library), and — unlike
//! the RustCrypto stack — builds on Rust 1.76, so this backend has the same
//! toolchain requirement as the default (FFI) build. With the feature disabled,
//! Cargo prunes this whole subtree, so it has no effect on the default build.
//!
//! PCCS configuration: one or more collateral endpoints are resolved from, in
//! order, the `PCCS_URLS` environment variable, the legacy `PCCS_URL`, the
//! `pccs_url` / `PCCS_URL` entry in `/etc/sgx_default_qcnl.conf`, and finally a
//! built-in default. Endpoints are tried in order so a secondary PCCS can take
//! over when the preferred service is unavailable.
//!
//! Verification collateral is cached in process by PCCS set, FMSPC and CA type.
//! `VERIFY_COLLATERAL_CACHE_REFRESH_HOURS` (72 hours by default) proactively
//! refreshes an entry before `VERIFY_COLLATERAL_CACHE_EXPIRE_HOURS` (168 hours
//! by default). Refresh failures retain the last successfully fetched
//! collateral, including after the cache TTL. Collateral freshness remains a
//! quote-verification policy decision rather than a cache-availability
//! decision. Concurrent refreshes are coalesced per cache key and failures are
//! retried with a bounded backoff.
//!
//! Scope: the collateral fetch currently supports quotes whose certification
//! data embeds the PCK certificate chain (PCK cert type 5), which is what cloud
//! TDX quotes use. Other certification data types return a clear error.
//!
//! The [`TcbVerificationResult`] returned here is populated to match the fields
//! the DCAP QVL (FFI) backend exposes, including `tcb_level_date_tag`, which is
//! reproduced by re-running Intel QVL's TCB-level matching over the platform TCB
//! (SGX TCB components + PCE SVN from the PCK certificate, TDX TEE TCB SVN from
//! the TD report).

use anyhow::{anyhow, bail, Context, Result};
use asn1_rs::{Any, FromDer, Oid};
use dcap_qvl::tcb_info::{TcbComponents, TcbInfo, TcbLevel};
use dcap_qvl::verify::{QuoteVerifier, VerifiedReport};
use dcap_qvl::QuoteCollateralV3;
use log::{debug, info, warn};
use serde_json::json;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;
use tokio::sync::Mutex;
use x509_parser::pem::Pem;
use x509_parser::prelude::*;

#[cfg(not(all(
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
)))]
use std::time::{Instant, SystemTime, UNIX_EPOCH};
#[cfg(all(
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
))]
use web_time::{Instant, SystemTime, UNIX_EPOCH};

use crate::tdx::quote::{parse_tdx_quote, TcbVerificationResult};
use crate::{DependencyStatus, VerifierError};

fn pccs_unavailable<E>(source: E) -> anyhow::Error
where
    E: Into<anyhow::Error>,
{
    VerifierError::DependencyUnavailable {
        dependency: "PCCS",
        source: source.into(),
    }
    .into()
}

fn pccs_bad_response<E>(source: E) -> anyhow::Error
where
    E: Into<anyhow::Error>,
{
    VerifierError::DependencyBadResponse {
        dependency: "PCCS",
        source: source.into(),
    }
    .into()
}

/// Default PCCS base URL, used only when neither an override, `PCCS_URLS`,
/// `PCCS_URL`, nor the QCNL config file provide one.
const DEFAULT_PCCS_URL: &str = "https://sgx-dcap-server.cn-beijing.aliyuncs.com";

/// QCNL config file read by the DCAP quote provider (FFI backend). We fall back
/// to its `pccs_url` so both backends can share one PCCS configuration.
const QCNL_CONF_PATH: &str = "/etc/sgx_default_qcnl.conf";

/// Intel QCNL's default verification collateral cache lifetime.
const DEFAULT_COLLATERAL_CACHE_EXPIRE_HOURS: u64 = 168;

/// Refresh well before the cache TTL so a PCCS incident does not first become
/// visible on the hard-expiry boundary.
const DEFAULT_COLLATERAL_CACHE_REFRESH_HOURS: u64 = 72;

/// Avoid retrying an unavailable PCCS on every attestation request.
const DEFAULT_COLLATERAL_CACHE_REFRESH_RETRY_SECS: u64 = 60 * 60;

/// QCNL setting shared with the FFI quote-provider backend.
const COLLATERAL_CACHE_EXPIRE_HOURS: &str = "VERIFY_COLLATERAL_CACHE_EXPIRE_HOURS";

/// AS-specific proactive refresh setting. It is intentionally separate from
/// Intel QCNL's hard cache-expiry setting.
const COLLATERAL_CACHE_REFRESH_HOURS: &str = "VERIFY_COLLATERAL_CACHE_REFRESH_HOURS";

/// Backoff after a failed proactive or blocking refresh.
const COLLATERAL_CACHE_REFRESH_RETRY_SECS: &str = "VERIFY_COLLATERAL_CACHE_REFRESH_RETRY_SECS";

/// Ordered comma-separated PCCS base URLs. The existing single-value
/// `PCCS_URL` remains supported as a fallback for compatibility.
const PCCS_URLS_ENV: &str = "PCCS_URLS";

/// Per-request timeout before moving to the next configured PCCS endpoint.
const PCCS_HTTP_TIMEOUT_SECS: &str = "PCCS_HTTP_TIMEOUT_SECS";
const DEFAULT_PCCS_HTTP_TIMEOUT_SECS: u64 = 60;

/// TEE type for TDX, matching the value the FFI backend reports in
/// `TcbVerificationResult::tee_type`.
const TEE_TYPE_TDX: u32 = 0x0000_0081;

/// Intel SGX extension OID (`1.2.840.113741.1.13.1`) and the sub-OIDs used here.
const OID_SGX_EXTENSION: &[u64] = &[1, 2, 840, 113741, 1, 13, 1];
const OID_SGX_TCB: &[u64] = &[1, 2, 840, 113741, 1, 13, 1, 2];
const OID_SGX_PCESVN: &[u64] = &[1, 2, 840, 113741, 1, 13, 1, 2, 17];
const OID_SGX_FMSPC: &[u64] = &[1, 2, 840, 113741, 1, 13, 1, 4];

/// Injectable PCCS base URL overrides (pure-lib / wasm host). When set, take
/// precedence over env / config-file resolution. The verifier crate does not
/// pull this from any config struct; whoever embeds the verifier calls
/// [`set_pccs_urls`] directly (e.g. a binary at startup, or the wasm host glue
/// before invoking verification). A `RwLock` lets tests and embedders update
/// the value across reconfiguration.
static PCCS_URLS_OVERRIDE: RwLock<Option<Vec<String>>> = RwLock::new(None);

/// Inject the PCCS base URL (pure-lib / wasm host). When set, takes precedence
/// over env / config-file resolution. The embedder is expected to call this
/// directly — the verifier crate itself never reads an AS config for it.
pub fn set_pccs_url(url: Option<String>) {
    set_pccs_urls(url.map(|url| vec![url]));
}

/// Inject an ordered PCCS fallback list (pure-lib / wasm host).
pub fn set_pccs_urls(urls: Option<Vec<String>>) {
    *PCCS_URLS_OVERRIDE.write().unwrap() = urls.map(normalize_pccs_urls);
}

/// Resolve ordered PCCS endpoints: injected override, `PCCS_URLS`, legacy
/// `PCCS_URL`, QCNL config, then the built-in default.
fn resolve_pccs_urls() -> Vec<String> {
    if let Some(urls) = PCCS_URLS_OVERRIDE.read().unwrap().clone() {
        if !urls.is_empty() {
            return urls;
        }
    }
    #[cfg(not(all(
        target_arch = "wasm32",
        target_vendor = "unknown",
        target_os = "unknown"
    )))]
    {
        if let Ok(value) = std::env::var(PCCS_URLS_ENV) {
            let urls = parse_pccs_urls(&value);
            if !urls.is_empty() {
                return urls;
            }
            warn!("dcap-qvl backend: ignoring empty {PCCS_URLS_ENV}");
        }
        if let Ok(v) = std::env::var("PCCS_URL") {
            if !v.is_empty() {
                return normalize_pccs_urls(vec![v]);
            }
        }
        if let Some(v) = std::fs::read_to_string(QCNL_CONF_PATH)
            .ok()
            .and_then(|c| parse_qcnl_pccs_url(&c))
        {
            debug!("dcap-qvl backend: using PCCS URL from {QCNL_CONF_PATH}");
            return normalize_pccs_urls(vec![v]);
        }
    }
    vec![DEFAULT_PCCS_URL.to_string()]
}

#[derive(Clone, Copy, Debug)]
struct CollateralCachePolicy {
    refresh_after: Duration,
    expire_after: Duration,
    retry_after: Duration,
}

impl CollateralCachePolicy {
    fn from_durations(
        refresh_after: Duration,
        expire_after: Duration,
        retry_after: Duration,
    ) -> Self {
        let refresh_after = if !expire_after.is_zero() && refresh_after >= expire_after {
            let adjusted = Duration::from_secs((expire_after.as_secs() / 2).max(1));
            warn!(
                "dcap-qvl backend: refresh interval {:?} must be shorter than cache expiry {:?}; using {:?}",
                refresh_after, expire_after, adjusted
            );
            adjusted
        } else {
            refresh_after
        };
        Self {
            refresh_after,
            expire_after,
            retry_after,
        }
    }
}

/// Resolve proactive refresh, cache expiry, and refresh retry policy. Existing
/// QCNL cache expiry remains authoritative; the new settings are optional.
fn resolve_collateral_cache_policy() -> CollateralCachePolicy {
    let expire_hours = resolve_u64_setting(
        COLLATERAL_CACHE_EXPIRE_HOURS,
        DEFAULT_COLLATERAL_CACHE_EXPIRE_HOURS,
    );
    let refresh_hours = resolve_u64_setting(
        COLLATERAL_CACHE_REFRESH_HOURS,
        DEFAULT_COLLATERAL_CACHE_REFRESH_HOURS,
    );
    let retry_secs = resolve_u64_setting(
        COLLATERAL_CACHE_REFRESH_RETRY_SECS,
        DEFAULT_COLLATERAL_CACHE_REFRESH_RETRY_SECS,
    );

    CollateralCachePolicy::from_durations(
        Duration::from_secs(refresh_hours.saturating_mul(60 * 60)),
        Duration::from_secs(expire_hours.saturating_mul(60 * 60)),
        Duration::from_secs(retry_secs),
    )
}

fn resolve_u64_setting(key: &str, default: u64) -> u64 {
    if let Ok(value) = std::env::var(key) {
        match value.parse::<u64>() {
            Ok(value) => return value,
            Err(e) => warn!("dcap-qvl backend: ignoring invalid {key}={value:?}: {e}"),
        }
    }

    std::fs::read_to_string(QCNL_CONF_PATH)
        .ok()
        .and_then(|content| parse_qcnl_u64(&content, key))
        .unwrap_or(default)
}

fn parse_pccs_urls(value: &str) -> Vec<String> {
    normalize_pccs_urls(value.split(',').map(str::to_string).collect())
}

fn normalize_pccs_urls(urls: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    urls.into_iter()
        .map(|url| normalize_pccs_base_url(url.trim()))
        .filter(|url| !url.is_empty() && seen.insert(url.clone()))
        .collect()
}

/// Extract the PCCS URL from QCNL config file contents, supporting both the JSON
/// form (`{"pccs_url": "https://..."}`, optionally with `//` comments) and the
/// legacy INI form (`PCCS_URL=https://...`).
fn parse_qcnl_pccs_url(content: &str) -> Option<String> {
    for raw in content.lines() {
        let line = raw.trim();
        if line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        let Some(key_pos) = line.to_ascii_lowercase().find("pccs_url") else {
            continue;
        };
        // After the key (INI `=` or JSON `":`), take the URL up to the next
        // quote / comma / whitespace. This covers both config styles.
        let after = &line[key_pos + "pccs_url".len()..];
        let Some(http_pos) = after.find("http") else {
            continue;
        };
        let url = &after[http_pos..];
        let end = url
            .find(|c: char| c == '"' || c == ',' || c.is_whitespace())
            .unwrap_or(url.len());
        let url = &url[..end];
        if !url.is_empty() {
            return Some(url.to_string());
        }
    }
    None
}

/// Parse an unsigned integer from either the JSON or legacy INI QCNL format.
fn parse_qcnl_u64(content: &str, key: &str) -> Option<u64> {
    let key = key.to_ascii_lowercase();
    for raw in content.lines() {
        let line = raw.trim();
        if line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        let Some(key_pos) = lower.find(&key) else {
            continue;
        };
        let after = &line[key_pos + key.len()..];
        let Some(start) = after.find(|c: char| c.is_ascii_digit()) else {
            continue;
        };
        let digits: String = after[start..]
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if let Ok(value) = digits.parse() {
            return Some(value);
        }
    }
    None
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct CollateralCacheKey {
    pccs_base_urls: Vec<String>,
    fmspc: String,
    ca: String,
}

#[derive(Clone)]
struct CachedCollateral {
    collateral: QuoteCollateralV3,
    cached_at: Instant,
    cached_at_unix: u64,
    last_successful_pccs: String,
    last_refresh_attempt_at: Option<u64>,
    last_refresh_error: Option<String>,
    next_refresh_allowed_at: Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CacheEntryState {
    Fresh,
    RefreshDue,
    CacheExpired,
}

/// Process-local collateral cache. Per-key refresh locks prevent a slow PCCS
/// for one platform from blocking refreshes for unrelated FMSPCs.
#[derive(Default)]
struct CollateralCache {
    entries: Mutex<HashMap<CollateralCacheKey, CachedCollateral>>,
    refresh_locks: Mutex<HashMap<CollateralCacheKey, Arc<Mutex<()>>>>,
}

impl CollateralCache {
    async fn lookup(&self, key: &CollateralCacheKey) -> Option<CachedCollateral> {
        self.entries.lock().await.get(key).cloned()
    }

    async fn refresh_lock(&self, key: &CollateralCacheKey) -> Arc<Mutex<()>> {
        self.refresh_locks
            .lock()
            .await
            .entry(key.clone())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    async fn store_success(
        &self,
        key: CollateralCacheKey,
        mut collateral: QuoteCollateralV3,
        successful_pccs: String,
    ) -> Instant {
        // The PCK chain belongs to the current quote and must never be shared
        // across machines that happen to use the same FMSPC and CA type.
        collateral.pck_certificate_chain = None;
        let now = Instant::now();
        self.entries.lock().await.insert(
            key,
            CachedCollateral {
                collateral,
                cached_at: now,
                cached_at_unix: unix_now(),
                last_successful_pccs: successful_pccs,
                last_refresh_attempt_at: Some(unix_now()),
                last_refresh_error: None,
                next_refresh_allowed_at: now,
            },
        );
        now
    }

    async fn record_refresh_attempt(&self, key: &CollateralCacheKey) {
        if let Some(entry) = self.entries.lock().await.get_mut(key) {
            entry.last_refresh_attempt_at = Some(unix_now());
        }
    }

    async fn record_refresh_failure(
        &self,
        key: &CollateralCacheKey,
        error: &anyhow::Error,
        retry_after: Duration,
    ) {
        if let Some(entry) = self.entries.lock().await.get_mut(key) {
            entry.last_refresh_attempt_at = Some(unix_now());
            entry.last_refresh_error = Some(format!("{error:#}"));
            entry.next_refresh_allowed_at = Instant::now() + retry_after;
        }
    }

    async fn retry_allowed(&self, key: &CollateralCacheKey) -> bool {
        self.lookup(key)
            .await
            .map(|entry| Instant::now() >= entry.next_refresh_allowed_at)
            .unwrap_or(true)
    }

    async fn statuses(
        &self,
        policy: CollateralCachePolicy,
        configured_pccs: Vec<String>,
    ) -> Vec<DependencyStatus> {
        let entries: Vec<(CollateralCacheKey, CachedCollateral)> = self
            .entries
            .lock()
            .await
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();

        if entries.is_empty() {
            let mut details = BTreeMap::new();
            details.insert("pccs_urls".into(), json!(configured_pccs));
            details.insert(
                "refresh_after_seconds".into(),
                json!(policy.refresh_after.as_secs()),
            );
            details.insert(
                "cache_expire_after_seconds".into(),
                json!(policy.expire_after.as_secs()),
            );
            details.insert(
                "refresh_retry_after_seconds".into(),
                json!(policy.retry_after.as_secs()),
            );
            return vec![DependencyStatus {
                kind: "tdx-collateral-cache".into(),
                name: "tdx-collateral-cache".into(),
                status: "not_initialized".into(),
                message: Some("no TDX collateral has been cached in this AS process".into()),
                details,
            }];
        }

        let now = Instant::now();
        let mut statuses = Vec::with_capacity(entries.len());
        for (key, entry) in entries {
            let state = classify_cache_entry(&entry, policy, now);
            let refresh_lock = self.refresh_lock(&key).await;
            let refresh_in_progress = refresh_lock.try_lock().is_err();
            let (status, message) = match state {
                CacheEntryState::Fresh => (
                    "ready",
                    "cached collateral is within the proactive refresh interval",
                ),
                CacheEntryState::CacheExpired => (
                    "degraded",
                    "cache TTL elapsed; cached collateral is retained for verification",
                ),
                CacheEntryState::RefreshDue if refresh_in_progress => (
                    "refresh_due",
                    "cached collateral is usable while proactive refresh is running",
                ),
                CacheEntryState::RefreshDue if entry.last_refresh_error.is_some() => (
                    "refresh_retrying",
                    "the last PCCS refresh failed; cached collateral is available while waiting to retry",
                ),
                CacheEntryState::RefreshDue => (
                    "refresh_due",
                    "cached collateral is usable and proactive refresh is due",
                ),
            };

            let mut details = BTreeMap::new();
            details.insert("fmspc".into(), json!(key.fmspc));
            details.insert("ca".into(), json!(key.ca));
            details.insert("pccs_urls".into(), json!(key.pccs_base_urls));
            details.insert(
                "cache_age_seconds".into(),
                json!(entry.cached_at.elapsed().as_secs()),
            );
            details.insert("cached_at".into(), json!(entry.cached_at_unix));
            details.insert(
                "last_successful_pccs".into(),
                json!(entry.last_successful_pccs),
            );
            details.insert(
                "last_refresh_attempt_at".into(),
                json!(entry.last_refresh_attempt_at),
            );
            details.insert("refresh_in_progress".into(), json!(refresh_in_progress));
            if let Some(error) = entry.last_refresh_error {
                details.insert("last_refresh_error".into(), json!(error));
            }

            statuses.push(DependencyStatus {
                kind: "tdx-collateral-cache".into(),
                name: format!("tdx-collateral:{}:{}", key.fmspc, key.ca),
                status: status.into(),
                message: Some(message.into()),
                details,
            });
        }
        statuses
    }
}

fn collateral_cache() -> &'static CollateralCache {
    static CACHE: OnceLock<CollateralCache> = OnceLock::new();
    CACHE.get_or_init(CollateralCache::default)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn classify_cache_entry(
    entry: &CachedCollateral,
    policy: CollateralCachePolicy,
    now: Instant,
) -> CacheEntryState {
    let age = now.saturating_duration_since(entry.cached_at);
    if age >= policy.expire_after {
        CacheEntryState::CacheExpired
    } else if age >= policy.refresh_after {
        CacheEntryState::RefreshDue
    } else {
        CacheEntryState::Fresh
    }
}

fn attach_pck_chain(mut collateral: QuoteCollateralV3, pck_chain: String) -> QuoteCollateralV3 {
    collateral.pck_certificate_chain = Some(pck_chain);
    collateral
}

fn cached_collateral(entry: &CachedCollateral, pck_chain: String) -> QuoteCollateralV3 {
    attach_pck_chain(entry.collateral.clone(), pck_chain)
}

async fn fetch_and_store(
    key: &CollateralCacheKey,
    policy: CollateralCachePolicy,
) -> Result<QuoteCollateralV3> {
    let (collateral, successful_pccs) =
        fetch_collateral_with_fallback(&key.pccs_base_urls, &key.fmspc, &key.ca).await?;
    let cached_at = collateral_cache()
        .store_success(key.clone(), collateral.clone(), successful_pccs)
        .await;
    schedule_refresh_after(key.clone(), policy, cached_at, policy.refresh_after);
    Ok(collateral)
}

/// Schedule a timer when collateral is stored, so refresh does not depend on a
/// verification request arriving at exactly the refresh boundary. The request
/// path still detects `RefreshDue` as a safety net for runtimes where a timer
/// was cancelled or delayed.
#[cfg(not(all(
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
)))]
fn schedule_refresh_after(
    key: CollateralCacheKey,
    policy: CollateralCachePolicy,
    cached_at: Instant,
    delay: Duration,
) {
    if delay.is_zero() {
        return;
    }

    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        warn!(
            "dcap-qvl backend: no Tokio runtime is available; proactive collateral refresh timer was not scheduled"
        );
        return;
    };

    runtime.spawn(async move {
        tokio::time::sleep(delay).await;
        let Some(entry) = collateral_cache().lookup(&key).await else {
            return;
        };
        // A newer successful refresh owns its own timer. Do not let an older
        // timer trigger another fetch for the same key.
        if entry.cached_at != cached_at {
            return;
        }
        trigger_background_refresh(key, policy).await;
    });
}

#[cfg(all(
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
))]
fn schedule_refresh_after(
    _key: CollateralCacheKey,
    _policy: CollateralCachePolicy,
    _cached_at: Instant,
    _delay: Duration,
) {
}

#[cfg(not(all(
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
)))]
async fn trigger_background_refresh(key: CollateralCacheKey, policy: CollateralCachePolicy) {
    if !collateral_cache().retry_allowed(&key).await {
        return;
    }
    let refresh_lock = collateral_cache().refresh_lock(&key).await;
    let Ok(refresh_guard) = refresh_lock.try_lock_owned() else {
        return;
    };

    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        warn!(
            "dcap-qvl backend: no Tokio runtime is available; proactive collateral refresh was skipped"
        );
        return;
    };

    runtime.spawn(async move {
        let _refresh_guard = refresh_guard;
        let Some(entry) = collateral_cache().lookup(&key).await else {
            return;
        };
        if classify_cache_entry(&entry, policy, Instant::now()) == CacheEntryState::Fresh {
            return;
        }

        collateral_cache().record_refresh_attempt(&key).await;
        match fetch_and_store(&key, policy).await {
            Ok(_) => info!(
                "event=tdx_collateral_refresh_succeeded fmspc={} ca={}",
                key.fmspc, key.ca
            ),
            Err(error) => {
                collateral_cache()
                    .record_refresh_failure(&key, &error, policy.retry_after)
                    .await;
                warn!(
                    "event=tdx_collateral_refresh_failed fmspc={} ca={} retry_after_seconds={} error={error:#}",
                    key.fmspc,
                    key.ca,
                    policy.retry_after.as_secs()
                );
                if let Some(entry) = collateral_cache().lookup(&key).await {
                    schedule_refresh_after(key, policy, entry.cached_at, policy.retry_after);
                }
            }
        }
    });
}

async fn refresh_blocking_or_use_stale(
    key: CollateralCacheKey,
    pck_chain: String,
    policy: CollateralCachePolicy,
) -> Result<QuoteCollateralV3> {
    let refresh_lock = collateral_cache().refresh_lock(&key).await;
    let _refresh_guard = refresh_lock.lock().await;

    if let Some(entry) = collateral_cache().lookup(&key).await {
        let state = classify_cache_entry(&entry, policy, Instant::now());
        if state == CacheEntryState::Fresh {
            return Ok(cached_collateral(&entry, pck_chain));
        }
        if !collateral_cache().retry_allowed(&key).await {
            return Ok(cached_collateral(&entry, pck_chain));
        }
    }

    collateral_cache().record_refresh_attempt(&key).await;
    match fetch_and_store(&key, policy).await {
        Ok(collateral) => Ok(attach_pck_chain(collateral, pck_chain)),
        Err(error) => {
            collateral_cache()
                .record_refresh_failure(&key, &error, policy.retry_after)
                .await;
            if let Some(entry) = collateral_cache().lookup(&key).await {
                warn!(
                    "event=tdx_collateral_stale_fallback fmspc={} ca={} cache_age_seconds={} error={error:#}",
                    key.fmspc,
                    key.ca,
                    entry.cached_at.elapsed().as_secs()
                );
                return Ok(cached_collateral(&entry, pck_chain));
            }
            Err(error)
        }
    }
}

async fn get_collateral(
    key: CollateralCacheKey,
    pck_chain: String,
    policy: CollateralCachePolicy,
) -> Result<QuoteCollateralV3> {
    if policy.expire_after.is_zero() {
        debug!("dcap-qvl backend: collateral cache disabled");
        let (collateral, _) =
            fetch_collateral_with_fallback(&key.pccs_base_urls, &key.fmspc, &key.ca).await?;
        return Ok(attach_pck_chain(collateral, pck_chain));
    }

    if let Some(entry) = collateral_cache().lookup(&key).await {
        match classify_cache_entry(&entry, policy, Instant::now()) {
            CacheEntryState::Fresh => {
                debug!(
                    "dcap-qvl backend: collateral cache hit fmspc={} ca={}",
                    key.fmspc, key.ca
                );
                return Ok(cached_collateral(&entry, pck_chain));
            }
            CacheEntryState::RefreshDue => {
                #[cfg(not(all(
                    target_arch = "wasm32",
                    target_vendor = "unknown",
                    target_os = "unknown"
                )))]
                {
                    trigger_background_refresh(key.clone(), policy).await;
                    return Ok(cached_collateral(&entry, pck_chain));
                }
                #[cfg(all(
                    target_arch = "wasm32",
                    target_vendor = "unknown",
                    target_os = "unknown"
                ))]
                return refresh_blocking_or_use_stale(key, pck_chain, policy).await;
            }
            CacheEntryState::CacheExpired => {}
        }
    }

    refresh_blocking_or_use_stale(key, pck_chain, policy).await
}

/// Generic dependency status consumed by both REST and gRPC AS transports.
pub async fn dependency_statuses() -> Vec<DependencyStatus> {
    collateral_cache()
        .statuses(resolve_collateral_cache_policy(), resolve_pccs_urls())
        .await
}

fn normalize_pccs_base_url(pccs_url: &str) -> String {
    pccs_url
        .trim_end_matches('/')
        .trim_end_matches("/sgx/certification/v4")
        .trim_end_matches("/tdx/certification/v4")
        .to_string()
}

fn pccs_http_client() -> Result<reqwest::Client> {
    static CLIENT: OnceLock<std::result::Result<reqwest::Client, String>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            let builder = reqwest::Client::builder();
            #[cfg(not(all(
                target_arch = "wasm32",
                target_vendor = "unknown",
                target_os = "unknown"
            )))]
            let builder = builder.timeout(Duration::from_secs(resolve_u64_setting(
                PCCS_HTTP_TIMEOUT_SECS,
                DEFAULT_PCCS_HTTP_TIMEOUT_SECS,
            )));
            builder.build().map_err(|e| e.to_string())
        })
        .as_ref()
        .cloned()
        .map_err(|e| pccs_unavailable(anyhow!("failed to build HTTP client for PCCS: {e}")))
}

pub async fn ecdsa_quote_verification(quote: &[u8]) -> Result<TcbVerificationResult> {
    let pccs_urls = resolve_pccs_urls();

    // The PCK certificate chain is embedded in the quote's certification data
    // (PCK cert type 5). Extract it and derive FMSPC / CA type for collateral.
    let pck_chain = extract_pck_chain_pem(quote)
        .context("failed to extract embedded PCK certificate chain from quote")
        .map_err(|source| VerifierError::InvalidQuote {
            field: "quote",
            source,
        })?;
    let leaf_der = first_cert_der(&pck_chain).map_err(|source| VerifierError::InvalidQuote {
        field: "quote",
        source,
    })?;
    let (fmspc, ca) =
        extract_fmspc_and_ca(&leaf_der).map_err(|source| VerifierError::InvalidQuote {
            field: "quote",
            source,
        })?;
    debug!("dcap-qvl backend: fmspc={fmspc}, ca={ca}, pccs={pccs_urls:?}");

    let cache_key = CollateralCacheKey {
        pccs_base_urls: pccs_urls,
        fmspc: fmspc.clone(),
        ca: ca.to_string(),
    };
    let cache_policy = resolve_collateral_cache_policy();
    let collateral = get_collateral(cache_key, pck_chain, cache_policy).await?;

    let real_now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let dates = CollateralDates::parse(&collateral).map_err(pccs_bad_response)?;
    let collateral_expired = real_now >= dates.earliest_expiration_date;
    debug!(
        "dcap-qvl backend: fmspc={fmspc} now={real_now} tcb_next={} expired={collateral_expired}",
        dates.tcb_info.next_update
    );

    // Match the FFI (DCAP QVL) backend, which defers these to the policy engine
    // rather than hard-failing:
    //   * allow_debug / allow_service_td  -> debug and service TDs are accepted;
    //   * allow_expired                   -> expired collateral (TCB info / QE
    //     identity past its `nextUpdate`) is non-fatal. Signatures and
    //     certificate chains are still fully verified; only the freshness check
    //     is relaxed. The real expiry is reported to the policy via
    //     `collateral_expired` below. This mirrors the FFI backend and, in
    //     particular, tolerates a PCCS that serves stale collateral for a
    //     platform's FMSPC.
    let report = QuoteVerifier::new_prod()
        .allow_debug(true)
        .allow_service_td(true)
        .allow_expired(true)
        .verify(quote, &collateral, real_now as u64)
        .map_err(|source| VerifierError::VerificationFailed {
            source: anyhow!("dcap-qvl quote verification failed: {source:#}"),
        })?;

    build_result(quote, &leaf_der, &report, &dates, collateral_expired)
}

// ---------------------------------------------------------------------------
// PCK chain / certificate parsing
// ---------------------------------------------------------------------------

/// Extract the PEM PCK certificate chain embedded in the quote's certification
/// data (PCK cert type 5). We locate it by scanning for the PEM boundaries,
/// which avoids re-parsing the whole ECDSA signature structure.
fn extract_pck_chain_pem(quote: &[u8]) -> Result<String> {
    const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
    const END: &[u8] = b"-----END CERTIFICATE-----";
    let start = find_sub(quote, BEGIN)
        .context("no PEM certificate found in quote (unsupported PCK cert type?)")?;
    let end =
        rfind_sub(quote, END).context("malformed PEM certificate chain in quote")? + END.len();
    let pem = std::str::from_utf8(&quote[start..end])
        .context("PCK certificate chain is not valid UTF-8")?;
    Ok(pem.to_string())
}

/// DER of the leaf (first) certificate in a PEM chain.
fn first_cert_der(pem_chain: &str) -> Result<Vec<u8>> {
    if let Some(pem) = Pem::iter_from_buffer(pem_chain.as_bytes()).next() {
        let pem = pem.context("failed to parse PEM block in PCK chain")?;
        return Ok(pem.contents);
    }
    bail!("PCK certificate chain contains no certificate")
}

/// Extract FMSPC (hex, upper-case) and CA type ("platform"/"processor") from
/// the leaf PCK certificate.
fn extract_fmspc_and_ca(leaf_der: &[u8]) -> Result<(String, &'static str)> {
    let (_, cert) =
        X509Certificate::from_der(leaf_der).context("failed to parse PCK leaf certificate")?;

    let sgx_ext = sgx_extension(&cert)?;
    let entries = parse_der_seq_of_pairs(sgx_ext).context("failed to parse Intel SGX extension")?;
    let fmspc_val = entries
        .iter()
        .find(|(oid, _)| oid == &arcs_str(OID_SGX_FMSPC))
        .map(|(_, v)| v)
        .context("SGX extension is missing FMSPC")?;
    let fmspc_bytes = der_octet_string(fmspc_val).context("FMSPC is not an OCTET STRING")?;
    let fmspc = hex::encode_upper(fmspc_bytes);

    // CA type is derived from the issuer common name.
    let issuer = cert.issuer().to_string();
    let ca = if issuer.contains("Platform") {
        "platform"
    } else {
        // "Processor" and unexpected issuers both follow Intel/Phala's
        // processor default.
        "processor"
    };

    Ok((fmspc, ca))
}

/// Extract the platform SGX TCB: 16 component SVNs and the PCE SVN, from the
/// PCK certificate's SGX extension. Needed to reproduce TCB-level matching.
fn extract_platform_sgx_tcb(leaf_der: &[u8]) -> Result<([u8; 16], u16)> {
    let (_, cert) =
        X509Certificate::from_der(leaf_der).context("failed to parse PCK leaf certificate")?;
    let sgx_ext = sgx_extension(&cert)?;
    let entries = parse_der_seq_of_pairs(sgx_ext)?;

    let tcb_val = entries
        .iter()
        .find(|(oid, _)| oid == &arcs_str(OID_SGX_TCB))
        .map(|(_, v)| v)
        .context("SGX extension is missing the TCB entry")?;
    // The TCB value is itself a SEQUENCE of (OID, value) pairs.
    let tcb_entries = parse_der_seq_of_pairs(tcb_val).context("failed to parse SGX TCB entry")?;

    let mut comps = [0u8; 16];
    for (n, comp) in comps.iter_mut().enumerate() {
        // Component OIDs are 1.2.840.113741.1.13.1.2.<n+1> for n in 0..16.
        let mut oid = OID_SGX_TCB.to_vec();
        oid.push((n + 1) as u64);
        let v = tcb_entries
            .iter()
            .find(|(o, _)| o == &arcs_str(&oid))
            .map(|(_, v)| v)
            .with_context(|| format!("SGX TCB component {} missing", n + 1))?;
        *comp = der_integer_u64(v)? as u8;
    }
    let pcesvn_val = tcb_entries
        .iter()
        .find(|(o, _)| o == &arcs_str(OID_SGX_PCESVN))
        .map(|(_, v)| v)
        .context("SGX TCB PCESVN missing")?;
    let pcesvn = der_integer_u64(pcesvn_val)? as u16;

    Ok((comps, pcesvn))
}

fn sgx_extension<'a>(cert: &'a X509Certificate<'a>) -> Result<&'a [u8]> {
    cert.extensions()
        .iter()
        .find(|e| e.oid.to_id_string() == arcs_str(OID_SGX_EXTENSION))
        .map(|e| e.value)
        .context("PCK certificate is missing the Intel SGX extension")
}

// ---------------------------------------------------------------------------
// Collateral fetch (PCCS)
// ---------------------------------------------------------------------------

async fn fetch_collateral_with_fallback(
    pccs_base_urls: &[String],
    fmspc: &str,
    ca: &str,
) -> Result<(QuoteCollateralV3, String)> {
    let mut last_error = None;
    for (index, pccs_base_url) in pccs_base_urls.iter().enumerate() {
        match fetch_collateral(pccs_base_url, fmspc, ca).await {
            Ok(collateral) => {
                if index > 0 {
                    info!(
                        "event=tdx_pccs_failover_succeeded fmspc={fmspc} ca={ca} selected_pccs={pccs_base_url} fallback_index={index}"
                    );
                }
                return Ok((collateral, pccs_base_url.clone()));
            }
            Err(error) => {
                warn!(
                    "event=tdx_pccs_endpoint_failed fmspc={fmspc} ca={ca} pccs={pccs_base_url} fallback_index={index} error={error:#}"
                );
                last_error = Some(error);
            }
        }
    }

    match last_error {
        Some(error) => Err(error.context(format!(
            "all {} configured PCCS endpoints failed",
            pccs_base_urls.len()
        ))),
        None => Err(pccs_unavailable(anyhow!("no PCCS endpoint is configured"))),
    }
}

async fn fetch_collateral(pccs_base_url: &str, fmspc: &str, ca: &str) -> Result<QuoteCollateralV3> {
    let client = pccs_http_client()?;
    debug!(
        "dcap-qvl backend: fetching collateral from PCCS fmspc={fmspc} ca={ca} pccs={pccs_base_url}"
    );

    // PCK CRL (always under the sgx path).
    let pckcrl_url = format!("{pccs_base_url}/sgx/certification/v4/pckcrl?ca={ca}&encoding=der");
    let (pck_crl_issuer_chain, pck_crl) =
        get_with_header(&client, &pckcrl_url, "SGX-PCK-CRL-Issuer-Chain").await?;

    // TCB info (tdx path for TDX).
    let tcb_url = format!("{pccs_base_url}/tdx/certification/v4/tcb?fmspc={fmspc}");
    let (tcb_info_issuer_chain, tcb_body) =
        get_with_header(&client, &tcb_url, "TCB-Info-Issuer-Chain").await?;
    let tcb_json: serde_json::Value = serde_json::from_slice(&tcb_body)
        .context("TCB info is not valid JSON")
        .map_err(pccs_bad_response)?;
    let tcb_info = tcb_json
        .get("tcbInfo")
        .context("TCB info response missing tcbInfo")
        .map_err(pccs_bad_response)?
        .to_string();
    let tcb_info_signature = hex::decode(
        tcb_json
            .get("signature")
            .and_then(|v| v.as_str())
            .context("TCB info response missing signature")
            .map_err(pccs_bad_response)?,
    )
    .context("TCB info signature is not valid hex")
    .map_err(pccs_bad_response)?;

    // QE identity (tdx path for TDX).
    let qe_url = format!("{pccs_base_url}/tdx/certification/v4/qe/identity?update=standard");
    let (qe_identity_issuer_chain, qe_body) =
        get_with_header(&client, &qe_url, "SGX-Enclave-Identity-Issuer-Chain").await?;
    let qe_json: serde_json::Value = serde_json::from_slice(&qe_body)
        .context("QE identity is not valid JSON")
        .map_err(pccs_bad_response)?;
    let qe_identity = qe_json
        .get("enclaveIdentity")
        .context("QE identity response missing enclaveIdentity")
        .map_err(pccs_bad_response)?
        .to_string();
    let qe_identity_signature = hex::decode(
        qe_json
            .get("signature")
            .and_then(|v| v.as_str())
            .context("QE identity response missing signature")
            .map_err(pccs_bad_response)?,
    )
    .context("QE identity signature is not valid hex")
    .map_err(pccs_bad_response)?;

    // Root CA CRL. PCCS serves it hex-encoded under the sgx path.
    let rootcacrl_url = format!("{pccs_base_url}/sgx/certification/v4/rootcacrl");
    let root_ca_crl_raw = client
        .get(&rootcacrl_url)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .context("failed to fetch root CA CRL")
        .map_err(pccs_unavailable)?
        .bytes()
        .await
        .context("failed to read root CA CRL body")
        .map_err(pccs_unavailable)?;
    let root_ca_crl = match std::str::from_utf8(&root_ca_crl_raw)
        .ok()
        .and_then(|s| hex::decode(s.trim()).ok())
    {
        Some(der) => der,
        None => root_ca_crl_raw.to_vec(),
    };

    Ok(QuoteCollateralV3 {
        pck_crl_issuer_chain,
        root_ca_crl,
        pck_crl,
        tcb_info_issuer_chain,
        tcb_info,
        tcb_info_signature,
        qe_identity_issuer_chain,
        qe_identity,
        qe_identity_signature,
        pck_certificate_chain: None,
    })
}

/// GET a URL, returning (url-decoded issuer-chain header value, body bytes).
async fn get_with_header(
    client: &reqwest::Client,
    url: &str,
    header: &str,
) -> Result<(String, Vec<u8>)> {
    let resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("failed to GET {url}"))
        .map_err(pccs_unavailable)?
        .error_for_status()
        .with_context(|| format!("PCCS returned an error for {url}"))
        .map_err(pccs_unavailable)?;
    let hdr = resp
        .headers()
        .get(header)
        .with_context(|| format!("PCCS response for {url} missing header {header}"))
        .map_err(pccs_bad_response)?
        .to_str()
        .context("issuer-chain header is not valid ASCII")
        .map_err(pccs_bad_response)?
        .to_string();
    let hdr = urlencoding::decode(&hdr)
        .context("failed to url-decode issuer-chain header")
        .map_err(pccs_bad_response)?
        .into_owned();
    let body = resp
        .bytes()
        .await
        .with_context(|| format!("failed to read body of {url}"))
        .map_err(pccs_unavailable)?
        .to_vec();
    Ok((hdr, body))
}

// ---------------------------------------------------------------------------
// Result mapping (including TCB-level matching for tcb_level_date_tag)
// ---------------------------------------------------------------------------

/// Collateral issue/expiration dates (union of TCB info and QE identity),
/// parsed once so they can be used both to clamp the verification timestamp and
/// to populate the result.
struct CollateralDates {
    tcb_info: TcbInfo,
    earliest_issue_date: i64,
    latest_issue_date: i64,
    earliest_expiration_date: i64,
}

impl CollateralDates {
    fn parse(collateral: &QuoteCollateralV3) -> Result<Self> {
        let tcb_info: TcbInfo =
            serde_json::from_str(&collateral.tcb_info).context("failed to parse tcb_info JSON")?;
        let qe_identity: serde_json::Value = serde_json::from_str(&collateral.qe_identity)
            .context("failed to parse qe_identity JSON")?;

        let tcb_issue = parse_iso8601(&tcb_info.issue_date)?;
        let tcb_next = parse_iso8601(&tcb_info.next_update)?;
        let qe_issue = qe_identity
            .get("issueDate")
            .and_then(|v| v.as_str())
            .map(parse_iso8601)
            .transpose()?;
        let qe_next = qe_identity
            .get("nextUpdate")
            .and_then(|v| v.as_str())
            .map(parse_iso8601)
            .transpose()?;

        Ok(Self {
            earliest_issue_date: qe_issue.map_or(tcb_issue, |q| tcb_issue.min(q)),
            latest_issue_date: qe_issue.map_or(tcb_issue, |q| tcb_issue.max(q)),
            earliest_expiration_date: qe_next.map_or(tcb_next, |q| tcb_next.min(q)),
            tcb_info,
        })
    }
}

fn build_result(
    quote: &[u8],
    leaf_der: &[u8],
    report: &VerifiedReport,
    dates: &CollateralDates,
    collateral_expired: bool,
) -> Result<TcbVerificationResult> {
    // Reproduce Intel QVL TCB-level matching to recover the matched level's
    // tcb_date (`tcb_level_date_tag`).
    let tcb_level_date_tag = match matched_tcb_level(quote, leaf_der, &dates.tcb_info) {
        Ok(level) => parse_iso8601(&level.tcb_date)?,
        Err(e) => {
            debug!("dcap-qvl backend: could not resolve matched TCB level: {e:#}");
            0
        }
    };

    Ok(TcbVerificationResult {
        tcb_status: report.status.clone(),
        tcb_status_code: status_to_code(&report.status),
        collateral_expired,
        earliest_issue_date: dates.earliest_issue_date,
        latest_issue_date: dates.latest_issue_date,
        earliest_expiration_date: dates.earliest_expiration_date,
        tcb_level_date_tag,
        tcb_eval_ref_num: dates.tcb_info.tcb_evaluation_data_number,
        advisory_ids: report.advisory_ids.join(","),
        tee_type: TEE_TYPE_TDX,
    })
}

/// Find the TCB level the platform is at, mirroring Intel QVL: canonically
/// sort the levels (highest TCB first) and return the first level the platform
/// satisfies component-wise.
fn matched_tcb_level<'a>(
    quote: &[u8],
    leaf_der: &[u8],
    tcb_info: &'a TcbInfo,
) -> Result<&'a TcbLevel> {
    let (sgx_comps, pcesvn) = extract_platform_sgx_tcb(leaf_der)?;
    let is_tdx = tcb_info.version >= 3 && tcb_info.id == "TDX";

    // Platform TDX TEE TCB SVN from the TD report.
    let tdx_svn: [u8; 16] = if is_tdx {
        let parsed = parse_tdx_quote(quote)?;
        parsed
            .tcb_svn()
            .try_into()
            .map_err(|_| anyhow!("unexpected TDX TEE TCB SVN length"))?
    } else {
        [0u8; 16]
    };

    // Canonical order: SGX components desc, then PCE SVN desc, then TDX
    // components desc (matches Intel QVL / dcap-qvl `canonicalize_tcb_levels`).
    let mut levels: Vec<&TcbLevel> = tcb_info.tcb_levels.iter().collect();
    levels.sort_by(|a, b| {
        svns(&b.tcb.sgx_components)
            .cmp(&svns(&a.tcb.sgx_components))
            .then(b.tcb.pce_svn.cmp(&a.tcb.pce_svn))
            .then(svns(&b.tcb.tdx_components).cmp(&svns(&a.tcb.tdx_components)))
    });

    for level in levels {
        if platform_meets(level, &sgx_comps, pcesvn, &tdx_svn, is_tdx) {
            return Ok(level);
        }
    }
    bail!("no TCB level matched the platform")
}

fn platform_meets(
    level: &TcbLevel,
    sgx_comps: &[u8; 16],
    pcesvn: u16,
    tdx_svn: &[u8; 16],
    is_tdx: bool,
) -> bool {
    for (i, c) in level.tcb.sgx_components.iter().enumerate() {
        if sgx_comps.get(i).copied().unwrap_or(0) < c.svn {
            return false;
        }
    }
    if pcesvn < level.tcb.pce_svn {
        return false;
    }
    if is_tdx {
        for (i, c) in level.tcb.tdx_components.iter().enumerate() {
            if tdx_svn.get(i).copied().unwrap_or(0) < c.svn {
                return false;
            }
        }
    }
    true
}

fn svns(comps: &[TcbComponents]) -> Vec<u8> {
    comps.iter().map(|c| c.svn).collect()
}

/// Map a TCB status string to the numeric code the FFI backend reports in
/// `TcbVerificationResult::tcb_status_code` (the `sgx_ql_qv_result_t` values).
fn status_to_code(status: &str) -> u32 {
    match status {
        "UpToDate" => 0x0000_0000,
        "ConfigurationNeeded" => 0x0000_A001,
        "OutOfDate" => 0x0000_A002,
        "OutOfDateConfigurationNeeded" => 0x0000_A003,
        "InvalidSignature" => 0x0000_A004,
        "Revoked" => 0x0000_A005,
        "Unspecified" => 0x0000_A006,
        "SWHardeningNeeded" => 0x0000_A007,
        "ConfigurationAndSWHardeningNeeded" => 0x0000_A008,
        _ => 0x0000_A006, // Unspecified
    }
}

// ---------------------------------------------------------------------------
// small DER / date helpers
// ---------------------------------------------------------------------------

fn parse_iso8601(s: &str) -> Result<i64> {
    // PCS timestamps are RFC 3339, e.g. "2024-03-13T00:00:00Z".
    let dt = chrono::DateTime::parse_from_rfc3339(s)
        .or_else(|_| chrono::DateTime::parse_from_rfc3339(&format!("{s}Z")))
        .with_context(|| format!("invalid timestamp: {s}"))?;
    Ok(dt.timestamp())
}

/// Dotted-decimal string for an OID given as numeric arcs.
fn arcs_str(arcs: &[u64]) -> String {
    arcs.iter()
        .map(|a| a.to_string())
        .collect::<Vec<_>>()
        .join(".")
}

/// Parse a DER `SEQUENCE OF SEQUENCE { OID, value }` into (dotted-OID, raw value
/// DER) pairs. `value` is the raw DER of whatever followed the OID.
fn parse_der_seq_of_pairs(der: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    let (_, top) = Any::from_der(der).map_err(|e| anyhow!("DER parse error: {e}"))?;
    let mut content = top.data;
    let mut out = Vec::new();
    while !content.is_empty() {
        let (rest, entry) = Any::from_der(content).map_err(|e| anyhow!("DER parse error: {e}"))?;
        let (after_oid, oid) =
            Oid::from_der(entry.data).map_err(|e| anyhow!("DER OID parse error: {e}"))?;
        out.push((oid.to_id_string(), after_oid.to_vec()));
        content = rest;
    }
    Ok(out)
}

/// Interpret a raw DER value as an OCTET STRING and return its bytes.
fn der_octet_string(der: &[u8]) -> Result<Vec<u8>> {
    let (_, any) = Any::from_der(der).map_err(|e| anyhow!("DER parse error: {e}"))?;
    Ok(any.data.to_vec())
}

/// Interpret a raw DER value as an INTEGER and return it as u64.
fn der_integer_u64(der: &[u8]) -> Result<u64> {
    let (_, any) = Any::from_der(der).map_err(|e| anyhow!("DER parse error: {e}"))?;
    let mut v: u64 = 0;
    for &b in any.data {
        v = (v << 8) | b as u64;
    }
    Ok(v)
}

fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn rfind_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).rposition(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::{
        cached_collateral, classify_cache_entry, collateral_cache, fetch_collateral_with_fallback,
        normalize_pccs_base_url, parse_pccs_urls, parse_qcnl_pccs_url, parse_qcnl_u64,
        refresh_blocking_or_use_stale, schedule_refresh_after, unix_now, CacheEntryState,
        CachedCollateral, CollateralCache, CollateralCacheKey, CollateralCachePolicy,
        QuoteCollateralV3, COLLATERAL_CACHE_EXPIRE_HOURS, COLLATERAL_CACHE_REFRESH_HOURS,
    };
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn cache_key() -> CollateralCacheKey {
        CollateralCacheKey {
            pccs_base_urls: vec!["https://pccs.example.com".into()],
            fmspc: "00906ED50000".into(),
            ca: "platform".into(),
        }
    }

    fn collateral() -> QuoteCollateralV3 {
        QuoteCollateralV3 {
            pck_crl_issuer_chain: "pck-crl-chain".into(),
            root_ca_crl: vec![1],
            pck_crl: vec![2],
            tcb_info_issuer_chain: "tcb-chain".into(),
            tcb_info: "{}".into(),
            tcb_info_signature: vec![3],
            qe_identity_issuer_chain: "qe-chain".into(),
            qe_identity: "{}".into(),
            qe_identity_signature: vec![4],
            pck_certificate_chain: None,
        }
    }

    fn policy() -> CollateralCachePolicy {
        CollateralCachePolicy::from_durations(
            Duration::from_secs(10),
            Duration::from_secs(20),
            Duration::from_secs(30),
        )
    }

    fn cached(age: Duration) -> CachedCollateral {
        let now = Instant::now();
        CachedCollateral {
            collateral: collateral(),
            cached_at: now - age,
            cached_at_unix: unix_now().saturating_sub(age.as_secs()),
            last_successful_pccs: "https://pccs.example.com".into(),
            last_refresh_attempt_at: Some(unix_now()),
            last_refresh_error: None,
            next_refresh_allowed_at: now,
        }
    }

    #[test]
    fn parse_qcnl_ini_form() {
        let conf = "# comment\nPCCS_URL=https://sgx-dcap-server.cn-hangzhou.aliyuncs.com/sgx/certification/v4/\nUSE_SECURE_CERT=false\n";
        assert_eq!(
            parse_qcnl_pccs_url(conf).as_deref(),
            Some("https://sgx-dcap-server.cn-hangzhou.aliyuncs.com/sgx/certification/v4/")
        );
    }

    #[test]
    fn parse_qcnl_json_form() {
        let conf = "{\n  // Intel default style\n  \"pccs_url\": \"https://pccs.example.com/sgx/certification/v4/\",\n  \"use_secure_cert\": true\n}\n";
        assert_eq!(
            parse_qcnl_pccs_url(conf).as_deref(),
            Some("https://pccs.example.com/sgx/certification/v4/")
        );
    }

    #[test]
    fn parse_qcnl_missing() {
        assert_eq!(parse_qcnl_pccs_url("USE_SECURE_CERT=false\n"), None);
    }

    #[test]
    fn parse_qcnl_cache_expiry() {
        assert_eq!(
            parse_qcnl_u64(
                "VERIFY_COLLATERAL_CACHE_EXPIRE_HOURS=168\n",
                COLLATERAL_CACHE_EXPIRE_HOURS
            ),
            Some(168)
        );
        assert_eq!(
            parse_qcnl_u64(
                "{\n  \"verify_collateral_cache_expire_hours\": 0\n}\n",
                COLLATERAL_CACHE_EXPIRE_HOURS
            ),
            Some(0)
        );
        assert_eq!(
            parse_qcnl_u64(
                "VERIFY_COLLATERAL_CACHE_REFRESH_HOURS=72\n",
                COLLATERAL_CACHE_REFRESH_HOURS
            ),
            Some(72)
        );
    }

    #[test]
    fn normalize_pccs_urls() {
        assert_eq!(
            normalize_pccs_base_url("https://pccs.example.com/sgx/certification/v4/"),
            "https://pccs.example.com"
        );
        assert_eq!(
            normalize_pccs_base_url("https://pccs.example.com/tdx/certification/v4/"),
            "https://pccs.example.com"
        );
        assert_eq!(
            parse_pccs_urls(
                "https://primary.example/sgx/certification/v4/, \
                 https://backup.example/tdx/certification/v4/,https://primary.example"
            ),
            vec![
                "https://primary.example".to_string(),
                "https://backup.example".to_string()
            ]
        );
    }

    #[test]
    fn refresh_interval_is_clamped_below_cache_expiry() {
        let policy = CollateralCachePolicy::from_durations(
            Duration::from_secs(20),
            Duration::from_secs(10),
            Duration::from_secs(1),
        );
        assert_eq!(policy.refresh_after, Duration::from_secs(5));
        assert_eq!(policy.expire_after, Duration::from_secs(10));
    }

    #[test]
    fn cache_state_depends_only_on_local_cache_age() {
        let now = Instant::now();
        assert_eq!(
            classify_cache_entry(&cached(Duration::from_secs(5)), policy(), now),
            CacheEntryState::Fresh
        );
        assert_eq!(
            classify_cache_entry(&cached(Duration::from_secs(15)), policy(), now),
            CacheEntryState::RefreshDue
        );
        assert_eq!(
            classify_cache_entry(&cached(Duration::from_secs(25)), policy(), now),
            CacheEntryState::CacheExpired
        );
    }

    #[tokio::test]
    async fn cache_does_not_share_quote_local_pck_chain() {
        let cache = CollateralCache::default();
        let mut fetched = collateral();
        fetched.pck_certificate_chain = Some("must-not-be-cached".into());
        cache
            .store_success(cache_key(), fetched, "https://pccs.example.com".into())
            .await;

        let entry = cache.lookup(&cache_key()).await.unwrap();
        assert!(entry.collateral.pck_certificate_chain.is_none());
        let first = cached_collateral(&entry, "pck-chain-1".into());
        let second = cached_collateral(&entry, "pck-chain-2".into());
        assert_eq!(first.pck_certificate_chain.as_deref(), Some("pck-chain-1"));
        assert_eq!(second.pck_certificate_chain.as_deref(), Some("pck-chain-2"));
    }

    #[tokio::test]
    async fn refresh_locks_are_single_flight_per_cache_key() {
        let cache = CollateralCache::default();
        let same_a = cache.refresh_lock(&cache_key()).await;
        let same_b = cache.refresh_lock(&cache_key()).await;
        assert!(Arc::ptr_eq(&same_a, &same_b));

        let mut other = cache_key();
        other.fmspc = "AABBCCDDEEFF".into();
        let other = cache.refresh_lock(&other).await;
        assert!(!Arc::ptr_eq(&same_a, &other));
    }

    #[tokio::test]
    async fn refresh_failure_preserves_stale_collateral_and_is_reported() {
        let cache = CollateralCache::default();
        let key = cache_key();
        cache
            .entries
            .lock()
            .await
            .insert(key.clone(), cached(Duration::from_secs(15)));
        cache
            .record_refresh_failure(
                &key,
                &anyhow::anyhow!("temporary PCCS error"),
                Duration::from_secs(60),
            )
            .await;

        let entry = cache.lookup(&key).await.unwrap();
        assert!(entry
            .last_refresh_error
            .as_deref()
            .unwrap()
            .contains("temporary PCCS error"));
        assert!(!cache.retry_allowed(&key).await);

        let statuses = cache
            .statuses(policy(), vec!["https://pccs.example.com".into()])
            .await;
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].status, "refresh_retrying");
        assert!(statuses[0].details.contains_key("last_refresh_error"));
        assert!(!statuses[0].details.contains_key("collateral_expires_at"));
        assert!(!statuses[0]
            .details
            .contains_key("collateral_valid_for_seconds"));
    }

    #[tokio::test]
    async fn status_reports_refresh_due_while_refresh_is_running_and_degraded_after_ttl() {
        let cache = CollateralCache::default();
        let key = cache_key();
        cache
            .entries
            .lock()
            .await
            .insert(key.clone(), cached(Duration::from_secs(15)));

        let refresh_lock = cache.refresh_lock(&key).await;
        let refresh_guard = refresh_lock.lock().await;
        let statuses = cache
            .statuses(policy(), vec!["https://pccs.example.com".into()])
            .await;
        assert_eq!(statuses[0].status, "refresh_due");
        assert_eq!(
            statuses[0].details.get("refresh_in_progress"),
            Some(&serde_json::json!(true))
        );
        drop(refresh_guard);

        cache
            .entries
            .lock()
            .await
            .insert(key, cached(Duration::from_secs(25)));
        let statuses = cache
            .statuses(policy(), vec!["https://pccs.example.com".into()])
            .await;
        assert_eq!(statuses[0].status, "degraded");
    }

    #[tokio::test]
    async fn proactive_refresh_timer_runs_without_a_request() {
        let key = CollateralCacheKey {
            pccs_base_urls: vec!["http://127.0.0.1:1".into()],
            fmspc: "TIMER00000001".into(),
            ca: "platform".into(),
        };
        let entry = cached(Duration::ZERO);
        let cached_at = entry.cached_at;
        collateral_cache()
            .entries
            .lock()
            .await
            .insert(key.clone(), entry);
        let policy = CollateralCachePolicy::from_durations(
            Duration::from_millis(10),
            Duration::from_secs(60),
            Duration::from_secs(3_600),
        );

        schedule_refresh_after(key.clone(), policy, cached_at, policy.refresh_after);
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if collateral_cache()
                    .lookup(&key)
                    .await
                    .and_then(|entry| entry.last_refresh_error)
                    .is_some()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the proactive refresh timer did not run");
    }

    #[tokio::test]
    async fn hard_expired_cache_falls_back_without_parsing_collateral_validity() {
        let key = CollateralCacheKey {
            pccs_base_urls: vec!["http://127.0.0.1:1".into()],
            fmspc: "STALE0000001".into(),
            ca: "platform".into(),
        };
        let mut entry = cached(Duration::from_secs(25));
        entry.collateral.tcb_info =
            r#"{"issueDate":"2019-01-01T00:00:00Z","nextUpdate":"2020-01-01T00:00:00Z"}"#.into();
        entry.collateral.qe_identity =
            r#"{"issueDate":"2019-01-01T00:00:00Z","nextUpdate":"2020-01-01T00:00:00Z"}"#.into();
        collateral_cache()
            .entries
            .lock()
            .await
            .insert(key.clone(), entry);

        let result =
            refresh_blocking_or_use_stale(key.clone(), "current-pck-chain".into(), policy())
                .await
                .unwrap();
        assert_eq!(
            result.pck_certificate_chain.as_deref(),
            Some("current-pck-chain")
        );
        assert!(collateral_cache()
            .lookup(&key)
            .await
            .unwrap()
            .last_refresh_error
            .is_some());
    }

    #[tokio::test]
    async fn pccs_failure_falls_back_to_the_next_endpoint() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backup = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            for _ in 0..4 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = vec![0; 4_096];
                let size = stream.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..size]);
                let path = request.split_whitespace().nth(1).unwrap();
                let (extra_header, body) = if path.contains("pckcrl") {
                    ("SGX-PCK-CRL-Issuer-Chain: chain\r\n", "crl")
                } else if path.contains("/tcb?") {
                    (
                        "TCB-Info-Issuer-Chain: chain\r\n",
                        r#"{"tcbInfo":{},"signature":"00"}"#,
                    )
                } else if path.contains("qe/identity") {
                    (
                        "SGX-Enclave-Identity-Issuer-Chain: chain\r\n",
                        r#"{"enclaveIdentity":{},"signature":"00"}"#,
                    )
                } else {
                    ("", "00")
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n{}\r\n{}",
                    body.len(),
                    extra_header,
                    body
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let (collateral, selected) = fetch_collateral_with_fallback(
            &["http://127.0.0.1:1".into(), backup.clone()],
            "00906ED50000",
            "platform",
        )
        .await
        .unwrap();
        assert_eq!(selected, backup);
        assert_eq!(collateral.pck_crl, b"crl");
        assert_eq!(collateral.root_ca_crl, vec![0]);
        server.await.unwrap();
    }

    #[test]
    #[serial_test::serial]
    fn pccs_override_wins() {
        // The injected override is returned in preference to the default/env
        // resolution. (`PCCS_URL` env is deliberately not set here, to avoid
        // polluting other tests' env state; the override wins regardless.)
        super::set_pccs_url(Some("https://my-pccs.example".into()));
        assert_eq!(
            super::resolve_pccs_urls(),
            vec!["https://my-pccs.example".to_string()]
        );

        // Clearing the override restores default resolution, and confirms the
        // shared global was reset so it cannot leak into other tests. The
        // `#[serial_test::serial]` attribute above serializes this test against
        // any other test that touches the same global PCCS override.
        super::set_pccs_url(None);
        assert_ne!(
            super::resolve_pccs_urls(),
            vec!["https://my-pccs.example".to_string()]
        );
    }
}
