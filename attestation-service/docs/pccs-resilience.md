# PCCS Configuration and TDX Collateral Resilience

This document describes PCCS selection, failover, and collateral caching for
the pure-Rust TDX verifier selected by the `tdx-dcap-rust` or
`all-verifier-rust` feature. The Intel DCAP FFI verifier continues to use the
quote-provider/QCNL implementation and is not affected by these settings.

## PCCS endpoints

Configure an ordered fallback list with `PCCS_URLS`:

```shell
export PCCS_URLS="http://sgx-dcap-server-vpc.${region_id}.aliyuncs.com,https://sgx-dcap-server.cn-hangzhou.aliyuncs.com"
export PCCS_HTTP_TIMEOUT_SECS=5
```

Each value may be either a host base URL or a URL ending in
`/sgx/certification/v4` or `/tdx/certification/v4`. AS normalizes the suffix,
removes duplicates, and tries the endpoints in the configured order. A failure
while fetching any item in a collateral set causes AS to retry the complete set
against the next PCCS. `PCCS_HTTP_TIMEOUT_SECS` is the timeout for each PCCS
HTTP request.

PCCS configuration is resolved in this order:

1. `verifier::tdx::set_pccs_urls` when the verifier is embedded as a library.
2. The comma-separated `PCCS_URLS` environment variable.
3. The backward-compatible single `PCCS_URL` environment variable.
4. `pccs_url` or `PCCS_URL` in `/etc/sgx_default_qcnl.conf`.
5. The built-in default PCCS.

Environment variables therefore override the QCNL file. Restart AS after
changing its environment or QCNL configuration.

## Collateral cache policy

The cache is local to each AS process and is keyed by the ordered PCCS list,
FMSPC, and CA type. The PCK certificate chain embedded in a quote is not shared
through the cache.

| Variable | Default | Meaning |
|----------|---------|---------|
| `VERIFY_COLLATERAL_CACHE_REFRESH_HOURS` | `72` | Schedule an asynchronous refresh after a successful cache fill. |
| `VERIFY_COLLATERAL_CACHE_EXPIRE_HOURS` | `168` | Mark the local cache entry stale after this age. `0` disables caching. |
| `VERIFY_COLLATERAL_CACHE_REFRESH_RETRY_SECS` | `3600` | Minimum delay before another refresh after PCCS failure. |

These numeric settings are read from the environment first, then from
`/etc/sgx_default_qcnl.conf`. If the refresh age is not shorter than the cache
expiry, AS clamps it to half of the expiry and emits a warning.

The three time boundaries have different purposes:

1. **Refresh age**: a native AS schedules a background timer as soon as it
   stores collateral. When the timer fires, verification continues with the
   current cache while one refresh runs for that cache key. A request that
   notices an overdue refresh also triggers it as a safety net.
2. **Cache expiry**: after this local TTL, the next request attempts a blocking
   refresh. If every PCCS is unavailable, AS falls back to the cached value.
3. **Collateral validity**: stale fallback is allowed only while the earliest
   signed TCB Info or QE Identity `nextUpdate` is still in the future. Intel
   collateral is commonly issued with a validity window of about 30 days, but
   AS uses the actual signed dates instead of assuming a fixed 30-day value.

Refreshes for the same key are coalesced. A slow PCCS for one FMSPC does not
block refreshes for other cache keys. Stable log event names are available for
alerting:

- `tdx_pccs_endpoint_failed`
- `tdx_pccs_failover_succeeded`
- `tdx_collateral_refresh_succeeded`
- `tdx_collateral_refresh_failed`
- `tdx_collateral_stale_fallback`

## Status API

AS exposes a generic dependency status model so other verifier dependencies can
reuse it in the future. Reading status never contacts PCCS.

For REST AS:

```shell
curl http://127.0.0.1:8080/status
```

For gRPC AS:

```shell
grpcurl \
  -plaintext \
  -import-path protos \
  -proto attestation.proto \
  -d '{}' 127.0.0.1:50004 \
  attestation.AttestationService/GetAttestationServiceStatus
```

Each TDX cache entry reports a stable `kind` of `tdx-collateral-cache` and one
of these states:

| Dependency state | Meaning |
|------------------|---------|
| `not_initialized` | This AS process has not verified TDX evidence yet. |
| `ready` | Cache age is below the proactive refresh threshold. |
| `refresh_due` | Collateral is usable and refresh is due or running. |
| `degraded` | Refresh failed or local cache TTL elapsed, but signed collateral remains valid. |
| `unhealthy` | Signed collateral has passed `nextUpdate`; PCCS recovery is required. |

Useful detail fields include `pccs_urls`, `last_successful_pccs`,
`last_refresh_attempt_at`, `last_refresh_error`, `refresh_in_progress`,
`cache_age_seconds`, `collateral_expires_at`, and
`collateral_valid_for_seconds`. Timestamp fields are Unix seconds.

For alerting, trigger an early operational warning when any dependency becomes
`degraded` or `last_refresh_error` appears. Trigger a page when it becomes
`unhealthy` or when `collateral_valid_for_seconds` approaches the team's repair
SLO. With the defaults, a failed refresh is visible around day 3, the local
cache TTL is day 7, and stale fallback remains bounded by the collateral's
signed validity.
