# On-demand RVPS queries from attestation policies

## Motivation

The original Anolis attestation flow loads every non-expired reference value
from RVPS before evaluating a policy and exposes the resulting map as
`data.reference`. Confidential Containers (CoCo) instead exposes
`query_reference_value(key)` to Rego and queries RVPS only when a policy needs a
value.

Anolis adopts the CoCo query model without removing its existing token brokers,
reference-value formats, expiry checks, or compatibility with deployed clients
and policies.

## Compatibility contract

The existing `QueryReferenceValue` RPC is extended rather than replaced:

- an empty `reference_value_id` requests the legacy JSON map;
- a non-empty `reference_value_id` requests one JSON value;
- a missing or expired keyed value is represented by an empty response;
- legacy hash-list values are returned as JSON arrays of strings;
- RVPS may also store and return arbitrary JSON policy values.

Adding field 1 to the previously empty protobuf request is wire compatible with
old clients: their empty request continues to select the bulk operation. The
response remains a string in field 1, which is also compatible with CoCo's
optional string response on the wire.

The AS supports both policy styles:

```rego
# New, preferred style
allowed_svn := query_reference_value("svn")

# Existing custom policies remain valid
allowed_svn := data.reference.svn
```

The bulk map is fetched lazily only when a policy actually refers to
`data.reference`. New policies therefore avoid an O(number of all reference
values) query.

## AS design

Each attestation evaluation creates one shared reference-value resolver. The
resolver:

1. queries RVPS by key on demand;
2. caches values and misses for the lifetime of the evaluation;
3. lazily caches the legacy bulk map if an old policy requires it;
4. enforces a bounded query timeout in the policy extension.

All Anolis token brokers (EAR, Simple and OIDC) receive the same resolver. Rego
evaluation runs on Tokio's blocking pool because Regorus is synchronous. The
`query_reference_value` Regorus extension bridges back to the asynchronous RVPS
client through the current runtime handle.

## RVPS data and security semantics

`ReferenceValue` keeps its existing `hash-value` representation and gains an
optional JSON policy value. Existing persisted data therefore deserializes
unchanged. Hash-list registration and merge semantics are preserved; a
non-hash JSON value is replaced atomically.

Both bulk and keyed queries filter expired records. This deliberately retains
Anolis' fail-closed expiry behavior, including for the new CoCo-style path.
Query errors and timeouts fail policy evaluation, while a genuinely missing
key evaluates to Rego `null` so policy authors can choose fail-open or
fail-closed behavior explicitly.

## Delivery and validation order

The change is split into reviewable commits in dependency order:

1. this design and compatibility contract;
2. compatible keyed RVPS protocol, storage model and clients;
3. shared per-attestation AS resolver and cache;
4. Regorus extension and lazy legacy-policy compatibility;
5. bundled policy and operator-documentation migration;
6. built-in and remote-RVPS end-to-end coverage.

Validation covers Rust 1.76, no-default-feature library builds, unit tests,
protobuf compatibility, all three token brokers, built-in RVPS, standalone
gRPC RVPS, missing/expired/error cases, and a real TEE attestation when an
environment is available.
