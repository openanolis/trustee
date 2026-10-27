# Gateway API end-to-end tests

This suite starts the real `trustee-gateway`, `kbs`, `grpc-as`, `restful-as`, and
`rvps` binaries and exercises their HTTP/gRPC chain. There are no fake upstream
servers. The two shared-storage cases start **two independent copies of every
service**, pointing to the same isolated MySQL database and stable test signing
identities. Legacy cases remain single-replica deployments.

## Coverage

The [API contract](api-contract.json) enumerates all 45 logical Gateway operations,
including both AS aliases and the four RVPS operations behind its wildcard route.
The ordinary Go test `TestGatewayRoutesMatchDocumentedE2EContract` checks the live
Gin route table, KBS RVPS dispatch branches, contract, and
[user-facing API documentation](../../trustee_gateway_api.md) for drift.
The E2E test separately requires a successful real-service call to **every**
contract entry. An unsupported-backend error alone is not counted as coverage.

| Resource backend | Component state | Replicas |
| --- | --- | --- |
| LocalFs | Legacy files; Gateway SQLite memory + shutdown backup | 1 |
| EncryptedLocalFs | Legacy files and managed key directory | 1 |
| EncryptedDb / SQLite | Legacy component state; SQLite encrypted resources | 1 |
| SharedStore / MySQL | Shared KBS sessions/policies, AS policies, RVPS, Gateway state | 2 |
| EncryptedDb / MySQL | Shared component state and encrypted resource/key database | 2 |

The workflow runs this matrix with both the default interpreter and the opt-in
Regorus VM, so policy compilation cache invalidation is exercised too.
MySQL's server default is deliberately set to COMPACT: new wide Gateway audit
tables must explicitly use DYNAMIC, and the shared key-value/encrypted-resource
schemas must still initialize correctly under the restrictive default.

The suite checks:

- RCAR challenge/cookie forwarding, nonce and client-key binding, cross-replica
  attestation, JWT signature verification against an independently held issuer
  public key, attested-session retries and bearer-token resource access.
- Resource create/read/update/list/delete and actual RSA-OAEP-256/AES-256-GCM JWE
  decryption; missing/tampered tokens and resource-policy denial.
- Administrator authentication on KBS policy/resource/key-maintenance/RVPS
  operations, including missing and invalid administrator JWTs.
- Attestation and resource policy CRUD, visible through the correct backend rather
  than a Gateway-local metadata copy, and immediate allow/deny/allow transitions.
- Reference registration and atomic JSON replacement; non-empty offline release
  manifest list import, append, refresh and delete; fresh decisions after RVPS
  changes. The fixture is intentionally offline, not a live Rekor/OCI availability
  test.
- Concurrent resource writes and same-name reference merges through independent
  KBS/AS/RVPS replicas, checking that no committed value disappears.
- Certificates and live certificate renewal, challenge-key rotation, Simple
  broker's documented OIDC 404s and configured OIDC JWKS/discovery success.
- Managed-key reload/rewrap/rotate, changed key generation, retained resource
  plaintext, new-key uploads and another replica observing the key-ring bump.
- Health response fields, CORS preflight, credentials present/missing, heartbeat
  validation/upsert and cross-replica listing, asynchronous audit filters/pagination
  and absence of raw evidence in stored audit bodies.
- Restarting an entire replica's Gateway/KBS/RESTful AS/gRPC AS/RVPS processes:
  persisted resources, policies, reference values, heartbeat/audit and shared
  pending/attested session state must survive.

There is **no generic Gateway cache-clear API**. The suite tests the observable
policy/reference/key-cache invalidation behavior instead of inventing endpoints.
Assertions preserve documented current backend errors (including some 500/502
responses); such errors never count as a successful API call.

## Local invocation

Prerequisites: Rust 1.88.0, Go compatible with `go.mod`, a C compiler, OpenSSL
development headers, `pkg-config`, `protoc`, and a disposable loopback MySQL 8.0
instance. No TDX/SNP hardware, DCAP library or external cloud credential is needed.

For example, start a dedicated **local-only** test database:

```shell
sudo docker run -d --name trustee-gateway-e2e-mysql \
  -e MYSQL_ALLOW_EMPTY_PASSWORD=yes \
  -p 127.0.0.1:33316:3306 mysql:8.0
```

Run from the repository root:

```shell
RUSTUP_TOOLCHAIN=1.88.0 \
MYSQL_TEST_URL=mysql://root@127.0.0.1:33316/ \
TRUSTEE_E2E_REGOVM=0 \
bash trustee-gateway/test/e2e/run.sh
```

Repeat with `TRUSTEE_E2E_REGOVM=1` for the VM engine. Both CI jobs do this without
silently skipping MySQL cases. A missing/unreachable MySQL service fails the
suite. The test account must be allowed to create/drop databases: each shared
case creates a new random `trustee_e2e_*` database and drops **only that database**
after its owned processes have stopped. Existing tables/databases are never reset.
Non-loopback MySQL hosts are rejected to prevent accidental production access.

`CARGO_TARGET_DIR` is respected. For already built binaries,
`TRUSTEE_E2E_SKIP_BUILD=1` and `TRUSTEE_E2E_BIN_DIR=/absolute/path/to/debug` avoid
rebuilding; the directory must contain all five binaries. Do not reuse binaries
from a different source revision or policy-engine feature selection.

The test uses random loopback ports, temporary configurations and generated test
keys. It does not change the existing deployment or write into `/etc/trustee`.
Backend-routing environment overrides inherited from the operator are stripped.
Private keys, administrator JWTs, cookies, evidence and resource bodies are not
included in assertions or uploaded as CI artifacts. Only the credential-free
`api-coverage.json` is uploaded; it lists successful operation counts.

The test's tagged package is intentionally not part of ordinary `go test ./...`:
use the script above to build/start real services. The route/documentation guard
does run in ordinary Go CI.

## Validation limits

The software `sample` verifier validates report-data binding and the real Trustee
protocol/policy/storage path; it cannot authenticate a physical TEE. Successful
tests do **not** establish TDX/SNP/CSV/TPM hardware authenticity, real guest-side
quote generation, production certificate trust, cloud KMS/HSM availability, or
external OCI/Rekor integration. These require their own hardware/service-backed
tests. The native E2E does not alter WASM in-memory persistence; existing WASM
checks remain in place.
