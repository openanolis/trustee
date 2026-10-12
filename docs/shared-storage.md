# Trustee shared storage and multi-replica deployment

Trustee can keep authoritative mutable state in MySQL instead of writable
pod-local files. This allows KBS, AS, RVPS, RVDS and Trustee Gateway replicas to
be replaced or scaled without sharing a writable PVC.

The feature is opt-in. Existing single-replica file, SQLite and in-memory
configurations continue to work unchanged. WASM builds continue to use their
in-memory component construction path and do not enable MySQL storage.

## Storage layout

One MySQL service can host the Trustee state plane. Rust components use a
namespaced `trustee_kv_entries` table, while Gateway and `EncryptedDb` keep
their purpose-built schemas. Namespaces isolate KBS resources, policies,
protocol sessions, AS policies, RVPS reference values and RVDS subscribers.

Signing keys and TLS credentials are not database state. Mount the same
pre-created signing keys read-only into every AS replica through a Kubernetes
Secret, CSI secret-store driver or KMS-backed volume.

## Helm configuration

Create the database and signing Secrets before installing the chart. Keep the
actual credential values out of `values.yaml` and shell history.
Set the component image tags to a Trustee build that includes shared-storage
support; the chart keeps its legacy image defaults for backward compatibility.

The storage Secret must contain:

- `mysql-url`: URL used by Rust services, such as
  `mysql://<user>:<password>@<host>:3306/<database>`.
- `gateway-dsn`: Go MySQL DSN used by Gateway, such as
  `<user>:<password>@tcp(<host>:3306)/<database>?parseTime=true`.

The AS key Secret must contain a P-256 token signer private key and an RSA
challenge-token private key under the keys configured below.
The TPM PCA Secret must contain the existing `ca.key` and `ca.crt`; this keeps
one TPM CA identity across KBS replicas instead of generating a key per pod.

```yaml
sharedStorage:
  enabled: true
  existingSecret: trustee-storage
  mysqlUrlKey: mysql-url
  gatewayDsnKey: gateway-dsn
  asKeysExistingSecret: trustee-as-keys
  tokenSignerKey: token-signer-key.pem
  challengeKey: challenge-key.pem
  maxConnections: 20
  minConnections: 2
  acquireTimeoutSeconds: 10

kbs:
  replicaCount: 3
  tpmPca:
    existingSecret: trustee-tpm-pca
    signingKeyKey: ca.key
    certificateKey: ca.crt
as:
  replicaCount: 3
asrestful:
  replicaCount: 3
rvps:
  replicaCount: 3
gateway:
  replicaCount: 3
```

With `sharedStorage.enabled=true`, the chart:

- selects MySQL with `require_shared=true` for KBS, AS and RVPS;
- selects the KBS `SharedStore` resource backend unless Aliyun KMS is enabled;
- injects database credentials only from the referenced Secret;
- mounts the AS signing keys read-only;
- mounts one pre-created TPM PCA key and certificate read-only in every KBS replica;
- seeds an empty shared AS policy namespace from the configured default-policy ConfigMap without overwriting an existing database policy;
- configures Gateway for MySQL and rejects a fallback to SQLite;
- omits writable KBS, RVPS and Gateway data volumes.

The legacy `kbs.resourceRepository` Secret-mount importer writes files and is
therefore rejected in shared mode. Import resources through the KBS API before
or after switching to `SharedStore`.

## KBS resource backend compatibility

| Resource backend | Multi-replica | Notes |
| --- | --- | --- |
| `SharedStore` with MySQL | Yes | Recommended unified storage path; opaque values use the `repository` namespace. |
| `EncryptedDb` with MySQL | Yes | Keeps its existing encrypted resource schema and key-rotation behavior; it is not limited to `SharedStore`. |
| `Aliyun` / `ExternalKms` | Yes | Resource data is already external; KBS sessions and policies still need shared storage. |
| `LocalFs` / `EncryptedLocalFs` | No for concurrent writers | Keep for legacy single-replica deployments only. |
| process memory | No | Intended for tests, single-process use and WASM. |

## Non-Helm configuration

Use the same `TRUSTEE_STORAGE_MYSQL_URL` Secret in KBS, AS, RVPS and RVDS.
Set each component's `require_shared` switch so a configuration error fails at
startup instead of silently using local state.

KBS:

```toml
session_storage_type = "mysql"

[storage_backend]
storage_type = "mysql"
require_shared = true

[storage_backend.backends.mysql]
url_env = "TRUSTEE_STORAGE_MYSQL_URL"

[[plugins]]
name = "resource"
type = "SharedStore"
```

Standalone RVPS:

```json
{
  "storage_backend": {
    "storage_type": "mysql",
    "require_shared": true,
    "backends": { "mysql": { "url_env": "TRUSTEE_STORAGE_MYSQL_URL" } }
  },
  "storage": { "type": "SharedStore" }
}
```

RVDS:

```text
RVDS_STORAGE_TYPE=mysql
RVDS_REQUIRE_SHARED=true
TRUSTEE_STORAGE_MYSQL_URL=<from-secret>
```

Gateway:

```yaml
database:
  type: mysql
  require_shared: true
```

Inject its DSN with `TRUSTEE_GATEWAY_DATABASE_DSN`.

AS additionally requires `storage_backend` with MySQL, an explicitly
configured token `signer.key_path`, and a pre-created `challenge_key_path`.
All replicas must read the same two keys.

## Migration and rollback

1. Back up existing PVC data and the Gateway SQLite database.
2. Provision MySQL and pre-create the AS signing keys.
3. Stop writes or scale the old deployment to one replica.
4. Import KBS resources and policies through their APIs. RVDS automatically
   imports an existing `subscribers.json` when it can still read that file.
5. Enable shared storage with one replica and validate reads and writes.
6. Scale components out and validate cross-replica visibility before removing
   old PVCs.

For rollback, stop writes, scale back to one replica, restore the backed-up
file or SQLite state, and disable `sharedStorage`. Do not run multiple writable
replicas against restored local storage.
