# EncryptedDb Resource Backend

`EncryptedDb` keeps both the resource encryption keys and the encrypted
resource envelopes in a shared SQL database (MySQL — including
MySQL-compatible managed services — or SQLite). It is the recommended
backend for **multi-replica** KBS deployments where every replica must
agree on which key wraps each resource and on the contents of every
resource.

The on-the-wire envelope format and the `/kbs/v0/resource/...` admin
API are unchanged from
[EncryptedLocalFs](./resource_storage_backend.md#encrypted-local-file-system-backend),
so client tooling such as `kbs/sdk/python/encrypt_resource.py` works
without modification.

## Why this backend exists

`EncryptedLocalFs` keeps both wrap keys (as `mkey-<nanos>.pem` files) and
resource envelopes on the local filesystem. Run more than one replica
and you immediately hit:

1. **Key divergence on cold start** — every replica generates its own
   key the first time it sees an empty `key_dir`, so a resource written
   on replica A cannot be read on replica B.
2. **Rotation tearing** — a `/rotate` on one replica deletes its old
   keys, but the other replicas keep using cached old keys until they
   restart or `/reload`, dropping reads in flight.
3. **Resource invisibility** — resources written via replica A's
   `dir_path` are simply not present on replica B unless that directory
   is shared.

`EncryptedDb` solves all three by making the **database** the source of
truth and the **master secret** the only thing operators have to keep
out of band.

## Architecture in 30 seconds

```
       client ── /pubkey ──► KBS replica ──┐
                                            │
       client ── POST envelope ────────────►│
                                            │
                                            ▼
                                ┌──────────────────────────┐
                                │  shared MySQL / SQLite    │
                                │                            │
                                │  kbs_managed_keys (wrap    │
                                │     private key encrypted  │
                                │     under master_key)      │
                                │  kbs_resources    (envelope│
                                │     JSON, generation tag)  │
                                │  kbs_meta         (primary │
                                │     pointer, bump counter, │
                                │     KDF salt + canary)     │
                                └──────────────────────────┘
```

- All replicas connect to the same database. Schema is created
  idempotently with `CREATE TABLE IF NOT EXISTS` (and a MySQL `GET_LOCK`
  advisory lock to serialize concurrent migrations).
- Each replica reads the master passphrase from a local tmpfs file at
  startup and derives a 32-byte master key via Argon2id (the salt and
  parameters live in `kbs_meta`). This master key only AES-256-GCM
  encrypts/decrypts the wrap private keys at rest — it never wraps
  resource CEKs.
- Resource envelopes themselves are unchanged: clients still RSA-wrap a
  per-resource AES-256-GCM CEK using the current public key.
- A `bump` counter in `kbs_meta` advertises that another replica
  rotated; each replica cheap-polls (default 5 s throttle) to know when
  to reload its in-memory key ring.

## Configuration

```toml
[[plugins]]
name = "resource"
type = "EncryptedDb"
master_secret_path = "/run/trustee/master.passphrase"   # default
bump_poll_interval_ms = 5000                            # default; ≥100 recommended

  [plugins.database]
  type = "mysql"                                        # or "sqlite"
  dsn  = "mysql://kbs:<password>@db-host:3306/trustee_kbs?ssl-mode=PREFERRED"
  max_open_conns = 20
  max_idle_conns = 5
  conn_max_lifetime = "1h"
  retired_key_purge_after = "30d"                       # "0" disables purging
```

Field reference:

| Field | Required | Description |
|---|---|---|
| `master_secret_path` | no (default `/run/trustee/master.passphrase`) | File holding the master passphrase. Read once at startup and zeroized; never re-read while running. |
| `bump_poll_interval_ms` | no (default `5000`) | Throttle on the cheap `SELECT bump` poll that detects another replica's rotation. Smaller values mean faster propagation and more DB traffic. |
| `database.type` | yes | `"mysql"` or `"sqlite"`. |
| `database.dsn` | required for `mysql` | SQLx MySQL DSN, e.g. `mysql://user:pass@host:port/db?ssl-mode=PREFERRED`. |
| `database.path` | required for `sqlite` | Filesystem path. Use `:memory:` for an ephemeral in-process database (testing only). |
| `database.max_open_conns` | no | Pool maximum (`PoolOptions::max_connections`). |
| `database.max_idle_conns` | no | Pool warm-pool floor (`PoolOptions::min_connections`). |
| `database.conn_max_lifetime` | no | `"1h"`, `"30m"`, etc. (humantime-style). Maps to `PoolOptions::max_lifetime`. |
| `database.retired_key_purge_after` | no (default `"30d"`) | Grace period a retired key remains in the DB for late-arriving reads before being physically deleted. `"0"` disables purging. The minimum non-zero value is `"1h"`. |

> Sensitive fields (DSN, master secret path) are intentionally **not**
> overridable through the `KBS_RESOURCE_STORAGE_*` environment variables.

## Master secret

The master secret is a passphrase you provision once at deployment.

- **Where it lives.** Each replica reads it from a local file (default
  `/run/trustee/master.passphrase`). On Kubernetes the canonical pattern
  is a `Secret` mounted as a tmpfs file:

  ```yaml
  volumes:
    - name: master-secret
      secret:
        secretName: trustee-master-secret
        defaultMode: 0400
  volumeMounts:
    - name: master-secret
      mountPath: /run/trustee
      readOnly: true
  ```

  The `Secret` itself stays in `etcd`; **make sure
  `--encryption-provider-config` is enabled on the API server** so etcd
  snapshots and backups do not contain plaintext.

- **How it is used.** On startup KBS reads the file, trims trailing
  whitespace, and derives a 32-byte master key with Argon2id (default
  parameters: `m_cost=64MiB`, `t_cost=3`, `p_cost=4`). The salt and
  parameters live in `kbs_meta` and are seeded the first time the
  database is initialized. The passphrase bytes are zeroed immediately
  after derivation; only the derived master key remains in memory.

- **Canary check.** The first time KBS bootstraps, it encrypts a fixed
  plaintext (`trustee-master-canary-v1`) under the master key and
  stores `(nonce, tag, ciphertext)` in `kbs_meta`. On every subsequent
  startup KBS verifies the canary first; **if the passphrase is wrong
  or the canary has been tampered with, KBS refuses to start**. This
  is what prevents a typo from silently corrupting the table with
  mis-keyed entries.

- **Rotation.** Master secret rotation is operationally disruptive
  (every replica must agree on the new passphrase). v1 supports it as
  an offline procedure: stop all replicas, run a one-shot tool that
  re-encrypts each `kbs_managed_keys` row with the new master key (and
  rewrites the canary + KDF salt), restart all replicas with the new
  passphrase. A future PR may automate this.

- **Recovery.** If the passphrase is lost, the wrap private keys
  cannot be decrypted and resources cannot be read. **Print the
  passphrase to a recovery sheet** and seal it in physical safe storage
  (or use a KMS-style secret-sharing scheme such as Shamir). The
  passphrase is the single root of trust for the whole DB.

## Key rotation

`POST /kbs/v0/resource/rotate` works the same way it does for
`EncryptedLocalFs` — atomically generates a new wrap key, rewraps every
resource envelope onto the new public key, retires the old key — but
with extra DB-level guarantees:

- The new wrap key is inserted, primary pointer advanced, and bump
  counter incremented in a short transaction. Any concurrent `/rotate`
  call from another replica blocks on a `SELECT FOR UPDATE` and
  observes the new state, so it returns a no-op.
- The rewrap pass over `kbs_resources` runs outside the transaction
  (streamed in 200-row batches) so reads and writes are not blocked
  by long-held locks.
- Other replicas pick up the new key within `bump_poll_interval_ms` —
  no `/reload` needed.
- A retired key is **not** physically deleted right away; it is
  marked `retired_at` and stays in the table for `retired_key_purge_after`
  (default 30 days) so a resource uploaded with a stale public key
  during a rotation race remains decryptable. Once the grace period
  expires, the next `/rotate` runs a final straggler-rewrap pass and
  then deletes the row.

`RotateReport` (the JSON returned by `/rotate`) includes a
`purged_keys` field counting how many retired keys were physically
removed during this rotation.

For step-by-step procedures and the cleanup story, see
[EncryptedDb Key Rotation](./encrypted_db_key_rotation.md).

## Concurrency model

| Concurrency | Behavior |
|---|---|
| `rotate` × `GET` | Reader takes a MVCC snapshot, sees the pre-rotate envelope, decrypts with its existing ring (which still includes the old key). After commit, the reader's bump poll triggers a reload and subsequent reads see the new envelope. **Never blocks; never fails.** |
| `rotate` × `POST` (same row) | UPSERT waits for the rotate's row lock; commits happen-after-rotate. **Brief block, no failure.** |
| `rotate` × `POST` (different row) | Independent row locks; no contention. |
| `rotate` × `DELETE` | Row lock; same as `POST`. |
| `rotate` × `rotate` | The `kbs_meta('primary_generation')` row lock serializes them; the second caller sees the new primary already in place and returns a noop report. |

A resource uploaded with a stale public key during the brief window
between rotation commit and the client refreshing `/pubkey` is **not**
orphaned: the corresponding wrap key stays in the DB until purge
grace expires, and any subsequent `/rotate` rewraps stragglers.

## Operational tips

- **Migrations.** Schema is `CREATE TABLE IF NOT EXISTS`; just point
  the new replica at the same DSN. No external migration tool is
  required.
- **Backups.** A `mysqldump` of `trustee_kbs.kbs_managed_keys` carries
  ciphertext only; the master secret is what attackers actually need.
  Make sure backups of the K8s Secret holding the passphrase are
  managed separately and at least as carefully.
- **Failure isolation.** Picking the same database that
  `trustee-gateway` uses is fine, but consider a dedicated database
  user with only the privileges KBS needs (`SELECT`, `INSERT`,
  `UPDATE`, `DELETE` on the three `kbs_*` tables; `CREATE TABLE` on
  first deploy).
- **Bare metal / single-instance.** If you run a single KBS replica,
  `EncryptedLocalFs` remains a perfectly valid option. `EncryptedDb`'s
  benefits — shared keys, atomic rotation, deferred purge — only
  matter once you have multiple replicas or want DB-grade durability
  on the resources themselves.
