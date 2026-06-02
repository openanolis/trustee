# EncryptedDb Key Rotation & Purge

`EncryptedDb` exposes the same admin API as `EncryptedLocalFs`
(`/rotate`, `/pubkey`, `/reload`, `/rewrap`), but the lifecycle of a
wrap key has one extra step: physical purging of retired keys after a
configurable grace period.

> Read the
> [EncryptedDb Resource Backend](./resource_storage_backend_encrypted_db.md)
> document first if you are not already familiar with the schema and
> the master-secret model.

## Lifecycle of a wrap key

```
        ┌──────────────────┐
        │      ACTIVE      │  retired_at IS NULL
        │  (primary if     │
        │  pointed at by   │
        │  kbs_meta:       │
        │  primary_gen)    │
        └────────┬─────────┘
                 │  /rotate succeeds → newer key becomes primary
                 ▼
        ┌──────────────────┐
        │     RETIRED      │  retired_at = NOW()
        │ (kept in DB so   │   row stays in kbs_managed_keys
        │  late uploads    │   for at least retired_key_purge_after
        │  with stale pub  │
        │  key still       │
        │  decrypt)        │
        └────────┬─────────┘
                 │  next /rotate, after grace elapsed,
                 │  runs a straggler-rewrap pass; once no
                 │  resource depends on this generation,
                 │  the row is deleted.
                 ▼
        ┌──────────────────┐
        │     PURGED       │  row no longer in kbs_managed_keys
        └──────────────────┘
```

The grace period is controlled by `[plugins.database] retired_key_purge_after`
(default `"30d"`, set `"0"` to disable; minimum non-zero value is
`"1h"`).

## One-shot rotation (the common case)

```bash
curl -X POST "$KBS/kbs/v0/resource/rotate" \
     -H "Authorization: Bearer $ADMIN_TOKEN"
# {
#   "public_key": "-----BEGIN PUBLIC KEY-----\n...",
#   "rewrapped":   100,
#   "skipped":     28,
#   "failed":      0,
#   "retired_keys": 1,
#   "purged_keys":  0
# }
```

What KBS does, atomically across all replicas:

1. Acquires an exclusive row lock on `kbs_meta('primary_generation')`
   so concurrent rotations serialize.
2. Generates a new RSA-3072 key pair, encrypts the private key under
   the master secret with AES-256-GCM (binding the generation
   identifier as AAD), and INSERTs it into `kbs_managed_keys`.
3. Streams every resource whose `generation` is older than the new
   one in 200-row batches, decrypts the CEK with the previous wrap
   key, RSA-OAEP-256 wraps it with the new public key, and writes
   the new envelope back to `kbs_resources`.
4. **If every row migrated cleanly** (`failed == 0`):
   * marks every older generation `retired_at = NOW()`,
   * advances `kbs_meta.primary_generation` to the new key,
   * increments `kbs_meta.bump` so other replicas know to reload.
   * **If any row failed** (`failed > 0`), the new key stays inserted
     but the primary pointer is *not* advanced and old keys are *not*
     retired, so unaffected clients keep working with the prior key.
     Re-run `/rotate` after fixing the cause.
5. Finally, runs a purge sweep (see below).

Other replicas pick up the new pubkey within `bump_poll_interval_ms`
(default 5 s) on their next request — no `/reload` needed.

## Hot reload, manual rewrap

Both endpoints from `EncryptedLocalFs` work the same way here:

- `POST /kbs/v0/resource/reload` — re-reads `kbs_managed_keys` and
  `kbs_meta` from the database and atomically swaps the in-memory
  ring. Useful after a side-channel change (e.g. an offline migration
  tool) or when you want to bypass the bump-poll throttle.
- `POST /kbs/v0/resource/rewrap` — rewraps every resource onto the
  current primary without generating a new key. Useful when you have
  inserted a wrap key by side-channel (for instance, importing an
  old key for migration purposes).

## Purge sweep details

Every `/rotate` ends with a purge sweep:

1. List candidates: every row in `kbs_managed_keys` whose
   `retired_at < NOW() - retired_key_purge_after`.
2. Run a final straggler-rewrap pass over `kbs_resources`. Any
   envelope that the current primary cannot decrypt but a candidate
   key can, is rewrapped to the primary on the spot.
3. Re-scan `kbs_resources` once more. For each candidate, if there is
   *still* a row that can only be decrypted with that candidate, the
   candidate is **left in place** and a warning is logged
   (`EncryptedDb: skipping purge of generation X`). The row is
   never orphaned.
4. Otherwise the candidate is `DELETE`d.

Set `retired_key_purge_after = "0"` to keep retired keys forever
(useful when running a backup/archival regime that re-imports old
data, or while validating the new backend on a sensitive workload).
Either way the table grows by **at most one row per rotation**, so
yearly rotation gives a few rows of overhead — negligible.

## Multi-replica notes

- All replicas must share the **same master secret** (typically a
  single Kubernetes Secret mounted into every pod).
- All replicas must share the **same database**. Distinct DBs cannot
  be reconciled — KBS makes no attempt to.
- The wrap key live for at least `retired_key_purge_after` after a
  rotation, so the **maximum delay a client can be running with a
  stale public key** without their writes being orphaned is exactly
  that grace period. Pick a value that comfortably covers your
  client's `/pubkey` refresh cadence.

## Relationship to EncryptedLocalFs

| Concern | `EncryptedLocalFs` | `EncryptedDb` |
|---|---|---|
| Wrap-key lifetime after rotate | Deleted from disk on success | `retired_at` marked; physically deleted after `retired_key_purge_after` |
| `RotateReport.retired_keys` | Count of files removed from disk | Count of rows newly marked retired |
| `RotateReport.purged_keys` | Always `0` | Count of rows physically deleted in this rotation's purge sweep |
| Client-uploaded with stale pubkey *after* rotate | Race window: very short on a single instance; can fail to decrypt | Survives the entire grace period; rewrapped on next rotation |

If you are migrating from `EncryptedLocalFs` to `EncryptedDb` and want
existing resources copied across, the simplest workflow is:

1. Stand up `EncryptedDb` next to `EncryptedLocalFs`.
2. For every existing resource, GET it from the old backend (which
   returns plaintext after decryption), encrypt it with the new
   backend's `/pubkey`, and POST it to the new backend.
3. Once verified, switch the `[[plugins]]` config to
   `type = "EncryptedDb"`, restart, and decommission the old backend.

A scripted version of this migration may land in a follow-up PR; for
now `kbs/sdk/python/encrypt_resource.py` is the building block.
