# Trustee key-value storage

This crate provides namespaced storage for mutable state shared by Trustee
replicas. `Memory` remains available for WASM, tests and single-process use.
`Mysql` stores authoritative state in an external InnoDB table.

The API includes revision-based compare-and-swap, create-if-absent and TTL.
Components must inspect backend capabilities during startup and fail closed if
their consistency requirements are not met.

```toml
[storage_backend]
storage_type = "mysql"
require_shared = true

[storage_backend.backends.mysql]
url = "mysql://trustee@mysql.example/trustee"
max_connections = 20
```

For production, omit `url` and inject `TRUSTEE_STORAGE_MYSQL_URL` from a
Secret. The database URL is intentionally redacted from `Debug` output.
