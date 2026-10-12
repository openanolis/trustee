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

[storage_backend.backends.mysql]
url = "mysql://trustee@mysql.example/trustee"
max_connections = 20
```

The database URL is treated as secret configuration and is intentionally
redacted from `Debug` output.
