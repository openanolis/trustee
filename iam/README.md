# Trustee IAM Service

This crate implements the first iteration of the Trustee IAM service that powers the unified role / policy / token flow described in `../../trustee-iam-architecture.md`.

## Features

- Account, principal, resource and role registration APIs.
- JSON policy language with trust and access policies, including string wildcard matching and basic condition operators.
- STS-style `AssumeRole` that can take attestation tokens as input.
- Access evaluation endpoint designed to be consumed by control planes (e.g. KBS, TNG, guest-components).
- JWT-based session tokens signed with an HMAC secret configurable through `config/iam.toml`.

## Usage

```bash
cargo run -p iam -- --config config/iam.toml
```

Example `iam.toml`:

```toml
[server]
bind_address = "0.0.0.0:8090"

[crypto]
issuer = "trustee-iam"
hmac_secret = "replace-with-strong-secret"
default_ttl_seconds = 900
```

## API Overview

| Endpoint | Description |
| --- | --- |
| `POST /accounts` | Create a logical account. |
| `POST /accounts/{account_id}/principals` | Create a principal (user/service/runtime) under an account. |
| `POST /resources` | Register a resource ARN. |
| `POST /roles` | Create a role with trust and access policies. |
| `POST /sts/assume-role` | Evaluate trust policy + attestation and issue a session token. |
| `POST /authz/evaluate` | Validate a token and evaluate the access policy for an action/resource. |

All payloads are JSON and map one-to-one to the request structs defined in `src/models.rs`.

