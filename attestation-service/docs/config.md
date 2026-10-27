# CoCo AS Configuration File

The Confidential Containers KBS properties can be configured through a
JSON-formatted configuration file.

## Configurable Properties

The following sections list the CoCo AS properties which can be set through the
configuration file.

### Global Properties

The following properties can be set globally, i.e. not under any configuration
section:

| Property                   | Type                        | Description                                         | Required | Default |
|----------------------------|-----------------------------|-----------------------------------------------------|----------|---------|
| `storage_backend`          | SharedStorageConfiguration  | Optional namespaced backend for AS policies and built-in RVPS reference values. | False | None |
| `work_dir`                 | String                      | The location for Attestation Service to store data. | False      | Firstly try to read from ENV `AS_WORK_DIR`. If not any, use `/opt/confidential-containers/attestation-service`       |
| `rvps_config`              | [RVPSConfiguration][2]      | RVPS configuration                                  | False      | -       |
| `artifact_server_address`  | String                      | Artifact Server URL used by policy `query_artifact_server`. | False | `https://attest-pre.aliyuncs.com` |
| `attestation_token_broker` | [AttestationTokeBroker][1]  | Attestation result token configuration.             | False      | -       |
| `challenge_key_path`       | String                      | Path to the RSA private key (PEM) used to sign and verify attestation challenge (nonce) tokens. The key is generated atomically on the first challenge request if the file does not exist, and is reloaded for every signing and verification request. | False | `/etc/trustee/attestation-service/nonce_token_issuer/key.pem` |

To rotate the challenge key without restarting AS, replace the key file
atomically. Outstanding challenge tokens signed by the previous key become
invalid immediately after replacement.

#### Shared Storage Configuration

Configure `storage_backend` together with the built-in RVPS `SharedStore`
backend to run multiple AS replicas over one authoritative state store. AS
policies use the `attestation_service_policy` namespace and reference values
use `reference_value`; compare-and-swap protects concurrent RVPS updates.

| Property | Type | Description | Default |
|----------|------|-------------|---------|
| `storage_type` | String | `memory` or `mysql`. | `memory` |
| `require_shared` | Boolean | Reject a backend without cross-replica sharing, compare-and-swap, and TTL. Set to `true` for HA. | `false` |
| `backends.mysql.url_env` | String | Environment variable containing the MySQL URL. | `TRUSTEE_STORAGE_MYSQL_URL` |
| `backends.mysql.max_connections` | Integer | Maximum connections in each replica's pool. | `10` |
| `backends.mysql.min_connections` | Integer | Minimum connections in each replica's pool. | `0` |
| `backends.mysql.acquire_timeout_seconds` | Integer | Connection acquisition timeout. | `10` |

The token-signing key, certificate, and challenge key are cryptographic key
material rather than ordinary mutable records. Every replica must receive the
same keys through a Kubernetes Secret, CSI secret-store driver, or KMS-backed
mount. Do not place private keys in the MySQL URL or inline configuration.

[1]: #attestationtokenbroker
[2]: #rvps-configuration

#### AttestationTokenBroker

| Property       | Type                    | Description                                          | Required | Default |
|----------------|-------------------------|------------------------------------------------------|----------|---------|
| `type`         | String                  | Type of token to issue (`Ear` or `Simple`)               | No       | `Ear`   |

When `type` field is set to `Ear`, the following extra properties can be set:

| Property       | Type                    | Description                                          | Required | Default |
|----------------|-------------------------|------------------------------------------------------|----------|---------|
| `duration_min` | Integer                 | Duration of the attestation result token in minutes. | No       | `5`     |
| `issuer_name`  | String                  | Issure name of the attestation result token.         | No       |`CoCo-Attestation-Service`|
| `developer_name`  | String               | The developer name to be used as part of the Verifier ID in the EAR | No       |`https://confidentialcontainers.org`|
| `build_name`  | String                  | The build name to be used as part of the Verifier ID in the EAR         | No       | Automatically generated from Cargo package and AS version|
| `profile_name`  | String                  | The Profile that describes the EAR token         | No       |tag:github.com,2024:confidential-containers/Trustee`|
| `policy_dir`  | String                  | The path to the work directory that contains policies to provision the tokens.        | No       |`/opt/confidential-containers/attestation-service/token/ear/policies`|
| `signer`       | [TokenSignerConfig][1]  | Signing material of the attestation result token.    | No       | None       |

[1]: #tokensignerconfig

When `type` field is set to `Simple`, the following extra properties can be set:
| Property       | Type                    | Description                                          | Required | Default |
|----------------|-------------------------|------------------------------------------------------|----------|---------|
| `duration_min` | Integer                 | Duration of the attestation result token in minutes. | No       | `5`     |
| `issuer_name`  | String                  | Issure name of the attestation result token.         | No       |`CoCo-Attestation-Service`|
| `policy_dir`  | String                  | The path to the work directory that contains policies to provision the tokens.        | No       |`/opt/confidential-containers/attestation-service/token//simple/policies`|
| `signer`       | [TokenSignerConfig][1]  | Signing material of the attestation result token.    | No       | None       |

[1]: #tokensignerconfig

#### TokenSignerConfig

This section is **optional**. When omitted, a new RSA key pair is generated and used.

| Property       | Type    | Description                                              | Required | Default |
|----------------|---------|----------------------------------------------------------|----------|---------|
| `key_path`     | String  | RSA Key Pair file (PEM format) path.                     | Yes      | -       |
| `cert_url`     | String  | RSA Public Key certificate chain (PEM format) URL.       | No       | -       |
| `cert_path`    | String  | RSA Public Key certificate chain (PEM format) file path. | No       | -       |

#### RVPS Configuration

| Property       | Type                    | Description                                          | Required | Default |
|----------------|-------------------------|------------------------------------------------------|----------|---------|
| `type`         | String                  | It can be either `BuiltIn` (Built-In RVPS) or `GrpcRemote` (connect to a remote gRPC RVPS) | No       | `BuiltIn` |

##### BuiltIn RVPS

If `type` is set to `BuiltIn`, the following extra properties can be set

| Property       | Type                    | Description                                                           | Required | Default  |
|----------------|-------------------------|-----------------------------------------------------------------------|----------|----------|
| `storage`   | ReferenceValueStorageConfig | Configuration of storage for reference values (`SharedStore`, `LocalFs`, `LocalJson`, or `InMemory`)       | No       | `LocalFs`|

`ReferenceValueStorageConfig` can contain a `SharedStore`, `LocalFs`,
`LocalJson`, or `InMemory` configuration. `SharedStore` has no extra fields and
requires `storage_backend`. The other variants retain their legacy behavior.

For `LocalFs`, the following properties can be set

| Property       | Type                    | Description                                              | Required | Default  |
|----------------|-------------------------|----------------------------------------------------------|----------|----------|
| `file_path`    | String                  | The path to the directory storing reference values       | No       | `/opt/confidential-containers/attestation-service/reference_values`|

For `LocalJson`, the following properties can be set

| Property       | Type                    | Description                                              | Required | Default  |
|----------------|-------------------------|----------------------------------------------------------|----------|----------|
| `file_path`    | String                  | The path to the file that storing reference values       | No       | `/opt/confidential-containers/attestation-service/reference_values.json`|

For `InMemory`, no additional properties can be set. Reference values are kept in memory without an on-disk database.

##### Remote RVPS

If `type` is set to `GrpcRemote`, the following extra properties can be set

| Property       | Type                    | Description                             | Required | Default          |
|----------------|-------------------------|-----------------------------------------|----------|------------------|
| `address`      | String                  | Remote address of the RVPS server       | No       | `127.0.0.1:50003`|


## Configuration Examples

Running multiple replicas with shared policies and a shared built-in RVPS:

```json
{
    "storage_backend": {
        "storage_type": "mysql",
        "require_shared": true,
        "backends": {
            "mysql": {
                "url_env": "TRUSTEE_STORAGE_MYSQL_URL",
                "max_connections": 20,
                "min_connections": 2,
                "acquire_timeout_seconds": 10
            }
        }
    },
    "work_dir": "/var/lib/attestation-service/",
    "challenge_key_path": "/run/secrets/trustee/challenge-key.pem",
    "rvps_config": {
        "type": "BuiltIn",
        "storage": {
            "type": "SharedStore"
        }
    },
    "artifact_server_address": "https://attest-pre.aliyuncs.com",
    "attestation_token_broker": {
        "type": "Ear",
        "duration_min": 5,
        "signer": {
            "key_path": "/run/secrets/trustee/token-signer-key.pem"
        }
    }
}
```

Set `TRUSTEE_STORAGE_MYSQL_URL` in every replica, for example from a
Kubernetes Secret. Omitting `storage_backend` keeps the existing filesystem
policy and RVPS configuration. Pure-library/WASM users continue to construct
the in-memory policy engine and `InMemory` RVPS through the fs-free APIs.

Running with a remote RVPS:

```json
{
    "work_dir": "/var/lib/attestation-service/",
    "policy_engine": "opa",
    "rvps_config": {
        "type": "GrpcRemote",
        "address": "127.0.0.1:50003"
    },
    "artifact_server_address": "https://attest-pre.aliyuncs.com",
    "attestation_token_broker": {
	"type": "Ear",
        "duration_min": 5
    }
}
```

Configurations for token signer

```json
{
    "work_dir": "/var/lib/attestation-service/",
    "policy_engine": "opa",
    "rvps_config": {
        "type": "GrpcRemote",
        "address": "127.0.0.1:50003"
    },
    "artifact_server_address": "https://attest-pre.aliyuncs.com",
    "attestation_token_broker": {
	"type": "Ear",
        "duration_min": 5,
        "issuer_name": "some-body",
        "signer": {
            "key_path": "/etc/coco-as/signer.key",
            "cert_url": "https://example.io/coco-as-certchain",
            "cert_path": "/etc/coco-as/signer.pub"
        }
    }
}
```
