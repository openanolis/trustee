# KBS Configuration File

The Confidential Containers KBS properties can be configured through a
TOML-formatted configuration file.

>NOTE: Additional formats such as YAML and JSON are supported. Other formats
>supported by the `config` crate may be supported as well. This document uses
>TOML in the configuration examples.

The location of the configuration file is passed to the KBS binary using the
`-c` or `--config-file` command line option, or using the `KBS_CONFIG_FILE`
environment variable.

## Configurable Properties

The following sections list the KBS properties which can be set through the
configuration file.

### HTTP Server Configuration

The following properties can be set under the `[http_server]` section.

| Property                 | Type         | Description                                      | Required | Default              |
|--------------------------|--------------|--------------------------------------------------|----------|----------------------|
| `sockets`                | String array | One or more sockets to listen on.                | No       | `["127.0.0.1:8080"]` |
| `insecure_http`          | Boolean      | Don't use TLS for the KBS HTTP endpoint.         | No       | `false`              |
| `private_key`            | String       | Path to a private key file to be used for HTTPS. | No       | None                 |
| `certificate`            | String       | Path to a certificate file to be used for HTTPS. | No       | None                 |
| `payload_request_size`   | Integer      | Request payload size in mega bytes.              | No       | 2                    |

### Attestation Token Configuration

Attestation Token configuration controls attestation token verifications. This
is important when a resource retrievement is handled by KBS. Usually an attestation
token will be together with the request, and KBS will first verify the token.

The following properties can be set under the `[attestation_token]` section.

| Property                   | Type         | Description                                                                                                                                               | Default |
|----------------------------|--------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|----------|
| `trusted_jwk_sets` | String Array      | Valid Url (`file://` or `https://`) pointing to trusted JWKSets (local or OpenID) for Attestation Tokens trustworthy verification                                                                                             | Empty       |
| `trusted_certs_paths` | String Array | Trusted Certificates file (PEM format) for Attestation Tokens trustworthy verification | Empty       |
| `extra_teekey_paths` | String Array | User defined paths to the tee public key in the JWT body  | Empty       |
| `insecure_key` | Boolean | Whether to check the trustworthy of the JWK inside JWT. See comments. | `false`      |

Each JWT contains a TEE Public Key. Users can use the `extra_teekey_paths` field to additionally specify the path of this Key in the JWT.
Example of `extra_teekey_paths` is `/attester_runtime_data/tee-pubkey` which refers to the key
`attester_runtime_data.tee-pubkey` inside the JWT body claims.

For Attestation Services like CoCo-AS, the public key to verify the JWT will be given
in the token's `jwk` field (with or without the public key cert chain `x5c`).

- If `insecure_key` is set to `true`, KBS will ignore to verify the trustworthy of the `jwk`.
- If `insecure_key` is set to `false`, KBS will look up its `trusted_certs_paths` and the `x5c`
field to verify the trustworthy of the `jwk`.

### Attestation Configuration

Attestation configuration defines the attestation service that KBS' RCAR protocol
will leverage.

The following properties can be set under the `[attestation_service]` section.

Concrete attestation service can be set via `type` field. Supported attestation
services are
- `coco_as_builtin`: CoCo AS that built inside KBS binary
- `coco_as_grpc`: CoCo AS service running remotely

Due to different `type` field, properties are different.

#### Built-In CoCo AS

When `type` is set to `coco_as_builtin`, the following properties can be set.

>Built-In CoCo AS is available only when one or more of the following features are enabled:
>`coco-as-builtin`, `coco-as-builtin-no-verifier`

| Property                   | Type                        | Description                                          | Default |
|----------------------------|-----------------------------|-----------------------------------------------------|----------|
| `timeout`            | Integer                      | The maximum time (in minutes) of the attestation session             |  5       |
| `work_dir`                 | String                      | The location for Attestation Service to store data. |  First try from env `AS_WORK_DIR`. If no this env, then use `/opt/confidential-containers/attestation-service`       |
| `policy_engine`            | String                      | Policy engine type. Valid values: `opa`             |  `opa`       |
| `rvps_config`              | [RVPSConfiguration][2]      | RVPS configuration                                  |  See [RVPSConfiguration][2]       |
| `attestation_token_broker` | [AttestationTokenConfig][1] | Attestation result token configuration.             |  See [AttestationTokenConfig][1]       |

[1]: #attestationtokenbroker
[2]: #rvps-configuration


##### AttestationTokenBroker

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

##### TokenSignerConfig

This section is **optional**. When omitted, an ephemeral RSA key pair is generated and used. 

| Property       | Type    | Description                                              | Required |
|----------------|---------|----------------------------------------------------------|----------|
| `key_path`     | String  | RSA Key Pair file (PEM format) path.                     | Yes      |
| `cert_url`     | String  | RSA Public Key certificate chain (PEM format) URL.       | No       |
| `cert_path`    | String  | RSA Public Key certificate chain (PEM format) file path. | No       |

##### RVPS Configuration

| Property       | Type                    | Description                                          | Required | Default |
|----------------|-------------------------|------------------------------------------------------|----------|---------|
| `type`         | String                  | It can be either `BuiltIn` (Built-In RVPS) or `GrpcRemote` (connect to a remote gRPC RVPS) | No       | `BuiltIn` |

##### BuiltIn RVPS

If `type` is set to `BuiltIn`, the following extra properties can be set

| Property       | Type                    | Description                                                           | Required | Default  |
|----------------|-------------------------|-----------------------------------------------------------------------|----------|----------|
| `storage`   | ReferenceValueStorageConfig | Configuration of the storage for reference values (`LocalFs` or `LocalJson`) | No       | `LocalFs`|

A `ReferenceValueStorageConfig` can either be of type `LocalFs` or `LocalJson`

For `LocalFs`, the following properties can be set

| Property       | Type                    | Description                                              | Required | Default  |
|----------------|-------------------------|----------------------------------------------------------|----------|----------|
| `file_path`    | String                  | The path to the directory storing reference values       | No       | `/opt/confidential-containers/attestation-service/reference_values`|

For `LocalJson`, the following properties can be set

| Property       | Type                    | Description                                              | Required | Default  |
|----------------|-------------------------|----------------------------------------------------------|----------|----------|
| `file_path`    | String                  | The path to the file that storing reference values       | No       | `/opt/confidential-containers/attestation-service/reference_values.json`|

##### Remote RVPS

If `type` is set to `GrpcRemote`, the following extra properties can be set

| Property       | Type                    | Description                             | Required | Default          |
|----------------|-------------------------|-----------------------------------------|----------|------------------|
| `address`      | String                  | Remote address of the RVPS server       | No       | `127.0.0.1:50003`|

#### gRPC CoCo AS

When `type` is set to `coco_as_grpc`, KBS will try to connect a remote CoCo AS for
attestation. The following properties can be set.

>gRPC CoCo AS is available only when `coco-as-grpc` feature is enabled.

| Property                   | Type                        | Description                                          | Default |
|----------------------------|-----------------------------|-----------------------------------------------------|----------|
| `timeout`            | Integer                      | The maximum time (in minutes) between RCAR handshake's `auth` and `attest` requests             |  5       |
| `as_addr`                 | String                      | The URL of the remote CoCoAS |  `http://127.0.0.1:50004`       |
| `pool_size`   | Integer         | The connections between KBS and CoCoAS are maintained in a conenction pool. This property determines the max size of the pool                      | `100`             |

### Admin API Configuration

The following properties can be set under the `[admin]` section.

| Property                 | Type         | Description                                                                                                | Required | Default              |
|--------------------------|--------------|------------------------------------------------------------------------------------------------------------|----------|----------------------|
| `auth_public_key`        | String       | Path to the public key used to authenticate the admin APIs                                                 | No       | None                 |
| `insecure_api`           | Boolean      | Whether KBS will not verify the public key when called admin APIs                                          | No       | `false`              |

### Policy Engine Configuration

The following properties can be set under the `[policy_engine]` section.

This section is **optional**. When omitted, a default configuration is used.

| Property                 | Type    | Description                                                                                                | Required                | Default                                        |
|--------------------------|---------|------------------------------------------------------------------------------------------------------------|-------------------------|------------------------------------------------|
| `policy_path`            | String  | Path to a file containing a policy for evaluating whether the TCB status has access to specific resources. | No                      | `/opa/confidential-containers/kbs/policy.rego` |

### Plugins Configuration

KBS supports different kinds of plugins, and they can be enabled via add corresponding configs.

Multiple `[[plugins]]` sections are allowed at the same time for different plugins.
Concrete attestation service can be set via `name` field.

#### Resource Configuration

The `name` field is `resource` to enable this plugin.

Resource plugin allows user with proper attestation token to access storage that KBS keeps.
This is also called "Repository" in old versions. The properties to be configured are listed.

| Property | Type   | Description                                                                   | Required | Default   |
|----------|--------|-------------------------------------------------------------------------------|----------|-----------|
| `type`   | String | The resource repository type. Valid values: `LocalFs`, `EncryptedLocalFs`, `EncryptedDb`, `Aliyun`, `ExternalKms` | Yes      | `LocalFs` |

Resource plugin configuration can also be overridden with environment
variables. Environment variables are applied after the configuration file is
loaded, so they take precedence over the `[[plugins]]` section. If the config
file does not contain a `resource` plugin, `KBS_RESOURCE_STORAGE_TYPE` must be
set to create one from environment variables.

| Environment Variable | Description |
|----------------------|-------------|
| `KBS_RESOURCE_STORAGE_TYPE` | Replaces or creates the resource backend type. Supported values: `LocalFs`, `EncryptedLocalFs`, `EncryptedDb`, `Aliyun`, `ExternalKms`. (For `EncryptedDb`, the database connection settings still need to come from the config file — they cannot be supplied through environment variables.) |
| `KBS_RESOURCE_STORAGE_DIR_PATH` | Overrides `dir_path` for `LocalFs` and `EncryptedLocalFs`. |
| `KBS_RESOURCE_STORAGE_PRIVATE_KEY_PATH` | Overrides `private_key_path` for `EncryptedLocalFs`. |
| `KBS_RESOURCE_STORAGE_LIBRARY_PATH` | Overrides `library_path` for `ExternalKms`. |
| `KBS_RESOURCE_STORAGE_INITIAL_BUFFER_SIZE` | Overrides `initial_buffer_size` for `ExternalKms`. |
| `KBS_RESOURCE_STORAGE_MAX_BUFFER_SIZE` | Overrides `max_buffer_size` for `ExternalKms`. |
| `KBS_RESOURCE_STORAGE_ERROR_BUFFER_SIZE` | Overrides `error_buffer_size` for `ExternalKms`. |

Aliyun backend fields can be overridden with the following variables:

| Environment Variable | Description |
|----------------------|-------------|
| `KBS_RESOURCE_STORAGE_ALIYUN_CLIENT_KEY` | Overrides `client_key`. |
| `KBS_RESOURCE_STORAGE_ALIYUN_KMS_INSTANCE_ID` | Overrides `kms_instance_id`. |
| `KBS_RESOURCE_STORAGE_ALIYUN_PASSWORD` | Overrides `password`. |
| `KBS_RESOURCE_STORAGE_ALIYUN_CERT_PEM` | Overrides `cert_pem`. |
| `KBS_RESOURCE_STORAGE_ALIYUN_ACCESS_KEY_ID` | Overrides `access_key_id`. |
| `KBS_RESOURCE_STORAGE_ALIYUN_ACCESS_KEY_SECRET` | Overrides `access_key_secret`. |
| `KBS_RESOURCE_STORAGE_ALIYUN_REGION_ID` | Overrides `region_id`. |
| `KBS_RESOURCE_STORAGE_ALIYUN_ENDPOINT` | Overrides `endpoint`. |
| `KBS_RESOURCE_STORAGE_ALIYUN_INSECURE_SKIP_TLS_VERIFY` | Overrides `insecure_skip_tls_verify`; use `true` or `false`. |

Example:

```shell
export KBS_RESOURCE_STORAGE_TYPE=ExternalKms
export KBS_RESOURCE_STORAGE_LIBRARY_PATH=/opt/trustee/kbs/libkms_provider.so
export KBS_RESOURCE_STORAGE_INITIAL_BUFFER_SIZE=4096
export KBS_RESOURCE_STORAGE_MAX_BUFFER_SIZE=1048576
export KBS_RESOURCE_STORAGE_ERROR_BUFFER_SIZE=1024
```

**`LocalFs` Properties**

| Property   | Type   | Description                     | Required | Default                                             |
|------------|--------|---------------------------------|----------|-----------------------------------------------------|
| `dir_path` | String | Path to a repository directory. | No       | `/opt/confidential-containers/kbs/repository`       |

**`EncryptedLocalFs` Properties**

The `EncryptedLocalFs` backend stores resources on the local filesystem as
RSA + AES-256-GCM encrypted envelopes and transparently decrypts them on read.
It is guarded by the Cargo feature `encrypted-local-fs`. See
[Resource Storage Backend](./resource_storage_backend.md#encrypted-local-file-system-backend)
for the envelope format, and
[Encrypted Local FS Key Rotation](./encrypted_local_fs_key_rotation.md) for the
rotation procedure.

By default KBS manages the keys itself (no key configuration needed): it
generates a key pair into `key_dir` on first start and rotates keys via the
`rotate` API. Alternatively, bring your own keys with `private_key_path` /
`private_key_dir` / `private_key_paths`.

| Property            | Type           | Description                                                                                                                                  | Required | Default                                             |
|---------------------|----------------|----------------------------------------------------------------------------------------------------------------------------------------------|----------|-----------------------------------------------------|
| `dir_path`          | String         | Path to a repository directory.                                                                                                              | No       | `/opt/confidential-containers/kbs/repository`       |
| `key_dir`           | String         | KBS-managed key store directory. KBS generates and rotates RSA keys here itself. Active when set, or when no other key is configured.        | No       | `/opt/confidential-containers/kbs/resource-keys` (when managed) |
| `private_key_path`  | String         | Bring-your-own primary RSA private key (PEM, PKCS#8 or PKCS#1). Primary / re-wrap target when no managed key store is in effect.             | No\*     | None                                                |
| `private_key_dir`   | String         | Bring-your-own directory of additional RSA private keys (`*.pem`), retained for decryption so previously encrypted resources still decrypt.   | No\*     | None                                                |
| `private_key_paths` | Array\<String> | Additional bring-your-own RSA private keys given as explicit paths.                                                                          | No\*     | `[]`                                                |

\* If none of `key_dir` / `private_key_path` / `private_key_dir` /
`private_key_paths` is set, KBS runs in managed mode at the default `key_dir`
and generates a key pair on first start.

Keys can be rotated at runtime, without a restart, through admin-authenticated
endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/kbs/v0/resource/rotate` | POST | **Managed keys, one-shot.** Generate a new key pair, re-wrap all resources onto it, and retire the old key. Returns `{ "public_key", "rewrapped", "skipped", "failed", "retired_keys" }`. |
| `/kbs/v0/resource/pubkey` | GET  | Return the current primary public key (PEM) for clients to encrypt with. |
| `/kbs/v0/resource/reload` | POST | Re-read the configured keys and swap the key ring atomically. Returns `{ "reloaded_keys": <n> }`. |
| `/kbs/v0/resource/rewrap` | POST | Re-wrap every resource's CEK onto the current primary key (no new key generated). Returns `{ "total", "rewrapped", "skipped", "failed" }`. |

See [EncryptedLocalFs Key Rotation](./encrypted_local_fs_key_rotation.md) for the
full procedure.

**`EncryptedDb` Properties**

The `EncryptedDb` backend stores both wrap keys and resource envelopes in a
shared SQL database (MySQL or SQLite) so that multiple KBS replicas can share
one consistent set of managed keys. Wrap private keys are encrypted at rest
under a deployment-level master secret derived from a passphrase via Argon2id.
It is guarded by the Cargo feature `encrypted-db`. See
[EncryptedDb Resource Backend](./resource_storage_backend_encrypted_db.md) for
the design and
[EncryptedDb Key Rotation](./encrypted_db_key_rotation.md) for the operational
procedures (rotation, purge, multi-replica considerations).

| Property                | Type   | Description                                                                                                                                | Required | Default                                |
|-------------------------|--------|--------------------------------------------------------------------------------------------------------------------------------------------|----------|----------------------------------------|
| `master_secret_path`    | String | Path to the file holding the master passphrase (typically a Kubernetes Secret mounted as a tmpfs file).                                    | No       | `/run/trustee/master.passphrase`       |
| `bump_poll_interval_ms` | Number | Throttle for the cheap `SELECT bump` poll that detects another replica's rotation. Smaller values mean faster propagation, more DB traffic. | No       | `5000`                                 |

The database connection settings are nested under `[plugins.database]`:

| Property                  | Type   | Description                                                                                                                                                                            | Required                | Default |
|---------------------------|--------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------|---------|
| `type`                    | String | `"mysql"` or `"sqlite"`.                                                                                                                                                              | Yes                     | —       |
| `dsn`                     | String | SQLx MySQL DSN (`mysql://user:pass@host:port/db?...`).                                                                                                                                | Yes for `mysql`         | —       |
| `path`                    | String | SQLite file path. `":memory:"` is allowed for ephemeral testing only.                                                                                                                  | Yes for `sqlite`        | —       |
| `max_open_conns`          | Number | Pool maximum connections.                                                                                                                                                              | No                      | `0` (unbounded) |
| `max_idle_conns`          | Number | Pool warm-pool floor (minimum idle connections).                                                                                                                                       | No                      | `0`     |
| `conn_max_lifetime`       | String | Humantime-style duration (`"1h"`, `"30m"`).                                                                                                                                            | No                      | `""` (driver default) |
| `retired_key_purge_after` | String | Grace period a retired key is kept in the database before being physically deleted. `"0"` disables purging. Minimum non-zero value is `"1h"`.                                          | No                      | `"30d"` |

Example:

```toml
[[plugins]]
name = "resource"
type = "EncryptedDb"
master_secret_path = "/run/trustee/master.passphrase"
bump_poll_interval_ms = 5000

  [plugins.database]
  type = "mysql"
  dsn  = "mysql://kbs:****@db-host:3306/trustee_kbs?ssl-mode=PREFERRED"
  max_open_conns = 20
  max_idle_conns = 5
  conn_max_lifetime = "1h"
  retired_key_purge_after = "30d"
```

The same `/kbs/v0/resource/rotate`, `/pubkey`, `/reload`, `/rewrap` admin API
applies (see the table for `EncryptedLocalFs` above). The rotate response on
`EncryptedDb` includes an additional `purged_keys` field.

**`Aliyun` Properties**

The Aliyun backend reads KBS resources from Aliyun KMS generic secrets. It
supports AAP client key authentication and AccessKey authentication.

| Property                   | Type    | Description                                                                                                                                      | Required | Example                                             |
|----------------------------|---------|--------------------------------------------------------------------------------------------------------------------------------------------------|----------|-----------------------------------------------------|
| `client_key`               | String  | The KMS instance's AAP client key                                                                                                                | No       | `{"KeyId": "KA..", "PrivateKeyData": "MIIJqwI..."}` |
| `kms_instance_id`          | String  | The KMS instance id                                                                                                                              | No       | `kst-shh668f7...`                                   |
| `password`                 | String  | AAP client key password                                                                                                                          | No       | `8f9989c18d27...`                                   |
| `access_key_id`            | String  | AccessKey ID. The recommended approach is to omit this field and set `ALIYUN_KMS_ACCESS_KEY_ID` in the environment.                              | No       | `LTAI...`                                           |
| `access_key_secret`        | String  | AccessKey Secret. The recommended approach is to omit this field and set `ALIYUN_KMS_ACCESS_KEY_SECRET` in the environment.                      | No       | `secret...`                                         |
| `region_id`                | String  | Region ID used by AccessKey authentication. The recommended approach is to omit this field and set `ALIYUN_KMS_REGION_ID` in the environment.    | No       | `cn-hangzhou`                                       |
| `endpoint`                 | String  | Optional KMS endpoint. If omitted, KBS uses the public cloud defaults: `{kms_instance_id}.cryptoservice.kms.aliyuncs.com` for AAP or `kms.{region_id}.aliyuncs.com` for AccessKey. Private cloud deployments should set the intranet endpoint provided by the KMS owner. | No       | `kms-intranet.cn-test.example.com`                  |
| `cert_pem`                 | String  | CA cert used to verify the KMS HTTPS endpoint. For AAP authentication this is the KMS instance CA cert. For private cloud AccessKey authentication, set this when the endpoint uses a private CA. | No       | `-----BEGIN CERTIFICATE----- ...`                   |
| `insecure_skip_tls_verify` | Boolean | Skip HTTPS certificate verification. This should only be used for development or temporary private cloud tests.                                 | No       | `false`                                             |

If the AAP client key fields above are not fully provided, KBS will fall back to
AccessKey authentication. For AccessKey authentication, the recommended approach
is to provide credentials through the following environment variables so secrets
do not need to be stored in the KBS config file:

| Environment Variable            | Description                          |
|---------------------------------|--------------------------------------|
| `ALIYUN_KMS_ACCESS_KEY_ID`      | AccessKey ID                         |
| `ALIYUN_KMS_ACCESS_KEY_SECRET`  | AccessKey Secret                     |
| `ALIYUN_KMS_REGION_ID`          | Region ID (e.g. `cn-hangzhou`)       |

Private cloud AccessKey example:

```toml
[[plugins]]
name = "resource"
type = "Aliyun"
endpoint = "kms-intranet.cn-test.example.com"
cert_pem = """-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----"""
```

Set the credentials and region in the KBS process environment:

```shell
export ALIYUN_KMS_ACCESS_KEY_ID="LTAI..."
export ALIYUN_KMS_ACCESS_KEY_SECRET="secret..."
export ALIYUN_KMS_REGION_ID="cn-test"
```

Private cloud AAP client key example:

```toml
[[plugins]]
name = "resource"
type = "Aliyun"
client_key = """{"KeyId":"KA...","PrivateKeyData":"..."}"""
kms_instance_id = "kst-..."
password = "..."
endpoint = "kst-....cryptoservice.kms-private.example.com"
cert_pem = """-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----"""
```

**`ExternalKms` Properties**

| Property              | Type    | Description                                                   | Required | Default                                      |
|-----------------------|---------|---------------------------------------------------------------|----------|----------------------------------------------|
| `library_path`        | String  | Path to the provider shared library (.so).                     | No       | `/opt/trustee/kbs/libkms_provider.so`        |
| `initial_buffer_size` | Integer | Initial buffer size (bytes) for secret data.                   | No       | `4096`                                       |
| `max_buffer_size`     | Integer | Max buffer size (bytes) for secret data.                       | No       | `1048576`                                    |
| `error_buffer_size`   | Integer | Buffer size (bytes) for error messages from the provider.      | No       | `1024`                                       |

#### TPM Private CA Configuration

The TPM Private CA plugin can be enabled by adding the following to the KBS config.

```yaml
[[plugins]]
name = "tpm-pca"
```

Detailed [documentation](#kbs/docs/plugins/tpm_pca.md).

#### Nebula CA Configuration

The Nebula CA plugin can be enabled by adding the following to the KBS config.

```yaml
[[plugins]]
name = "nebula-ca"
```

The properties below can be used to further configure the plugin. They are optional.

| Property               | Type   | Description                       | Default |
|------------------------|--------|-----------------------------------|----------|
| `nebula_cert_bin_path` | String | `nebula-cert` binary path | If not provided, `nebula-cert` will be searched in $PATH |
| `work_dir`             | String | This plugin work directory, it requires `rw` permission | `/opt/confidential-containers/kbs/nebula-ca` |
| `[plugins.self_signed_ca]` | SubSection | Properties used to create the Nebula CA key and certificate | See table below |

The properties below can be defined under `[plugins.self_signed_ca]` to override their default value. They are optional.

| Property            | Type    | Description                       | Default | Example                                   |
|---------------------|---------|-----------------------------------|----------|-----------------------------------------------------|
| `name`              | String  | Name of the certificate authority | `Trustee Nebula CA plugin`        | |
| `argon_iterations`  | Integer | Argon2 iterations parameter used for encrypted private key passphrase | 1 | |
| `argon_memory`      | Integer | Argon2 memory parameter (in KiB) used for encrypted private key passphrase | 2097152 | |
| `argon_parallelism` | Integer | Argon2 parallelism parameter used for encrypted private key passphrase | 4 | |
| `curve`             | String  | EdDSA/ECDSA Curve (25519, P256) | `25519` | |
| `duration`          | String  | Amount of time the certificate should be valid for. Valid time units are: <hours>"h"<minutes>"m"<seconds>"s" | `8760h0m0s` | |
| `groups`            | String  | Comma separated list of groups. This will limit which groups subordinate certs can use | "" | `server,ssh` |
| `ips`               | String  | Comma separated list of ipv4 address and network in CIDR notation. This will limit which ipv4 addresses and networks subordinate certs can use for ip addresses | "" | `192.168.100.10/24,192.168.100.15/24` |
| `out_qr`            | String  | Path to write a QR code image (png) of the certificate | | `/opt/confidential-containers/kbs/nebula-ca/ca/ca_qr.crt`|
| `subnets`           | String  | Comma separated list of ipv4 address and network in CIDR notation. This will limit which ipv4 addresses and networks subordinate certs can use in subnets | "" | `192.168.86.0/24` |

The Nebula CA key and certificate are stored in `${work_dir}/ca/ca.{key,crt}`. If these files were generated in a previous run or [generated out-of-band](https://nebula.defined.net/docs/guides/quick-start/#creating-your-first-certificate-authority), the plugin will just (re-)use them; otherwise, the plugin will generate new ones by calling the `nebula-cert` binary with the `[plugins.self_signed_ca]` properties.

Detailed [documentation](#kbs/docs/plugins/nebula_ca.md).

## Configuration Examples

Using a built-in CoCo AS:

```toml
[http_server]
sockets = ["0.0.0.0:8080"]
insecure_http = true

[admin]
insecure_api = true

[attestation_token]

[attestation_service]
type = "coco_as_builtin"
work_dir = "/opt/confidential-containers/attestation-service"
policy_engine = "opa"

[attestation_service.attestation_token_broker]
type = "Ear"
duration_min = 5

[attestation_service.rvps_config]
type = "BuiltIn"

[attestation_service.rvps_config.storage]
type = "LocalFs"

[[plugins]]
name = "resource"
type = "LocalFs"
dir_path = "/opt/confidential-containers/kbs/repository"
```

Using a remote CoCo AS:

```toml
[http_server]
insecure_http = true

[admin]
insecure_api = true

[attestation_service]
type = "coco_as_grpc"
as_addr = "http://127.0.0.1:50004"

[[plugins]]
name = "resource"
type = "LocalFs"
dir_path = "/opt/confidential-containers/kbs/repository"
```

Using Nebula CA plugin:

```toml
[http_server]
sockets = ["0.0.0.0:8080"]
insecure_http = true

[admin]
insecure_api = true

[attestation_token]

[attestation_service]
type = "coco_as_builtin"
work_dir = "/opt/confidential-containers/attestation-service"
policy_engine = "opa"

[attestation_service.attestation_token_broker]
type = "Ear"
duration_min = 5

[attestation_service.rvps_config]
type = "BuiltIn"

[attestation_service.rvps_config.storage]
type = "LocalFs"

[[plugins]]
name = "resource"
type = "LocalFs"
dir_path = "/opt/confidential-containers/kbs/repository"

[[plugins]]
name = "nebula-ca"
# If the Nebula CA key and certificate don't exist yet, the plugin will create them
# using the default configurations, which can be overriden here,
# e.g. the duration of the root CA.
#[plugin.self_signed_ca]
#duration = "4380hm0s0"
```

Distributing resources in Passport mode:

```toml
[http_server]
sockets = ["127.0.0.1:50002"]
insecure_http = true

[admin]
auth_public_key = "./work/kbs.pem"

[attestation_token]
trusted_certs_paths = ["./work/ca-cert.pem"]
insecure_key = false

[policy_engine]
policy_path = "./work/kbs-policy.rego"

[[plugins]]
name = "resource"
type = "LocalFs"
dir_path = "./work/repository"
```
