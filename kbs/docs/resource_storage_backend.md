# Resource Storage Backend 

KBS stores confidential resources through a `StorageBackend` abstraction specified
by a Rust trait. The `StorageBackend` interface can be implemented for different
storage backends like e.g. databases or local file systems.

The [KBS config file](./config.md)
defines which resource backend KBS will use. The default is the local
file system (`LocalFs`).

The resource backend can also be overridden by environment variables. These
variables are applied after the config file is loaded, so they take precedence
over the `[[plugins]] name = "resource"` section. Set
`KBS_RESOURCE_STORAGE_TYPE` to replace the backend type or to create the
resource plugin when the config file does not define one.

Common variables:

| Environment Variable | Description |
| -------------------- | ----------- |
| `KBS_RESOURCE_STORAGE_TYPE` | Backend type: `LocalFs`, `EncryptedLocalFs`, `Aliyun`, or `ExternalKms`. |
| `KBS_RESOURCE_STORAGE_DIR_PATH` | `dir_path` for `LocalFs` and `EncryptedLocalFs`. |
| `KBS_RESOURCE_STORAGE_PRIVATE_KEY_PATH` | `private_key_path` for `EncryptedLocalFs`. |

External KMS variables:

| Environment Variable | Description |
| -------------------- | ----------- |
| `KBS_RESOURCE_STORAGE_LIBRARY_PATH` | Provider shared library path. |
| `KBS_RESOURCE_STORAGE_INITIAL_BUFFER_SIZE` | Initial secret buffer size in bytes. |
| `KBS_RESOURCE_STORAGE_MAX_BUFFER_SIZE` | Maximum secret buffer size in bytes. |
| `KBS_RESOURCE_STORAGE_ERROR_BUFFER_SIZE` | Error buffer size in bytes. |

Aliyun variables use the `KBS_RESOURCE_STORAGE_ALIYUN_` prefix for backend
fields such as `ENDPOINT`, `CERT_PEM`, `CLIENT_KEY`, `KMS_INSTANCE_ID`,
`PASSWORD`, `ACCESS_KEY_ID`, `ACCESS_KEY_SECRET`, `REGION_ID`, and
`INSECURE_SKIP_TLS_VERIFY`. The existing `ALIYUN_KMS_ACCESS_KEY_ID`,
`ALIYUN_KMS_ACCESS_KEY_SECRET`, and `ALIYUN_KMS_REGION_ID` variables are still
supported as AccessKey fallback credentials when those fields are omitted.

### Local File System Backend

With the local file system backend default implementation, each resource
file maps to a KBS resource URL. The file path to URL conversion scheme is
defined below:

| Resource File Path  | Resource URL |
| ------------------- | -------------- |
| `file://<$(KBS_REPOSITORY_DIR)>/<repository_name>/<type>/<tag>`  |  `https://<kbs_address>/kbs/v0/resource/<repository_name>/<type>/<tag>`  |

The KBS root file system resource path is specified in the KBS config file
as well, and the default value is `/opt/confidential-containers/kbs/repository`.

### Encrypted Local File System Backend

The encrypted local backend (`EncryptedLocalFs`) keeps resources on the local
filesystem. Reads attempt to decrypt with the configured RSA private key ring
(one or more keys); the first key able to decrypt a resource is used. If the
payload is not in the expected encrypted format, it is returned as-is
(plaintext passthrough). If the payload *is* an encrypted envelope but none of
the configured keys can decrypt it, the read fails (the ciphertext is never
returned as plaintext).

**Payload format (JSON, Base64 fields)**
```
{
  "alg": "RSA-OAEP-256",        # or "RSA1_5" (deprecated)
  "enc_key": "<base64 RSA-encrypted CEK>",
  "iv": "<base64 12-byte GCM nonce>",
  "ciphertext": "<base64 ciphertext>",
  "tag": "<base64 16-byte GCM tag>"
}
```

**Encryption steps (client side)**
1) Generate a 32-byte CEK (AES-256-GCM) and a 12-byte IV (nonce).
2) Encrypt plaintext with AES-GCM (no AAD) to get ciphertext and a 16-byte tag.
3) Encrypt the CEK with the RSA public key using RSA-OAEP-256 (or RSA1_5, not recommended) to get `enc_key`.
4) Base64-encode `enc_key` / `iv` / `ciphertext` / `tag`, then store them in the JSON above as the resource file.
5) A ready-to-use helper script is available at `kbs/sdk/python/encrypt_resource.py`.

**Runtime behavior**
- Read: If the payload parses as the JSON above, it will be decrypted; otherwise it is returned verbatim (plaintext).
- Write: Same as `LocalFs`; no encryption is performed on write.

This backend is guarded by the Cargo feature `encrypted-local-fs`. Enable it
when building KBS to use this backend.

**Key management: KBS-managed (default) or bring-your-own**

By default KBS manages the RSA keys itself, so operators never have to generate
keys or edit config to rotate them:

- On first start KBS generates an RSA key pair into the managed key store
  (`key_dir`, default `/opt/confidential-containers/kbs/resource-keys`).
- Clients fetch the current public key from `GET /kbs/v0/resource/pubkey` and
  encrypt resources with it.
- A single `POST /kbs/v0/resource/rotate` performs the entire rotation
  server-side (see below).

```
[[plugins]]
name = "resource"
type = "EncryptedLocalFs"
dir_path = "/opt/confidential-containers/kbs/repository"
# key_dir defaults to /opt/confidential-containers/kbs/resource-keys; set it to override.
```

Alternatively, bring your own keys: set `private_key_path` (primary / re-wrap
target), and optionally `private_key_dir` / `private_key_paths` for additional
decryption keys. Bring-your-own keys can also coexist with a managed `key_dir`
as decrypt-only sources (useful when migrating to managed keys).

```
[[plugins]]
name = "resource"
type = "EncryptedLocalFs"
dir_path = "/opt/confidential-containers/kbs/repository"
private_key_path = "/etc/kbs/resource-keys/primary.pem"
private_key_dir  = "/etc/kbs/resource-keys/archive"
```

**Key rotation (admin API)**

Because the CEK is wrapped with an RSA public key, decryption requires the
matching private key. KBS holds a *ring* of decryption keys (the newest managed
key, or the bring-your-own primary, is tried first and is the re-wrap target),
so resources encrypted with an old key keep working while a new key is adopted.
Rotation runs with **no downtime, no manual file migration, and no config
edits**, through admin-authenticated endpoints:

- **One-shot rotate (managed keys).** `POST /kbs/v0/resource/rotate` generates a
  new key pair, re-wraps every resource onto it, and retires the old key — all
  server-side in one call. Returns `{ "public_key", "rewrapped", "skipped",
  "failed", "retired_keys" }`. If any resource fails to re-wrap, the old key is
  *kept* (not retired) so it stays decryptable. After rotation, read the new key
  from `GET /kbs/v0/resource/pubkey`.
- **Get public key.** `GET /kbs/v0/resource/pubkey` returns the current primary
  public key (PEM), for clients to encrypt with.
- **Hot reload.** `POST /kbs/v0/resource/reload` re-reads the configured keys
  (`key_dir`, `private_key_path`, `private_key_dir`, `private_key_paths`) and
  swaps the ring atomically without a restart.
- **Server-side re-wrap.** `POST /kbs/v0/resource/rewrap` re-wraps every resource
  onto the current primary key without generating a new one. Only the
  `enc_key`/`alg` envelope fields change; the AES-256-GCM ciphertext is
  untouched. Useful for bring-your-own-key rotations.

For the full step-by-step procedures, see
[EncryptedLocalFs Key Rotation](./encrypted_local_fs_key_rotation.md).
`kbs/sdk/python/reencrypt_resource.py` remains available for out-of-band
migration when the repository is not writable by KBS.

### Aliyun KMS

[Alibaba Cloud KMS](https://www.alibabacloud.com/en/product/kms?_p_lc=1)(a.k.a Aliyun KMS)
can also work as the KBS resource storage backend.
In this mode, resources will be stored with [generic secrets](https://www.alibabacloud.com/help/en/kms/user-guide/manage-and-use-generic-secrets?spm=a2c63.p38356.0.0.dc4d24f7s0ZuW7) in a [KMS instance](https://www.alibabacloud.com/help/en/kms/user-guide/kms-overview?spm=a2c63.p38356.0.0.4aacf9e6V7IQGW).
One KBS can be configured with a specified KMS instance by setting a
`[[plugins]]` section whose `name` is `resource` and whose `type` is `Aliyun`.
For config, see the [document](./config.md#resource-configuration).

The Aliyun backend supports two authentication modes:
- AAP client key authentication with `client_key`, `kms_instance_id`,
  `password`, and `cert_pem`. These materials can be found in the KMS
  instance's [AAP](https://www.alibabacloud.com/help/en/kms/user-guide/manage-aaps?spm=a3c0i.23458820.2359477120.1.4fd96e9bmEFST4).
- AccessKey authentication. The recommended approach is to set
  `ALIYUN_KMS_ACCESS_KEY_ID`, `ALIYUN_KMS_ACCESS_KEY_SECRET`, and
  `ALIYUN_KMS_REGION_ID` in the KBS process environment. The config file fields
  `access_key_id`, `access_key_secret`, and `region_id` are also supported for
  compatibility and local experiments.

Public cloud deployments can omit `endpoint` and use the built-in Aliyun public
cloud endpoint conventions. Private cloud deployments should set `endpoint` to
the KMS intranet endpoint provided by the private cloud KMS owner. If the private
cloud endpoint uses a private CA, set `cert_pem` to the CA certificate. The
`insecure_skip_tls_verify` option is available for temporary test environments
where the private cloud certificate cannot yet be trusted.

When being accessed, a resource URI of `kbs:///repo/type/tag` will be translated
into the generic secret with name `tag`. This means that the `repo/type` fields
will be ignored by the Aliyun backend.

### External KMS (Dynamic Provider)

The external KMS backend (`ExternalKms`) dynamically loads a provider shared library
and delegates secret retrieval to it at runtime. The library is loaded with no
compile-time dependency, which makes it suitable for integrating custom KMS
implementations without rebuilding KBS.

At read time, a resource URI of `kbs:///repo/type/tag` is translated into a secret
name `tag`. The `repo/type` fields are ignored.

Notes:
- Only read is supported. Write, delete, and list operations will return errors.
- The provider library is expected to export the `kms_provider_*` C APIs.

Config example:

```
[[plugins]]
name = "resource"
type = "ExternalKms"
library_path = "/opt/trustee/kbs/libkms_provider.so"
initial_buffer_size = 4096
max_buffer_size = 1048576
error_buffer_size = 1024
```
