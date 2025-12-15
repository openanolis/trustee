# Resource Storage Backend 

KBS stores confidential resources through a `StorageBackend` abstraction specified
by a Rust trait. The `StorageBackend` interface can be implemented for different
storage backends like e.g. databases or local file systems.

The [KBS config file](./config.md)
defines which resource backend KBS will use. The default is the local
file system (`LocalFs`).

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
filesystem. Reads attempt to decrypt with a configured RSA private key; if the
payload is not in the expected encrypted format, it is returned as-is
(plaintext passthrough).

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

Config example:

```
[[plugins]]
name = "resource"
type = "EncryptedLocalFs"
dir_path = "/opt/confidential-containers/kbs/repository"
private_key_path = "/etc/kbs/resource-private.pem"
```

### Aliyun KMS

[Alibaba Cloud KMS](https://www.alibabacloud.com/en/product/kms?_p_lc=1)(a.k.a Aliyun KMS)
can also work as the KBS resource storage backend.
In this mode, resources will be stored with [generic secrets](https://www.alibabacloud.com/help/en/kms/user-guide/manage-and-use-generic-secrets?spm=a2c63.p38356.0.0.dc4d24f7s0ZuW7) in a [KMS instance](https://www.alibabacloud.com/help/en/kms/user-guide/kms-overview?spm=a2c63.p38356.0.0.4aacf9e6V7IQGW).
One KBS can be configured with a specified KMS instance in `repository_config` field of KBS launch config. For config, see the [document](./config.md#repository-configuration).
These materials can be found in KMS instance's [AAP](https://www.alibabacloud.com/help/en/kms/user-guide/manage-aaps?spm=a3c0i.23458820.2359477120.1.4fd96e9bmEFST4).
When being accessed, a resource URI of `kbs:///repo/type/tag` will be translated into the generic secret with name `tag`. Hinting that `repo/type` field will be ignored.
