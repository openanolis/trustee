// Copyright (c) 2025 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use super::{
    local_fs::{LocalFs, LocalFsRepoDesc},
    ResourceDesc, RewrapReport, StorageBackend,
};
use aes_gcm::{
    aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rsa::sha2::Sha256;
use rsa::{
    pkcs1::DecodeRsaPrivateKey, pkcs8::DecodePrivateKey, Oaep, Pkcs1v15Encrypt, RsaPrivateKey,
    RsaPublicKey,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

const ALG_RSA1_5: &str = "RSA1_5";
const ALG_RSA_OAEP_256: &str = "RSA-OAEP-256";
const AES_GCM_KEY_LEN: usize = 32;
const AES_GCM_TAG_LEN: usize = 16;
const AES_GCM_NONCE_LEN: usize = 12;

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
struct Envelope {
    /// Algorithm: support RSA1_5 or RSA-OAEP-256
    pub alg: String,
    /// Encrypted CEK with public key (base64)
    pub enc_key: String,
    /// AES-GCM nonce (base64)
    pub iv: String,
    /// AES-GCM ciphertext (base64)
    pub ciphertext: String,
    /// AES-GCM tag (base64)
    pub tag: String,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Default)]
pub struct EncryptedLocalFsRepoDesc {
    #[serde(default)]
    pub dir_path: String,
    /// Primary (current) RSA private key. Tried first when decrypting, and used
    /// as the target key when re-wrapping resources. Its file is read fresh on
    /// every key reload, so rotating the primary key is just a matter of
    /// replacing this file and reloading.
    #[serde(default)]
    pub private_key_path: String,
    /// A directory of additional RSA private keys (`*.pem`). All keys found here
    /// are kept available for decryption, so resources encrypted with a previous
    /// key keep working during a rotation. Dropping a retired key into this
    /// directory (and reloading) needs no config change or restart.
    #[serde(default)]
    pub private_key_dir: String,
    /// Additional RSA private keys given as explicit paths. Equivalent to
    /// `private_key_dir` but for keys that live outside a single directory.
    #[serde(default)]
    pub private_key_paths: Vec<String>,
}

/// The set of places keys are loaded from. Held so the key ring can be rebuilt
/// on a hot reload without re-reading the whole KBS config.
struct KeySources {
    primary_path: String,
    dir: String,
    extra_paths: Vec<String>,
}

/// A loaded, immutable snapshot of the decryption keys. Swapped atomically on
/// reload.
struct KeyRing {
    /// Decryption keys, in the order they are tried. When a primary key is
    /// configured it is `keys[0]`.
    keys: Vec<RsaPrivateKey>,
    /// Public key of the primary private key, used as the re-wrap target. `None`
    /// when no `private_key_path` is configured.
    primary_public: Option<RsaPublicKey>,
}

pub struct EncryptedLocalFs {
    inner: LocalFs,
    sources: KeySources,
    /// Hot-swappable key ring. Reads take a cheap snapshot (clone the `Arc`);
    /// reloads replace it wholesale.
    ring: RwLock<Arc<KeyRing>>,
}

#[async_trait::async_trait]
impl StorageBackend for EncryptedLocalFs {
    async fn read_secret_resource(&self, resource_desc: ResourceDesc) -> Result<Vec<u8>> {
        let raw = self.inner.read_secret_resource(resource_desc).await?;

        if let Some(plain) = self.try_decrypt(&raw)? {
            Ok(plain)
        } else {
            Ok(raw)
        }
    }

    async fn write_secret_resource(&self, resource_desc: ResourceDesc, data: &[u8]) -> Result<()> {
        self.inner.write_secret_resource(resource_desc, data).await
    }

    async fn delete_secret_resource(&self, resource_desc: ResourceDesc) -> Result<()> {
        self.inner.delete_secret_resource(resource_desc).await
    }

    async fn list_secret_resources(&self) -> Result<Vec<ResourceDesc>> {
        self.inner.list_secret_resources().await
    }

    async fn reload_keys(&self) -> Result<usize> {
        let ring = Self::load_ring(&self.sources)?;
        let count = ring.keys.len();
        *self.ring.write().expect("key ring lock poisoned") = Arc::new(ring);
        Ok(count)
    }

    async fn rewrap_resources(&self) -> Result<RewrapReport> {
        let ring = self.ring_snapshot();
        let primary_public = ring.primary_public.clone().ok_or_else(|| {
            anyhow!("cannot re-wrap: no primary key configured (set `private_key_path`)")
        })?;

        let mut report = RewrapReport::default();
        for desc in self.inner.list_secret_resources().await? {
            report.total += 1;
            match self
                .rewrap_one(&desc, &ring, &primary_public)
                .await
                .with_context(|| format!("re-wrap resource `{desc}`"))
            {
                Ok(true) => report.rewrapped += 1,
                Ok(false) => report.skipped += 1,
                Err(e) => {
                    report.failed += 1;
                    log::warn!("{e:#}");
                }
            }
        }
        Ok(report)
    }
}

impl EncryptedLocalFs {
    pub fn new(desc: &EncryptedLocalFsRepoDesc) -> Result<Self> {
        let sources = KeySources {
            primary_path: desc.private_key_path.clone(),
            dir: desc.private_key_dir.clone(),
            extra_paths: desc.private_key_paths.clone(),
        };

        let ring = Self::load_ring(&sources)?;

        let dir_path = if desc.dir_path.is_empty() {
            LocalFsRepoDesc::default().dir_path
        } else {
            desc.dir_path.clone()
        };
        let inner = LocalFs::new(&LocalFsRepoDesc { dir_path })?;

        Ok(Self {
            inner,
            sources,
            ring: RwLock::new(Arc::new(ring)),
        })
    }

    /// Build the key ring from the configured sources. The primary key is first
    /// (so it is tried first and is the re-wrap target), followed by the keys
    /// from `private_key_dir` and `private_key_paths`. Duplicate files are
    /// loaded once.
    fn load_ring(sources: &KeySources) -> Result<KeyRing> {
        let mut ordered_paths: Vec<String> = Vec::new();
        let mut seen: HashSet<PathBuf> = HashSet::new();
        let mut push = |path: &str, ordered: &mut Vec<String>| {
            if path.is_empty() {
                return;
            }
            let canonical = fs::canonicalize(path).unwrap_or_else(|_| PathBuf::from(path));
            if seen.insert(canonical) {
                ordered.push(path.to_string());
            }
        };

        push(&sources.primary_path, &mut ordered_paths);
        if !sources.dir.is_empty() {
            for path in Self::scan_key_dir(&sources.dir)? {
                push(&path, &mut ordered_paths);
            }
        }
        for path in &sources.extra_paths {
            push(path, &mut ordered_paths);
        }

        if ordered_paths.is_empty() {
            bail!(
                "at least one of `private_key_path`, `private_key_dir`, or `private_key_paths` is required for encrypted local fs backend"
            );
        }

        let keys = ordered_paths
            .iter()
            .map(|p| Self::load_private_key(p))
            .collect::<Result<Vec<_>>>()?;

        // The primary public key (re-wrap target) is the public part of the
        // primary private key, which is `keys[0]` iff a primary path is set.
        let primary_public = if sources.primary_path.is_empty() {
            None
        } else {
            Some(keys[0].to_public_key())
        };

        Ok(KeyRing {
            keys,
            primary_public,
        })
    }

    /// Return the `*.pem` files in a key directory, sorted for a deterministic
    /// load order.
    fn scan_key_dir(dir: &str) -> Result<Vec<String>> {
        let mut paths = Vec::new();
        let entries = fs::read_dir(dir).with_context(|| format!("read private key dir `{dir}`"))?;
        for entry in entries {
            let path = entry
                .with_context(|| format!("read entry in `{dir}`"))?
                .path();
            if path.extension().and_then(|e| e.to_str()) == Some("pem") && path.is_file() {
                paths.push(path.to_string_lossy().into_owned());
            }
        }
        paths.sort();
        Ok(paths)
    }

    fn ring_snapshot(&self) -> Arc<KeyRing> {
        self.ring.read().expect("key ring lock poisoned").clone()
    }

    fn load_private_key(path: &str) -> Result<RsaPrivateKey> {
        let pem =
            fs::read_to_string(path).with_context(|| format!("read private key file `{path}`"))?;

        RsaPrivateKey::from_pkcs8_pem(&pem)
            .or_else(|_| RsaPrivateKey::from_pkcs1_pem(&pem))
            .with_context(|| format!("parse RSA private key from PEM `{path}`"))
    }

    /// Re-wrap a single resource's CEK to `primary_public`. Returns `Ok(true)`
    /// if it was re-wrapped, `Ok(false)` if it was left untouched (plaintext, or
    /// already wrapped with the primary key).
    async fn rewrap_one(
        &self,
        desc: &ResourceDesc,
        ring: &KeyRing,
        primary_public: &RsaPublicKey,
    ) -> Result<bool> {
        let raw = self.inner.read_secret_resource(desc.clone()).await?;
        let Ok(env) = serde_json::from_slice::<Envelope>(&raw) else {
            return Ok(false); // not an envelope -> plaintext, leave as-is
        };

        let enc_key = Self::decode_b64("enc_key", &env.enc_key)?;
        let iv = Self::decode_b64("iv", &env.iv)?;
        let ciphertext = Self::decode_b64("ciphertext", &env.ciphertext)?;
        let tag = Self::decode_b64("tag", &env.tag)?;

        // `keys[0]` is the primary key here (rewrap_resources verified one
        // exists). If it already decrypts an OAEP envelope, the resource is
        // current; skip rewriting.
        if env.alg == ALG_RSA_OAEP_256 {
            if let Ok(cek) = Self::recover_cek(&ring.keys[0], &env.alg, &enc_key) {
                if Self::aes_decrypt(&cek, &iv, &ciphertext, &tag).is_ok() {
                    return Ok(false);
                }
            }
        }

        // Recover the CEK with whichever key works, verifying via the AES-GCM tag.
        let cek = ring
            .keys
            .iter()
            .find_map(|key| {
                let cek = Self::recover_cek(key, &env.alg, &enc_key).ok()?;
                Self::aes_decrypt(&cek, &iv, &ciphertext, &tag).ok()?;
                Some(cek)
            })
            .context("no configured key can decrypt this resource")?;

        // Re-wrap the same CEK with the primary public key (RSA-OAEP-256). The
        // RNG is scoped so the non-Send `ThreadRng` is dropped before the await.
        let new_enc_key = {
            let mut rng = rand::thread_rng();
            primary_public
                .encrypt(&mut rng, Oaep::new::<Sha256>(), &cek)
                .context("re-wrap CEK with primary public key")?
        };

        let new_env = Envelope {
            alg: ALG_RSA_OAEP_256.to_string(),
            enc_key: STANDARD.encode(new_enc_key),
            iv: env.iv,
            ciphertext: env.ciphertext,
            tag: env.tag,
        };
        let bytes = serde_json::to_vec(&new_env).context("serialize re-wrapped envelope")?;
        self.inner
            .write_secret_resource(desc.clone(), &bytes)
            .await?;
        Ok(true)
    }

    fn try_decrypt(&self, data: &[u8]) -> Result<Option<Vec<u8>>> {
        let env: Envelope = match serde_json::from_slice(data) {
            Ok(v) => v,
            Err(_) => return Ok(None), // 不是加密封装，按明文透传
        };

        self.decrypt_envelope(&env).map(Some)
    }

    /// Decode base64 field and add context to error
    fn decode_b64(name: &str, v: &str) -> Result<Vec<u8>> {
        STANDARD
            .decode(v)
            .with_context(|| format!("base64 decode `{name}`"))
    }

    fn decrypt_envelope(&self, env: &Envelope) -> Result<Vec<u8>> {
        // Key-independent decoding and validation. A failure here means the
        // envelope itself is malformed, so no key could ever decrypt it.
        let enc_key = Self::decode_b64("enc_key", &env.enc_key)?;
        let iv = Self::decode_b64("iv", &env.iv)?;
        let ciphertext = Self::decode_b64("ciphertext", &env.ciphertext)?;
        let tag = Self::decode_b64("tag", &env.tag)?;

        if !matches!(env.alg.as_str(), ALG_RSA1_5 | ALG_RSA_OAEP_256) {
            bail!("unsupported simple envelope alg `{}`", env.alg);
        }

        if tag.len() != AES_GCM_TAG_LEN {
            bail!(
                "unexpected GCM tag length {}, expect {} bytes",
                tag.len(),
                AES_GCM_TAG_LEN
            );
        }

        if iv.len() != AES_GCM_NONCE_LEN {
            bail!(
                "unexpected GCM nonce length {}, expect {} bytes",
                iv.len(),
                AES_GCM_NONCE_LEN
            );
        }

        // Try each key in the ring; the first one able to decrypt wins. This is
        // what allows resources encrypted with a previous key to keep working
        // after a key rotation. A wrong key is always rejected: RSA padding
        // fails, the CEK length check fails, or the AES-GCM tag check fails.
        let ring = self.ring_snapshot();
        let mut last_err = None;
        for key in &ring.keys {
            match Self::recover_cek(key, &env.alg, &enc_key)
                .and_then(|cek| Self::aes_decrypt(&cek, &iv, &ciphertext, &tag))
            {
                Ok(plaintext) => return Ok(plaintext),
                Err(e) => last_err = Some(e),
            }
        }

        Err(anyhow!(
            "failed to decrypt resource with any of the {} configured private key(s): {}",
            ring.keys.len(),
            last_err.expect("key ring is never empty")
        ))
    }

    /// Unwrap the content encryption key with one RSA private key. Does not
    /// verify the CEK is correct; the caller must confirm via the AES-GCM tag.
    fn recover_cek(private_key: &RsaPrivateKey, alg: &str, enc_key: &[u8]) -> Result<Vec<u8>> {
        let cek = match alg {
            ALG_RSA1_5 => private_key
                .decrypt(Pkcs1v15Encrypt, enc_key)
                .context("RSA1_5 decrypt content encryption key (simple envelope)")?,
            ALG_RSA_OAEP_256 => {
                let padding = Oaep::new::<Sha256>();
                private_key
                    .decrypt(padding, enc_key)
                    .context("RSA-OAEP-256 decrypt content encryption key (simple envelope)")?
            }
            _ => bail!("unsupported simple envelope alg `{alg}`"),
        };

        if cek.len() != AES_GCM_KEY_LEN {
            bail!(
                "unexpected CEK length {}, expect {} bytes for AES-256-GCM",
                cek.len(),
                AES_GCM_KEY_LEN
            );
        }

        Ok(cek)
    }

    /// AES-256-GCM decrypt the payload. A wrong CEK fails the authentication tag
    /// here, which is the final guarantee that only correctly decrypted data is
    /// ever returned.
    fn aes_decrypt(cek: &[u8], iv: &[u8], ciphertext: &[u8], tag: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(cek).context("build AES-256-GCM cipher with CEK")?;
        let nonce = Nonce::from_slice(iv);
        let mut plaintext = ciphertext.to_vec();
        let tag = GenericArray::from_slice(tag);

        cipher
            .decrypt_in_place_detached(nonce, b"", &mut plaintext, tag)
            .map_err(|e| {
                anyhow!("AES-256-GCM decrypt resource payload (simple envelope): {e:?}")
            })?;

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EncryptedLocalFs, EncryptedLocalFsRepoDesc, Envelope, ALG_RSA1_5, ALG_RSA_OAEP_256,
    };
    use aes_gcm::{aead::AeadInPlace, Aes256Gcm, KeyInit, Nonce};
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use openssl::rsa::Rsa;
    use rand::Rng;
    use rsa::sha2::Sha256;
    use rsa::{BigUint, Oaep, Pkcs1v15Encrypt, RsaPublicKey};
    use tempfile::tempdir;

    use super::ResourceDesc;
    use crate::plugins::implementations::resource::StorageBackend;

    const TEST_DATA: &[u8] = b"testdata";

    fn write_key(
        tmp_dir: &tempfile::TempDir,
        name: &str,
        rsa: &Rsa<openssl::pkey::Private>,
    ) -> String {
        let key_path = tmp_dir.path().join(name);
        std::fs::write(&key_path, rsa.private_key_to_pem().unwrap()).unwrap();
        key_path.to_string_lossy().into()
    }

    fn build_backend(
        tmp_dir: &tempfile::TempDir,
        rsa: &Rsa<openssl::pkey::Private>,
    ) -> EncryptedLocalFs {
        let key_path = write_key(tmp_dir, "rsa.pem", rsa);

        EncryptedLocalFs::new(&EncryptedLocalFsRepoDesc {
            dir_path: tmp_dir.path().to_string_lossy().into(),
            private_key_path: key_path,
            private_key_paths: vec![],
            ..Default::default()
        })
        .expect("create encrypted local fs backend")
    }

    fn encrypt_envelope(
        rsa: &Rsa<openssl::pkey::Private>,
        alg: &str,
        plaintext: &[u8],
    ) -> Envelope {
        let mut rng = rand::thread_rng();
        let cek = Aes256Gcm::generate_key(&mut rng);
        let iv: [u8; 12] = rng.gen();
        let nonce = Nonce::from_slice(&iv);

        let cipher = Aes256Gcm::new(&cek);
        let mut payload = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(nonce, b"", &mut payload)
            .expect("encrypt");

        let n = BigUint::from_bytes_be(rsa.n().to_vec().as_slice());
        let e = BigUint::from_bytes_be(rsa.e().to_vec().as_slice());
        let rsa_pub = RsaPublicKey::new(n, e).expect("build rsa public key");
        let encrypted_key = match alg {
            ALG_RSA1_5 => rsa_pub
                .encrypt(&mut rng, Pkcs1v15Encrypt, cek.as_slice())
                .expect("rsa1_5 encrypt cek"),
            ALG_RSA_OAEP_256 => {
                let padding = Oaep::new::<Sha256>();
                rsa_pub
                    .encrypt(&mut rng, padding, cek.as_slice())
                    .expect("rsa-oaep encrypt cek")
            }
            _ => unreachable!(),
        };

        Envelope {
            alg: alg.into(),
            enc_key: STANDARD.encode(encrypted_key),
            iv: STANDARD.encode(iv),
            ciphertext: STANDARD.encode(payload),
            tag: STANDARD.encode(tag),
        }
    }

    #[tokio::test]
    async fn decrypts_encrypted_resource() {
        let tmp_dir = tempdir().unwrap();
        let rsa = Rsa::generate(2048).unwrap();
        let backend = build_backend(&tmp_dir, &rsa);

        let resource_desc = ResourceDesc {
            repository_name: "default".into(),
            resource_type: "encrypted".into(),
            resource_tag: "secret".into(),
        };

        let encrypted = encrypt_envelope(&rsa, ALG_RSA_OAEP_256, TEST_DATA);
        let encrypted_bytes = serde_json::to_vec(&encrypted).unwrap();

        backend
            .write_secret_resource(resource_desc.clone(), &encrypted_bytes)
            .await
            .unwrap();

        let data = backend
            .read_secret_resource(resource_desc)
            .await
            .expect("decrypt resource");
        assert_eq!(data, TEST_DATA);
    }

    #[tokio::test]
    async fn passes_through_plaintext() {
        let tmp_dir = tempdir().unwrap();
        let rsa = Rsa::generate(2048).unwrap();
        let backend = build_backend(&tmp_dir, &rsa);

        let resource_desc = ResourceDesc {
            repository_name: "default".into(),
            resource_type: "plain".into(),
            resource_tag: "raw".into(),
        };

        backend
            .write_secret_resource(resource_desc.clone(), TEST_DATA)
            .await
            .unwrap();

        let data = backend.read_secret_resource(resource_desc).await.unwrap();

        assert_eq!(data, TEST_DATA);
    }

    fn resource_desc(tag: &str) -> ResourceDesc {
        ResourceDesc {
            repository_name: "default".into(),
            resource_type: "encrypted".into(),
            resource_tag: tag.into(),
        }
    }

    // A resource encrypted with an old key is still readable after rotation, as
    // long as the old key is kept in `private_key_paths`. The new (primary) key
    // is configured but does not match this resource.
    #[tokio::test]
    async fn decrypts_with_rotated_old_key() {
        let tmp_dir = tempdir().unwrap();
        let old_rsa = Rsa::generate(2048).unwrap();
        let new_rsa = Rsa::generate(2048).unwrap();

        let backend = EncryptedLocalFs::new(&EncryptedLocalFsRepoDesc {
            dir_path: tmp_dir.path().to_string_lossy().into(),
            private_key_path: write_key(&tmp_dir, "new.pem", &new_rsa),
            private_key_paths: vec![write_key(&tmp_dir, "old.pem", &old_rsa)],
            ..Default::default()
        })
        .expect("create backend with rotated key ring");

        let desc = resource_desc("legacy");
        let encrypted = encrypt_envelope(&old_rsa, ALG_RSA_OAEP_256, TEST_DATA);
        backend
            .write_secret_resource(desc.clone(), &serde_json::to_vec(&encrypted).unwrap())
            .await
            .unwrap();

        let data = backend
            .read_secret_resource(desc)
            .await
            .expect("legacy resource must decrypt with the retained old key");
        assert_eq!(data, TEST_DATA);
    }

    // Within a single key ring, resources encrypted with either key both decrypt
    // regardless of which key is primary.
    #[tokio::test]
    async fn decrypts_with_either_key_in_ring() {
        let tmp_dir = tempdir().unwrap();
        let rsa_a = Rsa::generate(2048).unwrap();
        let rsa_b = Rsa::generate(2048).unwrap();

        let backend = EncryptedLocalFs::new(&EncryptedLocalFsRepoDesc {
            dir_path: tmp_dir.path().to_string_lossy().into(),
            private_key_path: write_key(&tmp_dir, "a.pem", &rsa_a),
            private_key_paths: vec![write_key(&tmp_dir, "b.pem", &rsa_b)],
            ..Default::default()
        })
        .expect("create backend");

        for (tag, rsa) in [("with-a", &rsa_a), ("with-b", &rsa_b)] {
            let desc = resource_desc(tag);
            let encrypted = encrypt_envelope(rsa, ALG_RSA_OAEP_256, TEST_DATA);
            backend
                .write_secret_resource(desc.clone(), &serde_json::to_vec(&encrypted).unwrap())
                .await
                .unwrap();
            let data = backend.read_secret_resource(desc).await.expect("decrypt");
            assert_eq!(data, TEST_DATA);
        }
    }

    // A resource whose key is in none of the configured keys must error, not be
    // returned as ciphertext-as-plaintext.
    #[tokio::test]
    async fn errors_when_no_key_matches() {
        let tmp_dir = tempdir().unwrap();
        let configured_rsa = Rsa::generate(2048).unwrap();
        let foreign_rsa = Rsa::generate(2048).unwrap();
        let backend = build_backend(&tmp_dir, &configured_rsa);

        let desc = resource_desc("unknown");
        let encrypted = encrypt_envelope(&foreign_rsa, ALG_RSA_OAEP_256, TEST_DATA);
        backend
            .write_secret_resource(desc.clone(), &serde_json::to_vec(&encrypted).unwrap())
            .await
            .unwrap();

        let err = backend
            .read_secret_resource(desc)
            .await
            .expect_err("must not decrypt with a foreign key");
        assert!(err.to_string().contains("any of the"));
    }

    // RSA1_5 envelopes also work through the key ring, exercising the path where
    // a wrong key may yield a wrong-length CEK rather than a clean padding error.
    #[tokio::test]
    async fn decrypts_rsa1_5_through_ring() {
        let tmp_dir = tempdir().unwrap();
        let old_rsa = Rsa::generate(2048).unwrap();
        let new_rsa = Rsa::generate(2048).unwrap();

        let backend = EncryptedLocalFs::new(&EncryptedLocalFsRepoDesc {
            dir_path: tmp_dir.path().to_string_lossy().into(),
            private_key_path: write_key(&tmp_dir, "new.pem", &new_rsa),
            private_key_paths: vec![write_key(&tmp_dir, "old.pem", &old_rsa)],
            ..Default::default()
        })
        .expect("create backend");

        let desc = resource_desc("rsa15");
        let encrypted = encrypt_envelope(&old_rsa, ALG_RSA1_5, TEST_DATA);
        backend
            .write_secret_resource(desc.clone(), &serde_json::to_vec(&encrypted).unwrap())
            .await
            .unwrap();

        let data = backend.read_secret_resource(desc).await.expect("decrypt");
        assert_eq!(data, TEST_DATA);
    }

    #[test]
    fn rejects_empty_key_configuration() {
        let tmp_dir = tempdir().unwrap();
        let err = EncryptedLocalFs::new(&EncryptedLocalFsRepoDesc {
            dir_path: tmp_dir.path().to_string_lossy().into(),
            private_key_path: String::new(),
            private_key_paths: vec![],
            ..Default::default()
        })
        .err()
        .expect("a backend with no keys must fail to initialize");
        assert!(err.to_string().contains("private_key"));
    }

    // A backend can pick up keys from `private_key_dir`, and `reload_keys`
    // re-reads the configured sources at runtime: after the primary file is
    // replaced with a new key (old key retained in the dir), both the old and
    // new resources decrypt without a restart.
    #[tokio::test]
    async fn reload_picks_up_rotated_keys() {
        let tmp_dir = tempdir().unwrap();
        let keys_dir = tmp_dir.path().join("keys");
        std::fs::create_dir(&keys_dir).unwrap();

        let old_rsa = Rsa::generate(2048).unwrap();
        let new_rsa = Rsa::generate(2048).unwrap();

        // Start with the old key as primary.
        let primary_path = keys_dir.join("primary.pem");
        std::fs::write(&primary_path, old_rsa.private_key_to_pem().unwrap()).unwrap();

        let backend = EncryptedLocalFs::new(&EncryptedLocalFsRepoDesc {
            dir_path: tmp_dir.path().to_string_lossy().into(),
            private_key_path: primary_path.to_string_lossy().into(),
            private_key_dir: keys_dir.to_string_lossy().into(),
            ..Default::default()
        })
        .expect("create backend");

        // Resource encrypted with the old key.
        let legacy = resource_desc("legacy");
        let enc_old = encrypt_envelope(&old_rsa, ALG_RSA_OAEP_256, TEST_DATA);
        backend
            .write_secret_resource(legacy.clone(), &serde_json::to_vec(&enc_old).unwrap())
            .await
            .unwrap();

        // Rotate: archive old key into the dir, write new key as primary, reload.
        std::fs::write(
            keys_dir.join("old.pem"),
            old_rsa.private_key_to_pem().unwrap(),
        )
        .unwrap();
        std::fs::write(&primary_path, new_rsa.private_key_to_pem().unwrap()).unwrap();
        let count = backend.reload_keys().await.expect("reload");
        assert_eq!(count, 2, "primary + archived old key");

        // Old resource still decrypts (old key retained)...
        assert_eq!(
            backend.read_secret_resource(legacy).await.expect("old"),
            TEST_DATA
        );
        // ...and a resource freshly encrypted with the new key decrypts too.
        let fresh = resource_desc("fresh");
        let enc_new = encrypt_envelope(&new_rsa, ALG_RSA_OAEP_256, TEST_DATA);
        backend
            .write_secret_resource(fresh.clone(), &serde_json::to_vec(&enc_new).unwrap())
            .await
            .unwrap();
        assert_eq!(
            backend.read_secret_resource(fresh).await.expect("new"),
            TEST_DATA
        );
    }

    // Server-side re-wrap migrates an old-key resource onto the primary key, so
    // the old key can later be retired. Resources already on the primary key are
    // skipped, and plaintext resources are left untouched.
    #[tokio::test]
    async fn rewrap_migrates_to_primary_key() {
        let tmp_dir = tempdir().unwrap();
        let old_rsa = Rsa::generate(2048).unwrap();
        let new_rsa = Rsa::generate(2048).unwrap();

        let backend = EncryptedLocalFs::new(&EncryptedLocalFsRepoDesc {
            dir_path: tmp_dir.path().to_string_lossy().into(),
            private_key_path: write_key(&tmp_dir, "new.pem", &new_rsa),
            private_key_paths: vec![write_key(&tmp_dir, "old.pem", &old_rsa)],
            ..Default::default()
        })
        .expect("create backend");

        // One resource on the old key, one already on the new (primary) key, and
        // one plaintext resource.
        let legacy = resource_desc("legacy");
        backend
            .write_secret_resource(
                legacy.clone(),
                &serde_json::to_vec(&encrypt_envelope(&old_rsa, ALG_RSA_OAEP_256, TEST_DATA))
                    .unwrap(),
            )
            .await
            .unwrap();
        let current = resource_desc("current");
        backend
            .write_secret_resource(
                current.clone(),
                &serde_json::to_vec(&encrypt_envelope(&new_rsa, ALG_RSA_OAEP_256, TEST_DATA))
                    .unwrap(),
            )
            .await
            .unwrap();
        let plain = resource_desc("plain");
        backend
            .write_secret_resource(plain.clone(), TEST_DATA)
            .await
            .unwrap();

        let report = backend.rewrap_resources().await.expect("rewrap");
        assert_eq!(report.total, 3);
        assert_eq!(report.rewrapped, 1, "only the legacy resource");
        assert_eq!(report.skipped, 2, "current (already primary) + plaintext");
        assert_eq!(report.failed, 0);

        // The migrated resource must now decrypt with ONLY the new key.
        let new_only = EncryptedLocalFs::new(&EncryptedLocalFsRepoDesc {
            dir_path: tmp_dir.path().to_string_lossy().into(),
            private_key_path: write_key(&tmp_dir, "new2.pem", &new_rsa),
            ..Default::default()
        })
        .expect("new-only backend");
        assert_eq!(
            new_only
                .read_secret_resource(legacy)
                .await
                .expect("migrated"),
            TEST_DATA
        );
    }

    // Re-wrap requires a primary key (the target). Without `private_key_path`
    // it must error rather than silently doing nothing.
    #[tokio::test]
    async fn rewrap_without_primary_key_errors() {
        let tmp_dir = tempdir().unwrap();
        let rsa = Rsa::generate(2048).unwrap();
        let backend = EncryptedLocalFs::new(&EncryptedLocalFsRepoDesc {
            dir_path: tmp_dir.path().to_string_lossy().into(),
            private_key_paths: vec![write_key(&tmp_dir, "only.pem", &rsa)],
            ..Default::default()
        })
        .expect("create backend with no primary");

        let err = backend
            .rewrap_resources()
            .await
            .expect_err("rewrap without a primary key must fail");
        assert!(err.to_string().contains("no primary key"));
    }
}
