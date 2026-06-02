// Copyright (c) 2025 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use super::{
    local_fs::{LocalFs, LocalFsRepoDesc},
    ResourceDesc, RewrapReport, RotateReport, StorageBackend,
};
use aes_gcm::{
    aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rsa::pkcs8::{EncodePublicKey, LineEnding};
use rsa::sha2::Sha256;
use rsa::{
    pkcs1::DecodeRsaPrivateKey, pkcs8::DecodePrivateKey, Oaep, Pkcs1v15Encrypt, RsaPrivateKey,
    RsaPublicKey,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

const ALG_RSA1_5: &str = "RSA1_5";
const ALG_RSA_OAEP_256: &str = "RSA-OAEP-256";
const AES_GCM_KEY_LEN: usize = 32;
const AES_GCM_TAG_LEN: usize = 16;
const AES_GCM_NONCE_LEN: usize = 12;

/// Bit size of RSA key pairs generated and managed by KBS itself.
const RSA_KEY_BITS: u32 = 3072;
/// Default directory for the KBS-managed key store, used when the backend is
/// enabled without any key configuration at all.
const DEFAULT_MANAGED_KEY_DIR: &str = "/opt/confidential-containers/kbs/resource-keys";
/// Filename prefix for KBS-managed keys: `mkey-<unix_nanos>.pem`. The numeric
/// suffix orders generations, so the newest file is the current primary key.
const MANAGED_KEY_PREFIX: &str = "mkey-";
const MANAGED_KEY_EXT: &str = "pem";

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
    /// Directory of the KBS-managed key store. When set (or when no key is
    /// configured at all, in which case a default location is used), KBS owns
    /// the RSA key pairs here: it generates one on first start, picks the newest
    /// as the primary, and rotates them via the `rotate` API. Operators never
    /// have to generate keys or edit config to rotate.
    #[serde(default)]
    pub key_dir: String,
    /// Bring-your-own primary RSA private key. Used as the primary (re-wrap
    /// target) only when no managed key store is in effect. Tried first when
    /// decrypting in that case.
    #[serde(default)]
    pub private_key_path: String,
    /// Bring-your-own directory of additional RSA private keys (`*.pem`), kept
    /// available for decryption so resources encrypted with a previous key keep
    /// working. Also serves as a decrypt-only source when migrating to a managed
    /// key store.
    #[serde(default)]
    pub private_key_dir: String,
    /// Additional bring-your-own RSA private keys given as explicit paths.
    #[serde(default)]
    pub private_key_paths: Vec<String>,
}

/// The set of places keys are loaded from. Held so the key ring can be rebuilt
/// on a hot reload without re-reading the whole KBS config.
struct KeySources {
    /// KBS-managed key store directory. Empty in bring-your-own-key mode.
    key_dir: String,
    /// Bring-your-own primary key path. Empty in managed mode.
    primary_path: String,
    /// Bring-your-own additional key directory.
    byok_dir: String,
    /// Bring-your-own additional key paths.
    extra_paths: Vec<String>,
}

impl KeySources {
    fn managed(&self) -> bool {
        !self.key_dir.is_empty()
    }
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

    async fn current_public_key_pem(&self) -> Result<String> {
        let ring = self.ring_snapshot();
        let public = ring
            .primary_public
            .clone()
            .ok_or_else(|| anyhow!("no primary key available to export a public key"))?;
        public
            .to_public_key_pem(LineEnding::LF)
            .context("encode primary public key as PEM")
    }

    async fn rotate_keys(&self) -> Result<RotateReport> {
        if !self.sources.managed() {
            bail!("key rotation requires a KBS-managed key store; set `key_dir` (or enable the backend with no bring-your-own key)");
        }

        // 1. Generate a new key pair; being the newest, it becomes the primary.
        let new_key = Self::generate_managed_key(&self.sources.key_dir)?;
        // 2. Reload so the new key is primary while old keys stay for decryption.
        self.reload_keys().await?;
        // 3. Re-wrap every resource onto the new primary key.
        let rewrap = self.rewrap_resources().await?;
        // 4. Retire the old managed keys, but only if everything migrated; if any
        //    resource failed, keep the old keys so it stays decryptable.
        let mut retired = 0;
        if rewrap.failed == 0 {
            retired = Self::retire_managed_keys_except(&self.sources.key_dir, &new_key)?;
            self.reload_keys().await?;
        }
        let public_key = self.current_public_key_pem().await?;

        Ok(RotateReport {
            public_key,
            rewrapped: rewrap.rewrapped,
            skipped: rewrap.skipped,
            failed: rewrap.failed,
            retired_keys: retired,
            purged_keys: 0,
        })
    }
}

impl EncryptedLocalFs {
    pub fn new(desc: &EncryptedLocalFsRepoDesc) -> Result<Self> {
        let byok_empty = desc.private_key_path.is_empty()
            && desc.private_key_dir.is_empty()
            && desc.private_key_paths.is_empty();

        // Managed mode is active when `key_dir` is set, or when no key is
        // configured at all (then KBS manages keys at the default location).
        let key_dir = if !desc.key_dir.is_empty() {
            desc.key_dir.clone()
        } else if byok_empty {
            DEFAULT_MANAGED_KEY_DIR.to_string()
        } else {
            String::new()
        };

        let sources = KeySources {
            key_dir,
            primary_path: desc.private_key_path.clone(),
            byok_dir: desc.private_key_dir.clone(),
            extra_paths: desc.private_key_paths.clone(),
        };

        // In managed mode, generate the initial key pair on first start.
        if sources.managed() {
            Self::ensure_key_dir(&sources.key_dir)?;
            if Self::scan_managed_keys(&sources.key_dir)?.is_empty() {
                Self::generate_managed_key(&sources.key_dir)?;
            }
        }

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
    /// (tried first and the re-wrap target): the newest managed key in managed
    /// mode, otherwise the bring-your-own `private_key_path`. Remaining managed
    /// and bring-your-own keys follow, for decryption only. Duplicate files are
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

        // Managed keys first, newest (current primary) at the front.
        let managed = if sources.managed() {
            Self::scan_managed_keys(&sources.key_dir)?
        } else {
            Vec::new()
        };
        let has_managed = !managed.is_empty();
        for path in &managed {
            push(path, &mut ordered_paths);
        }

        // Bring-your-own keys (primary, then dir, then explicit paths).
        push(&sources.primary_path, &mut ordered_paths);
        if !sources.byok_dir.is_empty() {
            for path in Self::scan_pem_dir(&sources.byok_dir)? {
                push(&path, &mut ordered_paths);
            }
        }
        for path in &sources.extra_paths {
            push(path, &mut ordered_paths);
        }

        if ordered_paths.is_empty() {
            bail!(
                "no keys available: set `key_dir` for KBS-managed keys, or a `private_key_path` / `private_key_dir` / `private_key_paths`"
            );
        }

        let keys = ordered_paths
            .iter()
            .map(|p| Self::load_private_key(p))
            .collect::<Result<Vec<_>>>()?;

        // The primary public key (re-wrap / rotate target) is the public part of
        // `keys[0]`, which is the newest managed key, or the bring-your-own
        // primary. It is `None` only when neither exists (decrypt-only keys).
        let primary_public = if has_managed || !sources.primary_path.is_empty() {
            Some(keys[0].to_public_key())
        } else {
            None
        };

        Ok(KeyRing {
            keys,
            primary_public,
        })
    }

    /// Return the `*.pem` files in a directory, name-sorted for determinism.
    fn scan_pem_dir(dir: &str) -> Result<Vec<String>> {
        let mut paths = Vec::new();
        let entries = fs::read_dir(dir).with_context(|| format!("read private key dir `{dir}`"))?;
        for entry in entries {
            let path = entry
                .with_context(|| format!("read entry in `{dir}`"))?
                .path();
            if path.extension().and_then(|e| e.to_str()) == Some(MANAGED_KEY_EXT) && path.is_file()
            {
                paths.push(path.to_string_lossy().into_owned());
            }
        }
        paths.sort();
        Ok(paths)
    }

    /// Managed key files (`mkey-<nanos>.pem`) in the store, sorted newest-first
    /// by the embedded generation timestamp.
    fn scan_managed_keys(dir: &str) -> Result<Vec<String>> {
        let mut keys: Vec<(u128, String)> = Vec::new();
        let entries = fs::read_dir(dir).with_context(|| format!("read managed key dir `{dir}`"))?;
        for entry in entries {
            let path = entry
                .with_context(|| format!("read entry in `{dir}`"))?
                .path();
            if !path.is_file() {
                continue;
            }
            if let Some(nanos) = Self::managed_key_generation(&path) {
                keys.push((nanos, path.to_string_lossy().into_owned()));
            }
        }
        // Newest first.
        keys.sort_by(|a, b| b.0.cmp(&a.0));
        Ok(keys.into_iter().map(|(_, p)| p).collect())
    }

    /// Parse the generation timestamp out of a managed key filename, or `None`
    /// if the file is not a managed key.
    fn managed_key_generation(path: &Path) -> Option<u128> {
        let name = path.file_name()?.to_str()?;
        let rest = name.strip_prefix(MANAGED_KEY_PREFIX)?;
        let stem = rest.strip_suffix(&format!(".{MANAGED_KEY_EXT}"))?;
        stem.parse::<u128>().ok()
    }

    /// Create the managed key directory (private, `0700`) if it does not exist.
    fn ensure_key_dir(dir: &str) -> Result<()> {
        if !Path::new(dir).exists() {
            fs::create_dir_all(dir).with_context(|| format!("create managed key dir `{dir}`"))?;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
                .with_context(|| format!("set permissions on `{dir}`"))?;
        }
        Ok(())
    }

    /// Generate a fresh RSA key pair and persist it (private, `0600`) into the
    /// managed key directory. Returns the new key's path.
    fn generate_managed_key(dir: &str) -> Result<PathBuf> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock before unix epoch")?
            .as_nanos();
        let path = Path::new(dir).join(format!("{MANAGED_KEY_PREFIX}{nanos}.{MANAGED_KEY_EXT}"));

        // openssl generates RSA keys natively (fast); the PEM is then loadable by
        // the `rsa` crate for decryption.
        let rsa = openssl::rsa::Rsa::generate(RSA_KEY_BITS).context("generate RSA key pair")?;
        let pem = rsa
            .private_key_to_pem()
            .context("encode RSA private key PEM")?;
        fs::write(&path, pem).with_context(|| format!("write managed key `{path:?}`"))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("set permissions on `{path:?}`"))?;
        Ok(path)
    }

    /// Delete every managed key except `keep`. Returns the number removed.
    fn retire_managed_keys_except(dir: &str, keep: &Path) -> Result<usize> {
        let keep = fs::canonicalize(keep).unwrap_or_else(|_| keep.to_path_buf());
        let mut removed = 0;
        for path in Self::scan_managed_keys(dir)? {
            let canonical = fs::canonicalize(&path).unwrap_or_else(|_| PathBuf::from(&path));
            if canonical != keep {
                fs::remove_file(&path).with_context(|| format!("remove retired key `{path}`"))?;
                removed += 1;
            }
        }
        Ok(removed)
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
    use rsa::pkcs8::DecodePublicKey;
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

    fn encrypt_with_pub(rsa_pub: &RsaPublicKey, alg: &str, plaintext: &[u8]) -> Envelope {
        let mut rng = rand::thread_rng();
        let cek = Aes256Gcm::generate_key(&mut rng);
        let iv: [u8; 12] = rng.gen();
        let nonce = Nonce::from_slice(&iv);

        let cipher = Aes256Gcm::new(&cek);
        let mut payload = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(nonce, b"", &mut payload)
            .expect("encrypt");

        let encrypted_key = match alg {
            ALG_RSA1_5 => rsa_pub
                .encrypt(&mut rng, Pkcs1v15Encrypt, cek.as_slice())
                .expect("rsa1_5 encrypt cek"),
            ALG_RSA_OAEP_256 => rsa_pub
                .encrypt(&mut rng, Oaep::new::<Sha256>(), cek.as_slice())
                .expect("rsa-oaep encrypt cek"),
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

    fn encrypt_envelope(
        rsa: &Rsa<openssl::pkey::Private>,
        alg: &str,
        plaintext: &[u8],
    ) -> Envelope {
        let n = BigUint::from_bytes_be(rsa.n().to_vec().as_slice());
        let e = BigUint::from_bytes_be(rsa.e().to_vec().as_slice());
        let rsa_pub = RsaPublicKey::new(n, e).expect("build rsa public key");
        encrypt_with_pub(&rsa_pub, alg, plaintext)
    }

    /// Encrypt a resource for whatever public key the backend currently exposes.
    async fn encrypt_for_backend(backend: &EncryptedLocalFs, plaintext: &[u8]) -> Envelope {
        let pem = backend
            .current_public_key_pem()
            .await
            .expect("backend public key");
        let pubkey = RsaPublicKey::from_public_key_pem(&pem).expect("parse pubkey pem");
        encrypt_with_pub(&pubkey, ALG_RSA_OAEP_256, plaintext)
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

    fn build_managed_backend(tmp_dir: &tempfile::TempDir) -> EncryptedLocalFs {
        EncryptedLocalFs::new(&EncryptedLocalFsRepoDesc {
            dir_path: tmp_dir.path().to_string_lossy().into(),
            key_dir: tmp_dir.path().join("keys").to_string_lossy().into(),
            ..Default::default()
        })
        .expect("create managed backend")
    }

    fn managed_key_count(key_dir: &std::path::Path) -> usize {
        std::fs::read_dir(key_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("pem"))
            .count()
    }

    // With a managed key store and no operator-provided key, KBS generates its
    // own key pair on start, exposes the public key, and round-trips resources.
    #[tokio::test]
    async fn managed_mode_auto_generates_key() {
        let tmp_dir = tempdir().unwrap();
        let backend = build_managed_backend(&tmp_dir);

        let pem = backend.current_public_key_pem().await.expect("pubkey");
        assert!(pem.contains("BEGIN PUBLIC KEY"));
        assert_eq!(managed_key_count(&tmp_dir.path().join("keys")), 1);

        let desc = resource_desc("managed");
        let env = encrypt_for_backend(&backend, TEST_DATA).await;
        backend
            .write_secret_resource(desc.clone(), &serde_json::to_vec(&env).unwrap())
            .await
            .unwrap();
        assert_eq!(
            backend.read_secret_resource(desc).await.expect("decrypt"),
            TEST_DATA
        );
    }

    // One-shot rotate: generate a new key, re-wrap resources onto it, retire the
    // old key. The resource stays readable, the public key changes, and a freshly
    // loaded backend (only the new key on disk) can still decrypt it.
    #[tokio::test]
    async fn rotate_generates_rewraps_and_retires() {
        let tmp_dir = tempdir().unwrap();
        let key_dir = tmp_dir.path().join("keys");
        let backend = build_managed_backend(&tmp_dir);

        let desc = resource_desc("secret");
        let env = encrypt_for_backend(&backend, TEST_DATA).await;
        backend
            .write_secret_resource(desc.clone(), &serde_json::to_vec(&env).unwrap())
            .await
            .unwrap();
        let pubkey_before = backend.current_public_key_pem().await.unwrap();

        let report = backend.rotate_keys().await.expect("rotate");
        assert_eq!(report.failed, 0);
        assert_eq!(report.rewrapped, 1);
        assert_eq!(report.retired_keys, 1, "the previous key is retired");
        assert!(report.public_key.contains("BEGIN PUBLIC KEY"));

        let pubkey_after = backend.current_public_key_pem().await.unwrap();
        assert_ne!(pubkey_before, pubkey_after, "rotation changes the key");
        assert_eq!(report.public_key, pubkey_after);
        assert_eq!(managed_key_count(&key_dir), 1, "old key retired");

        assert_eq!(
            backend
                .read_secret_resource(desc.clone())
                .await
                .expect("after rotate"),
            TEST_DATA
        );

        let reopened = build_managed_backend(&tmp_dir);
        assert_eq!(
            reopened
                .read_secret_resource(desc)
                .await
                .expect("reopened decrypt"),
            TEST_DATA
        );
    }

    // Rotation is only meaningful with a managed key store; bring-your-own mode
    // must reject it.
    #[tokio::test]
    async fn rotate_requires_managed_mode() {
        let tmp_dir = tempdir().unwrap();
        let rsa = Rsa::generate(2048).unwrap();
        let backend = build_backend(&tmp_dir, &rsa);

        let err = backend
            .rotate_keys()
            .await
            .expect_err("bring-your-own mode cannot rotate");
        assert!(err.to_string().contains("managed"));
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
