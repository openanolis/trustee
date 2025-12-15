// Copyright (c) 2025 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use super::{
    local_fs::{LocalFs, LocalFsRepoDesc},
    ResourceDesc, StorageBackend,
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
};
use serde::{Deserialize, Serialize};
use std::fs;

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

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct EncryptedLocalFsRepoDesc {
    #[serde(default)]
    pub dir_path: String,
    pub private_key_path: String,
}

pub struct EncryptedLocalFs {
    inner: LocalFs,
    private_key: RsaPrivateKey,
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
}

impl EncryptedLocalFs {
    pub fn new(desc: &EncryptedLocalFsRepoDesc) -> Result<Self> {
        if desc.private_key_path.is_empty() {
            bail!("`private_key_path` is required for encrypted local fs backend");
        }

        let dir_path = if desc.dir_path.is_empty() {
            LocalFsRepoDesc::default().dir_path
        } else {
            desc.dir_path.clone()
        };

        let inner = LocalFs::new(&LocalFsRepoDesc { dir_path })?;
        let private_key = Self::load_private_key(&desc.private_key_path)?;

        Ok(Self { inner, private_key })
    }

    fn load_private_key(path: &str) -> Result<RsaPrivateKey> {
        let pem = fs::read_to_string(path).context("read private key file")?;

        RsaPrivateKey::from_pkcs8_pem(&pem)
            .or_else(|_| RsaPrivateKey::from_pkcs1_pem(&pem))
            .context("parse RSA private key from PEM")
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
        let enc_key = Self::decode_b64("enc_key", &env.enc_key)?;
        let cek = match env.alg.as_str() {
            ALG_RSA1_5 => self
                .private_key
                .decrypt(Pkcs1v15Encrypt, &enc_key)
                .context("RSA1_5 decrypt content encryption key (simple envelope)")?,
            ALG_RSA_OAEP_256 => {
                let padding = Oaep::new::<Sha256>();
                self.private_key
                    .decrypt(padding, &enc_key)
                    .context("RSA-OAEP-256 decrypt content encryption key (simple envelope)")?
            }
            _ => bail!("unsupported simple envelope alg `{}`", env.alg),
        };

        let iv = Self::decode_b64("iv", &env.iv)?;
        let ciphertext = Self::decode_b64("ciphertext", &env.ciphertext)?;
        let tag = Self::decode_b64("tag", &env.tag)?;

        if cek.len() != AES_GCM_KEY_LEN {
            bail!(
                "unexpected CEK length {}, expect {} bytes for AES-256-GCM",
                cek.len(),
                AES_GCM_KEY_LEN
            );
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

        let cipher =
            Aes256Gcm::new_from_slice(&cek).context("build AES-256-GCM cipher with CEK")?;
        let nonce = Nonce::from_slice(&iv);
        let mut plaintext = ciphertext.clone();
        let tag = GenericArray::from_slice(&tag);

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

    fn build_backend(
        tmp_dir: &tempfile::TempDir,
        rsa: &Rsa<openssl::pkey::Private>,
    ) -> EncryptedLocalFs {
        let key_path = tmp_dir.path().join("rsa.pem");
        std::fs::write(&key_path, rsa.private_key_to_pem().unwrap()).unwrap();

        EncryptedLocalFs::new(&EncryptedLocalFsRepoDesc {
            dir_path: tmp_dir.path().to_string_lossy().into(),
            private_key_path: key_path.to_string_lossy().into(),
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
}
