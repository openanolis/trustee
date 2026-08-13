use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use rand::rngs::OsRng;
use rsa::{
    pkcs1::DecodeRsaPrivateKey as _,
    pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _, LineEnding},
    RsaPrivateKey,
};

use super::RSA_KEY_BITS;

use super::{build_challenge_json, verify_jwt};

const DEFAULT_KEY_DIR: &str = "/etc/trustee/attestation-service/nonce_token_issuer";
const DEFAULT_PRIV_KEY_PEM: &str = "key.pem";

/// Default filesystem path of the RSA private key used to sign/verify
/// attestation challenge (nonce) tokens. Used when no explicit path is
/// configured in the Attestation Service config.
fn default_challenge_key_path() -> PathBuf {
    Path::new(DEFAULT_KEY_DIR).join(DEFAULT_PRIV_KEY_PEM)
}

/// [`super::Challenger`] backed by an RSA private key on the filesystem.
///
/// JWT-based (RS384) challenge key — the issued JWT itself is the nonce, so
/// see [`super::build_challenge_json`] for why the `exp` claim gives freshness
/// across replicas without synchronizing every signed token.
///
/// The key is read lazily on each call (and, on the `fs` feature, generated
/// on first use) at the configured `path`. Native / config-file compatibility
/// path — the AS default until a caller opts into an in-memory impl.
pub struct FsJwtChallenger {
    path: PathBuf,
}

impl FsJwtChallenger {
    /// Construct with an explicit on-disk key path.
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// The built-in default path (`/etc/trustee/attestation-service/nonce_token_issuer/key.pem`).
    pub fn default_path() -> PathBuf {
        default_challenge_key_path()
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg_attr(
    all(
        target_arch = "wasm32",
        target_vendor = "unknown",
        target_os = "unknown"
    ),
    async_trait::async_trait(?Send)
)]
#[cfg_attr(
    not(all(
        target_arch = "wasm32",
        target_vendor = "unknown",
        target_os = "unknown"
    )),
    async_trait::async_trait
)]
impl crate::Challenger for FsJwtChallenger {
    async fn generate_challenge(&self) -> Result<String> {
        let key = ensure_keypair(self.path())?;
        build_challenge_json(&key)
    }

    async fn verify_challenge_and_extract_nonce_b64url(&self, token: &str) -> Result<String> {
        let key = ensure_keypair(self.path())?;
        verify_jwt(token, &key)
    }
}

fn ensure_keypair(key_path: &Path) -> Result<RsaPrivateKey> {
    if let Some(dir) = key_path.parent() {
        if !dir.as_os_str().is_empty() && !dir.exists() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("create dir {} failed", dir.display()))?;
        }
    }

    if key_path.exists() {
        let pem = std::fs::read_to_string(key_path).context("read private key pem failed")?;
        // Accept both PKCS#8 (what we write now) and legacy PKCS#1 (what the
        // previous implementation's `private_key_to_pem` wrote).
        let rsa = RsaPrivateKey::from_pkcs8_pem(&pem)
            .or_else(|_| RsaPrivateKey::from_pkcs1_pem(&pem))
            .context("parse private key pem failed")?;
        return Ok(rsa);
    }

    let mut rng = OsRng;
    let rsa = RsaPrivateKey::new(&mut rng, RSA_KEY_BITS as usize)?;
    let pem = rsa
        .to_pkcs8_pem(LineEnding::LF)
        .context("dump private key to pem failed")?;
    std::fs::write(key_path, pem.as_bytes()).context("write private key pem failed")?;
    Ok(rsa)
}

#[cfg(test)]
mod tests {
    use base64::{
        engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
        Engine as _,
    };
    use serde_json::Value;

    use crate::Challenger as _;

    use super::*;

    /// `FsJwtChallenger`: sign + verify round-trip on a temp dir, pinning the
    /// on-disk PKCS#8 format this module writes.
    #[tokio::test]
    async fn fs_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let key_file = tmp.path().join("key.pem");
        let c = FsJwtChallenger::new(key_file.clone());

        let challenge_json = c.generate_challenge().await.expect("generate");
        let outer: Value = serde_json::from_str(&challenge_json).expect("outer json");
        let jwt = outer["extra-params"]["jwt"]
            .as_str()
            .expect("jwt in extra-params")
            .to_string();

        // The key file must have been created on first use.
        assert!(key_file.exists(), "key file created on first use");

        let nonce_back = c
            .verify_challenge_and_extract_nonce_b64url(&jwt)
            .await
            .expect("verify");
        let nonce_original = outer["nonce"].as_str().unwrap().to_string();

        let nonce_back_bytes = URL_SAFE_NO_PAD
            .decode(&nonce_back)
            .expect("decode nonce_back");
        let nonce_original_bytes = STANDARD
            .decode(&nonce_original)
            .expect("decode nonce_original");
        assert_eq!(
            nonce_back_bytes, nonce_original_bytes,
            "nonce bytes must round-trip"
        );
    }

    /// A second `FsJwtChallenger` instance on the same path must verify a token
    /// the first issued — the key is persisted, not regenerated per call.
    #[tokio::test]
    async fn fs_persisted_across_instances() {
        let tmp = tempfile::tempdir().unwrap();
        let key_file = tmp.path().join("key.pem");

        let issuer = FsJwtChallenger::new(key_file.clone());
        let challenge_json = issuer.generate_challenge().await.expect("generate");
        let outer: Value = serde_json::from_str(&challenge_json).expect("outer json");
        let jwt = outer["extra-params"]["jwt"]
            .as_str()
            .expect("jwt")
            .to_string();

        let verifier = FsJwtChallenger::new(key_file);
        verifier
            .verify_challenge_and_extract_nonce_b64url(&jwt)
            .await
            .expect("a different instance verifies using the persisted key");
    }
}
