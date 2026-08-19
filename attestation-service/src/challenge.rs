use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::signature::{Signer, Verifier};
#[cfg(feature = "fs")]
use rsa::{
    pkcs1::DecodeRsaPrivateKey as _,
    pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _, LineEnding},
};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Value};
use sha2::Sha384;

#[cfg(feature = "fs")]
use std::{
    io::Write,
    path::{Path, PathBuf},
};
#[cfg(feature = "fs")]
use tempfile::NamedTempFile;

#[cfg(not(all(
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
)))]
use std::time::{SystemTime, UNIX_EPOCH};
#[cfg(all(
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
))]
use web_time::{SystemTime, UNIX_EPOCH};

pub const RSA_KEY_BITS: u32 = 2048;
const TOKEN_ALG: &str = "RS384";

#[cfg(feature = "fs")]
const DEFAULT_KEY_DIR: &str = "/etc/trustee/attestation-service/nonce_token_issuer";
#[cfg(feature = "fs")]
const DEFAULT_PRIV_KEY_PEM: &str = "key.pem";

/// Default filesystem path of the RSA private key used to sign/verify
/// attestation challenge (nonce) tokens. Used when no explicit path is
/// configured in the Attestation Service config.
#[cfg(feature = "fs")]
fn default_challenge_key_path() -> PathBuf {
    Path::new(DEFAULT_KEY_DIR).join(DEFAULT_PRIV_KEY_PEM)
}

/// JWT-based (RS384) challenge key — the issued JWT itself is the challenge
/// token, so the `exp` claim gives freshness across replicas without
/// synchronizing every signed token; see [`build_challenge_json`] for details.
pub struct JwtChallenger {
    key_source: PrivateKeySource,
}

enum PrivateKeySource {
    InMemory(Box<RsaPrivateKey>),
    #[cfg(feature = "fs")]
    File(PathBuf),
}

impl JwtChallenger {
    /// Construct with an explicit on-disk key path. The key is deliberately
    /// not read here: file-backed challengers reload it for every request so
    /// key rotation does not require restarting the Attestation Service.
    #[cfg(feature = "fs")]
    pub async fn new_with_private_key_path(path: &Path) -> Result<Self> {
        Ok(Self {
            key_source: PrivateKeySource::File(path.to_path_buf()),
        })
    }

    /// The built-in default path (`/etc/trustee/attestation-service/nonce_token_issuer/key.pem`).
    #[cfg(feature = "fs")]
    pub async fn new_with_private_key_default_path() -> Result<Self> {
        Self::new_with_private_key_path(&default_challenge_key_path()).await
    }

    pub fn new_with_private_key(key: RsaPrivateKey) -> Self {
        Self {
            key_source: PrivateKeySource::InMemory(Box::new(key)),
        }
    }

    pub fn new() -> Result<Self> {
        let mut rng = OsRng;
        let key = RsaPrivateKey::new(&mut rng, RSA_KEY_BITS as usize)?;
        Ok(Self::new_with_private_key(key))
    }

    pub async fn generate_challenge_json(&self) -> Result<String> {
        match &self.key_source {
            PrivateKeySource::InMemory(key) => build_challenge_json(key),
            #[cfg(feature = "fs")]
            PrivateKeySource::File(path) => {
                let key = load_or_create_private_key(path).await?;
                build_challenge_json(&key)
            }
        }
    }

    /// Verify the challenge token JWT — signature and `exp` (freshness).
    /// The token is the JWT the client echoes from `extra-params.jwt` in the
    /// challenge response; the client is not expected to send a separate
    /// nonce, so verification is signature + expiry only. Binding to the TEE
    /// report is handled by the TEE measuring the `runtime_data` (which
    /// carries the challenge token) into its report.
    pub async fn verify_challenge_token(&self, challenge_token: &str) -> Result<()> {
        match &self.key_source {
            PrivateKeySource::InMemory(key) => verify_jwt(challenge_token, key),
            #[cfg(feature = "fs")]
            PrivateKeySource::File(path) => {
                // Verification must not create a missing key. Otherwise an
                // invalid request could unexpectedly rotate service state.
                let key = read_private_key(path).await?;
                verify_jwt(challenge_token, &key)
            }
        }
    }
}

#[cfg(feature = "fs")]
fn parse_private_key(pem: &str) -> Result<RsaPrivateKey> {
    // Accept both PKCS#8 (what we write now) and legacy PKCS#1 (what the
    // implementation before #221 wrote).
    RsaPrivateKey::from_pkcs8_pem(pem)
        .or_else(|_| RsaPrivateKey::from_pkcs1_pem(pem))
        .context("parse private key pem failed")
}

#[cfg(feature = "fs")]
async fn read_private_key_if_exists(key_path: &Path) -> Result<Option<RsaPrivateKey>> {
    let pem = match tokio::fs::read_to_string(key_path).await {
        Ok(pem) => pem,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(source)
                .with_context(|| format!("read private key pem {} failed", key_path.display()))
        }
    };

    parse_private_key(&pem).map(Some)
}

#[cfg(feature = "fs")]
async fn read_private_key(key_path: &Path) -> Result<RsaPrivateKey> {
    read_private_key_if_exists(key_path)
        .await?
        .ok_or_else(|| anyhow!("private key pem {} does not exist", key_path.display()))
}

#[cfg(feature = "fs")]
fn key_parent(key_path: &Path) -> &Path {
    key_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// Publish a complete key without ever replacing an existing key. Creating
/// the temporary file in the destination directory keeps the final operation
/// on one filesystem; `persist_noclobber` makes concurrent creators race on a
/// single atomic no-replace operation.
#[cfg(feature = "fs")]
fn persist_private_key_noclobber(key_path: &Path, pem: &str) -> Result<bool> {
    let mut temporary = NamedTempFile::new_in(key_parent(key_path)).with_context(|| {
        format!(
            "create temporary private key beside {} failed",
            key_path.display()
        )
    })?;
    temporary
        .write_all(pem.as_bytes())
        .context("write temporary private key pem failed")?;
    temporary
        .as_file_mut()
        .sync_all()
        .context("sync temporary private key pem failed")?;

    match temporary.persist_noclobber(key_path) {
        Ok(_) => Ok(true),
        Err(source) if source.error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(source) => Err(source.error).with_context(|| {
            format!(
                "atomically persist private key pem {} failed",
                key_path.display()
            )
        }),
    }
}

#[cfg(feature = "fs")]
async fn load_or_create_private_key(key_path: &Path) -> Result<RsaPrivateKey> {
    if let Some(key) = read_private_key_if_exists(key_path).await? {
        return Ok(key);
    }

    tokio::fs::create_dir_all(key_parent(key_path))
        .await
        .with_context(|| {
            format!(
                "create private key dir {} failed",
                key_parent(key_path).display()
            )
        })?;

    // Check again after creating the directory: another request or AS replica
    // may have installed the key while this request was waiting.
    if let Some(key) = read_private_key_if_exists(key_path).await? {
        return Ok(key);
    }

    let mut rng = OsRng;
    let key = RsaPrivateKey::new(&mut rng, RSA_KEY_BITS as usize)?;
    let pem = key
        .to_pkcs8_pem(LineEnding::LF)
        .context("dump private key to pem failed")?;

    if persist_private_key_noclobber(key_path, &pem)? {
        Ok(key)
    } else {
        // A concurrent creator won. Its rename/link is complete before
        // `AlreadyExists` is observed, so readers never see a partial PEM.
        read_private_key(key_path).await
    }
}

/// Build the challenge JSON `{"nonce", "extra-params":{"jwt"}}` signed with
/// `key` (RS384, 5-minute `exp`).
///
/// The issued JWT serves as the challenge token. The `exp` claim bounds its
/// validity window, which gives freshness when the Attestation Service runs
/// with multiple replicas sharing the same signing key: each replica can
/// verify a token's signature and `exp` independently, so a JWT that has
/// already been consumed by one replica cannot be replayed once `exp` passes.
/// This avoids, to a degree, the need to synchronize a record of every
/// signed JWT across replicas — the short `exp` window bounds the window in
/// which a consumed-but-unsynced token could be replayed, without requiring
/// shared state on the hot path.
///
/// The `nonce` field (STANDARD base64 of 32 random bytes) and the JWT
/// `nonce` claim carry the same string. The client echoes only the JWT into
/// `runtime_data` as `challenge_token`; [`JwtChallenger::verify_challenge_token`]
/// checks signature + `exp` and does not compare the nonce — binding to the
/// TEE report is handled by the TEE measuring the `runtime_data` (which
/// carries the token) into its report.
fn build_challenge_json(key: &RsaPrivateKey) -> Result<String> {
    // nonce
    let mut nonce = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut nonce)
        .context("generate nonce failed")?;
    let nonce_b64 = STANDARD.encode(nonce);

    // header
    let header_value = json!({
        "typ": "JWT",
        "alg": TOKEN_ALG,
    });
    let header_string = serde_json::to_string(&header_value)?;
    let header_b64 = URL_SAFE_NO_PAD.encode(header_string.as_bytes());

    // claims with 5-minute expiry
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("time error")?
        .as_secs();
    let exp = now + 5 * 60;
    let claims_value = json!({
        "nonce": nonce_b64,
        "iat": now,
        "exp": exp,
    });
    let claims_string = serde_json::to_string(&claims_value)?;
    let claims_b64 = URL_SAFE_NO_PAD.encode(claims_string.as_bytes());

    // sign
    let signing_input = format!("{}.{}", header_b64, claims_b64);
    let signature = rs384_sign(key, signing_input.as_bytes())?;
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature);
    let jwt = format!("{}.{}", signing_input, signature_b64);

    // output json
    let output = json!({
        "nonce": claims_value["nonce"].as_str().unwrap_or_default(),
        "extra-params": { "jwt": jwt },
    });
    Ok(serde_json::to_string(&output)?)
}

fn rs384_sign(rsa: &RsaPrivateKey, payload: &[u8]) -> Result<Vec<u8>> {
    let signing_key = SigningKey::<Sha384>::new(rsa.clone());
    let sig: Signature = signing_key.sign(payload);
    Ok(Box::<[u8]>::from(sig).to_vec())
}

/// Verify a challenge_token JWT signed by the public half of `key` and
/// enforce its `exp` (freshness). Signature + expiry is the only check the
/// Attestation Service performs on the challenge token — the binding to the
/// TEE report comes from the TEE measuring the `runtime_data` (which carries
/// the token) into its report, so there is no nonce string to compare and
/// nothing to return.
fn verify_jwt(token: &str, key: &RsaPrivateKey) -> Result<()> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        bail!("invalid JWT format in challenge_token");
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig = URL_SAFE_NO_PAD
        .decode(parts[2])
        .context("invalid JWT signature encoding")?;

    let public_key: RsaPublicKey = key.to_public_key();
    let verifying_key = VerifyingKey::<Sha384>::new(public_key);
    let sig_obj = Signature::try_from(sig.as_slice()).context("invalid signature bytes")?;
    verifying_key
        .verify(signing_input.as_bytes(), &sig_obj)
        .context("verify signature failed")?;

    let payload = URL_SAFE_NO_PAD
        .decode(parts[1])
        .context("invalid JWT payload encoding")?;
    let v: Value = serde_json::from_slice(&payload).context("invalid JWT payload json")?;

    // exp
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("time error")?
        .as_secs() as i64;
    let exp = v
        .get("exp")
        .and_then(|x| x.as_i64())
        .ok_or_else(|| anyhow!("missing exp claim in challenge_token"))?;
    if now > exp {
        bail!("challenge_token expired");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    fn challenge_jwt(challenge_json: &str) -> String {
        let outer: Value = serde_json::from_str(challenge_json).expect("outer json");
        outer["extra-params"]["jwt"]
            .as_str()
            .expect("jwt in extra-params")
            .to_string()
    }

    /// Helper mirroring the `lib.rs` evaluate contract: the client echoes the
    /// challenge JSON's JWT into `runtime_data` as `challenge_token`, and the
    /// challenger verifies signature + `exp` (freshness only — no nonce is
    /// sent by the client).
    async fn issue_and_verify(c: &JwtChallenger, challenge_json: &str) {
        let jwt = challenge_jwt(challenge_json);

        c.verify_challenge_token(&jwt)
            .await
            .expect("valid token verifies");
    }

    /// In-memory challenger: issue + verify round-trip, no filesystem. JWT
    /// freshness is the signature + `exp`, checked at `verify_challenge_token`.
    #[tokio::test]
    async fn ephemeral_roundtrip() {
        let c = JwtChallenger::new().expect("new ephemeral challenger");
        let challenge_json = c.generate_challenge_json().await.expect("generate");
        issue_and_verify(&c, &challenge_json).await;
    }

    /// A tampered JWT (wrong signature) must be rejected.
    #[tokio::test]
    async fn ephemeral_tampered_token_rejected() {
        let c = JwtChallenger::new().expect("new ephemeral challenger");
        let challenge_json = c.generate_challenge_json().await.expect("generate");
        let outer: Value = serde_json::from_str(&challenge_json).expect("outer json");
        let mut jwt = outer["extra-params"]["jwt"]
            .as_str()
            .expect("jwt")
            .to_string();
        // Flip the last char of the signature segment to break the signature.
        let last = jwt.len() - 1;
        let b = jwt.as_bytes()[last];
        jwt.replace_range(last.., if b == b'A' { "B" } else { "A" });

        c.verify_challenge_token(&jwt)
            .await
            .expect_err("tampered token rejected");
    }

    /// `fs` challenger: issue + verify round-trip on a temp dir, pinning the
    /// on-disk PKCS#8 format this module writes. JWT freshness is the
    /// signature + `exp`, checked at `verify_challenge_token`.
    #[cfg(feature = "fs")]
    #[tokio::test]
    async fn fs_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let key_file = tmp.path().join("keys/key.pem");
        let c = JwtChallenger::new_with_private_key_path(&key_file)
            .await
            .expect("new with key file");

        assert!(
            !key_file.exists(),
            "constructing a file-backed challenger must not create its key"
        );
        assert!(
            !key_file.parent().unwrap().exists(),
            "the key directory is also created lazily"
        );

        let challenge_json = c.generate_challenge_json().await.expect("generate");
        // The key file must have been created on first use.
        assert!(key_file.exists(), "key file created on first use");
        issue_and_verify(&c, &challenge_json).await;
    }

    /// Verifying against a missing file is an error and must not create a new
    /// key as a side effect of an untrusted request.
    #[cfg(feature = "fs")]
    #[tokio::test]
    async fn fs_verify_does_not_create_missing_key() {
        let tmp = tempfile::tempdir().unwrap();
        let key_file = tmp.path().join("keys/key.pem");
        let c = JwtChallenger::new_with_private_key_path(&key_file)
            .await
            .expect("new with key file");

        let error = c
            .verify_challenge_token("not.a.jwt")
            .await
            .expect_err("verification without a key must fail");
        assert!(error.to_string().contains("does not exist"), "{error:#}");
        assert!(!key_file.exists());
        assert!(!key_file.parent().unwrap().exists());
    }

    /// A second `JwtChallenger` instance on the same path must verify a token
    /// the first issued — the key is persisted, not regenerated per call.
    #[cfg(feature = "fs")]
    #[tokio::test]
    async fn fs_persisted_across_instances() {
        let tmp = tempfile::tempdir().unwrap();
        let key_file = tmp.path().join("key.pem");

        let issuer = JwtChallenger::new_with_private_key_path(&key_file)
            .await
            .expect("new with key file");
        let challenge_json = issuer.generate_challenge_json().await.expect("generate");

        let verifier = JwtChallenger::new_with_private_key_path(&key_file)
            .await
            .expect("second instance");
        issue_and_verify(&verifier, &challenge_json).await;
    }

    /// A long-running file-backed challenger must observe a key replacement
    /// on both its signing and verification paths without being reconstructed.
    #[cfg(feature = "fs")]
    #[tokio::test]
    async fn fs_reloads_rotated_key_per_request() {
        let tmp = tempfile::tempdir().unwrap();
        let key_file = tmp.path().join("key.pem");
        let c = JwtChallenger::new_with_private_key_path(&key_file)
            .await
            .expect("new with key file");

        let old_challenge = c
            .generate_challenge_json()
            .await
            .expect("initial challenge");
        let old_jwt = challenge_jwt(&old_challenge);

        let mut rng = OsRng;
        let rotated_key = RsaPrivateKey::new(&mut rng, RSA_KEY_BITS as usize).unwrap();
        let rotated_pem = rotated_key.to_pkcs8_pem(LineEnding::LF).unwrap();
        let replacement = tmp.path().join("replacement.pem");
        std::fs::write(&replacement, rotated_pem.as_bytes()).unwrap();
        std::fs::rename(&replacement, &key_file).unwrap();

        let new_challenge = c
            .generate_challenge_json()
            .await
            .expect("rotated challenge");
        let new_jwt = challenge_jwt(&new_challenge);
        verify_jwt(&new_jwt, &rotated_key).expect("new challenge uses rotated key");
        c.verify_challenge_token(&new_jwt)
            .await
            .expect("same challenger verifies with rotated key");
        c.verify_challenge_token(&old_jwt)
            .await
            .expect_err("rotation invalidates outstanding tokens from the old key");
    }

    /// Concurrent first writers must never overwrite each other or expose a
    /// partially-written file. Exactly one complete candidate is published.
    #[cfg(feature = "fs")]
    #[test]
    fn fs_key_creation_is_atomic_and_noclobber() {
        use std::sync::{Arc, Barrier};

        let tmp = tempfile::tempdir().unwrap();
        let key_file = tmp.path().join("key.pem");
        let barrier = Arc::new(Barrier::new(3));
        let candidates: Vec<String> = (0..2)
            .map(|_| {
                RsaPrivateKey::new(&mut OsRng, 1024)
                    .unwrap()
                    .to_pkcs8_pem(LineEnding::LF)
                    .unwrap()
                    .to_string()
            })
            .collect();

        let handles: Vec<_> = candidates
            .into_iter()
            .map(|candidate| {
                let barrier = Arc::clone(&barrier);
                let key_file = key_file.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    let published = persist_private_key_noclobber(&key_file, &candidate).unwrap();
                    (published, candidate)
                })
            })
            .collect();

        barrier.wait();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        let winners: Vec<_> = results
            .iter()
            .filter_map(|(published, candidate)| published.then_some(candidate))
            .collect();

        assert_eq!(winners.len(), 1, "exactly one creator wins");
        let persisted = std::fs::read_to_string(&key_file).unwrap();
        assert_eq!(&persisted, winners[0]);
        parse_private_key(&persisted).expect("the complete winning PEM is readable");
    }
}
