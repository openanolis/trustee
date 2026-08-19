use anyhow::*;
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
use std::path::{Path, PathBuf};

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

/// [`super::JwtChallenger`] backed by an in-memory RSA private key.
///
/// JWT-based (RS384) challenge key — the issued JWT itself is the challenge
/// token, so the `exp` claim gives freshness across replicas without
/// synchronizing every signed token; see [`build_challenge_json`] for details.
///
/// Native / config-file compatibility path — the AS default until a caller
/// opts into an in-memory impl.
pub struct JwtChallenger {
    key: RsaPrivateKey,
}

impl JwtChallenger {
    /// Construct with an explicit on-disk key path.
    #[cfg(feature = "fs")]
    pub async fn new_with_private_key_path(path: &Path) -> Result<Self> {
        let key = ensure_keypair(path).await?;
        Ok(Self::new_with_private_key(key))
    }

    /// The built-in default path (`/etc/trustee/attestation-service/nonce_token_issuer/key.pem`).
    #[cfg(feature = "fs")]
    pub async fn new_with_private_key_default_path() -> Result<Self> {
        Self::new_with_private_key_path(&default_challenge_key_path()).await
    }

    pub fn new_with_private_key(key: RsaPrivateKey) -> Self {
        Self { key }
    }

    pub fn new() -> Result<Self> {
        let mut rng = OsRng;
        let key = RsaPrivateKey::new(&mut rng, RSA_KEY_BITS as usize)?;
        Ok(Self::new_with_private_key(key))
    }

    pub async fn generate_challenge_json(&self) -> Result<String> {
        build_challenge_json(&self.key)
    }

    /// Verify the challenge token JWT — signature and `exp` (freshness).
    /// The token is the JWT the client echoes from `extra-params.jwt` in the
    /// challenge response; the client is not expected to send a separate
    /// nonce, so verification is signature + expiry only. Binding to the TEE
    /// report is handled by the TEE measuring the `runtime_data` (which
    /// carries the challenge token) into its report.
    pub async fn verify_challenge_token(&self, challenge_token: &str) -> Result<()> {
        verify_jwt(challenge_token, &self.key)
    }
}

#[cfg(feature = "fs")]
async fn ensure_keypair(key_path: &Path) -> Result<RsaPrivateKey> {
    if let Some(dir) = key_path.parent() {
        if !dir.as_os_str().is_empty() && !dir.exists() {
            tokio::fs::create_dir_all(dir)
                .await
                .with_context(|| format!("create dir {} failed", dir.display()))?;
        }
    }

    if key_path.exists() {
        let pem = tokio::fs::read_to_string(key_path)
            .await
            .context("read private key pem failed")?;
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
    tokio::fs::write(key_path, pem.as_bytes())
        .await
        .context("write private key pem failed")?;
    Ok(rsa)
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

    /// Helper mirroring the `lib.rs` evaluate contract: the client echoes the
    /// challenge JSON's JWT into `runtime_data` as `challenge_token`, and the
    /// challenger verifies signature + `exp` (freshness only — no nonce is
    /// sent by the client).
    async fn issue_and_verify(c: &JwtChallenger, challenge_json: &str) {
        let outer: Value = serde_json::from_str(challenge_json).expect("outer json");
        let jwt = outer["extra-params"]["jwt"]
            .as_str()
            .expect("jwt in extra-params")
            .to_string();

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
        let key_file = tmp.path().join("key.pem");
        let c = JwtChallenger::new_with_private_key_path(&key_file)
            .await
            .expect("new with key file");

        let challenge_json = c.generate_challenge_json().await.expect("generate");
        // The key file must have been created on first use.
        assert!(key_file.exists(), "key file created on first use");
        issue_and_verify(&c, &challenge_json).await;
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
}
