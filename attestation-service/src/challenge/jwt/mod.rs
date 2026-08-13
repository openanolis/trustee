use anyhow::*;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::signature::{Signer, Verifier};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Value};
use sha2::Sha384;

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

pub(super) mod ephemeral_jwt;
#[cfg(feature = "fs")]
pub(super) mod fs_jwt;

pub(self) const RSA_KEY_BITS: u32 = 2048;
const TOKEN_ALG: &str = "RS384";

/// Build the challenge JSON `{"nonce", "extra-params":{"jwt"}}` signed with
/// `key` (RS384, 5-minute `exp`). Shared by every JWT-based [`Challenger`]
/// impl.
///
/// The issued JWT itself serves as the nonce. The `exp` claim bounds its
/// validity window, which gives freshness when the Attestation Service runs
/// with multiple replicas sharing the same signing key: each replica can
/// verify a token's signature and `exp` independently, so a JWT that has
/// already been consumed by one replica cannot be replayed once `exp` passes.
/// This avoids, to a degree, the need to synchronize a record of every
/// signed JWT across replicas — the short `exp` window bounds the window in
/// which a consumed-but-unsynced token could be replayed, without requiring
/// shared state on the hot path.
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

/// Verify a challenge_token JWT signed by the public half of `key`, enforce
/// `exp`, and return the nonce base64url-no-pad encoded. Shared by every
/// [`Challenger`] impl.
fn verify_jwt(token: &str, key: &RsaPrivateKey) -> Result<String> {
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

    let nonce_b64 = v
        .get("nonce")
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("missing nonce claim in challenge_token"))?;
    let nonce_bytes = STANDARD
        .decode(nonce_b64)
        .or_else(|_| URL_SAFE_NO_PAD.decode(nonce_b64))
        .context("invalid nonce base64")?;
    Ok(URL_SAFE_NO_PAD.encode(nonce_bytes))
}
