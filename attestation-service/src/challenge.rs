use anyhow::*;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rsa::signature::{Signer, Verifier};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Value};
use sha2::Sha384;
use std::fs;
use std::path::{Path, PathBuf};

const RSA_KEY_BITS: u32 = 2048;
const TOKEN_ALG: &str = "RS384";
const DEFAULT_KEY_DIR: &str = "/etc/trustee/attestation-service/nonce_token_issuer";
const DEFAULT_PRIV_KEY_PEM: &str = "key.pem";

/// Default filesystem path of the RSA private key used to sign/verify
/// attestation challenge (nonce) tokens. Used when no explicit path is
/// configured in the Attestation Service config.
pub fn default_challenge_key_path() -> PathBuf {
    Path::new(DEFAULT_KEY_DIR).join(DEFAULT_PRIV_KEY_PEM)
}

fn ensure_keypair(key_path: &Path) -> Result<RsaPrivateKey> {
    if let Some(dir) = key_path.parent() {
        if !dir.as_os_str().is_empty() && !dir.exists() {
            fs::create_dir_all(dir)
                .with_context(|| format!("create dir {} failed", dir.display()))?;
        }
    }

    if key_path.exists() {
        let pem = fs::read_to_string(key_path).context("read private key pem failed")?;
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
    fs::write(key_path, pem.as_bytes()).context("write private key pem failed")?;
    Ok(rsa)
}

fn rs384_sign(rsa: &RsaPrivateKey, payload: &[u8]) -> Result<Vec<u8>> {
    let signing_key = SigningKey::<Sha384>::new(rsa.clone());
    let sig: Signature = signing_key.sign(payload);
    Ok(Box::<[u8]>::from(sig).to_vec())
}

pub fn generate_common_challenge(key_path: &Path) -> Result<String> {
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
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
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
    let rsa = ensure_keypair(key_path)?;
    let signature = rs384_sign(&rsa, signing_input.as_bytes())?;
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature);
    let jwt = format!("{}.{}", signing_input, signature_b64);

    // output json
    let output = json!({
        "nonce": claims_value["nonce"].as_str().unwrap_or_default(),
        "extra-params": { "jwt": jwt },
    });
    Ok(serde_json::to_string(&output)?)
}

pub fn verify_challenge_and_extract_nonce_b64url(token: &str, key_path: &Path) -> Result<String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        bail!("invalid JWT format in challenge_token");
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig = URL_SAFE_NO_PAD
        .decode(parts[2])
        .context("invalid JWT signature encoding")?;

    let pem_str = fs::read_to_string(key_path).context("read nonce token key failed")?;
    let rsa = RsaPrivateKey::from_pkcs8_pem(&pem_str)
        .or_else(|_| RsaPrivateKey::from_pkcs1_pem(&pem_str))
        .context("parse nonce token key failed")?;
    let public_key: RsaPublicKey = rsa.to_public_key();

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
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Sign a challenge and verify it round-trips. Pins the rustcrypto RS384
    /// implementation against the on-disk key format this module writes.
    #[test]
    fn challenge_sign_verify_roundtrip() {
        // Use a temp key dir so we don't touch /etc/trustee/...
        let tmp = tempfile::tempdir().unwrap();
        let key_file = tmp.path().join("key.pem");

        let challenge_json = generate_common_challenge(&key_file).expect("generate");
        let outer: serde_json::Value = serde_json::from_str(&challenge_json).expect("json");
        let jwt = outer["extra-params"]["jwt"]
            .as_str()
            .expect("jwt in extra-params")
            .to_string();

        // verify must accept the token we just issued and return the nonce.
        let nonce_back =
            verify_challenge_and_extract_nonce_b64url(&jwt, &key_file).expect("verify");
        let nonce_original = outer["nonce"].as_str().unwrap().to_string();
        // The challenge JSON uses STANDARD base64 for the nonce, while
        // verify_challenge_and_extract_nonce_b64url returns URL_SAFE_NO_PAD.
        // Compare the decoded bytes, not the encoded strings.
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
}
