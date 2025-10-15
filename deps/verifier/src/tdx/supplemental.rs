use anyhow::*;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rand::rand_bytes;
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use serde_json::json;
use std::fs;
use std::path::Path;

const RSA_KEY_BITS: u32 = 2048;
const TOKEN_ALG: &str = "RS384";
const KEY_DIR: &str = "/etc/trustee/attestation-service/nonce_token_issuer";
const PRIV_KEY_PEM: &str = "key.pem";

fn ensure_keypair() -> Result<Rsa<Private>> {
    let dir = Path::new(KEY_DIR);
    if !dir.exists() {
        fs::create_dir_all(dir).with_context(|| format!("create dir {} failed", KEY_DIR))?;
    }

    let key_path = dir.join(PRIV_KEY_PEM);
    if key_path.exists() {
        let pem = fs::read(&key_path).context("read private key pem failed")?;
        let rsa = Rsa::private_key_from_pem(&pem).context("parse private key pem failed")?;
        return Ok(rsa);
    }

    let rsa = Rsa::generate(RSA_KEY_BITS)?;
    let pem = rsa
        .private_key_to_pem()
        .context("dump private key to pem failed")?;
    fs::write(&key_path, pem).context("write private key pem failed")?;
    Ok(rsa)
}

fn rs384_sign(rsa: &Rsa<Private>, payload: &[u8]) -> Result<Vec<u8>> {
    let rsa_pkey = PKey::from_rsa(rsa.clone())?;
    let mut signer = Signer::new(MessageDigest::sha384(), &rsa_pkey)?;
    signer.update(payload)?;
    Ok(signer.sign_to_vec()?)
}

pub(crate) fn generate_supplemental_challenge_impl(_tee_parameters: String) -> Result<String> {
    // 1) 生成 32 字节随机 nonce 并 base64url 编码
    let mut nonce = [0u8; 32];
    rand_bytes(&mut nonce)?;
    let nonce_b64 = STANDARD.encode(nonce);

    // 2) 构造最小 JWT
    let header_value = json!({
        "typ": "JWT",
        "alg": TOKEN_ALG,
    });
    let header_string = serde_json::to_string(&header_value)?;
    let header_b64 = URL_SAFE_NO_PAD.encode(header_string.as_bytes());

    // 5分钟有效期
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| anyhow!("time error: {:?}", e))?
        .as_secs();
    let exp = now + 5 * 60;

    let claims_value = json!({
        "nonce": nonce_b64,
        "iat": now,
        "exp": exp,
    });
    let claims_string = serde_json::to_string(&claims_value)?;
    let claims_b64 = URL_SAFE_NO_PAD.encode(claims_string.as_bytes());

    let signing_input = format!("{}.{}", header_b64, claims_b64);

    let rsa = ensure_keypair()?;
    let signature = rs384_sign(&rsa, signing_input.as_bytes())?;
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature);
    let jwt = format!("{}.{}", signing_input, signature_b64);

    // 3) 返回所需 JSON 字符串
    let output = json!({
        "nonce": claims_value["nonce"].as_str().unwrap_or_default(),
        "extra-params": { "jwt": jwt },
    });
    Ok(serde_json::to_string(&output)?)
}
