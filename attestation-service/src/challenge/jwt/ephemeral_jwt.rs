use anyhow::Result;
use rand::rngs::OsRng;
use rsa::RsaPrivateKey;

use crate::Challenger;

use super::{build_challenge_json, verify_jwt, RSA_KEY_BITS};

/// [`super::Challenger`] backed by a random RSA key generated once at
/// construction and held purely in memory for the process lifetime.
///
/// JWT-based (RS384) challenge key — the issued JWT itself is the nonce, so
/// see [`super::build_challenge_json`] for why the `exp` claim gives freshness
/// across replicas without synchronizing every signed token.
///
/// Wasm- and pure-lib-friendly; the default challenger on fs-free builds.
/// Each process restart gets a fresh key, so challenge tokens issued by one
/// instance cannot be verified by another.
pub struct EphemeralJwtChallenger {
    key: RsaPrivateKey,
}

impl EphemeralJwtChallenger {
    /// Generate a fresh 2048-bit RSA key with `OsRng`.
    pub fn new() -> Result<Self> {
        let mut rng = OsRng;
        let key = RsaPrivateKey::new(&mut rng, RSA_KEY_BITS as usize)?;
        Ok(Self { key })
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
impl Challenger for EphemeralJwtChallenger {
    async fn generate_challenge(&self) -> Result<String> {
        build_challenge_json(&self.key)
    }

    async fn verify_challenge_and_extract_nonce_b64url(&self, token: &str) -> Result<String> {
        verify_jwt(token, &self.key)
    }
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use base64::Engine as _;
    use serde_json::Value;

    use crate::Challenger as _;

    use super::*;

    /// `EphemeralJwtChallenger`: sign + verify round-trip, no filesystem.
    #[tokio::test]
    async fn ephemeral_roundtrip() {
        let c = EphemeralJwtChallenger::new().expect("new ephemeral challenger");

        let challenge_json = c.generate_challenge().await.expect("generate");
        let outer: Value = serde_json::from_str(&challenge_json).expect("outer json");
        let jwt = outer["extra-params"]["jwt"]
            .as_str()
            .expect("jwt in extra-params")
            .to_string();

        let nonce_back = c
            .verify_challenge_and_extract_nonce_b64url(&jwt)
            .await
            .expect("verify");
        let nonce_original = outer["nonce"].as_str().unwrap().to_string();

        // generate uses STANDARD base64 for the nonce; verify returns
        // URL_SAFE_NO_PAD. Compare decoded bytes, not the encoded strings.
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
