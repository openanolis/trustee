use std::collections::HashSet;
use std::sync::Mutex;

use anyhow::{Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::{json, Value};

/// [`super::Challenger`] that mints a purely local random nonce with no JWT
/// and no cryptographic key.
///
/// On each [`Self::generate_challenge`] it draws 32 random bytes, builds the
/// challenge JSON `{"nonce": <b64>}`, stores the **full JSON string**
/// (`serde_json::to_string(&output)`) in an in-memory set, and returns that
/// same string. There is no `extra-params` wrapper and no `jwt` field,
/// because the nonce itself is the single-use token: nothing is signed, so
/// no separate signed token is needed.
///
/// The AS verify path reads `runtime_data["challenge_token"]` (see
/// `AttestationService::evaluate`). For the JWT-based challengers the client
/// sources that field from `extra-params.jwt`; here there is none, so the
/// client echoes the entire challenge JSON back as
/// `runtime_data["challenge_token"]`.
/// [`Self::verify_challenge_and_extract_nonce_b64url`] looks the full JSON
/// string up in the set and removes it on success — each token is
/// single-use and a replay is rejected.
///
/// Unlike the JWT-based [`super::EphemeralJwtChallenger`] /
/// [`super::FsJwtChallenger`] there is no signature and no `exp` claim:
/// freshness comes entirely from one-time consumption. This trades the
/// multi-replica story of the JWT impls for a stronger single-instance
/// guarantee — a consumed token can never be replayed, not even within an
/// `exp` window. The cost is that the nonce set lives only in this process:
/// tokens issued here cannot be verified by another replica, and the set is
/// lost on restart. It is therefore unsuitable for multi-replica deployments.
/// The set also grows with issued-but-unconsumed tokens, so in a long-running
/// process keep the client round-trip short.
pub struct LocalNonceChallenger {
    issued: Mutex<HashSet<String>>,
}

impl LocalNonceChallenger {
    /// Build an empty local challenger.
    pub fn new() -> Self {
        Self {
            issued: Mutex::new(HashSet::new()),
        }
    }
}

impl Default for LocalNonceChallenger {
    fn default() -> Self {
        Self::new()
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
impl super::Challenger for LocalNonceChallenger {
    async fn generate_challenge(&self) -> Result<String> {
        let mut nonce = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut nonce)
            .context("generate nonce failed")?;

        // The nonce IS the single-use token. Emit it under the standard
        // `nonce` field (no `extra-params` wrapper) — the client echoes the
        // entire JSON string back as `runtime_data["challenge_token"]`,
        // which is what `verify` receives. Store the same JSON string so
        // the lookup matches exactly.
        let token = URL_SAFE_NO_PAD.encode(nonce);
        let output = json!({ "nonce": token });
        let challenge_json = serde_json::to_string(&output)?;

        self.issued
            .lock()
            .expect("issued-nonce mutex poisoned")
            .insert(challenge_json.clone());

        Ok(challenge_json)
    }

    async fn verify_challenge_and_extract_nonce_b64url(&self, token: &str) -> Result<String> {
        // Single-use: remove on success. A missing entry means the token was
        // never issued here, was already consumed, or was issued by another
        // process — all are treated as a verification failure.
        let removed = self
            .issued
            .lock()
            .expect("issued-nonce mutex poisoned")
            .remove(token);
        if !removed {
            anyhow::bail!("challenge_token not recognized or already consumed");
        }
        // The token is the full JSON string `{"nonce":"<b64url>"}`. Parse
        // it to extract the nonce — already base64url-no-pad, matching the
        // trait's return contract.
        let v: Value = serde_json::from_str(token).context("invalid challenge_token json")?;
        let nonce_b64url = v
            .get("nonce")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow::anyhow!("missing nonce field in challenge_token"))?;
        Ok(nonce_b64url.to_string())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use crate::Challenger as _;

    use super::*;

    /// `LocalNonceChallenger`: generate + verify round-trip, no JWT, no
    /// filesystem, no `extra-params`. The full JSON string from
    /// `generate_challenge` is the token the client echoes back as
    /// `challenge_token`.
    #[tokio::test]
    async fn local_roundtrip() {
        let c = LocalNonceChallenger::new();

        let challenge_json = c.generate_challenge().await.expect("generate");
        let outer: Value = serde_json::from_str(&challenge_json).expect("outer json");
        // No extra-params: the token is the full JSON string.
        assert!(
            outer.get("extra-params").is_none(),
            "local challenger emits no extra-params"
        );

        let nonce_back = c
            .verify_challenge_and_extract_nonce_b64url(&challenge_json)
            .await
            .expect("verify");

        // Both generate and verify use URL_SAFE_NO_PAD — compare strings
        // directly.
        let nonce_original = outer["nonce"].as_str().expect("nonce field present");
        assert_eq!(nonce_back, nonce_original, "nonce must round-trip");
    }

    /// A token is single-use: the second verification of the same token must
    /// fail because the first consumed it.
    #[tokio::test]
    async fn local_token_is_single_use() {
        let c = LocalNonceChallenger::new();
        let challenge_json = c.generate_challenge().await.expect("generate");

        c.verify_challenge_and_extract_nonce_b64url(&challenge_json)
            .await
            .expect("first verify consumes the token");
        let second = c
            .verify_challenge_and_extract_nonce_b64url(&challenge_json)
            .await;
        assert!(second.is_err(), "replayed token must be rejected");
    }

    /// An unknown token (never issued) must be rejected.
    #[tokio::test]
    async fn local_unknown_token_rejected() {
        let c = LocalNonceChallenger::new();
        let bogus = serde_json::to_string(&json!({ "nonce": URL_SAFE_NO_PAD.encode([0u8; 32]) }))
            .expect("bogus json");
        let res = c.verify_challenge_and_extract_nonce_b64url(&bogus).await;
        assert!(res.is_err(), "unissued token must be rejected");
    }
}
