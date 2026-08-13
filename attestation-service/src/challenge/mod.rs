use anyhow::*;

mod jwt;

pub use jwt::ephemeral_jwt::EphemeralJwtChallenger;
#[cfg(feature = "fs")]
pub use jwt::fs_jwt::FsJwtChallenger;

/// Abstraction over how the Attestation Service signs and verifies
/// attestation-challenge (nonce) tokens. Implementations differ only in how
/// they obtain the RSA private key; the JWT protocol itself is shared.
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
pub trait Challenger {
    /// Issue a fresh challenge (nonce) token. Returns the outer JSON
    /// `{"nonce": <b64>, "extra-params": {"jwt": <jwt>}}` — same shape as the
    /// historical free function, so the public AS API is unchanged.
    async fn generate_challenge(&self) -> Result<String>;

    /// Verify a challenge_token JWT, enforce its `exp` claim, and return the
    /// nonce base64url-no-pad encoded. Rejects bad signatures / expired
    /// tokens.
    async fn verify_challenge_and_extract_nonce_b64url(&self, token: &str) -> Result<String>;
}
