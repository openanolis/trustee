use anyhow::*;

mod jwt;
mod nonce;

pub use jwt::ephemeral_jwt::EphemeralJwtChallenger;
#[cfg(feature = "fs")]
pub use jwt::fs_jwt::FsJwtChallenger;
pub use nonce::LocalNonceChallenger;

/// Abstraction over how the Attestation Service issues and verifies
/// attestation-challenge (nonce) tokens. The AS verify path reads
/// `runtime_data["challenge_token"]` and passes that string to
/// [`Challenger::verify_challenge_and_extract_nonce_b64url`]; how the client
/// populates `challenge_token`, and how the token is minted and checked, is
/// impl-specific:
///
/// - the JWT-based [`EphemeralJwtChallenger`] / [`FsJwtChallenger`] return
///   `{"nonce": <b64>, "extra-params": {"jwt": <signed jwt>}}`, and the client
///   sources `challenge_token` from `extra-params.jwt`; freshness is the
///   JWT signature + `exp` (multi-replica friendly).
/// - [`LocalNonceChallenger`] returns just `{"nonce": <b64>}` — the nonce
///   itself is the single-use token, so the client echoes the `nonce` back as
///   `challenge_token`; freshness is one-time set membership (single-instance,
///   single-use).
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

    /// Verify a challenge token (the string the client returns as
    /// `challenge_token`), enforce its freshness, and return the nonce
    /// base64url-no-pad encoded. What "freshness" means is impl-specific:
    /// signature + `exp` for the JWT challengers, one-time set membership for
    /// [`LocalNonceChallenger`]. Rejects bad / replayed / expired tokens.
    async fn verify_challenge_and_extract_nonce_b64url(&self, token: &str) -> Result<String>;
}
