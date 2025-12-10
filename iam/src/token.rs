//! Token signing and verification utilities.

use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};

use crate::config::CryptoConfig;
use crate::error::IamError;
use crate::models::{Principal, Role, SessionClaims};

/// Wrapper around JWT HMAC helpers.
pub struct TokenSigner {
    encoding: EncodingKey,
    decoding: DecodingKey,
    issuer: String,
    default_ttl: Duration,
}

/// Convenience struct returned by [`TokenSigner::issue`].
pub struct SignedToken {
    pub token: String,
    pub claims: SessionClaims,
}

impl TokenSigner {
    /// Build a signer using the configured shared secret.
    pub fn new(config: &CryptoConfig) -> Result<Self, IamError> {
        let encoding = EncodingKey::from_secret(config.hmac_secret.as_bytes());
        let decoding = DecodingKey::from_secret(config.hmac_secret.as_bytes());
        Ok(Self {
            encoding,
            decoding,
            issuer: config.issuer.clone(),
            default_ttl: Duration::seconds(config.default_ttl_seconds as i64),
        })
    }

    /// Issue a short-lived session token for a principal/role pair.
    pub fn issue(
        &self,
        principal: &Principal,
        role: &Role,
        env: serde_json::Map<String, serde_json::Value>,
        custom: serde_json::Map<String, serde_json::Value>,
        requested_duration: Option<u64>,
        session_name: Option<String>,
    ) -> Result<SignedToken, IamError> {
        let now = Utc::now();
        let duration = requested_duration
            .map(|seconds| Duration::seconds(seconds as i64))
            .unwrap_or(self.default_ttl);
        let claims = SessionClaims {
            sub: principal.id.clone(),
            tenant: principal.account_id.clone(),
            role: role.id.clone(),
            iss: self.issuer.clone(),
            iat: now.timestamp(),
            exp: (now + duration).timestamp(),
            session_name,
            env,
            custom,
        };

        let token = encode(&Header::new(Algorithm::HS256), &claims, &self.encoding)
            .map_err(|err| IamError::Internal(format!("failed to sign token: {err}")))?;

        Ok(SignedToken { token, claims })
    }

    /// Verify and decode a previously issued token.
    pub fn verify(&self, token: &str) -> Result<SessionClaims, IamError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[self.issuer.as_str()]);
        decode::<SessionClaims>(token, &self.decoding, &validation)
            .map(|data| data.claims)
            .map_err(|err| IamError::Unauthorized(format!("invalid token: {err}")))
    }
}
