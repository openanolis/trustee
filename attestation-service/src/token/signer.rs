// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Shared, generic signing-key providers for the token brokers.
//!
//! [`SignKeyProvider`]`<K>` is the common trait; [`FsSigner`]`<K>` (key
//! material loaded from a [`SignerConfig`] on disk, fs-gated construction)
//! and [`EphemeralSigner`]`<K>` (a fresh key generated at runtime) are the
//! two implementations. The shared cert-chain / cert-url / cert-pem-live
//! plumbing is written once in the generic trait impls; K-specific
//! construction (PEM parsing, key generation) is provided via concrete
//! inherent impls on the specific key types the brokers use
//! (`rsa::RsaPrivateKey`, `p256::SecretKey`).

#[cfg(feature = "fs")]
use anyhow::Context;
use anyhow::Result;
use p256::SecretKey;
use rand::rngs::OsRng;
use rsa::RsaPrivateKey;
use rustls_pki_types::CertificateDer;
use serde::Deserialize;

#[cfg(feature = "fs")]
use p256::pkcs8::DecodePrivateKey as EcDecodePrivateKey;
#[cfg(feature = "fs")]
use rsa::pkcs1::DecodeRsaPrivateKey;
#[cfg(feature = "fs")]
use rustls_pki_types::pem::PemObject;

/// Shared RSA key size (bits) for ephemeral RSA signers.
const RSA_KEY_BITS: u32 = 2048;

/// A signing-key provider. `K` is the concrete key type and is fixed per
/// broker, so `dyn SignKeyProvider<RsaPrivateKey>` /
/// `dyn SignKeyProvider<SecretKey>` are valid trait objects: every method has
/// no method-level generics and does not return `Self`.
pub trait SignKeyProvider<K>: Send + Sync {
    fn private_key(&self) -> &K;
    fn cert_chain(&self) -> Option<Result<Vec<CertificateDer<'static>>>>;
    fn cert_url(&self) -> Option<&str>;
    /// The signer's certificate-chain raw PEM bytes, read lazily from the
    /// configured `cert_path` on each call (not cached at construction).
    /// `None` when no `cert_path` is configured. Ephemeral signers return
    /// `None`. The broker forwards this through `signer_cert_pem_live`.
    fn cert_pem_live(&self) -> Option<Result<Vec<u8>>>;
    /// Whether this signer was loaded from explicit configuration
    /// ([`FsSigner`]) rather than an ephemeral key generated at runtime
    /// ([`EphemeralSigner`]).
    ///
    /// Brokers use this to decide whether to publish the signer's public key
    /// at the `/jwks` endpoint: the attestation service has historically
    /// published a JWKS only when a signer was explicitly configured,
    /// answering `404` otherwise. An ephemeral key is freshly generated per
    /// process start, so clients cannot pin it and it is not published.
    /// [`FsSigner`] overrides this to `true`; [`EphemeralSigner`] keeps the
    /// default `false`.
    fn is_configured(&self) -> bool {
        false
    }
}

/// Signer resolved from a [`SignerConfig`] (native/serde path). Reads
/// `key_path`/`cert_path` on disk under the `fs` feature.
#[cfg(feature = "fs")]
pub struct FsSigner<K> {
    private_key: K,
    cert_url: Option<String>,
    // Kept so `cert_pem_live` can re-read the raw PEM bytes lazily on each call.
    // This mirrors the historical `get_token_broker_cert_config` /
    // `get_cert_content` cert endpoint, which always served the *current*
    // on-disk certificate (no cache) — the right behavior for an endpoint
    // whose job is to expose whatever cert is deployed.
    cert_path: Option<String>,
    // Parsed certificate chain, loaded *once* at construction and cached.
    // This backs the `x5c`/`jwk` embedded in issued tokens via `cert_chain()`.
    // Caching (rather than re-reading per attest) does two things:
    //   1. avoids a file read + PEM parse on every token issuance; and
    //   2. keeps the cert chain and `private_key` as a single
    //      construction-time snapshot, so the `x5c` in a token always matches
    //      the key that signed it — even if the cert file is swapped at run
    //      time. (A re-read-per-attest design would let `x5c` drift away from
    //      the cached signing key.) This matches the historical behavior of
    //      the attestation-service brokers, which loaded and cached the cert
    //      chain once at construction (alongside the private key) and reused
    //      it for every issued token.
    // Note: `cert_path` is kept separately above so `cert_pem_live` (the cert
    // *endpoint*) can still re-read lazily — the two paths have different
    // semantics and must not be unified.
    cert_chain: Option<Vec<CertificateDer<'static>>>,
}

/// Ephemeral signer: generates a fresh key at runtime. Used when no signer is
/// configured (both `from_config` and `from_components`).
pub struct EphemeralSigner<K> {
    private_key: K,
}

#[cfg(feature = "fs")]
impl<K: Send + Sync> SignKeyProvider<K> for FsSigner<K> {
    fn private_key(&self) -> &K {
        &self.private_key
    }
    // Returns the construction-time cached chain (see field doc). Never reads
    // disk here — the read+parse already happened in `from_config`, so by the
    // time this is called the result is infallible. (The `Result` in the
    // return type is kept to satisfy the trait signature; other impls may be
    // fallible at call time.)
    fn cert_chain(&self) -> Option<Result<Vec<CertificateDer<'static>>>> {
        self.cert_chain.clone().map(Ok)
    }
    fn cert_url(&self) -> Option<&str> {
        self.cert_url.as_deref()
    }
    fn cert_pem_live(&self) -> Option<Result<Vec<u8>>> {
        self.cert_path.as_ref().map(|path| {
            use std::io::Read as _;
            // Read certificate from file
            let mut file = std::fs::File::open(path)
                .map_err(|e| anyhow::anyhow!("Failed to open certificate file: {}", e))?;
            let mut content = Vec::new();
            file.read_to_end(&mut content)
                .map_err(|e| anyhow::anyhow!("Failed to read certificate file: {}", e))?;
            Ok(content)
        })
    }
    // Loaded from an explicit `SignerConfig` on disk — publishable.
    fn is_configured(&self) -> bool {
        true
    }
}

impl<K: Send + Sync> SignKeyProvider<K> for EphemeralSigner<K> {
    fn private_key(&self) -> &K {
        &self.private_key
    }
    fn cert_chain(&self) -> Option<Result<Vec<CertificateDer<'static>>>> {
        None
    }
    fn cert_url(&self) -> Option<&str> {
        None
    }
    fn cert_pem_live(&self) -> Option<Result<Vec<u8>>> {
        None
    }
}

/// Shared signer configuration (deserialized from the token-broker config).
///
/// Note: unifying on `#[serde(default)]` for `cert_url`/`cert_path` relaxes
/// the simple/oidc configs (which previously errored on a missing field) to
/// match ear's existing tolerant behavior. This does not affect emitted
/// tokens; `cert_url`/`cert_path` only influence `x5u`/`x5c` when set.
#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct SignerConfig {
    pub key_path: String,
    #[serde(default)]
    pub cert_url: Option<String>,
    // PEM format certificate chain.
    #[serde(default)]
    pub cert_path: Option<String>,
}

// --- Concrete construction impls ("specific code on the generic") ---

/// Read and PEM-parse a certificate chain from `cert_path` once, returning
/// the parsed `CertificateDer` list (or `None` when no `cert_path` is
/// configured). Used by both `FsSigner::*::from_config` to populate the
/// cached `cert_chain` field at construction time.
#[cfg(feature = "fs")]
fn load_cert_chain(cert_path: &Option<String>) -> Result<Option<Vec<CertificateDer<'static>>>> {
    match cert_path {
        Some(cert_path) => {
            let pem_cert_chain =
                std::fs::read_to_string(cert_path).context("Read Token Signer cert file failed")?;
            let chain: Result<Vec<_>, rustls_pki_types::pem::Error> =
                CertificateDer::pem_slice_iter(pem_cert_chain.as_bytes()).collect();
            Ok(Some(chain.context("Invalid PEM certificate chain")?))
        }
        None => Ok(None),
    }
}

#[cfg(feature = "fs")]
impl FsSigner<RsaPrivateKey> {
    /// Parse an RSA private key from `SignerConfig::key_path` (PKCS#8, with a
    /// PKCS#1 fallback).
    pub fn from_config(signer: SignerConfig) -> Result<Self> {
        let pem_data = std::fs::read_to_string(&signer.key_path)
            .context("Read Token Signer private key failed")?;
        let private_key = RsaPrivateKey::from_pkcs8_pem(&pem_data)
            .or_else(|_| RsaPrivateKey::from_pkcs1_pem(&pem_data))
            .context("Parse Token Signer private key failed")?;
        // Cache the cert chain at construction (see `cert_chain` field doc).
        let cert_chain = load_cert_chain(&signer.cert_path)?;
        Ok(Self {
            private_key,
            cert_url: signer.cert_url,
            cert_path: signer.cert_path,
            cert_chain,
        })
    }
}

#[cfg(feature = "fs")]
impl FsSigner<SecretKey> {
    /// Parse an EC P-256 private key from `SignerConfig::key_path` (SEC1, with
    /// a PKCS#8 fallback).
    pub fn from_config(signer: SignerConfig) -> Result<Self> {
        let pem_data =
            std::fs::read(&signer.key_path).context("Read Token Signer private key failed")?;
        let pem_str = std::str::from_utf8(&pem_data).context("Token Signer key not UTF-8")?;
        let private_key = SecretKey::from_sec1_pem(pem_str)
            .or_else(|_| SecretKey::from_pkcs8_pem(pem_str))
            .context("Parse Token Signer private key failed")?;
        // Cache the cert chain at construction (see `cert_chain` field doc).
        let cert_chain = load_cert_chain(&signer.cert_path)?;
        Ok(Self {
            private_key,
            cert_url: signer.cert_url,
            cert_path: signer.cert_path,
            cert_chain,
        })
    }
}

impl EphemeralSigner<RsaPrivateKey> {
    /// Generate a fresh 2048-bit RSA key.
    pub fn new() -> Result<Self> {
        let mut rng = OsRng;
        Ok(Self {
            private_key: RsaPrivateKey::new(&mut rng, RSA_KEY_BITS as usize)?,
        })
    }
}

impl EphemeralSigner<SecretKey> {
    /// Generate a fresh EC P-256 key.
    pub fn new() -> Self {
        let mut rng = OsRng;
        Self {
            private_key: SecretKey::random(&mut rng),
        }
    }
}

impl Default for EphemeralSigner<SecretKey> {
    fn default() -> Self {
        Self::new()
    }
}
