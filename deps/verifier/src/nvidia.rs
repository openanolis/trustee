// Copyright (c) 2026 Alibaba Cloud
// SPDX-License-Identifier: Apache-2.0

//! NVIDIA NRAS verification, following the CoCo remote NVIDIA verifier.
//! Unlike parsing measurements, this validates the signed verification result
//! covering device/RIM signatures, certificate chains, revocation and freshness.

use anyhow::{anyhow, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[cfg(not(target_arch = "wasm32"))]
mod local;

pub(crate) enum NvidiaVerifier {
    Rim(crate::nvidia_config::NvidiaVerifierConfig),
    Nras(NrasVerifier),
}

impl NvidiaVerifier {
    pub(crate) async fn new(config: &crate::nvidia_config::NvidiaVerifierConfig) -> Result<Self> {
        let config = config.resolve()?;
        match config.mode {
            crate::nvidia_config::NvidiaVerificationMode::Rim => Ok(Self::Rim(config)),
            crate::nvidia_config::NvidiaVerificationMode::Nras => {
                Ok(Self::Nras(NrasVerifier::new(&config).await?))
            }
        }
    }

    pub(crate) async fn verify(
        &self,
        arch: &str,
        report: &str,
        certificate: &str,
        nonce: &[u8; 32],
    ) -> Result<Value> {
        ensure!(
            matches!(arch, "HOPPER" | "BLACKWELL"),
            "Unsupported NVIDIA architecture"
        );
        for field in [report, certificate] {
            let decoded = STANDARD.decode(field)?;
            ensure!(
                !decoded.is_empty() && decoded.len() <= 128 * 1024,
                "Invalid NVIDIA evidence size"
            );
        }
        match self {
            Self::Nras(verifier) => verifier.verify(arch, report, certificate, nonce).await,
            Self::Rim(config) => {
                #[cfg(not(target_arch = "wasm32"))]
                {
                    local::verify(config, arch, report, certificate, nonce).await
                }
                #[cfg(target_arch = "wasm32")]
                {
                    let _ = config;
                    anyhow::bail!("Local NVIDIA RIM verification requires native NVAT; select NRAS explicitly for wasm")
                }
            }
        }
    }
}

const ISSUER: &str = "https://nras.attestation.nvidia.com";
const MAX_RESPONSE_SIZE: usize = 1024 * 1024;

pub(crate) struct NrasVerifier {
    client: reqwest::Client,
    keys: JwkSet,
    url: String,
}

impl NrasVerifier {
    pub(crate) async fn new(config: &crate::nvidia_config::NvidiaVerifierConfig) -> Result<Self> {
        let builder = reqwest::Client::builder();
        #[cfg(not(target_arch = "wasm32"))]
        let builder = builder.timeout(std::time::Duration::from_secs(60));
        let client = builder.build()?;
        let response = client
            .get(&config.nras_jwks_url)
            .send()
            .await?
            .error_for_status()?;
        let bytes = response.bytes().await?;
        ensure!(
            bytes.len() <= MAX_RESPONSE_SIZE,
            "NRAS JWKS response too large"
        );
        let keys: JwkSet = serde_json::from_slice(&bytes)?;
        ensure!(!keys.keys.is_empty(), "NRAS JWKS is empty");
        Ok(Self {
            client,
            keys,
            url: config.nras_url.clone(),
        })
    }

    pub(crate) async fn verify(
        &self,
        arch: &str,
        report: &str,
        certificate: &str,
        nonce: &[u8; 32],
    ) -> Result<Value> {
        ensure!(
            matches!(arch, "HOPPER" | "BLACKWELL"),
            "Unsupported NVIDIA architecture"
        );
        // Validate inputs before contacting the remote verifier. Empty reports
        // and missing certificates must never produce successful GPU claims.
        ensure!(!STANDARD.decode(report)?.is_empty(), "Empty NVIDIA report");
        ensure!(
            !STANDARD.decode(certificate)?.is_empty(),
            "Empty NVIDIA certificate"
        );
        let request = json!({
            "nonce": hex::encode(nonce),
            "arch": arch,
            "evidence_list": [{"evidence": report, "certificate": certificate}],
            "claims_version": "4.0",
        });
        let response = self
            .client
            .post(&self.url)
            .json(&request)
            .send()
            .await?
            .error_for_status()
            .context("NRAS GPU verification request failed")?;
        let bytes = response.bytes().await?;
        ensure!(bytes.len() <= MAX_RESPONSE_SIZE, "NRAS response too large");
        verify_response(&bytes, &self.keys, nonce)
    }
}

/// A Detached EAT Bundle: [["JWT", overall_jwt], {device_id: device_jwt}].
#[derive(Deserialize)]
struct DetachedEat(Vec<String>, BTreeMap<String, String>);

fn verified_jwt(jwt: &str, keys: &JwkSet) -> Result<Value> {
    let header = decode_header(jwt)?;
    ensure!(header.alg == Algorithm::ES384, "NRAS requires ES384");
    let key = keys
        .find(
            header
                .kid
                .as_deref()
                .ok_or_else(|| anyhow!("Missing NRAS key ID"))?,
        )
        .ok_or_else(|| anyhow!("Unknown NRAS key ID"))?;
    let mut validation = Validation::new(Algorithm::ES384);
    validation.set_issuer(&[ISSUER]);
    validation.set_required_spec_claims(&["exp", "nbf", "iat", "iss"]);
    validation.validate_nbf = true;
    validation.validate_aud = false;
    validation.leeway = 0;
    Ok(decode::<Value>(jwt, &DecodingKey::from_jwk(key)?, &validation)?.claims)
}

fn check_nonce(claims: &Value, expected: &[u8; 32]) -> Result<()> {
    let nonce = claims["eat_nonce"]
        .as_str()
        .ok_or_else(|| anyhow!("Missing NRAS nonce"))?;
    ensure!(hex::decode(nonce)? == expected, "NRAS nonce mismatch");
    Ok(())
}

fn require_true(claims: &Value, name: &str) -> Result<()> {
    ensure!(
        claims[name] == true,
        "NVIDIA verification did not pass: {name}"
    );
    Ok(())
}

fn check_gpu_claims(claims: &Value) -> Result<()> {
    for name in [
        "x-nvidia-gpu-attestation-report-parsed",
        "x-nvidia-gpu-attestation-report-signature-verified",
        "x-nvidia-gpu-attestation-report-cert-chain-fwid-match",
        "x-nvidia-gpu-attestation-report-nonce-match",
        "x-nvidia-gpu-arch-check",
        "x-nvidia-gpu-driver-rim-fetched",
        "x-nvidia-gpu-driver-rim-signature-verified",
        "x-nvidia-gpu-driver-rim-measurements-available",
        "x-nvidia-gpu-driver-rim-version-match",
        "x-nvidia-gpu-vbios-rim-fetched",
        "x-nvidia-gpu-vbios-rim-signature-verified",
        "x-nvidia-gpu-vbios-rim-measurements-available",
        "x-nvidia-gpu-vbios-rim-version-match",
        "x-nvidia-gpu-vbios-index-no-conflict",
        "secboot",
    ] {
        require_true(claims, name)?;
    }
    // NVAT 2.0 no longer emits separate schema flags. A successfully parsed,
    // authenticated RIM and matched measurements are still mandatory. NRAS
    // may emit these flags; reject explicit false values when present.
    for name in [
        "x-nvidia-gpu-driver-rim-schema-validated",
        "x-nvidia-gpu-vbios-rim-schema-validated",
    ] {
        if claims.get(name).is_some() {
            require_true(claims, name)?;
        }
    }
    ensure!(
        claims["measres"] == "success",
        "NVIDIA measurement mismatch"
    );
    ensure!(
        claims["dbgstat"] == "disabled",
        "NVIDIA debug facilities enabled or unknown"
    );
    ensure!(
        claims["ueid"].as_str().is_some_and(|id| !id.is_empty()),
        "Missing NVIDIA device identity"
    );
    ensure!(
        claims
            .get("x-nvidia-attestation-warning")
            .is_none_or(|v| v.is_null() || v == false),
        "NVIDIA attestation warning"
    );
    for name in [
        "x-nvidia-gpu-attestation-report-cert-chain",
        "x-nvidia-gpu-driver-rim-cert-chain",
        "x-nvidia-gpu-vbios-rim-cert-chain",
    ] {
        let chain = &claims[name];
        ensure!(
            chain["x-nvidia-cert-status"] == "valid",
            "Invalid or expired NVIDIA certificate: {name}"
        );
        ensure!(
            chain["x-nvidia-cert-ocsp-status"] == "good",
            "NVIDIA certificate revoked or unknown: {name}"
        );
        require_true(chain, "x-nvidia-cert-ocsp-nonce-matches")?;
        require_true(chain, "x-nvidia-cert-ocsp-response-valid")?;
    }
    if let Some(details) = claims.get("x-nvidia-error-details") {
        ensure!(details.is_null(), "NRAS reported verification errors");
    }
    Ok(())
}

fn verify_response(bytes: &[u8], keys: &JwkSet, nonce: &[u8; 32]) -> Result<Value> {
    let DetachedEat(overall, devices) = serde_json::from_slice(bytes)?;
    ensure!(
        overall.len() == 2 && overall[0] == "JWT",
        "Invalid NRAS EAT format"
    );
    ensure!(devices.len() == 1, "NRAS must return exactly one device");
    let overall = verified_jwt(&overall[1], keys)?;
    check_nonce(&overall, nonce)?;
    require_true(&overall, "x-nvidia-overall-att-result")?;
    ensure!(
        overall["x-nvidia-ver"] == "4.0",
        "Unexpected NVIDIA claims version"
    );
    let submods = overall["submods"]
        .as_object()
        .ok_or_else(|| anyhow!("Missing NRAS submods"))?;
    ensure!(submods.len() == 1, "Unexpected NRAS submod count");
    let (name, token) = devices
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("Missing device JWT"))?;
    // Authenticating both JWTs alone does not bind them to each other. Verify
    // the signed overall token's digest of the exact detached device JWT.
    let expected = json!([
        "DIGEST",
        ["SHA-256", hex::encode(Sha256::digest(token.as_bytes()))]
    ]);
    ensure!(
        submods.get(&name) == Some(&expected),
        "NRAS detached JWT digest mismatch"
    );
    let mut claims = verified_jwt(&token, keys)?;
    check_nonce(&claims, nonce)?;
    check_gpu_claims(&claims)?;
    let claims_map = claims
        .as_object_mut()
        .ok_or_else(|| anyhow!("Invalid NRAS GPU claims"))?;
    claims_map.insert("x-nvidia-overall-att-result".into(), json!(true));
    claims_map.insert("verifier".into(), json!("nras"));
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use p384::{
        elliptic_curve::{rand_core::OsRng, sec1::ToEncodedPoint},
        pkcs8::{EncodePrivateKey, LineEnding},
        SecretKey,
    };

    pub(super) fn valid_claims() -> Value {
        let chain = json!({"x-nvidia-cert-status": "valid", "x-nvidia-cert-ocsp-status": "good",
            "x-nvidia-cert-ocsp-nonce-matches": true, "x-nvidia-cert-ocsp-response-valid": true});
        json!({
            "eat_nonce": hex::encode([7u8; 32]), "ueid": "test-device", "secboot": true,
            "dbgstat": "disabled", "measres": "success",
            "x-nvidia-gpu-attestation-report-parsed": true,
            "x-nvidia-gpu-attestation-report-signature-verified": true,
            "x-nvidia-gpu-attestation-report-cert-chain-fwid-match": true,
            "x-nvidia-gpu-attestation-report-nonce-match": true,
            "x-nvidia-gpu-arch-check": true,
            "x-nvidia-gpu-driver-rim-fetched": true,
            "x-nvidia-gpu-driver-rim-signature-verified": true,
            "x-nvidia-gpu-driver-rim-measurements-available": true,
            "x-nvidia-gpu-driver-rim-version-match": true,
            "x-nvidia-gpu-vbios-rim-fetched": true,
            "x-nvidia-gpu-vbios-rim-signature-verified": true,
            "x-nvidia-gpu-vbios-rim-measurements-available": true,
            "x-nvidia-gpu-vbios-rim-version-match": true,
            "x-nvidia-gpu-vbios-index-no-conflict": true,
            "x-nvidia-gpu-attestation-report-cert-chain": chain.clone(),
            "x-nvidia-gpu-driver-rim-cert-chain": chain.clone(),
            "x-nvidia-gpu-vbios-rim-cert-chain": chain,
        })
    }

    struct Signer {
        key: EncodingKey,
        keys: JwkSet,
    }
    impl Signer {
        fn new() -> Self {
            // Generated for this test only; no persisted private key or vendor token.
            let secret = SecretKey::random(&mut OsRng);
            let pem = secret.to_pkcs8_pem(LineEnding::LF).unwrap();
            let point = secret.public_key().to_encoded_point(false);
            let keys = serde_json::from_value(json!({"keys": [{"kty": "EC", "crv": "P-384",
                "alg": "ES384", "use": "sig", "kid": "test-key",
                "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
                "y": URL_SAFE_NO_PAD.encode(point.y().unwrap())}]}))
            .unwrap();
            Self {
                key: EncodingKey::from_ec_pem(pem.as_bytes()).unwrap(),
                keys,
            }
        }
        fn sign(&self, mut claims: Value) -> String {
            let now = jsonwebtoken::get_current_timestamp();
            let map = claims.as_object_mut().unwrap();
            for (name, value) in [
                ("iss", json!(ISSUER)),
                ("exp", json!(now + 3600)),
                ("iat", json!(now)),
                ("nbf", json!(now - 1)),
            ] {
                map.entry(name).or_insert(value);
            }
            let mut header = Header::new(Algorithm::ES384);
            header.kid = Some("test-key".into());
            encode(&header, &claims, &self.key).unwrap()
        }
        fn bundle(&self, claims: Value, mut overall: Value) -> Vec<u8> {
            let device = self.sign(claims);
            let map = overall.as_object_mut().unwrap();
            map.entry("eat_nonce")
                .or_insert(json!(hex::encode([7u8; 32])));
            map.entry("x-nvidia-ver").or_insert(json!("4.0"));
            map.entry("x-nvidia-overall-att-result")
                .or_insert(json!(true));
            map.entry("submods").or_insert(json!({"GPU-0": ["DIGEST", ["SHA-256", hex::encode(Sha256::digest(device.as_bytes()))]]}));
            serde_json::to_vec(&json!([["JWT", self.sign(overall)], {"GPU-0": device}])).unwrap()
        }
    }

    #[test]
    fn nras_accepts_authenticated_bound_success() {
        let signer = Signer::new();
        let claims = verify_response(
            &signer.bundle(valid_claims(), json!({})),
            &signer.keys,
            &[7; 32],
        )
        .unwrap();
        assert_eq!(claims["verifier"], "nras");
        assert_eq!(claims["ueid"], "test-device");
    }

    #[test]
    fn nras_rejects_wrong_key_time_issuer_nonce_and_detached_digest() {
        let signer = Signer::new();
        let good = signer.bundle(valid_claims(), json!({}));
        assert!(verify_response(&good, &Signer::new().keys, &[7; 32]).is_err());
        assert!(verify_response(&good, &signer.keys, &[8; 32]).is_err());
        for overall in [
            json!({"exp": 1}),
            json!({"nbf": jsonwebtoken::get_current_timestamp() + 3600}),
            json!({"iss": "https://attacker.example"}),
            json!({"x-nvidia-overall-att-result": false}),
            json!({"submods": {"GPU-0": ["DIGEST", ["SHA-256", "wrong"]]}}),
        ] {
            assert!(verify_response(
                &signer.bundle(valid_claims(), overall),
                &signer.keys,
                &[7; 32]
            )
            .is_err());
        }
    }

    #[test]
    fn nras_rejects_negative_missing_and_revoked_device_checks() {
        let signer = Signer::new();
        for (key, value) in [
            (
                "x-nvidia-gpu-attestation-report-signature-verified",
                json!(false),
            ),
            ("x-nvidia-gpu-attestation-report-nonce-match", json!(false)),
            ("x-nvidia-gpu-driver-rim-signature-verified", Value::Null),
            ("measres", json!("fail")),
            ("dbgstat", json!("enabled")),
            ("eat_nonce", json!(hex::encode([8; 32]))),
            ("ueid", Value::Null),
        ] {
            let mut claims = valid_claims();
            claims[key] = value;
            assert!(
                verify_response(&signer.bundle(claims, json!({})), &signer.keys, &[7; 32]).is_err(),
                "{key}"
            );
        }
        for status in ["revoked", "unknown", "expired"] {
            let mut claims = valid_claims();
            claims["x-nvidia-gpu-driver-rim-cert-chain"]["x-nvidia-cert-status"] = json!(status);
            assert!(
                verify_response(&signer.bundle(claims, json!({})), &signer.keys, &[7; 32]).is_err()
            );
        }
    }

    fn real_blackwell() -> (String, String, [u8; 32]) {
        let report =
            hex::decode(include_str!("../test_data/nvidia/blackwell_coco_report.txt").trim())
                .unwrap();
        let certificate = include_bytes!("../test_data/nvidia/blackwell_coco_certs.txt");
        let nonce = hex::decode("d622979b6c3ab8b8e7b30a43f2dc7f553ebbc187536231d531effa496ec03fb5")
            .unwrap()
            .try_into()
            .unwrap();
        (STANDARD.encode(report), STANDARD.encode(certificate), nonce)
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    #[ignore = "Requires NVIDIA NVAT 2.x and live RIM/OCSP services"]
    async fn live_real_blackwell_rim_and_tampering() {
        let mut config = crate::nvidia_config::NvidiaVerifierConfig::default()
            .resolve()
            .unwrap();
        // Local verification must work with an unreachable NRAS endpoint.
        config.nras_url = "https://127.0.0.1:1/unused".into();
        config.nras_jwks_url = "https://127.0.0.1:1/unused-jwks".into();
        let verifier = NvidiaVerifier::Rim(config);
        let (report, certificate, nonce) = real_blackwell();
        let claims = verifier
            .verify("BLACKWELL", &report, &certificate, &nonce)
            .await
            .unwrap();
        assert_eq!(claims["verifier"], "rim");
        assert_eq!(claims["x-nvidia-gpu-driver-version"], "595.58.03");
        assert!(verifier
            .verify("BLACKWELL", &report, &certificate, &[0; 32])
            .await
            .is_err());
        let mut tampered = STANDARD.decode(&report).unwrap();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(verifier
            .verify(
                "BLACKWELL",
                &STANDARD.encode(tampered),
                &certificate,
                &nonce
            )
            .await
            .is_err());
        let wrong_cert = STANDARD.encode(include_bytes!(
            "../test_data/nvidia/hopper_cert_chain_case1.txt"
        ));
        assert!(verifier
            .verify("BLACKWELL", &report, &wrong_cert, &nonce)
            .await
            .is_err());
    }

    #[tokio::test]
    #[ignore = "Requires live NVIDIA NRAS and JWKS services"]
    async fn live_real_blackwell_nras_and_wrong_nonce() {
        let config = crate::nvidia_config::NvidiaVerifierConfig::default()
            .resolve()
            .unwrap();
        let verifier = NrasVerifier::new(&config).await.unwrap();
        let (report, certificate, nonce) = real_blackwell();
        let claims = verifier
            .verify("BLACKWELL", &report, &certificate, &nonce)
            .await
            .unwrap();
        assert_eq!(claims["verifier"], "nras");
        assert!(verifier
            .verify("BLACKWELL", &report, &certificate, &[0; 32])
            .await
            .is_err());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    #[ignore = "Requires NVIDIA NVAT 2.x and live RIM/OCSP services"]
    async fn live_real_hopper_expired_rim_is_rejected() {
        let config = crate::nvidia_config::NvidiaVerifierConfig::default()
            .resolve()
            .unwrap();
        let verifier = NvidiaVerifier::Rim(config);
        let report = STANDARD.encode(
            hex::decode(include_str!("../test_data/nvidia/hopperAttestationReport.txt").trim())
                .unwrap(),
        );
        let cert = STANDARD.encode(include_bytes!(
            "../test_data/nvidia/hopper_cert_chain_case1.txt"
        ));
        let nonce = hex::decode("931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb")
            .unwrap()
            .try_into()
            .unwrap();
        let error = verifier
            .verify("HOPPER", &report, &cert, &nonce)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("exit 12"), "{error}");
    }

    // Files stay outside the repository: fresh reports identify the test GPU.
    #[cfg(not(target_arch = "wasm32"))]
    fn hardware_evidence() -> (Value, Vec<u8>) {
        let evidence = std::fs::read(
            std::env::var("TRUSTEE_NVIDIA_HARDWARE_EVIDENCE")
                .expect("Set TRUSTEE_NVIDIA_HARDWARE_EVIDENCE to collected evidence JSON"),
        )
        .unwrap();
        let report_data =
            std::fs::read(std::env::var("TRUSTEE_NVIDIA_HARDWARE_REPORT_DATA").expect(
                "Set TRUSTEE_NVIDIA_HARDWARE_REPORT_DATA to the original 64-byte challenge",
            ))
            .unwrap();
        assert_eq!(report_data.len(), 64);
        (serde_json::from_slice(&evidence).unwrap(), report_data)
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    #[ignore = "Requires fresh GPU evidence and live NVIDIA services; see nvidia/README.md"]
    async fn live_hardware_gpu_evidence() {
        let (evidence, report_data) = hardware_evidence();
        let mut config = crate::nvidia_config::NvidiaVerifierConfig::default()
            .resolve()
            .unwrap();
        let verifier = match config.mode {
            crate::nvidia_config::NvidiaVerificationMode::Rim => {
                config.nras_url = "https://127.0.0.1:1/unused".into();
                config.nras_jwks_url = "https://127.0.0.1:1/unused-jwks".into();
                NvidiaVerifier::Rim(config)
            }
            crate::nvidia_config::NvidiaVerificationMode::Nras => {
                NvidiaVerifier::Nras(NrasVerifier::new(&config).await.unwrap())
            }
        };
        let nonce = crate::tdx::gpu::gpu_nonce(&report_data);
        let gpus = evidence["gpu_evidence"]["evidence_list"]
            .as_array()
            .unwrap();
        assert!(!gpus.is_empty());
        for gpu in gpus {
            let arch = gpu["arch"].as_str().unwrap();
            let report = gpu["attestation_report"].as_str().unwrap();
            let certificate = gpu["certificate"].as_str().unwrap();
            let claims = verifier
                .verify(arch, report, certificate, &nonce)
                .await
                .unwrap();
            assert_eq!(claims["x-nvidia-gpu-driver-version"], gpu["driver_version"]);
            let mut wrong_nonce = nonce;
            wrong_nonce[0] ^= 1;
            assert!(verifier
                .verify(arch, report, certificate, &wrong_nonce)
                .await
                .is_err());
            let mut tampered = STANDARD.decode(report).unwrap();
            *tampered.last_mut().unwrap() ^= 1;
            assert!(verifier
                .verify(arch, &STANDARD.encode(tampered), certificate, &nonce)
                .await
                .is_err());
            let wrong_certificate = STANDARD.encode(include_bytes!(
                "../test_data/nvidia/blackwell_coco_certs.txt"
            ));
            assert!(verifier
                .verify(arch, report, &wrong_certificate, &nonce)
                .await
                .is_err());
            println!("GPU hardware verification passed: mode={}, arch={}, driver={}; wrong nonce, signature and certificate rejected",
                claims["verifier"], arch, claims["x-nvidia-gpu-driver-version"]);
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    #[ignore = "Requires fresh combined TDX/GPU evidence, PCCS and NVIDIA services"]
    async fn live_hardware_tdx_gpu_binding() {
        use crate::{InitDataHash, ReportData, Verifier};
        let (evidence, report_data) = hardware_evidence();
        let verifier = crate::tdx::Tdx::default();
        let expected_report_data = ReportData::Value(&report_data);
        let init_data_hash = InitDataHash::NotProvided;
        let verify = |evidence| verifier.evaluate(evidence, &expected_report_data, &init_data_hash);
        let (claims, _) = verify(evidence.clone()).await.unwrap();
        let count = evidence["gpu_evidence"]["evidence_list"]
            .as_array()
            .unwrap()
            .len();
        assert!(count > 0);
        assert_eq!(claims["nvidia_gpu_count"], count);
        let mut wrong_data = report_data.clone();
        wrong_data[0] ^= 1;
        assert!(verifier
            .evaluate(
                evidence.clone(),
                &ReportData::Value(&wrong_data),
                &InitDataHash::NotProvided
            )
            .await
            .is_err());
        let mut removed = evidence.clone();
        removed.as_object_mut().unwrap().remove("gpu_evidence");
        assert!(verify(removed).await.is_err());
        let mut changed = evidence.clone();
        let original = changed["gpu_evidence"]["evidence_list"][0]["attestation_report"]
            .as_str()
            .unwrap();
        let mut bytes = STANDARD.decode(original).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        changed["gpu_evidence"]["evidence_list"][0]["attestation_report"] =
            json!(STANDARD.encode(bytes));
        assert!(verify(changed).await.is_err());
        println!("TDX + {count} GPU(s) verification passed; changed challenge, removed GPU evidence and changed GPU report rejected");
    }
}
