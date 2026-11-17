use crate::{nvidia::NvidiaVerifier, nvidia_config::NvidiaVerifierConfig, TeeEvidenceParsedClaim};
use anyhow::{anyhow, ensure, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashSet;

/// Compatibility API. Prefer nvidia_verifier.rim_url in AS configuration.
/// Environment settings still take precedence.
#[deprecated(note = "Use NvidiaVerifierConfig.rim_url")]
pub fn set_rim_service_url(url: Option<String>) {
    crate::nvidia_config::set_legacy_rim_url(url.map(|url| {
        url.trim_end_matches('/')
            .trim_end_matches("/v1/rim")
            .to_owned()
    }));
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuEvidenceList {
    #[serde(default)]
    pub binding_version: u32,
    pub evidence_list: Vec<GpuEvidence>,
    pub collection_time: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuEvidence {
    pub arch: String,
    pub index: u32,
    pub uuid: String,
    pub name: String,
    pub driver_version: String,
    pub vbios_version: String,
    pub attestation_report: Option<String>,
    pub certificate: Option<String>,
    pub cc_enabled: bool,
}

pub fn gpu_nonce(padded_report_data: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"tdx-nvidia-nonce-v1\0");
    hash.update(padded_report_data);
    hash.finalize().into()
}

impl GpuEvidenceList {
    pub fn bound_report_data(&self, report_data: &[u8]) -> Result<Vec<u8>> {
        ensure!(report_data.len() <= 64, "TDX report data exceeds 64 bytes");
        ensure!(
            self.binding_version == 1,
            "Unbound or unsupported GPU evidence version"
        );
        ensure!(
            !self.evidence_list.is_empty() && self.evidence_list.len() <= 32,
            "Invalid GPU count"
        );
        let mut padded = [0u8; 64];
        padded[..report_data.len()].copy_from_slice(report_data);
        let mut hash = Sha512::new();
        hash.update(b"tdx-nvidia-evidence-v1\0");
        hash.update(padded);
        hash.update((self.evidence_list.len() as u32).to_le_bytes());
        let mut indices = HashSet::new();
        for gpu in &self.evidence_list {
            ensure!(indices.insert(gpu.index), "Duplicate GPU index");
            ensure!(
                matches!(gpu.arch.as_str(), "HOPPER" | "BLACKWELL"),
                "Unsupported NVIDIA architecture"
            );
            hash.update(gpu.index.to_le_bytes());
            let (report, cert) = gpu.report_and_certificate()?;
            for field in [gpu.arch.as_bytes(), report.as_slice(), cert.as_slice()] {
                hash.update(u32::try_from(field.len())?.to_le_bytes());
                hash.update(field);
            }
        }
        Ok(hash.finalize().to_vec())
    }

    pub async fn evaluate(
        &self,
        nonce: &[u8; 32],
        config: &NvidiaVerifierConfig,
    ) -> Result<serde_json::Map<String, serde_json::Value>> {
        let verifier = NvidiaVerifier::new(config).await?;
        let mut claims = serde_json::Map::new();
        let mut identities = HashSet::new();
        for (index, gpu) in self.evidence_list.iter().enumerate() {
            let claim = gpu.evaluate(&verifier, nonce).await?;
            let identity = claim["ueid"]
                .as_str()
                .ok_or_else(|| anyhow!("Missing GPU identity"))?;
            ensure!(
                identities.insert(identity.to_owned()),
                "Repeated NVIDIA device identity"
            );
            claims.insert(format!("nvidia_gpu.{index}"), claim);
        }
        claims.insert(
            "nvidia_gpu_count".into(),
            serde_json::json!(identities.len()),
        );
        Ok(claims)
    }
}

impl GpuEvidence {
    fn report_and_certificate(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let report = STANDARD.decode(
            self.attestation_report
                .as_ref()
                .ok_or_else(|| anyhow!("Missing NVIDIA report"))?,
        )?;
        let cert = STANDARD.decode(
            self.certificate
                .as_ref()
                .ok_or_else(|| anyhow!("Missing NVIDIA certificate"))?,
        )?;
        ensure!(
            !report.is_empty() && !cert.is_empty(),
            "Empty NVIDIA report or certificate"
        );
        ensure!(
            report.len() <= 128 * 1024 && cert.len() <= 128 * 1024,
            "NVIDIA evidence too large"
        );
        Ok((report, cert))
    }

    async fn evaluate(
        &self,
        verifier: &NvidiaVerifier,
        nonce: &[u8; 32],
    ) -> Result<TeeEvidenceParsedClaim> {
        self.report_and_certificate()?;
        // Guest-provided UUID, name, CC state, driver and VBIOS versions are
        // metadata, not device-signed facts. Only authenticated verifier claims
        // enter policy input, including the signed device identity (ueid).
        verifier
            .verify(
                &self.arch,
                self.attestation_report
                    .as_deref()
                    .ok_or_else(|| anyhow!("Missing NVIDIA report"))?,
                self.certificate
                    .as_deref()
                    .ok_or_else(|| anyhow!("Missing NVIDIA certificate"))?,
                nonce,
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn vector() -> (serde_json::Value, Vec<u8>, GpuEvidenceList) {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../test_data/nvidia/tdx_gpu_binding_v1.json"
        ))
        .unwrap();
        let data = hex::decode(vector["report_data"].as_str().unwrap()).unwrap();
        let gpus = serde_json::from_value(vector["gpu_evidence"].clone()).unwrap();
        (vector, data, gpus)
    }
    #[test]
    fn shared_cpu_gpu_binding_vector() {
        let (vector, data, gpus) = vector();
        assert_eq!(
            hex::encode(gpus.bound_report_data(&data).unwrap()),
            vector["bound_report_data"]
        );
        assert_eq!(hex::encode(gpu_nonce(&data)), vector["nonce"]);
        let mut changed = data.clone();
        changed[63] ^= 1;
        assert_ne!(gpu_nonce(&data), gpu_nonce(&changed));
    }
    #[test]
    fn gpu_removal_reordering_and_substitution_change_cpu_commitment() {
        let (_, data, gpus) = vector();
        let expected = gpus.bound_report_data(&data).unwrap();
        let mut partial = gpus.clone();
        partial.evidence_list.pop();
        assert_ne!(expected, partial.bound_report_data(&data).unwrap());
        let mut reordered = gpus.clone();
        reordered.evidence_list.reverse();
        assert_ne!(expected, reordered.bound_report_data(&data).unwrap());
        let mut substituted = gpus;
        substituted.evidence_list[0].certificate = Some(STANDARD.encode(b"another certificate"));
        assert_ne!(expected, substituted.bound_report_data(&data).unwrap());
        // Stripping the whole list cannot recover the original CPU report data.
        assert_ne!(expected, data);
    }
    #[test]
    fn unbound_empty_duplicate_and_partial_gpu_evidence_is_rejected() {
        let (_, data, gpus) = vector();
        let mut old = gpus.clone();
        old.binding_version = 0;
        assert!(old.bound_report_data(&data).is_err());
        let mut empty = gpus.clone();
        empty.evidence_list.clear();
        assert!(empty.bound_report_data(&data).is_err());
        let mut duplicate = gpus.clone();
        duplicate.evidence_list[1].index = duplicate.evidence_list[0].index;
        assert!(duplicate.bound_report_data(&data).is_err());
        let mut missing = gpus;
        missing.evidence_list[0].attestation_report = None;
        assert!(missing.bound_report_data(&data).is_err());
    }
}
