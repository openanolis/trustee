use std::collections::HashMap;
use std::env;
use std::process::Command;

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use chrono::{Months, Timelike, Utc};
use serde::Deserialize;
use tempfile::NamedTempFile;

use crate::{
    reference_value::{AuditProof, REFERENCE_VALUE_VERSION},
    ReferenceValue,
};

use super::Extractor;

#[derive(Debug, Deserialize)]
struct RvdsPayload {
    artifact_type: String,
    slsa_provenance: Vec<String>,
    #[allow(dead_code)]
    artifacts_download_url: Vec<String>,
    #[serde(default)]
    audit_proof: Option<AuditProof>,
}

#[derive(Debug, Deserialize)]
struct Subject {
    name: String,
    digest: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct SlsaProvenance {
    #[serde(rename = "_type")]
    #[serde(default)]
    statement_type: Option<String>,
    #[serde(rename = "predicateType")]
    #[serde(default)]
    predicate_type: Option<String>,
    #[serde(default)]
    subject: Vec<Subject>,
    #[serde(default)]
    subjects: Vec<Subject>,
}

/// Extractor for SLSA provenance delivered by RVDS.
#[derive(Default)]
pub struct SlsaExtractor;

/// Optional external verifier configuration using `slsa-verifier` CLI.
#[derive(Debug, Clone, Default)]
struct SlsaVerifierSettings {
    bin: String,
    source_uri: Option<String>,
    builder_id: Option<String>,
    rekor_url: Option<String>,
    certificate_identity: Option<String>,
    certificate_oidc_issuer: Option<String>,
    extra_args: Option<String>,
}

impl SlsaVerifierSettings {
    /// Build verifier config from environment. Enable when either SLSA_VERIFIER_BIN
    /// is provided or SLSA_VERIFIER_ENFORCE=1 to avoid hard dependency in tests.
    fn from_env() -> Option<Self> {
        let enforce = env::var("SLSA_VERIFIER_ENFORCE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let bin = env::var("SLSA_VERIFIER_BIN").ok();
        if !enforce && bin.is_none() {
            return None;
        }

        Some(Self {
            bin: bin.unwrap_or_else(|| "slsa-verifier".to_string()),
            source_uri: env::var("SLSA_VERIFIER_SOURCE_URI").ok(),
            builder_id: env::var("SLSA_VERIFIER_BUILDER_ID").ok(),
            rekor_url: env::var("SLSA_VERIFIER_REKOR_URL").ok(),
            certificate_identity: env::var("SLSA_VERIFIER_CERT_IDENTITY").ok(),
            certificate_oidc_issuer: env::var("SLSA_VERIFIER_CERT_OIDC_ISSUER").ok(),
            extra_args: env::var("SLSA_VERIFIER_EXTRA_ARGS").ok(),
        })
    }

    /// Verify a single provenance document with the slsa-verifier CLI.
    fn verify_one(&self, provenance_doc: &str, digest: (&str, &str)) -> Result<()> {
        let mut tmp = NamedTempFile::new().context("create temp file for slsa verifier")?;
        std::io::Write::write_all(&mut tmp, provenance_doc.as_bytes())
            .context("write provenance to temp file")?;

        let mut cmd = Command::new(&self.bin);
        cmd.arg("verify-attestation")
            .arg("--provenance-path")
            .arg(tmp.path())
            .arg("--digest")
            .arg(format!("{}:{}", digest.0, digest.1));

        if let Some(src) = &self.source_uri {
            cmd.arg("--source-uri").arg(src);
        }
        if let Some(bid) = &self.builder_id {
            cmd.arg("--builder-id").arg(bid);
        }
        if let Some(rekor) = &self.rekor_url {
            cmd.arg("--rekor-url").arg(rekor);
        }
        if let Some(cert) = &self.certificate_identity {
            cmd.arg("--certificate-identity").arg(cert);
        }
        if let Some(issuer) = &self.certificate_oidc_issuer {
            cmd.arg("--certificate-oidc-issuer").arg(issuer);
        }
        if let Some(extra) = &self.extra_args {
            // Allow users to pass extra flags, split by whitespace.
            cmd.args(extra.split_whitespace());
        }

        let status = cmd
            .status()
            .with_context(|| format!("execute slsa-verifier via {:?}", cmd))?;

        if !status.success() {
            return Err(anyhow!(
                "slsa-verifier failed (code {:?}) for digest {}:{}",
                status.code(),
                digest.0,
                digest.1
            ));
        }

        Ok(())
    }

    /// Verify all provenance docs using the preferred digest from subjects.
    fn verify_all(&self, prov_docs: &[String], subjects: &[Subject]) -> Result<()> {
        let (alg, val) = pick_preferred_digest(subjects)
            .ok_or_else(|| anyhow!("no digest available for slsa verification"))?;

        for doc in prov_docs {
            let slsa_str = match base64::engine::general_purpose::STANDARD.decode(doc) {
                Ok(bytes) => String::from_utf8(bytes).unwrap_or_else(|_| doc.to_string()),
                Err(_) => doc.to_string(),
            };
            self.verify_one(&slsa_str, (&alg, &val))?;
        }
        Ok(())
    }
}

impl SlsaExtractor {
    fn parse_payload(&self, provenance: &str) -> Result<RvdsPayload> {
        // Try direct JSON first, then fall back to base64-encoded JSON.
        serde_json::from_str(provenance).or_else(|_| {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(provenance)
                .context("decode base64 provenance payload")?;
            serde_json::from_slice(&decoded).context("deserialize provenance payload")
        })
    }

    fn parse_slsa_documents(&self, docs: &[String]) -> Result<Vec<Subject>> {
        let mut subjects = Vec::new();

        for raw in docs {
            // Accept raw JSON or base64-wrapped JSON.
            let slsa_str = match base64::engine::general_purpose::STANDARD.decode(raw) {
                Ok(bytes) => String::from_utf8(bytes).unwrap_or_else(|_| raw.to_string()),
                Err(_) => raw.to_string(),
            };

            let slsa: SlsaProvenance =
                serde_json::from_str(&slsa_str).context("parse slsa provenance json")?;

            // Basic SLSA statement checks to guard obviously malformed provenance.
            if let Some(st) = &slsa.statement_type {
                if st != "https://in-toto.io/Statement/v1" {
                    return Err(anyhow!("unexpected statement _type: {st}"));
                }
            }
            if let Some(pt) = &slsa.predicate_type {
                if !pt.contains("slsa") {
                    return Err(anyhow!("unexpected predicateType: {pt}"));
                }
            }

            subjects.extend(slsa.subject);
            subjects.extend(slsa.subjects);
        }

        if subjects.is_empty() {
            return Err(anyhow!("slsa provenance does not contain subjects"));
        }

        // Ensure each subject has at least one digest; otherwise reject.
        for subj in subjects.iter() {
            if subj.digest.is_empty() {
                return Err(anyhow!("subject {} has no digest entries", subj.name));
            }
        }

        Ok(subjects)
    }
}

impl Extractor for SlsaExtractor {
    fn verify_and_extract(&self, provenance: &str) -> Result<Vec<ReferenceValue>> {
        // Parse RVDS wrapper payload first.
        let envelope = self.parse_payload(provenance)?;

        if envelope.artifact_type.is_empty() {
            return Err(anyhow!("artifact_type cannot be empty"));
        }

        // Parse SLSA provenance to retrieve digest subjects.
        let subjects = self.parse_slsa_documents(&envelope.slsa_provenance)?;

        // If external verifier is configured, enforce signature/rekor/identity verification.
        if let Some(verifier) = SlsaVerifierSettings::from_env() {
            verifier
                .verify_all(&envelope.slsa_provenance, &subjects)
                .map_err(|e| anyhow!("slsa-verifier failed during provenance verification: {e}"))?;
        } else {
            log::warn!("slsa-verifier not configured; provenance signature validation is skipped");
        }

        let expiration = Utc::now()
            .with_nanosecond(0)
            .and_then(|t| t.checked_add_months(Months::new(12)))
            .ok_or_else(|| anyhow!("failed to compute expiration time"))?;

        let mut rvs = Vec::new();
        for subject in subjects {
            // Skip subjects without digest entries to avoid empty reference values.
            if subject.digest.is_empty() {
                continue;
            }

            let mut rv = ReferenceValue::new()?
                .set_version(REFERENCE_VALUE_VERSION)
                .set_name(&subject.name)
                .set_expiration(expiration)
                .set_audit_proof(envelope.audit_proof.clone());

            for (alg, value) in subject.digest.iter() {
                rv = rv.add_hash_value(alg.to_string(), value.to_string());
            }

            rvs.push(rv);
        }

        if rvs.is_empty() {
            return Err(anyhow!("no digest entries found in slsa subjects"));
        }

        Ok(rvs)
    }
}

/// Select a preferred digest (sha256 if present, otherwise first available).
fn pick_preferred_digest(subjects: &[Subject]) -> Option<(String, String)> {
    for subj in subjects {
        if let Some(val) = subj.digest.get("sha256") {
            return Some(("sha256".to_string(), val.clone()));
        }
    }
    for subj in subjects {
        if let Some((alg, val)) = subj.digest.iter().next() {
            return Some((alg.clone(), val.clone()));
        }
    }
    None
}
