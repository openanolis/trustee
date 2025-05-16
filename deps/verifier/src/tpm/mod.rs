// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use super::*;
use async_trait::async_trait;
use base64::Engine;
use eventlog_rs::Eventlog;
use log::info;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashMap;
use tss_esapi::structures::{Attest, AttestInfo};
use tss_esapi::traits::UnMarshall;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TpmEvidence {
    // PEM format of EK certificate
    pub ek_cert: Option<String>,
    // PEM format of AK public key
    pub ak_pubkey: String,
    // TPM Quote (Contained PCRs)
    pub quote: HashMap<String, TpmQuote>,
    // Base64 encoded Eventlog ACPI table
    pub eventlog: Option<String>,
    // AA Eventlog
    pub aa_eventlog: Option<String>,
}

#[derive(Debug, Serialize, Clone, Deserialize)]
pub struct TpmQuote {
    // Base64 encoded
    attest_body: String,
    // Base64 encoded
    attest_sig: String,
    // PCRs
    pcrs: Vec<String>,
}

#[derive(Debug, Default)]
pub struct TpmVerifier {}

#[async_trait]
impl Verifier for TpmVerifier {
    async fn evaluate(
        &self,
        evidence: &[u8],
        expected_report_data: &ReportData,
        _expected_init_data_hash: &InitDataHash,
    ) -> Result<TeeEvidenceParsedClaim> {
        let tpm_evidence = serde_json::from_slice::<TpmEvidence>(evidence)
            .context("Deserialize TPM Evidence failed.")?;

        // Verify Quote and PCRs
        for (algorithm, quote) in &tpm_evidence.quote {
            quote.verify_signature(tpm_evidence.ak_pubkey.clone().as_bytes())?;
            quote.check_pcrs(algorithm)?;
            if let ReportData::Value(expected_report_data) = expected_report_data {
                quote.check_report_data(expected_report_data)?;
            }
        }

        // TODO: Verify integrity of Eventlogs

        // Parse Evidence
        parse_tpm_evidence(tpm_evidence)
    }
}

fn parse_tpm_evidence(tpm_evidence: TpmEvidence) -> Result<TeeEvidenceParsedClaim> {
    let mut parsed_claims = Map::new();
    let engine = base64::engine::general_purpose::STANDARD;

    // Parse EK certificate issuer
    if let Some(ek_cert) = tpm_evidence.ek_cert {
        let ek_cert_x509 = X509::from_pem(ek_cert.as_bytes())?;
        let ek_issuer_name = ek_cert_x509.issuer_name();

        let mut ek_issuer_info = Map::new();
        for entry in ek_issuer_name.entries() {
            ek_issuer_info.insert(
                String::from_utf8_lossy(entry.object().nid().short_name()?.as_bytes()).to_string(),
                serde_json::Value::String(
                    String::from_utf8_lossy(entry.data().as_slice()).to_string(),
                ),
            );
        }

        parsed_claims.insert(
            "EK_cert_issuer".to_string(),
            serde_json::Value::Object(ek_issuer_info),
        );
    }

    // Parse TPM Quote
    for (algorithm, quote) in &tpm_evidence.quote {
        let tpm_quote = Attest::unmarshall(&engine.decode(quote.attest_body.clone())?)?;
        parsed_claims.insert(
            format!("{algorithm}.quote.signer"),
            serde_json::Value::String(hex::encode(tpm_quote.qualified_signer().value())),
        );
        parsed_claims.insert(
            format!("{algorithm}.quote.clock_info"),
            serde_json::Value::String(tpm_quote.clock_info().clock().to_string()),
        );
        parsed_claims.insert(
            format!("{algorithm}.quote.firmware_version"),
            serde_json::Value::String(tpm_quote.firmware_version().to_string()),
        );
        parsed_claims.insert(
            "report_data".to_string(),
            serde_json::Value::String(hex::encode(tpm_quote.extra_data().value())),
        );

        for (index, pcr_digest) in quote.pcrs.iter().enumerate() {
            let key_name = format!("{algorithm}.pcr{index}");
            let digest_string = hex::encode(pcr_digest.clone());
            parsed_claims.insert(key_name, serde_json::Value::String(digest_string));
        }
    }

    // Parse TCG Eventlogs
    if let Some(b64_eventlog) = tpm_evidence.eventlog {
        let eventlog_bytes = engine.decode(b64_eventlog)?;
        let eventlog = Eventlog::try_from(eventlog_bytes)
            .map_err(|e| anyhow!("parse TCG Eventlog failed: {e}"))?;
        for event in eventlog.log {
            let claim_event_key = format!(
                "TCG.eventlog.{}.{}.{}",
                event.event_type,
                event.digests[0].algorithm,
                hex::encode(event.digests[0].digest.clone())
            );
            let event_data = match String::from_utf8(event.event_desc.clone()) {
                Result::Ok(d) => d,
                Result::Err(_) => hex::encode(event.event_desc),
            };
            parsed_claims.insert(claim_event_key, serde_json::Value::String(event_data));
        }
    }

    // Parse AA Eventlogs
    if let Some(aael) = tpm_evidence.aa_eventlog {
        let aa_eventlog: Vec<&str> = aael.split('\n').collect();

        for event in aa_eventlog.iter() {
            let event_split: Vec<&str> = event.splitn(3, ' ').collect();

            if event_split[0] == "INIT" {
                let claims_key = format!("AA.eventlog.INIT.{}", event_split[0]);
                parsed_claims.insert(
                    claims_key,
                    serde_json::Value::String(event_split[1].to_string()),
                );
                continue;
            } else if event_split[0].to_string().is_empty() {
                break;
            }

            if event_split.len() != 3 {
                bail!("Illegal AA eventlog format");
            }

            let claims_key = format!("AA.eventlog.{}.{}", event_split[0], event_split[1]);
            parsed_claims.insert(
                claims_key,
                serde_json::Value::String(event_split[2].to_string()),
            );
        }
    }

    Ok(Value::Object(parsed_claims) as TeeEvidenceParsedClaim)
}

impl TpmQuote {
    fn verify_signature(&self, ak_pubkey_bytes: &[u8]) -> Result<()> {
        let ak_pubkey = PKey::public_key_from_pem(ak_pubkey_bytes)?;
        let mut verifier = openssl::sign::Verifier::new(MessageDigest::sha256(), &ak_pubkey)?;

        let engine = base64::engine::general_purpose::STANDARD;
        verifier.update(&engine.decode(&self.attest_body)?)?;
        let is_verified = verifier.verify(&engine.decode(&self.attest_sig)?)?;
        if !is_verified {
            bail!("Verify TPM quote signature failed");
        }

        info!("Verify TPM Quote signature succussfully");
        Ok(())
    }

    fn check_report_data(&self, expected_report_data: &[u8]) -> Result<()> {
        let engine = base64::engine::general_purpose::STANDARD;
        let quote_data = Attest::unmarshall(&engine.decode(&self.attest_body)?)?
            .extra_data()
            .value()
            .to_vec();
        if expected_report_data.to_vec()[..] != quote_data[..expected_report_data.to_vec().len()] {
            debug!(
                "{}",
                format!(
                    "Expect REPORT_DATA: {}, Quote report data: {}",
                    hex::encode(expected_report_data),
                    hex::encode(quote_data)
                )
            );
            bail!("Expected REPORT_DATA is different from that in TPM Quote");
        }

        Ok(())
    }

    fn check_pcrs(&self, pcr_algorithm: &str) -> Result<()> {
        use sha2::{Digest, Sha256};

        let attest = Attest::unmarshall(
            &base64::engine::general_purpose::STANDARD.decode(self.attest_body.clone())?,
        )?;
        let AttestInfo::Quote { info } = attest.attested() else {
            bail!("Invalid TPM quote");
        };

        let quote_pcr_digest = info.pcr_digest();

        let mut hasher = Sha256::new();
        for pcr in self.pcrs.iter() {
            hasher.update(&hex::decode(pcr)?);
        }
        let pcr_digest = hasher.finalize().to_vec();

        if quote_pcr_digest[..] != pcr_digest[..] {
            let error_info = format!(
                "[{pcr_algorithm}] Digest in Quote ({}) is unmatched to Digest of PCR ({})",
                hex::encode(&quote_pcr_digest[..]),
                hex::encode(&pcr_digest),
            );
            bail!(error_info);
        }

        info!("Check TPM {pcr_algorithm} PCRs succussfully");

        Ok(())
    }
}
