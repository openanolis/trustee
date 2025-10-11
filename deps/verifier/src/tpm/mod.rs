// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use super::*;
use ::eventlog::CcEventLog;
use async_trait::async_trait;
use base64::Engine;
use eventlog_rs::{BiosEventlog, Eventlog};
use log::info;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashMap;
use tss_esapi::structures::{Attest, AttestInfo};
use tss_esapi::traits::UnMarshall;

const TPM_REPORT_DATA_SIZE: usize = 32;

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
    // Base64 encoded TCG2 encoding AA Eventlog
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
        evidence: TeeEvidence,
        expected_report_data: &ReportData,
        _expected_init_data_hash: &InitDataHash,
    ) -> Result<(TeeEvidenceParsedClaim, TeeClass)> {
        let tpm_evidence = serde_json::from_value::<TpmEvidence>(evidence)
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
        let claims = parse_tpm_evidence(tpm_evidence)?;
        Ok((claims, "cpu".to_string()))
    }
}

#[allow(dead_code)]
struct UefiImageLoadEvent {
    image_location_in_memory: u64,
    image_length_in_memory: u64,
    image_link_time_address: u64,
    length_of_device_path: u64,
    device_path: Vec<u8>,
}

impl UefiImageLoadEvent {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 32 {
            bail!("Event data too short for UefiImageLoadEvent");
        }

        let image_location_in_memory = u64::from_le_bytes(bytes[0..8].try_into()?);
        let image_length_in_memory = u64::from_le_bytes(bytes[8..16].try_into()?);
        let image_link_time_address = u64::from_le_bytes(bytes[16..24].try_into()?);
        let length_of_device_path = u64::from_le_bytes(bytes[24..32].try_into()?);

        if bytes.len() < 32 + length_of_device_path as usize {
            bail!("Event data too short for device path");
        }

        let device_path = bytes[32..32 + length_of_device_path as usize].to_vec();

        Ok(Self {
            image_location_in_memory,
            image_length_in_memory,
            image_link_time_address,
            length_of_device_path,
            device_path,
        })
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
    for quote in tpm_evidence.quote.values() {
        let tpm_quote = Attest::unmarshall(&engine.decode(quote.attest_body.clone())?)?;
        parsed_claims.insert(
            "quote.signer".to_string(),
            serde_json::Value::String(hex::encode(tpm_quote.qualified_signer().value())),
        );
        parsed_claims.insert(
            "quote.clock_info".to_string(),
            serde_json::Value::String(tpm_quote.clock_info().clock().to_string()),
        );
        parsed_claims.insert(
            "quote.firmware_version".to_string(),
            serde_json::Value::String(tpm_quote.firmware_version().to_string()),
        );
        parsed_claims.insert(
            "report_data".to_string(),
            serde_json::Value::String(hex::encode(tpm_quote.extra_data().value())),
        );

        // for (index, pcr_digest) in quote.pcrs.iter().enumerate() {
        //     let key_name = format!("{algorithm}.pcr{index}");
        //     let digest_string = hex::encode(pcr_digest.clone());
        //     parsed_claims.insert(key_name, serde_json::Value::String(digest_string));
        // }
    }

    // Parse TCG Eventlogs
    if let Some(b64_eventlog) = tpm_evidence.eventlog {
        let eventlog_bytes = engine.decode(b64_eventlog)?;

        if let Result::Ok(eventlog) = Eventlog::try_from(eventlog_bytes.clone()) {
            log::info!("TCG Eventlog parsed successfully");
            // Process TCG format event log
            for event in eventlog.log {
                let event_desc = &event.event_desc;
                let event_data = match String::from_utf8(event_desc.clone()) {
                    Result::Ok(d) => d,
                    Result::Err(_) => hex::encode(event_desc),
                };

                let event_digest_algorithm =
                    event.digests[0].algorithm.trim_start_matches("TPM_ALG_");
                let event_digest = &event.digests[0].digest;

                parse_measurements_from_event(
                    &mut parsed_claims,
                    event.event_type.as_str(),
                    &event_data,
                    event_digest_algorithm,
                    event_digest,
                )?;
            }
        } else if let Result::Ok(eventlog) = BiosEventlog::try_from(eventlog_bytes.clone()) {
            log::info!("BIOS Eventlog parsed successfully");
            // Process BIOS format event log
            for event in eventlog.log {
                let event_desc = &event.event_data;
                let event_data = match String::from_utf8(event_desc.clone()) {
                    Result::Ok(d) => d,
                    Result::Err(_) => hex::encode(event_desc),
                };

                // If it's BIOS Eventlog, use SHA1 as the digest algorithm
                let event_digest_algorithm = "SHA1";
                let event_digest = &event.digest;

                parse_measurements_from_event(
                    &mut parsed_claims,
                    event.event_type.as_str(),
                    &event_data,
                    event_digest_algorithm,
                    event_digest,
                )?;
            }
        } else {
            return Err(anyhow!("Failed to parse eventlog"));
        }
    }

    // Parse AA Eventlogs in TCG2 encoding
    if let Some(aael) = tpm_evidence.aa_eventlog {
        let aa_ccel_data = base64::engine::general_purpose::STANDARD.decode(aael)?;
        let aa_ccel = CcEventLog::try_from(aa_ccel_data)?;
        let result = serde_json::to_value(aa_ccel.clone().log)?;
        parsed_claims.insert("uefi_event_logs".to_string(), result);
    }

    Ok(Value::Object(parsed_claims) as TeeEvidenceParsedClaim)
}

// Parse EV_EFI_BOOT_SERVICES_APPLICATION events
fn parse_boot_services_event(
    parsed_claims: &mut Map<String, Value>,
    event_data: &str,
    event_digest_algorithm: &str,
    event_digest: &[u8],
) -> Result<()> {
    let event_data_bytes = hex::decode(event_data).map_err(|e| {
        anyhow!("Failed to hex decode event data of EV_EFI_BOOT_SERVICES_APPLICATION: {e}")
    })?;

    let image_load_event = UefiImageLoadEvent::from_bytes(&event_data_bytes)
        .map_err(|e| anyhow!("Failed to parse UefiImageLoadEvent: {e}"))?;

    let device_path_str = String::from_utf8_lossy(&image_load_event.device_path).to_lowercase();

    let device_path_str = device_path_str
        .chars()
        .filter(|c| c.is_ascii() && !c.is_ascii_control())
        .collect::<String>();

    println!("device_path_str: {}", device_path_str);

    if device_path_str.contains("shim") {
        parsed_claims.insert(
            format!("measurement.shim.{}", event_digest_algorithm),
            serde_json::Value::String(hex::encode(event_digest)),
        );
    }
    if device_path_str.contains("grub") {
        parsed_claims.insert(
            format!("measurement.grub.{}", event_digest_algorithm),
            serde_json::Value::String(hex::encode(event_digest)),
        );
    }

    Ok(())
}

fn parse_measurements_from_event(
    parsed_claims: &mut Map<String, Value>,
    event_type: &str,
    event_data: &str,
    event_digest_algorithm: &str,
    event_digest: &[u8],
) -> Result<()> {
    if event_type == "EV_EFI_BOOT_SERVICES_APPLICATION" {
        parse_boot_services_event(
            parsed_claims,
            event_data,
            event_digest_algorithm,
            event_digest,
        )?;
    }

    // Kernel blob measurement
    // Check if event_desc contains "Kernel" or starts with "/boot/vmlinuz"
    if event_data.contains("Kernel") || event_data.starts_with("/boot/vmlinuz") {
        let kernel_claim_key = format!("measurement.kernel.{}", event_digest_algorithm);
        parsed_claims.insert(
            kernel_claim_key,
            serde_json::Value::String(hex::encode(event_digest)),
        );
    }

    // Kernel command line measurement
    // Check if event_desc starts with "grub_cmd linux", "kernel_cmdline", or "grub_kernel_cmdline"
    if event_data.starts_with("grub_cmd linux")
        || event_data.starts_with("kernel_cmdline")
        || event_data.starts_with("grub_kernel_cmdline")
    {
        let kernel_cmdline_claim_key =
            format!("measurement.kernel_cmdline.{}", event_digest_algorithm);
        parsed_claims.insert(
            kernel_cmdline_claim_key,
            serde_json::Value::String(hex::encode(event_digest)),
        );
        parsed_claims.insert(
            "kernel_cmdline".to_string(),
            serde_json::Value::String(event_data.to_string()),
        );
    }

    // Initrd blob measurement
    // Check if event_desc contains "Initrd" or starts with "/boot/initramfs"
    if event_data.contains("Initrd") || event_data.starts_with("/boot/initramfs") {
        let initrd_claim_key = format!("measurement.initrd.{}", event_digest_algorithm);
        parsed_claims.insert(
            initrd_claim_key,
            serde_json::Value::String(hex::encode(event_digest)),
        );
    }

    Ok(())
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

        // If expected_report_data or quote_data is larger than TPM_REPORT_DATA_SIZE, truncate it to TPM_REPORT_DATA_SIZE
        let expected_report_data = if expected_report_data.len() > TPM_REPORT_DATA_SIZE {
            &expected_report_data[..TPM_REPORT_DATA_SIZE]
        } else {
            expected_report_data
        };
        let quote_data = if quote_data.len() > TPM_REPORT_DATA_SIZE {
            &quote_data[..TPM_REPORT_DATA_SIZE]
        } else {
            &quote_data
        };

        if expected_report_data != &quote_data[..expected_report_data.len()] {
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
