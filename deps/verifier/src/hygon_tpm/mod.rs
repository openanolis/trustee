// Copyright (c) 2026 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

use super::*;
use ::eventlog::CcEventLog;
use async_trait::async_trait;
use base64::Engine;
use eventlog_rs::{BiosEventlog, Eventlog};
use log::{debug, info};
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::sign::Verifier as OpenSslVerifier;
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sm3::{Digest as Sm3Digest, Sm3};
use std::collections::HashMap;
use tss_esapi::structures::{Attest, AttestInfo, Signature};
use tss_esapi::traits::UnMarshall;

const TPM_REPORT_DATA_SIZE: usize = 32;
const PCR_BANK_SM3: &str = "SM3";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HygonSm2PublicKey {
    pub x: String,
    pub y: String,
}

#[derive(Debug, Serialize, Clone, Deserialize)]
pub struct HygonTpmQuote {
    pub attest_body: String,
    pub attest_sig: String,
    pub pcrs: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HygonTpmEvidence {
    pub ek_cert: Option<String>,
    pub ak_pubkey: HygonSm2PublicKey,
    pub quote: HashMap<String, HygonTpmQuote>,
    pub eventlog: Option<String>,
    pub aa_eventlog: Option<String>,
}

#[derive(Debug, Default)]
pub struct HygonTpmVerifier {}

#[async_trait]
impl Verifier for HygonTpmVerifier {
    async fn evaluate(
        &self,
        evidence: TeeEvidence,
        expected_report_data: &ReportData,
        _expected_init_data_hash: &InitDataHash,
    ) -> Result<(TeeEvidenceParsedClaim, TeeClass)> {
        let hygon_tpm_evidence = serde_json::from_value::<HygonTpmEvidence>(evidence)
            .context("Deserialize Hygon TPM evidence failed.")?;

        for (algorithm, quote) in &hygon_tpm_evidence.quote {
            quote.verify_signature(&hygon_tpm_evidence.ak_pubkey)?;
            quote.check_pcrs(algorithm)?;
            if let ReportData::Value(expected_report_data) = expected_report_data {
                quote.check_report_data(expected_report_data)?;
            }
        }

        let claims = parse_hygon_tpm_evidence(hygon_tpm_evidence)?;
        Ok((claims, "cpu".to_string()))
    }
}

fn create_sm2_pkey(ak_pubkey: &HygonSm2PublicKey) -> Result<PKey<openssl::pkey::Public>> {
    let nid = Nid::from_raw(openssl_sys::NID_sm2);
    let group = EcGroup::from_curve_name(nid)?;
    let mut ctx = BigNumContext::new()?;
    let bx = BigNum::from_hex_str(&ak_pubkey.x)?;
    let by = BigNum::from_hex_str(&ak_pubkey.y)?;
    let mut ec_point = EcPoint::new(&group)?;
    ec_point.set_affine_coordinates_gfp(&group, &bx, &by, &mut ctx)?;
    let ec_key = EcKey::from_public_key(&group, &ec_point)?;
    Ok(PKey::from_ec_key(ec_key)?)
}

fn signature_to_der(sig_b64: &str) -> Result<Vec<u8>> {
    let sig_bytes = base64::engine::general_purpose::STANDARD.decode(sig_b64)?;
    let signature = Signature::unmarshall(&sig_bytes)?;
    let Signature::Sm2(sm2_sig) = signature else {
        bail!("Unexpected TPM signature type, expected SM2");
    };

    let r = BigNum::from_slice(sm2_sig.signature_r().value())?;
    let s = BigNum::from_slice(sm2_sig.signature_s().value())?;
    let sig = EcdsaSig::from_private_components(r, s)?;
    Ok(sig.to_der()?)
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

fn parse_hygon_tpm_evidence(hygon_tpm_evidence: HygonTpmEvidence) -> Result<TeeEvidenceParsedClaim> {
    let mut parsed_claims = Map::new();
    let engine = base64::engine::general_purpose::STANDARD;

    if let Some(ek_cert) = hygon_tpm_evidence.ek_cert {
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

    for quote in hygon_tpm_evidence.quote.values() {
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
    }

    if let Some(b64_eventlog) = hygon_tpm_evidence.eventlog {
        let eventlog_bytes = engine.decode(b64_eventlog)?;

        if let Result::Ok(eventlog) = Eventlog::try_from(eventlog_bytes.clone()) {
            info!("Hygon TPM TCG eventlog parsed successfully");
            for event in eventlog.log {
                let event_desc = &event.event_desc;
                let event_data = match String::from_utf8(event_desc.clone()) {
                    Result::Ok(d) => d,
                    Result::Err(_) => hex::encode(event_desc),
                };
                let algo_clean = event.digests[0].algorithm.trim_start_matches("TPM_ALG_");
                let mut event_digest_algorithm = algo_clean.replace('_', "-");
                if !event_digest_algorithm.contains('-') {
                    if let Some(idx) = event_digest_algorithm.find(|c: char| c.is_ascii_digit()) {
                        event_digest_algorithm.insert(idx, '-');
                    }
                }
                let event_digest = &event.digests[0].digest;

                parse_measurements_from_event(
                    &mut parsed_claims,
                    event.event_type.as_str(),
                    &event_data,
                    &event_digest_algorithm,
                    event_digest,
                )?;
            }
        } else if let Result::Ok(eventlog) = BiosEventlog::try_from(eventlog_bytes.clone()) {
            info!("Hygon TPM BIOS eventlog parsed successfully");
            for event in eventlog.log {
                let event_desc = &event.event_data;
                let event_data = match String::from_utf8(event_desc.clone()) {
                    Result::Ok(d) => d,
                    Result::Err(_) => hex::encode(event_desc),
                };

                parse_measurements_from_event(
                    &mut parsed_claims,
                    event.event_type.as_str(),
                    &event_data,
                    PCR_BANK_SM3,
                    &event.digest,
                )?;
            }
        } else {
            return Err(anyhow!("Failed to parse eventlog"));
        }
    }

    if let Some(aael) = hygon_tpm_evidence.aa_eventlog {
        let aa_ccel_data = base64::engine::general_purpose::STANDARD.decode(aael)?;
        let aa_ccel = CcEventLog::try_from(aa_ccel_data)?;
        let result = serde_json::to_value(aa_ccel.clone().log)?;
        parsed_claims.insert("uefi_event_logs".to_string(), result);
    }

    Ok(Value::Object(parsed_claims) as TeeEvidenceParsedClaim)
}

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

    if event_data.contains("Kernel") || event_data.starts_with("/boot/vmlinuz") {
        let kernel_claim_key = format!("measurement.kernel.{}", event_digest_algorithm);
        parsed_claims.insert(
            kernel_claim_key,
            serde_json::Value::String(hex::encode(event_digest)),
        );
    }

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

    if event_data.contains("Initrd") || event_data.starts_with("/boot/initramfs") {
        let initrd_claim_key = format!("measurement.initrd.{}", event_digest_algorithm);
        parsed_claims.insert(
            initrd_claim_key,
            serde_json::Value::String(hex::encode(event_digest)),
        );
    }

    Ok(())
}

impl HygonTpmQuote {
    fn verify_signature(&self, ak_pubkey: &HygonSm2PublicKey) -> Result<()> {
        let pkey = create_sm2_pkey(ak_pubkey)?;
        let signature_der = signature_to_der(&self.attest_sig)?;
        let attest_body = base64::engine::general_purpose::STANDARD.decode(&self.attest_body)?;

        // Reuse OpenSSL's current SM2-capable verification path that works with
        // the crate version in this workspace. If real hardware shows a different
        // distinguishing-ID requirement, we can narrow it on-device without
        // changing the evidence schema or policy surface.
        let mut verifier = OpenSslVerifier::new(MessageDigest::sm3(), &pkey)?;
        verifier.update(&attest_body)?;
        if !verifier.verify(&signature_der)? {
            bail!("Verify Hygon TPM quote signature failed");
        }

        info!("Verify Hygon TPM quote signature successfully");
        Ok(())
    }

    fn check_report_data(&self, expected_report_data: &[u8]) -> Result<()> {
        let engine = base64::engine::general_purpose::STANDARD;
        let quote_data = Attest::unmarshall(&engine.decode(&self.attest_body)?)?
            .extra_data()
            .value()
            .to_vec();

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
                "Expect REPORT_DATA: {}, Quote report data: {}",
                hex::encode(expected_report_data),
                hex::encode(quote_data)
            );
            bail!("Expected REPORT_DATA is different from that in Hygon TPM quote");
        }

        Ok(())
    }

    fn check_pcrs(&self, pcr_algorithm: &str) -> Result<()> {
        let attest =
            Attest::unmarshall(&base64::engine::general_purpose::STANDARD.decode(&self.attest_body)?)?;
        let AttestInfo::Quote { info } = attest.attested() else {
            bail!("Invalid Hygon TPM quote");
        };

        let quote_pcr_digest = info.pcr_digest();
        let mut hasher = Sm3::new();
        for pcr in self.pcrs.iter() {
            hasher.update(hex::decode(pcr)?);
        }
        let pcr_digest = hasher.finalize().to_vec();

        if quote_pcr_digest[..] != pcr_digest[..] {
            bail!(
                "[{pcr_algorithm}] Digest in quote ({}) is unmatched to digest of PCR ({})",
                hex::encode(&quote_pcr_digest[..]),
                hex::encode(&pcr_digest),
            );
        }

        info!("Check Hygon TPM {pcr_algorithm} PCRs successfully");
        Ok(())
    }
}
