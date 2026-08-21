// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use super::*;
use ::eventlog::ccel::tcg_enum::{TcgAlgorithm, TcgEventType};
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
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tss_esapi::structures::{Attest, AttestInfo};
use tss_esapi::traits::UnMarshall;

use crate::tpm_registrar;

const TPM_REPORT_DATA_SIZE: usize = 32;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TpmEvidence {
    // Base64 encoded TPMT_PUBLIC of the EK
    #[serde(default)]
    pub ek_pubkey: Option<String>,
    // PEM format of EK certificate
    pub ek_cert: Option<String>,
    // PEM format of AK public key
    pub ak_pubkey: String,
    // Optional Keylime agent UUID
    pub keylime_agent_uuid: Option<String>,
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

        // If keylime uuid provided, fetch registrar AK/EK info and compare.
        // The registrar data is fetched over a shared, pooled HTTP client and
        // cached per-UUID so repeated attestations do not hit the registrar.
        if let Some(uuid) = &tpm_evidence.keylime_agent_uuid {
            let registrar = tpm_registrar::registrar_url();

            let results = tpm_registrar::get_agent_results(&registrar, uuid).await?;
            let get_str = |k: &str| -> Result<String> {
                results
                    .get(k)
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .ok_or_else(|| anyhow!(format!("Missing '{k}' in registrar results")))
            };
            let ek_tpm_b64 = get_str("ek_tpm")?;
            let ekcert_b64 = results.get("ekcert").and_then(Value::as_str);
            let aik_tpm_b64 = get_str("aik_tpm")?;

            let engine = base64::engine::general_purpose::STANDARD;
            let registrar_ek_raw = engine
                .decode(ek_tpm_b64)
                .map_err(|e| anyhow!(format!("decode registrar EK (TPM2B_PUBLIC): {e}")))?;
            if registrar_ek_raw.len() <= 2 {
                bail!("Invalid registrar EK (TPM2B_PUBLIC) length (<= 2)");
            }

            // Prefer comparing the TPMT_PUBLIC directly. SVSM-backed vTPMs
            // have an ephemeral EK and normally do not have a manufacturer EK
            // certificate, while the Keylime registrar still records ek_tpm
            // after credential activation.
            let mut ek_bound = false;
            if let Some(evidence_ek_b64) = &tpm_evidence.ek_pubkey {
                let evidence_ek_raw = engine
                    .decode(evidence_ek_b64)
                    .map_err(|e| anyhow!(format!("decode evidence EK (TPMT_PUBLIC): {e}")))?;
                if registrar_ek_raw[2..] != evidence_ek_raw {
                    bail!("EK public key mismatch with keylime registrar");
                }
                ek_bound = true;
            }

            // Preserve compatibility with physical TPM evidence that carries
            // an EK certificate but predates the ek_pubkey field.
            if let Some(evidence_ek_pem) = &tpm_evidence.ek_cert {
                let evidence_ek_der = X509::from_pem(evidence_ek_pem.as_bytes())
                    .map_err(|e| anyhow!(format!("parse evidence EK cert (PEM): {e}")))?
                    .to_der()
                    .map_err(|e| anyhow!(format!("encode evidence EK cert (DER): {e}")))?;
                let registrar_ek_der = engine
                    .decode(ekcert_b64.context(
                        "Keylime registrar response is missing ekcert required by TPM evidence",
                    )?)
                    .map_err(|e| anyhow!(format!("decode registrar EK cert (base64 DER): {e}")))?;
                if registrar_ek_der != evidence_ek_der {
                    bail!("EK certificate mismatch with keylime registrar");
                }
                ek_bound = true;
            }

            if !ek_bound {
                bail!("TPM evidence contains neither an EK public key nor an EK certificate");
            }

            // Compare AK public key (registrar TPM2B_PUBLIC vs evidence PEM)
            let registrar_ak_raw = engine
                .decode(aik_tpm_b64)
                .map_err(|e| anyhow!(format!("decode registrar AK (TPM2B_PUBLIC base64): {e}")))?;
            if registrar_ak_raw.len() <= 2 {
                bail!("Invalid registrar AK (TPM2B_PUBLIC) length (<= 2)");
            }
            let ak_bytes = &registrar_ak_raw[2..];
            let registrar_ak = pkey_from_tpm2b_public(ak_bytes)
                .map_err(|e| anyhow!(format!("parse registrar AK (TPM2B_PUBLIC): {e}")))?;
            let evidence_ak = PKey::public_key_from_pem(tpm_evidence.ak_pubkey.as_bytes())
                .map_err(|e| anyhow!(format!("parse evidence AK (PEM): {e}")))?;
            if registrar_ak.public_key_to_der()? != evidence_ak.public_key_to_der()? {
                bail!("AK public key mismatch with keylime registrar");
            }
        }

        // Verify Quote and PCRs
        for (algorithm, quote) in &tpm_evidence.quote {
            quote.verify_signature(tpm_evidence.ak_pubkey.clone().as_bytes())?;
            quote.check_pcrs(algorithm)?;
            if let ReportData::Value(expected_report_data) = expected_report_data {
                quote.check_report_data(expected_report_data)?;
            }
        }

        verify_eventlog_integrity(&tpm_evidence)?;

        // Parse Evidence
        let claims = parse_tpm_evidence(tpm_evidence)?;
        Ok((claims, "cpu".to_string()))
    }
}

#[derive(Clone, Copy)]
enum PcrBank {
    Sha1,
    Sha256,
}

impl PcrBank {
    fn quote_key(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
        }
    }

    fn eventlog_name(self) -> &'static str {
        match self {
            Self::Sha1 => "TPM_ALG_SHA1",
            Self::Sha256 => "TPM_ALG_SHA256",
        }
    }

    fn digest_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }

    fn extend(self, current: &[u8], digest: &[u8]) -> Result<Vec<u8>> {
        if current.len() != self.digest_len() || digest.len() != self.digest_len() {
            bail!(
                "Invalid {} PCR/digest length: {}/{}",
                self.quote_key(),
                current.len(),
                digest.len()
            );
        }

        Ok(match self {
            Self::Sha1 => {
                let mut hasher = Sha1::new();
                hasher.update(current);
                hasher.update(digest);
                hasher.finalize().to_vec()
            }
            Self::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(current);
                hasher.update(digest);
                hasher.finalize().to_vec()
            }
        })
    }
}

type ReplayedPcrs = HashMap<u32, Vec<u8>>;

fn extend_replayed_pcr(
    pcrs: &mut ReplayedPcrs,
    index: u32,
    bank: PcrBank,
    digest: &[u8],
) -> Result<()> {
    let current = pcrs
        .entry(index)
        .or_insert_with(|| vec![0; bank.digest_len()]);
    *current = bank.extend(current, digest)?;
    Ok(())
}

fn replay_tcg_eventlog(eventlog: &Eventlog, bank: PcrBank, pcrs: &mut ReplayedPcrs) -> Result<()> {
    for event in &eventlog.log {
        // Informational events are logged but are not extended into a PCR.
        if event.event_type == "EV_NO_ACTION" {
            continue;
        }

        if let Some(digest) = event
            .digests
            .iter()
            .find(|digest| digest.algorithm == bank.eventlog_name())
        {
            extend_replayed_pcr(
                pcrs,
                event.target_measurement_registry,
                bank,
                &digest.digest,
            )?;
        }
    }
    Ok(())
}

fn tcg_algorithm_for_bank(bank: PcrBank) -> TcgAlgorithm {
    match bank {
        PcrBank::Sha1 => TcgAlgorithm::Sha1,
        PcrBank::Sha256 => TcgAlgorithm::Sha256,
    }
}

/// Replay a crypto-agile TCG2 log. A TPM2 `StartupLocality` EV_NO_ACTION
/// event changes the initial value of PCR 0 without being extended, so it must
/// be handled explicitly before normal event replay.
fn replay_cc_eventlog(
    eventlog: &CcEventLog,
    bank: PcrBank,
    pcrs: &mut ReplayedPcrs,
    honor_startup_locality: bool,
) -> Result<()> {
    const STARTUP_LOCALITY_SIGNATURE: &[u8] = b"StartupLocality\0";

    for event in &eventlog.log {
        if event.event_type == TcgEventType::EvNoAction {
            if honor_startup_locality && event.index == 0 {
                let event_data = base64::engine::general_purpose::STANDARD
                    .decode(&event.event)
                    .context("Decode EV_NO_ACTION event data")?;
                if event_data.starts_with(STARTUP_LOCALITY_SIGNATURE)
                    && event_data.len() == STARTUP_LOCALITY_SIGNATURE.len() + 1
                {
                    if pcrs.contains_key(&0) {
                        bail!("TPM StartupLocality event appears after PCR 0 was extended");
                    }
                    let mut initial = vec![0; bank.digest_len()];
                    let last = initial.len() - 1;
                    initial[last] = event_data[STARTUP_LOCALITY_SIGNATURE.len()];
                    pcrs.insert(0, initial);
                }
            }
            continue;
        }

        if let Some(digest) = event
            .digests
            .iter()
            .find(|digest| digest.alg == tcg_algorithm_for_bank(bank))
        {
            extend_replayed_pcr(pcrs, event.index, bank, &digest.digest)?;
        }
    }
    Ok(())
}

fn replay_bios_eventlog(eventlog: &BiosEventlog, pcrs: &mut ReplayedPcrs) -> Result<()> {
    for event in &eventlog.log {
        if event.event_type == "EV_NO_ACTION" {
            continue;
        }
        extend_replayed_pcr(pcrs, event.pcr_index, PcrBank::Sha1, &event.digest)?;
    }
    Ok(())
}

fn check_replayed_pcrs(
    quote: &TpmQuote,
    bank: PcrBank,
    replayed_pcrs: &ReplayedPcrs,
) -> Result<()> {
    for (index, replayed) in replayed_pcrs {
        let quoted = quote
            .pcrs
            .get(*index as usize)
            .ok_or_else(|| anyhow!("{} quote is missing PCR {index}", bank.quote_key()))?;
        let quoted = hex::decode(quoted)
            .with_context(|| format!("Decode quoted {} PCR {index}", bank.quote_key()))?;
        if quoted != *replayed {
            bail!(
                "{} eventlog replay mismatch for PCR {index}: replayed {}, quoted {}",
                bank.quote_key(),
                hex::encode(replayed),
                hex::encode(quoted)
            );
        }
    }
    Ok(())
}

/// Verify that every PCR represented by the supplied boot/AA event logs
/// replays to the value protected by the TPM Quote. An event log that cannot be
/// parsed is rejected instead of being treated as an informational claim.
fn verify_eventlog_integrity(evidence: &TpmEvidence) -> Result<()> {
    let engine = base64::engine::general_purpose::STANDARD;
    let mut sha1_pcrs = ReplayedPcrs::new();
    let mut sha256_pcrs = ReplayedPcrs::new();

    if let Some(encoded) = &evidence.eventlog {
        let raw = engine.decode(encoded).context("Decode TPM boot eventlog")?;
        if let std::result::Result::Ok(eventlog) = CcEventLog::try_from(raw.clone()) {
            replay_cc_eventlog(&eventlog, PcrBank::Sha1, &mut sha1_pcrs, true)?;
            replay_cc_eventlog(&eventlog, PcrBank::Sha256, &mut sha256_pcrs, true)?;
        } else if let std::result::Result::Ok(eventlog) = Eventlog::try_from(raw.clone()) {
            replay_tcg_eventlog(&eventlog, PcrBank::Sha1, &mut sha1_pcrs)?;
            replay_tcg_eventlog(&eventlog, PcrBank::Sha256, &mut sha256_pcrs)?;
        } else if let std::result::Result::Ok(eventlog) = BiosEventlog::try_from(raw) {
            replay_bios_eventlog(&eventlog, &mut sha1_pcrs)?;
        } else {
            bail!("Failed to parse TPM boot eventlog for integrity verification");
        }
    }

    if let Some(encoded) = &evidence.aa_eventlog {
        let raw = engine.decode(encoded).context("Decode AA eventlog")?;
        let eventlog = CcEventLog::try_from(raw).context("Parse AA eventlog")?;
        replay_cc_eventlog(&eventlog, PcrBank::Sha256, &mut sha256_pcrs, false)?;
    }

    if !sha1_pcrs.is_empty() {
        let quote = evidence
            .quote
            .get(PcrBank::Sha1.quote_key())
            .context("TPM evidence has a SHA1 eventlog but no SHA1 quote")?;
        check_replayed_pcrs(quote, PcrBank::Sha1, &sha1_pcrs)?;
    }
    if !sha256_pcrs.is_empty() {
        let quote = evidence
            .quote
            .get(PcrBank::Sha256.quote_key())
            .context("TPM evidence has a SHA256 eventlog but no SHA256 quote")?;
        check_replayed_pcrs(quote, PcrBank::Sha256, &sha256_pcrs)?;
    }

    Ok(())
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

    if let Some(ek_pubkey) = tpm_evidence.ek_pubkey {
        parsed_claims.insert("ek_pubkey".to_string(), Value::String(ek_pubkey));
    }

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
    }

    for (algorithm, quote) in &tpm_evidence.quote {
        for (index, pcr_digest) in quote.pcrs.iter().enumerate() {
            parsed_claims.insert(
                format!("pcrs.{algorithm}.{index}"),
                Value::String(pcr_digest.clone()),
            );
        }
    }

    // Parse TCG Eventlogs
    if let Some(b64_eventlog) = tpm_evidence.eventlog {
        let eventlog_bytes = engine.decode(b64_eventlog)?;

        if let Result::Ok(eventlog) = CcEventLog::try_from(eventlog_bytes.clone()) {
            log::info!("TCG2 Eventlog parsed successfully");
            for event in eventlog.log {
                let event_type = serde_json::to_value(event.event_type)?
                    .as_str()
                    .context("TCG event type did not serialize as a string")?
                    .to_string();
                let event_desc = engine.decode(event.event)?;
                let event_data = match String::from_utf8(event_desc.clone()) {
                    Result::Ok(d) => d,
                    Result::Err(_) => hex::encode(event_desc),
                };
                for digest in event.digests {
                    let algorithm = serde_json::to_value(digest.alg)?
                        .as_str()
                        .context("TCG digest algorithm did not serialize as a string")?
                        .to_string();
                    parse_measurements_from_event(
                        &mut parsed_claims,
                        &event_type,
                        &event_data,
                        &algorithm,
                        &digest.digest,
                    )?;
                }
            }
        } else if let Result::Ok(eventlog) = Eventlog::try_from(eventlog_bytes.clone()) {
            log::info!("TCG Eventlog parsed successfully");
            // Process TCG format event log
            for event in eventlog.log {
                let Some(first_digest) = event.digests.first() else {
                    continue;
                };
                let event_desc = &event.event_desc;
                let event_data = match String::from_utf8(event_desc.clone()) {
                    Result::Ok(d) => d,
                    Result::Err(_) => hex::encode(event_desc),
                };
                // Normalize digest algorithm label:
                // - Remove "TPM_ALG_" prefix
                // - Replace underscores with hyphens
                // - If there is no hyphen between letters and digits, insert one
                //   Examples: "SHA256" -> "SHA-256", "SHA_384" -> "SHA-384", "SM3_256" -> "SM3-256"
                let algo_clean = first_digest.algorithm.trim_start_matches("TPM_ALG_");
                let mut event_digest_algorithm = algo_clean.replace('_', "-");
                if !event_digest_algorithm.contains('-') {
                    if let Some(idx) = event_digest_algorithm.find(|c: char| c.is_ascii_digit()) {
                        event_digest_algorithm.insert(idx, '-');
                    }
                }
                let event_digest = &first_digest.digest;

                parse_measurements_from_event(
                    &mut parsed_claims,
                    event.event_type.as_str(),
                    &event_data,
                    &event_digest_algorithm,
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
                let event_digest_algorithm = "SHA-1";
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
        // Preserve the existing claim key used by Trustee policies. The
        // integrity check above has already replayed these AA runtime events.
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

    println!("device_path_str: {device_path_str}");

    if device_path_str.contains("shim") {
        parsed_claims.insert(
            format!("measurement.shim.{event_digest_algorithm}"),
            serde_json::Value::String(hex::encode(event_digest)),
        );
    }
    if device_path_str.contains("grub") {
        parsed_claims.insert(
            format!("measurement.grub.{event_digest_algorithm}"),
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
        let kernel_claim_key = format!("measurement.kernel.{event_digest_algorithm}");
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
            format!("measurement.kernel_cmdline.{event_digest_algorithm}");
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
        let initrd_claim_key = format!("measurement.initrd.{event_digest_algorithm}");
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
                "Expect REPORT_DATA: {}, Quote report data: {}",
                hex::encode(expected_report_data),
                hex::encode(quote_data)
            );
            bail!("Expected REPORT_DATA is different from that in TPM Quote");
        }

        Ok(())
    }

    fn check_pcrs(&self, pcr_algorithm: &str) -> Result<()> {
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

fn pkey_from_tpm2b_public(tpm2b_public: &[u8]) -> Result<PKey<openssl::pkey::Public>> {
    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey, EcPoint};
    use openssl::nid::Nid;
    use openssl::rsa::Rsa;
    use tss_esapi::interface_types::ecc::EccCurve;
    use tss_esapi::structures::Public;

    let public = Public::unmarshall(tpm2b_public)
        .map_err(|e| anyhow!(format!("unmarshall TPM2B_PUBLIC: {e}")))?;

    match public {
        Public::Rsa {
            parameters, unique, ..
        } => {
            let n = BigNum::from_slice(unique.value())?;
            let mut e_val = parameters.exponent().value();
            if e_val == 0 {
                e_val = 65537;
            }
            let e = BigNum::from_u32(e_val)?;
            let rsa = Rsa::from_public_components(n, e)?;
            Ok(PKey::from_rsa(rsa)?)
        }
        Public::Ecc {
            parameters, unique, ..
        } => {
            let nid = match parameters.ecc_curve() {
                EccCurve::NistP256 => Nid::X9_62_PRIME256V1,
                EccCurve::NistP384 => Nid::SECP384R1,
                EccCurve::NistP521 => Nid::SECP521R1,
                _ => bail!("Unsupported ECC curve in TPM2B_PUBLIC"),
            };
            let group = EcGroup::from_curve_name(nid)?;
            let mut ctx = openssl::bn::BigNumContext::new()?;
            let bx = BigNum::from_slice(unique.x().value())?;
            let by = BigNum::from_slice(unique.y().value())?;
            let mut ec_point = EcPoint::new(&group)?;
            ec_point.set_affine_coordinates_gfp(&group, &bx, &by, &mut ctx)?;
            let ec_key = EcKey::from_public_key(&group, &ec_point)?;
            Ok(PKey::from_ec_key(ec_key)?)
        }
        _ => bail!("Unsupported or invalid TPM public key"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replayed_pcr_is_checked_against_quote() {
        let event_digest = Sha256::digest(b"runtime event").to_vec();
        let mut replayed = ReplayedPcrs::new();
        extend_replayed_pcr(&mut replayed, 17, PcrBank::Sha256, &event_digest).unwrap();

        let mut quoted_pcrs = vec!["00".repeat(32); 24];
        quoted_pcrs[17] = hex::encode(replayed.get(&17).unwrap());
        let quote = TpmQuote {
            attest_body: String::new(),
            attest_sig: String::new(),
            pcrs: quoted_pcrs,
        };

        check_replayed_pcrs(&quote, PcrBank::Sha256, &replayed).unwrap();

        let mut tampered = replayed;
        tampered.get_mut(&17).unwrap()[0] ^= 1;
        let err = check_replayed_pcrs(&quote, PcrBank::Sha256, &tampered).unwrap_err();
        assert!(err
            .to_string()
            .contains("eventlog replay mismatch for PCR 17"));
    }

    #[test]
    fn startup_locality_initializes_pcr_zero() {
        let mut event_data = b"StartupLocality\0".to_vec();
        event_data.push(3);
        let eventlog = CcEventLog {
            log: vec![::eventlog::EventlogEntry {
                details: ::eventlog::EventDetails::empty(),
                digests: vec![],
                event: base64::engine::general_purpose::STANDARD.encode(event_data),
                index: 0,
                event_type: TcgEventType::EvNoAction,
            }],
        };
        let mut replayed = ReplayedPcrs::new();

        replay_cc_eventlog(&eventlog, PcrBank::Sha256, &mut replayed, true).unwrap();

        let mut expected = vec![0; 32];
        expected[31] = 3;
        assert_eq!(replayed.get(&0), Some(&expected));
    }
}
