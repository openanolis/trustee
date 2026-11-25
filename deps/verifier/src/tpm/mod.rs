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
use std::collections::{BTreeMap, HashMap};
use std::env::VarError;
use std::sync::LazyLock;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::structures::{Attest, AttestInfo};
use tss_esapi::traits::UnMarshall;

use crate::tpm_registrar;

const TPM_REPORT_DATA_SIZE: usize = 32;
const TPM_QUOTE_PCR_COUNT: usize = 24;
const ALLOW_SHA256_ONLY_ENV: &str = "TRUSTEE_TPM_ALLOW_SHA256_ONLY";
static ALLOW_SHA256_ONLY: LazyLock<Result<bool, &'static str>> =
    LazyLock::new(|| parse_sha256_only_setting(std::env::var(ALLOW_SHA256_ONLY_ENV)));

fn parse_sha256_only_setting(value: Result<String, VarError>) -> Result<bool, &'static str> {
    use std::result::Result::Ok;

    match value.as_deref() {
        Err(VarError::NotPresent) | Ok("false") => Ok(false),
        Ok("true") => Ok(true),
        _ => Err("TRUSTEE_TPM_ALLOW_SHA256_ONLY must be true or false"),
    }
}

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
        let allow_sha256_only = (*ALLOW_SHA256_ONLY).map_err(|message| anyhow!(message))?;
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

        let claims = verify_tpm_quotes(tpm_evidence, expected_report_data, allow_sha256_only)?;
        Ok((claims, "cpu".to_string()))
    }
}

fn verify_tpm_quotes(
    evidence: TpmEvidence,
    expected_report_data: &ReportData,
    allow_sha256_only: bool,
) -> Result<TeeEvidenceParsedClaim> {
    let sha256_only = allow_sha256_only && !evidence.quote.contains_key(PcrBank::Sha1.quote_key());
    if allow_sha256_only {
        if !evidence.quote.contains_key(PcrBank::Sha256.quote_key()) {
            bail!("TPM SHA256-only support requires a SHA256 quote");
        }
        if evidence
            .quote
            .keys()
            .any(|bank| bank != PcrBank::Sha1.quote_key() && bank != PcrBank::Sha256.quote_key())
        {
            bail!("Unsupported PCR bank in TPM evidence");
        }
    }

    for (algorithm, quote) in &evidence.quote {
        quote.verify_signature(evidence.ak_pubkey.as_bytes())?;
        if allow_sha256_only && algorithm == PcrBank::Sha256.quote_key() {
            quote.check_sha256_selection()?;
        }
        quote.check_pcrs(algorithm)?;
        if let ReportData::Value(expected_report_data) = expected_report_data {
            quote.check_report_data(expected_report_data)?;
        }
    }

    verify_eventlog_integrity(&evidence, sha256_only)?;
    parse_tpm_evidence(evidence, sha256_only)
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

fn replay_tcg_eventlog(
    eventlog: &Eventlog,
    bank: PcrBank,
    pcrs: &mut ReplayedPcrs,
    require_digest: bool,
) -> Result<()> {
    for event in &eventlog.log {
        // Informational events are logged but are not extended into a PCR.
        if event.event_type == "EV_NO_ACTION" {
            continue;
        }

        let mut digests = event
            .digests
            .iter()
            .filter(|digest| digest.algorithm == bank.eventlog_name());
        if let Some(digest) = digests.next() {
            if require_digest && digests.next().is_some() {
                bail!("Multiple SHA256 digests in one TPM boot event");
            }
            extend_replayed_pcr(
                pcrs,
                event.target_measurement_registry,
                bank,
                &digest.digest,
            )?;
        } else if require_digest {
            bail!("Missing SHA256 digest in TPM boot event");
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
    require_digest: bool,
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

        let mut digests = event
            .digests
            .iter()
            .filter(|digest| digest.alg == tcg_algorithm_for_bank(bank));
        if let Some(digest) = digests.next() {
            if require_digest && digests.next().is_some() {
                bail!("Multiple SHA256 digests in one TPM event");
            }
            extend_replayed_pcr(pcrs, event.index, bank, &digest.digest)?;
        } else if require_digest {
            bail!("Missing SHA256 digest in TPM event");
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
fn verify_eventlog_integrity(evidence: &TpmEvidence, sha256_only: bool) -> Result<()> {
    let engine = base64::engine::general_purpose::STANDARD;
    let mut sha1_pcrs = ReplayedPcrs::new();
    let mut sha256_pcrs = ReplayedPcrs::new();

    if let Some(encoded) = &evidence.eventlog {
        let raw = engine.decode(encoded).context("Decode TPM boot eventlog")?;
        if let std::result::Result::Ok(eventlog) = CcEventLog::try_from(raw.clone()) {
            if !sha256_only {
                replay_cc_eventlog(&eventlog, PcrBank::Sha1, &mut sha1_pcrs, true, false)?;
            }
            replay_cc_eventlog(
                &eventlog,
                PcrBank::Sha256,
                &mut sha256_pcrs,
                true,
                sha256_only,
            )?;
        } else if let std::result::Result::Ok(eventlog) = Eventlog::try_from(raw.clone()) {
            if !sha256_only {
                replay_tcg_eventlog(&eventlog, PcrBank::Sha1, &mut sha1_pcrs, false)?;
            }
            replay_tcg_eventlog(&eventlog, PcrBank::Sha256, &mut sha256_pcrs, sha256_only)?;
        } else if let std::result::Result::Ok(eventlog) = BiosEventlog::try_from(raw) {
            if sha256_only {
                bail!("SHA256-only TPM evidence cannot authenticate a legacy BIOS event log");
            }
            replay_bios_eventlog(&eventlog, &mut sha1_pcrs)?;
        } else {
            bail!("Failed to parse TPM boot eventlog for integrity verification");
        }
    }

    if let Some(encoded) = &evidence.aa_eventlog {
        let raw = engine.decode(encoded).context("Decode AA eventlog")?;
        let eventlog = CcEventLog::try_from(raw).context("Parse AA eventlog")?;
        replay_cc_eventlog(
            &eventlog,
            PcrBank::Sha256,
            &mut sha256_pcrs,
            false,
            sha256_only,
        )?;
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

fn parse_tpm_evidence(
    tpm_evidence: TpmEvidence,
    sha256_only: bool,
) -> Result<TeeEvidenceParsedClaim> {
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
        let mut boot_event_digests = BTreeMap::<u32, Vec<String>>::new();

        if let Result::Ok(eventlog) = CcEventLog::try_from(eventlog_bytes.clone()) {
            log::info!("TCG2 Eventlog parsed successfully");
            for event in eventlog.log {
                if sha256_only && event.event_type == TcgEventType::EvNoAction {
                    continue;
                }
                let event_type = serde_json::to_value(event.event_type)?
                    .as_str()
                    .context("TCG event type did not serialize as a string")?
                    .to_string();
                let event_desc = engine.decode(event.event)?;
                let event_data = match String::from_utf8(event_desc.clone()) {
                    Result::Ok(d) => d,
                    Result::Err(_) => hex::encode(&event_desc),
                };
                for digest in event.digests {
                    if sha256_only && digest.alg != TcgAlgorithm::Sha256 {
                        continue;
                    }
                    if sha256_only {
                        boot_event_digests
                            .entry(event.index)
                            .or_default()
                            .push(hex::encode(&digest.digest));
                        if Sha256::digest(&event_desc).as_slice() != digest.digest {
                            continue;
                        }
                    }
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
                        sha256_only,
                    )?;
                }
            }
        } else if let Result::Ok(eventlog) = Eventlog::try_from(eventlog_bytes.clone()) {
            log::info!("TCG Eventlog parsed successfully");
            // Process TCG format event log
            for event in eventlog.log {
                if sha256_only && event.event_type == "EV_NO_ACTION" {
                    continue;
                }
                let digest = if sha256_only {
                    event
                        .digests
                        .iter()
                        .find(|digest| digest.algorithm == PcrBank::Sha256.eventlog_name())
                } else {
                    event.digests.first()
                };
                let Some(digest) = digest else {
                    continue;
                };
                let event_desc = &event.event_desc;
                if sha256_only {
                    boot_event_digests
                        .entry(event.target_measurement_registry)
                        .or_default()
                        .push(hex::encode(&digest.digest));
                    if Sha256::digest(event_desc).as_slice() != digest.digest {
                        continue;
                    }
                }
                let event_data = match String::from_utf8(event_desc.clone()) {
                    Result::Ok(d) => d,
                    Result::Err(_) => hex::encode(event_desc),
                };
                // Normalize digest algorithm label:
                // - Remove "TPM_ALG_" prefix
                // - Replace underscores with hyphens
                // - If there is no hyphen between letters and digits, insert one
                //   Examples: "SHA256" -> "SHA-256", "SHA_384" -> "SHA-384", "SM3_256" -> "SM3-256"
                let algo_clean = digest.algorithm.trim_start_matches("TPM_ALG_");
                let mut event_digest_algorithm = algo_clean.replace('_', "-");
                if !event_digest_algorithm.contains('-') {
                    if let Some(idx) = event_digest_algorithm.find(|c: char| c.is_ascii_digit()) {
                        event_digest_algorithm.insert(idx, '-');
                    }
                }
                parse_measurements_from_event(
                    &mut parsed_claims,
                    event.event_type.as_str(),
                    &event_data,
                    &event_digest_algorithm,
                    &digest.digest,
                    sha256_only,
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
                    false,
                )?;
            }
        } else {
            return Err(anyhow!("Failed to parse eventlog"));
        }
        if sha256_only {
            parsed_claims.insert(
                "boot_event_digests".to_string(),
                serde_json::to_value(boot_event_digests)?,
            );
        }
    }

    // Parse AA Eventlogs in TCG2 encoding
    if let Some(aael) = tpm_evidence.aa_eventlog {
        let aa_ccel_data = base64::engine::general_purpose::STANDARD.decode(aael)?;
        let mut aa_ccel = CcEventLog::try_from(aa_ccel_data)?;
        if sha256_only {
            aa_ccel
                .log
                .retain(|event| event.event_type != TcgEventType::EvNoAction);
            for event in &mut aa_ccel.log {
                event
                    .digests
                    .retain(|digest| digest.alg == TcgAlgorithm::Sha256);
                let [digest] = event.digests.as_slice() else {
                    bail!("AA runtime event must have exactly one SHA256 digest");
                };
                let event_data = engine
                    .decode(&event.event)
                    .context("Decode AA runtime event data")?;
                if event.event_type != TcgEventType::EvEventTag
                    || event.details.unicode_name.as_deref() != Some("AAEL")
                    || Sha256::digest(event_data).as_slice() != digest.digest
                {
                    bail!("AA runtime event data does not match its measured SHA256 digest");
                }
            }
        }
        let result = serde_json::to_value(aa_ccel.log)?;
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
    sha256_only: bool,
) -> Result<()> {
    // The TPM authenticates event digests in PCR order. A firmware descriptor
    // and its type do not prove which image produced a separately measured hash.
    if !sha256_only && event_type == "EV_EFI_BOOT_SERVICES_APPLICATION" {
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

        if !quote_data.starts_with(expected_report_data) {
            debug!(
                "Expect REPORT_DATA: {}, Quote report data: {}",
                hex::encode(expected_report_data),
                hex::encode(quote_data)
            );
            bail!("Expected REPORT_DATA is different from that in TPM Quote");
        }

        Ok(())
    }

    fn check_sha256_selection(&self) -> Result<()> {
        let attest = Attest::unmarshall(
            &base64::engine::general_purpose::STANDARD.decode(&self.attest_body)?,
        )?;
        let AttestInfo::Quote { info } = attest.attested() else {
            bail!("Invalid TPM quote");
        };
        let [selection] = info.pcr_selection().get_selections() else {
            bail!("SHA256 quote must select a single PCR bank");
        };
        let selected_slots = selection
            .selected()
            .into_iter()
            .fold(0, |bits, slot| bits | u32::from(slot));
        if selection.hashing_algorithm() != HashingAlgorithm::Sha256
            || selected_slots != (1 << TPM_QUOTE_PCR_COUNT) - 1
        {
            bail!("SHA256 quote must select SHA256 PCRs 0 through 23");
        }
        if self.pcrs.len() != TPM_QUOTE_PCR_COUNT
            || self
                .pcrs
                .iter()
                .any(|pcr| pcr.len() != PcrBank::Sha256.digest_len() * 2)
        {
            bail!("SHA256 quote must contain 24 SHA256 PCR values");
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
    use base64::engine::general_purpose::STANDARD;
    use openssl::{pkey::Private, rsa::Rsa, sign::Signer};

    const CHALLENGE: [u8; TPM_REPORT_DATA_SIZE] = [0x2a; TPM_REPORT_DATA_SIZE];

    fn tcg2_log() -> Vec<u8> {
        let mut spec_id = b"Spec ID Event03\0".to_vec();
        spec_id.extend_from_slice(&[0, 0, 0, 0, 0, 2, 0, 2]);
        spec_id.extend_from_slice(&2u32.to_le_bytes());
        for bank in [PcrBank::Sha1, PcrBank::Sha256] {
            spec_id.extend_from_slice(&(tcg_algorithm_for_bank(bank) as u16).to_le_bytes());
            spec_id.extend_from_slice(&(bank.digest_len() as u16).to_le_bytes());
        }
        spec_id.push(0); // No vendor data.

        let mut log = vec![0; 28];
        log[4..8].copy_from_slice(&(TcgEventType::EvNoAction as u32).to_le_bytes());
        log.extend_from_slice(&(spec_id.len() as u32).to_le_bytes());
        log.extend_from_slice(&spec_id);
        log
    }

    fn append_event(
        log: &mut Vec<u8>,
        index: u32,
        event_type: TcgEventType,
        data: &[u8],
        digests: &[(PcrBank, Vec<u8>)],
    ) {
        log.extend_from_slice(&index.to_le_bytes());
        log.extend_from_slice(&(event_type as u32).to_le_bytes());
        log.extend_from_slice(&(digests.len() as u32).to_le_bytes());
        for (bank, digest) in digests {
            log.extend_from_slice(&(tcg_algorithm_for_bank(*bank) as u16).to_le_bytes());
            log.extend_from_slice(digest);
        }
        log.extend_from_slice(&(data.len() as u32).to_le_bytes());
        log.extend_from_slice(data);
    }

    fn signed_quote(
        ak: &PKey<Private>,
        bank: PcrBank,
        pcr_selection: [u8; 3],
        pcrs: Vec<Vec<u8>>,
    ) -> TpmQuote {
        // Marshal a TPMS_ATTEST with a TPMS_QUOTE_INFO. In the fixture the
        // attestation key is temporary and the supplied PCR list is signed.
        let mut body = 0xff54_4347u32.to_be_bytes().to_vec(); // TPM_GENERATED_VALUE
        body.extend_from_slice(&0x8018u16.to_be_bytes()); // TPM_ST_ATTEST_QUOTE
        body.extend_from_slice(&0u16.to_be_bytes()); // Empty qualified signer.
        body.extend_from_slice(&(CHALLENGE.len() as u16).to_be_bytes());
        body.extend_from_slice(&CHALLENGE);
        body.extend_from_slice(&[0; 25]); // Clock info and firmware version.
        body.extend_from_slice(&1u32.to_be_bytes()); // One PCR bank.
        body.extend_from_slice(&(tcg_algorithm_for_bank(bank) as u16).to_be_bytes());
        body.push(pcr_selection.len() as u8);
        body.extend_from_slice(&pcr_selection);
        let digest = Sha256::digest(pcrs.concat());
        body.extend_from_slice(&(digest.len() as u16).to_be_bytes());
        body.extend_from_slice(&digest);

        let mut signer = Signer::new(MessageDigest::sha256(), ak).unwrap();
        signer.update(&body).unwrap();
        TpmQuote {
            attest_body: STANDARD.encode(body),
            attest_sig: STANDARD.encode(signer.sign_to_vec().unwrap()),
            pcrs: pcrs.into_iter().map(hex::encode).collect(),
        }
    }

    fn tpm_evidence(
        ak: &PKey<Private>,
        quotes: impl IntoIterator<Item = (PcrBank, TpmQuote)>,
        boot_log: Option<&[u8]>,
        aa_log: Option<&[u8]>,
    ) -> TpmEvidence {
        TpmEvidence {
            ek_pubkey: None,
            ek_cert: None,
            ak_pubkey: String::from_utf8(ak.public_key_to_pem().unwrap()).unwrap(),
            keylime_agent_uuid: None,
            quote: quotes
                .into_iter()
                .map(|(bank, quote)| (bank.quote_key().to_string(), quote))
                .collect(),
            eventlog: boot_log.map(|log| STANDARD.encode(log)),
            aa_eventlog: aa_log.map(|log| STANDARD.encode(log)),
        }
    }

    fn empty_pcrs(bank: PcrBank) -> Vec<Vec<u8>> {
        vec![vec![0; bank.digest_len()]; TPM_QUOTE_PCR_COUNT]
    }

    #[test]
    fn sha256_only_setting_is_disabled_when_unset_and_rejects_invalid_values() {
        use std::os::unix::ffi::OsStringExt;
        use std::result::Result::Ok;

        assert_eq!(
            parse_sha256_only_setting(Err(VarError::NotPresent)),
            Ok(false)
        );
        assert_eq!(
            parse_sha256_only_setting(Ok("false".to_string())),
            Ok(false)
        );
        assert_eq!(parse_sha256_only_setting(Ok("true".to_string())), Ok(true));
        assert!(parse_sha256_only_setting(Ok("TRUE".to_string())).is_err());
        assert!(parse_sha256_only_setting(Err(VarError::NotUnicode(
            std::ffi::OsString::from_vec(vec![0xff])
        )))
        .is_err());
    }

    #[test]
    fn sha256_only_preserves_legacy_quote_checks_and_does_not_emit_unquoted_digests() {
        let ak = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut sha1_pcrs = empty_pcrs(PcrBank::Sha1);
        let mut sha256_pcrs = empty_pcrs(PcrBank::Sha256);
        let data = b"Kernel boot measurement";
        let sha1_digest = Sha1::digest(data).to_vec();
        let sha256_digest = Sha256::digest(data).to_vec();
        let mut boot_log = tcg2_log();
        append_event(
            &mut boot_log,
            7,
            TcgEventType::EvIpl,
            data,
            &[
                (PcrBank::Sha1, sha1_digest.clone()),
                (PcrBank::Sha256, sha256_digest.clone()),
            ],
        );
        sha1_pcrs[7] = PcrBank::Sha1.extend(&sha1_pcrs[7], &sha1_digest).unwrap();
        sha256_pcrs[7] = PcrBank::Sha256
            .extend(&sha256_pcrs[7], &sha256_digest)
            .unwrap();
        let sha1 = signed_quote(&ak, PcrBank::Sha1, [0xff; 3], sha1_pcrs);
        let sha256 = signed_quote(&ak, PcrBank::Sha256, [0xff; 3], sha256_pcrs);
        let expected = ReportData::Value(&CHALLENGE);

        let dual = tpm_evidence(
            &ak,
            [(PcrBank::Sha1, sha1), (PcrBank::Sha256, sha256.clone())],
            Some(&boot_log),
            None,
        );
        let legacy = verify_tpm_quotes(dual.clone(), &expected, false).unwrap();
        assert_eq!(
            verify_tpm_quotes(dual.clone(), &expected, true).unwrap(),
            legacy
        );
        assert_eq!(legacy["measurement.kernel.SHA-1"], hex::encode(sha1_digest));
        let mut invalid_dual = dual;
        invalid_dual
            .quote
            .get_mut("SHA1")
            .unwrap()
            .attest_sig
            .clear();
        assert!(verify_tpm_quotes(invalid_dual, &expected, true).is_err());

        let single = tpm_evidence(&ak, [(PcrBank::Sha256, sha256)], Some(&boot_log), None);
        assert!(verify_tpm_quotes(single.clone(), &expected, false).is_err());
        let claims = verify_tpm_quotes(single, &expected, true).unwrap();
        assert_eq!(
            claims["measurement.kernel.SHA-256"],
            hex::encode(&sha256_digest)
        );
        assert_eq!(
            claims["boot_event_digests"]["7"][0],
            hex::encode(sha256_digest)
        );
        assert!(claims.get("measurement.kernel.SHA-1").is_none());
        assert!(claims.get("pcrs.SHA1.7").is_none());
    }

    #[test]
    fn legacy_sha1_only_requires_the_default_policy() {
        let ak = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut pcrs = empty_pcrs(PcrBank::Sha1);
        let data = b"Kernel legacy boot measurement";
        let digest = Sha1::digest(data).to_vec();
        let mut boot_log = tcg2_log();
        append_event(
            &mut boot_log,
            7,
            TcgEventType::EvIpl,
            data,
            &[(PcrBank::Sha1, digest.clone())],
        );
        pcrs[7] = PcrBank::Sha1.extend(&pcrs[7], &digest).unwrap();
        let quote = signed_quote(&ak, PcrBank::Sha1, [0xff; 3], pcrs);
        let legacy = tpm_evidence(&ak, [(PcrBank::Sha1, quote)], Some(&boot_log), None);
        let expected = ReportData::Value(&CHALLENGE);
        assert!(verify_tpm_quotes(legacy.clone(), &expected, false).is_ok());
        let error = verify_tpm_quotes(legacy, &expected, true).unwrap_err();
        assert!(error.to_string().contains("requires a SHA256 quote"));
    }

    #[test]
    fn sha256_only_requires_the_signed_full_sha256_selection_and_pcr_values() {
        let ak = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let expected = ReportData::Value(&CHALLENGE);
        let pcrs = empty_pcrs(PcrBank::Sha256);

        for (bank, selection) in [
            (PcrBank::Sha1, [0xff; 3]),
            (PcrBank::Sha256, [0xfe, 0xff, 0xff]),
        ] {
            let quote = signed_quote(&ak, bank, selection, pcrs.clone());
            let evidence = tpm_evidence(&ak, [(PcrBank::Sha256, quote)], None, None);
            let error = verify_tpm_quotes(evidence, &expected, true).unwrap_err();
            assert!(error
                .to_string()
                .contains("must select SHA256 PCRs 0 through 23"));
        }

        let mut quote = signed_quote(&ak, PcrBank::Sha256, [0xff; 3], pcrs);
        quote.pcrs.pop();
        let evidence = tpm_evidence(&ak, [(PcrBank::Sha256, quote)], None, None);
        let error = verify_tpm_quotes(evidence, &expected, true).unwrap_err();
        assert!(error
            .to_string()
            .contains("must contain 24 SHA256 PCR values"));
    }

    #[test]
    fn sha256_only_checks_sha256_coverage_for_each_event_and_replays_the_digest() {
        let ak = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let expected = ReportData::Value(&CHALLENGE);
        let mut pcrs = empty_pcrs(PcrBank::Sha256);
        let data = b"Kernel boot measurement";
        let digest = Sha256::digest(data).to_vec();
        pcrs[7] = PcrBank::Sha256.extend(&pcrs[7], &digest).unwrap();
        let quote = signed_quote(&ak, PcrBank::Sha256, [0xff; 3], pcrs);

        let mut log = tcg2_log();
        append_event(
            &mut log,
            7,
            TcgEventType::EvIpl,
            data,
            &[(PcrBank::Sha256, digest.clone())],
        );
        let unrelated = b"Initrd legacy-only event in the same PCR";
        append_event(
            &mut log,
            7,
            TcgEventType::EvIpl,
            unrelated,
            &[(PcrBank::Sha1, Sha1::digest(unrelated).to_vec())],
        );
        let evidence = tpm_evidence(&ak, [(PcrBank::Sha256, quote.clone())], Some(&log), None);
        let error = verify_tpm_quotes(evidence, &expected, true).unwrap_err();
        assert!(error.to_string().contains("Missing SHA256 digest"));

        let mut tampered_digest = digest;
        tampered_digest[0] ^= 1;
        let mut log = tcg2_log();
        append_event(
            &mut log,
            7,
            TcgEventType::EvIpl,
            data,
            &[(PcrBank::Sha256, tampered_digest)],
        );
        let evidence = tpm_evidence(&ak, [(PcrBank::Sha256, quote)], Some(&log), None);
        let error = verify_tpm_quotes(evidence, &expected, true).unwrap_err();
        assert!(error.to_string().contains("eventlog replay mismatch"));
    }

    #[test]
    fn sha256_only_does_not_publish_typed_claims_for_unmeasured_descriptors() {
        let ak = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let expected = ReportData::Value(&CHALLENGE);
        let mut pcrs = empty_pcrs(PcrBank::Sha256);
        let digest = Sha256::digest(b"Measured boot image").to_vec();
        pcrs[7] = PcrBank::Sha256.extend(&pcrs[7], &digest).unwrap();
        let quote = signed_quote(&ak, PcrBank::Sha256, [0xff; 3], pcrs);
        let mut log = tcg2_log();
        append_event(
            &mut log,
            7,
            TcgEventType::EvIpl,
            b"kernel_cmdline unauthenticated text",
            &[(PcrBank::Sha256, digest.clone())],
        );
        let evidence = tpm_evidence(&ak, [(PcrBank::Sha256, quote)], Some(&log), None);
        let claims = verify_tpm_quotes(evidence, &expected, true).unwrap();
        assert_eq!(claims["boot_event_digests"]["7"][0], hex::encode(digest));
        assert!(claims.get("measurement.kernel_cmdline.SHA-256").is_none());
        assert!(claims.get("kernel_cmdline").is_none());
    }

    #[test]
    fn sha256_only_checks_runtime_event_data_before_issuing_claims() {
        fn aa_tag(data: &[u8]) -> Vec<u8> {
            let mut tagged = 0x4141_454cu32.to_le_bytes().to_vec();
            tagged.extend_from_slice(&(data.len() as u32).to_le_bytes());
            tagged.extend_from_slice(data);
            tagged
        }

        let ak = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let expected = ReportData::Value(&CHALLENGE);
        let mut pcrs = empty_pcrs(PcrBank::Sha256);
        let tag = aa_tag(b"test.domain process stable-content");
        let digest = Sha256::digest(&tag).to_vec();
        pcrs[17] = PcrBank::Sha256.extend(&pcrs[17], &digest).unwrap();
        let quote = signed_quote(&ak, PcrBank::Sha256, [0xff; 3], pcrs);
        let event_digests = [
            (PcrBank::Sha1, Sha1::digest(&tag).to_vec()),
            (PcrBank::Sha256, digest),
        ];
        let mut log = tcg2_log();
        append_event(&mut log, 17, TcgEventType::EvEventTag, &tag, &event_digests);
        let evidence = tpm_evidence(&ak, [(PcrBank::Sha256, quote.clone())], None, Some(&log));
        let claims = verify_tpm_quotes(evidence, &expected, true).unwrap();
        let event = &claims["uefi_event_logs"][0];
        assert_eq!(event["details"]["data"]["content"], "stable-content");
        let digests = event["digests"].as_array().unwrap();
        assert_eq!(digests.len(), 1);
        assert_eq!(digests[0]["alg"], "SHA-256");

        let mut log = tcg2_log();
        let tampered = aa_tag(b"test.domain process modified-content");
        append_event(
            &mut log,
            17,
            TcgEventType::EvEventTag,
            &tampered,
            &event_digests,
        );
        let evidence = tpm_evidence(&ak, [(PcrBank::Sha256, quote)], None, Some(&log));
        let error = verify_tpm_quotes(evidence, &expected, true).unwrap_err();
        assert!(error.to_string().contains("event data does not match"));
    }

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

        replay_cc_eventlog(&eventlog, PcrBank::Sha256, &mut replayed, true, false).unwrap();

        let mut expected = vec![0; 32];
        expected[31] = 3;
        assert_eq!(replayed.get(&0), Some(&expected));
    }
}
