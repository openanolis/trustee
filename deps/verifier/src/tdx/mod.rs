use std::str::FromStr;

use anyhow::anyhow;
use log::{debug, error, info, warn};

use crate::{eventlog::AAEventlog, tdx::claims::generate_parsed_claim};

use super::*;
use async_trait::async_trait;
use base64::Engine;
use eventlog::{CcEventLog, Rtmr};
use quote::{ecdsa_quote_verification, parse_tdx_quote};
use serde::{Deserialize, Serialize};

use serde_json::Value;

pub(crate) mod claims;
pub mod eventlog;
pub(crate) mod gpu;
pub(crate) mod quote;

use crate::tdx::gpu::GpuEvidenceList;

#[derive(Serialize, Deserialize, Debug)]
struct TdxEvidence {
    // Base64 encoded CC Eventlog ACPI table
    // refer to https://uefi.org/specs/ACPI/6.5/05_ACPI_Software_Programming_Model.html#cc-event-log-acpi-table.
    cc_eventlog: Option<String>,
    // Base64 encoded TD quote.
    quote: String,
    // Eventlog of Attestation Agent
    aa_eventlog: Option<String>,
    // GPU Evidence
    gpu_evidence: Option<GpuEvidenceList>,
}

#[derive(Debug, Default)]
pub struct Tdx {}

#[async_trait]
impl Verifier for Tdx {
    async fn evaluate(
        &self,
        evidence: &[u8],
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<TeeEvidenceParsedClaim> {
        let tdx_evidence = serde_json::from_slice::<TdxEvidence>(evidence)
            .context("Deserialize TDX Evidence failed.")?;

        verify_evidence(expected_report_data, expected_init_data_hash, tdx_evidence)
            .await
            .map_err(|e| anyhow!("TDX Verifier: {:?}", e))
    }
}

async fn verify_evidence(
    expected_report_data: &ReportData<'_>,
    expected_init_data_hash: &InitDataHash<'_>,
    evidence: TdxEvidence,
) -> Result<TeeEvidenceParsedClaim> {
    if evidence.quote.is_empty() {
        bail!("TDX Quote is empty.");
    }

    // Verify TD quote ECDSA signature.
    let quote_bin = base64::engine::general_purpose::STANDARD.decode(evidence.quote)?;
    ecdsa_quote_verification(quote_bin.as_slice()).await?;

    info!("Quote DCAP check succeeded.");

    // Parse quote and Compare report data
    let quote = parse_tdx_quote(&quote_bin)?;

    debug!("{quote}");

    if let ReportData::Value(expected_report_data) = expected_report_data {
        debug!("Check the binding of REPORT_DATA.");
        let expected_report_data = regularize_data(expected_report_data, 64, "REPORT_DATA", "TDX");
        if expected_report_data != quote.report_data() {
            bail!("REPORT_DATA is different from that in TDX Quote");
        }
    }

    if let InitDataHash::Value(expected_init_data_hash) = expected_init_data_hash {
        debug!("Check the binding of MRCONFIGID.");
        let expected_init_data_hash =
            regularize_data(expected_init_data_hash, 48, "MRCONFIGID", "TDX");
        if expected_init_data_hash != quote.mr_config_id() {
            error!("MRCONFIGID (Initdata) verification failed.");
            bail!("MRCONFIGID is different from that in TDX Quote");
        }
    }

    info!("MRCONFIGID check succeeded.");

    // Verify Integrity of CC Eventlog
    let mut ccel_option = Option::default();
    match &evidence.cc_eventlog {
        Some(el) if !el.is_empty() => {
            let ccel_data = base64::engine::general_purpose::STANDARD.decode(el)?;
            let ccel = CcEventLog::try_from(ccel_data)
                .map_err(|e| anyhow!("Parse CC Eventlog failed: {:?}", e))?;
            ccel_option = Some(ccel.clone());

            log::debug!("Get CC Eventlog. \n{}\n", &ccel.cc_events);

            let rtmr_from_quote = Rtmr {
                rtmr0: quote.rtmr_0().try_into().expect("must be 48 bytes"),
                rtmr1: quote.rtmr_1().try_into().expect("must be 48 bytes"),
                rtmr2: quote.rtmr_2().try_into().expect("must be 48 bytes"),
                rtmr3: quote.rtmr_3().try_into().expect("must be 48 bytes"),
            };

            ccel.integrity_check(rtmr_from_quote)?;
            info!("CCEL integrity check succeeded.");
        }
        _ => {
            warn!("No CC Eventlog included inside the TDX evidence.");
        }
    }

    // Verify Integrity of AA eventlog
    let aael = match &evidence.aa_eventlog {
        Some(el) if !el.is_empty() => {
            let aael =
                AAEventlog::from_str(el).context("failed to parse AA Eventlog from evidence")?;
            // We assume we always use PCR 17, rtmr 3 for the application side events.

            aael.integrity_check(quote.rtmr_3())?;
            info!("CCEL integrity check succeeded.");
            Some(aael)
        }
        _ => {
            warn!("No AA Eventlog included inside the TDX evidence.");
            None
        }
    };

    let mut tdx_attestation_claims: serde_json::Value =
        generate_parsed_claim(quote, ccel_option, aael)? as serde_json::Value;

    // Parse AA eventlog
    if let Some(aa_eventlog_str) = &evidence.aa_eventlog {
        let mut aa_eventlog_claims = serde_json::Map::new();
        let aa_eventlog_lines: Vec<&str> = aa_eventlog_str.split('\n').collect();

        for event_line in aa_eventlog_lines.iter() {
            let event_split: Vec<&str> = event_line.splitn(3, ' ').collect();

            if event_split[0] == "INIT" {
                continue;
            } else if event_split[0].is_empty() {
                break;
            }

            if event_split.len() != 3 {
                warn!("Illegal AA eventlog format in line: {}", event_line);
                continue;
            }

            let claims_key = format!("AA.eventlog.{}.{}", event_split[0], event_split[1]);
            aa_eventlog_claims.insert(
                claims_key,
                serde_json::Value::String(event_split[2].to_string()),
            );
        }

        // Merge AA eventlog claims into tdx_attestation_claims
        let aa_claims_value = serde_json::Value::Object(aa_eventlog_claims);
        tdx_attestation_claims = match (tdx_attestation_claims.clone(), aa_claims_value) {
            (Value::Object(mut tdx), Value::Object(aa)) => {
                tdx.extend(aa);
                Value::Object(tdx)
            }
            _ => {
                warn!("Merge TDX and AA eventlog claims failed");
                tdx_attestation_claims
            }
        };
    }

    if let Some(gpu_evidence) = evidence.gpu_evidence {
        let mut gpu_claims = serde_json::Map::new();

        // Create tasks for parallel GPU processing
        let mut tasks = Vec::new();
        for (index, single_gpu_evidence) in gpu_evidence.evidence_list.iter().enumerate() {
            let gpu_evidence = single_gpu_evidence.clone();
            let task = tokio::spawn(async move {
                let result = gpu::GpuEvidence::evaluate(&gpu_evidence).await;
                (index, result)
            });
            tasks.push(task);
        }

        // Wait for all tasks to complete
        for task in tasks {
            match task.await {
                std::result::Result::Ok((index, std::result::Result::Ok(gpu_evidence_claims))) => {
                    gpu_claims.insert(format!("nvidia_gpu.{}", index), gpu_evidence_claims);
                }
                std::result::Result::Ok((index, std::result::Result::Err(e))) => {
                    warn!("GPU {} evaluation failed: {}", index, e);
                    // Continue with other GPUs
                }
                std::result::Result::Err(e) => {
                    warn!("GPU task failed: {}", e);
                }
            }
        }

        tdx_attestation_claims = match (tdx_attestation_claims.clone(), gpu_claims) {
            (Value::Object(mut tdx), gpu) => {
                tdx.extend(gpu);
                Value::Object(tdx)
            }
            _ => {
                warn!("Merge TDX and GPU evidence claims failed");
                tdx_attestation_claims
            }
        };
    } else {
        warn!("GPU Attestation Evidence is null, skipping GPU Evidence validation.");
    }

    Ok(tdx_attestation_claims as TeeEvidenceParsedClaim)
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::{fs, str::FromStr};

    #[test]
    fn test_generate_parsed_claim() {
        let ccel_bin = fs::read("./test_data/CCEL_data").unwrap();
        let ccel = CcEventLog::try_from(ccel_bin).unwrap();
        let quote_bin = fs::read("./test_data/tdx_quote_4.dat").unwrap();
        let quote = parse_tdx_quote(&quote_bin).unwrap();

        let parsed_claim = generate_parsed_claim(quote, Some(ccel), None);
        assert!(parsed_claim.is_ok());

        let _ = fs::write(
            "./test_data/evidence_claim_output.txt",
            format!("{:?}", parsed_claim.unwrap()),
        );
    }

    #[test]
    fn test_aael_binding() {
        let aael_bin = fs::read_to_string("./test_data/aael/AAEL_data_1").unwrap();
        let aael = AAEventlog::from_str(&aael_bin).unwrap();
        let quote_bin = fs::read("./test_data/aael/AAEL_quote_tdx").unwrap();
        let quote = parse_tdx_quote(&quote_bin).unwrap();
        aael.integrity_check(quote.rtmr_3()).unwrap();
    }
}
