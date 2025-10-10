use ::eventlog::{ccel::tcg_enum::TcgAlgorithm, CcEventLog, ReferenceMeasurement};
use anyhow::anyhow;
use log::{debug, error, info, warn};

use crate::tdx::claims::generate_parsed_claim;

use super::*;
use async_trait::async_trait;
use base64::Engine;
use quote::{ecdsa_quote_verification, parse_tdx_quote};
use serde::{Deserialize, Serialize};

use serde_json::Value;

pub(crate) mod claims;
pub(crate) mod gpu;
pub(crate) mod quote;

use crate::tdx::gpu::GpuEvidenceList;

#[derive(Serialize, Deserialize, Debug)]
struct TdxEvidence {
    // Base64 encoded TD quote.
    quote: String,

    /// Base64 encoded Eventlog
    /// This might include the
    /// - CCEL: <https://uefi.org/specs/ACPI/6.5/05_ACPI_Software_Programming_Model.html#cc-event-log-acpi-table>
    /// - AAEL in TCG2 encoding: <https://github.com/confidential-containers/trustee/blob/main/kbs/docs/confidential-containers-eventlog.md>
    cc_eventlog: Option<String>,

    // GPU Evidence
    gpu_evidence: Option<GpuEvidenceList>,
}

#[derive(Debug, Default)]
pub struct Tdx {}

#[async_trait]
impl Verifier for Tdx {
    async fn evaluate(
        &self,
        evidence: TeeEvidence,
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<(TeeEvidenceParsedClaim, TeeClass)> {
        let tdx_evidence = serde_json::from_value::<TdxEvidence>(evidence)
            .context("Deserialize TDX Evidence failed.")?;

        let claims = verify_evidence(expected_report_data, expected_init_data_hash, tdx_evidence)
            .await
            .map_err(|e| anyhow!("TDX Verifier: {:?}", e))?;

        Ok((claims, "cpu".to_string()))
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
    if let Some(el) = &evidence.cc_eventlog {
        let ccel_data = base64::engine::general_purpose::STANDARD.decode(el)?;
        let ccel = CcEventLog::try_from(ccel_data)
            .map_err(|e| anyhow!("Parse CC Eventlog failed: {:?}", e))?;
        ccel_option = Some(ccel.clone());
        let compare_obj: Vec<ReferenceMeasurement> = vec![
            ReferenceMeasurement {
                index: 1,
                algorithm: TcgAlgorithm::Sha384,
                reference: quote.rtmr_0().to_vec(),
            },
            ReferenceMeasurement {
                index: 2,
                algorithm: TcgAlgorithm::Sha384,
                reference: quote.rtmr_1().to_vec(),
            },
            ReferenceMeasurement {
                index: 3,
                algorithm: TcgAlgorithm::Sha384,
                reference: quote.rtmr_2().to_vec(),
            },
            ReferenceMeasurement {
                index: 4,
                algorithm: TcgAlgorithm::Sha384,
                reference: quote.rtmr_3().to_vec(),
            },
        ];

        ccel.replay_and_match(compare_obj)?;
        info!("EventLog integrity check succeeded.");
    } else {
        warn!("No Eventlog included inside the TDX evidence.");
    }

    let mut tdx_attestation_claims: serde_json::Value =
        generate_parsed_claim(quote, ccel_option)? as serde_json::Value;

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
    use std::fs;

    #[test]
    fn test_generate_parsed_claim() {
        let ccel_bin = fs::read("./test_data/CCEL_data").unwrap();
        let ccel = CcEventLog::try_from(ccel_bin).unwrap();
        let quote_bin = fs::read("./test_data/tdx_quote_4.dat").unwrap();
        let quote = parse_tdx_quote(&quote_bin).unwrap();

        let parsed_claim = generate_parsed_claim(quote, Some(ccel));
        assert!(parsed_claim.is_ok());

        let _ = fs::write(
            "./test_data/evidence_claim_output.txt",
            format!("{:?}", parsed_claim.unwrap()),
        );
    }
}
