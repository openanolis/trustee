use ::eventlog::{ccel::tcg_enum::TcgAlgorithm, CcEventLog, ReferenceMeasurement};
use anyhow::anyhow;
use log::{debug, error, info, warn};
use std::env;

use crate::tdx::claims::generate_parsed_claim;

use super::*;
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use quote::parse_tdx_quote;
use serde::{Deserialize, Serialize};
use verify::ecdsa_quote_verification;

use serde_json::Value;

pub(crate) mod claims;
pub(crate) mod gpu;
pub(crate) mod quote;
pub(crate) mod verify;

#[cfg(feature = "tdx-dcap-rust")]
pub use verify::set_pccs_url;

use crate::tdx::gpu::GpuEvidenceList;
use crate::VerifierError;

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
        let tdx_evidence = serde_json::from_value::<TdxEvidence>(evidence).map_err(|source| {
            VerifierError::InvalidEvidenceFormat {
                field: "evidence",
                source: source.into(),
            }
        })?;

        let claims = verify_evidence(expected_report_data, expected_init_data_hash, tdx_evidence)
            .await
            .context("TDX verifier")?;

        Ok((claims, "cpu".to_string()))
    }
}

async fn verify_evidence(
    expected_report_data: &ReportData<'_>,
    expected_init_data_hash: &InitDataHash<'_>,
    evidence: TdxEvidence,
) -> Result<TeeEvidenceParsedClaim> {
    if evidence.quote.is_empty() {
        return Err(VerifierError::InvalidEvidenceFormat {
            field: "quote",
            source: anyhow!("TDX quote is empty"),
        }
        .into());
    }

    let quote_bin = decode_base64(&evidence.quote, "quote")?;

    // Parse before accessing the quote verification backend. Besides producing
    // a precise client error, this avoids contacting collateral services for a
    // structurally invalid quote.
    let quote = parse_tdx_quote(&quote_bin).map_err(|source| VerifierError::InvalidQuote {
        field: "quote",
        source,
    })?;

    // Verify TD quote ECDSA signature.
    let tcb_verification_result = ecdsa_quote_verification(quote_bin.as_slice()).await?;

    info!(
        "Quote DCAP check succeeded. TCB status: {}",
        tcb_verification_result.tcb_status
    );

    debug!("{quote}");

    if let ReportData::Value(expected_report_data) = expected_report_data {
        debug!("Check the binding of REPORT_DATA.");
        let expected_report_data = regularize_data(expected_report_data, 64, "REPORT_DATA", "TDX");
        if expected_report_data != quote.report_data() {
            return Err(VerifierError::BindingMismatch {
                field: "quote.report_data",
                source: anyhow!("REPORT_DATA differs from the value in the TDX quote"),
            }
            .into());
        }
    }

    if let InitDataHash::Value(expected_init_data_hash) = expected_init_data_hash {
        debug!("Check the binding of MRCONFIGID.");
        let expected_init_data_hash =
            regularize_data(expected_init_data_hash, 48, "MRCONFIGID", "TDX");
        if expected_init_data_hash != quote.mr_config_id() {
            error!("MRCONFIGID (Initdata) verification failed.");
            return Err(VerifierError::BindingMismatch {
                field: "quote.mr_config_id",
                source: anyhow!("MRCONFIGID differs from the value in the TDX quote"),
            }
            .into());
        }
    }

    info!("MRCONFIGID check succeeded.");

    // Verify Integrity of CC Eventlog
    let mut ccel_option = Option::default();
    if let Some(el) = &evidence.cc_eventlog {
        let ccel_data = decode_base64(el, "cc_eventlog")?;
        let ccel = CcEventLog::try_from(ccel_data).map_err(|source| {
            VerifierError::InvalidEvidenceFormat {
                field: "cc_eventlog",
                source: anyhow!("{source:?}"),
            }
        })?;
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

        ccel.replay_and_match(compare_obj)
            .map_err(|source| VerifierError::BindingMismatch {
                field: "cc_eventlog",
                source: anyhow!("{source:?}"),
            })?;
        info!("EventLog integrity check succeeded.");
    } else {
        warn!("No Eventlog included inside the TDX evidence.");
    }

    let mut tdx_attestation_claims: serde_json::Value =
        generate_parsed_claim(quote, ccel_option, Some(tcb_verification_result))?
            as serde_json::Value;

    if let Some(gpu_evidence) = evidence.gpu_evidence {
        let mut gpu_claims = serde_json::Map::new();
        let skip_gpu_verify = env::var("TRUSTEE_SKIP_NVGPU_VERIFY")
            .map(|value| value.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        if skip_gpu_verify {
            info!("Skipping GPU evidence verification per TRUSTEE_SKIP_NVGPU_VERIFY.");
            for (index, single_gpu_evidence) in gpu_evidence.evidence_list.iter().enumerate() {
                match serde_json::to_value(single_gpu_evidence) {
                    Result::Ok(ev) => {
                        gpu_claims.insert(format!("nvidia_gpu.{}", index), ev);
                    }
                    Result::Err(err) => {
                        warn!("GPU {} serialization failed: {}", index, err);
                    }
                }
            }
        } else {
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
                    std::result::Result::Ok((
                        index,
                        std::result::Result::Ok(gpu_evidence_claims),
                    )) => {
                        gpu_claims.insert(format!("nvidia_gpu.{}", index), gpu_evidence_claims);
                    }
                    std::result::Result::Ok((index, std::result::Result::Err(e))) => {
                        warn!("GPU {} evaluation failed: {}", index, e);
                    }
                    std::result::Result::Err(e) => {
                        warn!("GPU task failed: {}", e);
                    }
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

fn decode_base64(value: &str, field: &'static str) -> Result<Vec<u8>> {
    STANDARD
        .decode(value)
        .map_err(|source| VerifierError::InvalidEvidenceEncoding {
            field,
            source: source.into(),
        })
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {

    use super::*;
    use serde_json::json;
    use std::fs;

    fn classified_error(error: &anyhow::Error) -> &VerifierError {
        error
            .downcast_ref::<VerifierError>()
            .expect("error should retain its verifier classification")
    }

    #[tokio::test]
    async fn invalid_quote_encoding_is_classified() {
        let error = Tdx::default()
            .evaluate(
                json!({ "quote": "AAAAA_A" }),
                &ReportData::NotProvided,
                &InitDataHash::NotProvided,
            )
            .await
            .unwrap_err();

        assert!(matches!(
            classified_error(&error),
            VerifierError::InvalidEvidenceEncoding { field: "quote", .. }
        ));
    }

    #[tokio::test]
    async fn missing_quote_is_classified() {
        let error = Tdx::default()
            .evaluate(
                json!({}),
                &ReportData::NotProvided,
                &InitDataHash::NotProvided,
            )
            .await
            .unwrap_err();

        assert!(matches!(
            classified_error(&error),
            VerifierError::InvalidEvidenceFormat {
                field: "evidence",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn malformed_quote_is_classified_before_verification() {
        let quote = STANDARD.encode([0_u8; 4]);
        let error = Tdx::default()
            .evaluate(
                json!({ "quote": quote }),
                &ReportData::NotProvided,
                &InitDataHash::NotProvided,
            )
            .await
            .unwrap_err();

        assert!(matches!(
            classified_error(&error),
            VerifierError::InvalidQuote { field: "quote", .. }
        ));
    }

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
}
