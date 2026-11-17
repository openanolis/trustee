use ::eventlog::{ccel::tcg_enum::TcgAlgorithm, CcEventLog, ReferenceMeasurement};
use anyhow::anyhow;
use log::{debug, error, info, warn};
#[cfg(not(all(
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
)))]
use std::env;
use std::sync::RwLock;

use crate::tdx::claims::generate_parsed_claim;

use super::*;
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use quote::parse_tdx_quote;
use serde::{Deserialize, Serialize};
use verify::ecdsa_quote_verification;

pub(crate) mod claims;
pub(crate) mod gpu;
pub(crate) mod quote;
pub(crate) mod verify;

#[cfg(feature = "tdx-dcap-rust")]
pub use verify::{dependency_statuses, set_pccs_url, set_pccs_urls};

#[allow(deprecated)]
pub use gpu::set_rim_service_url;

use crate::tdx::gpu::GpuEvidenceList;
use crate::VerifierError;

/// Legacy override retained for source compatibility. Requesting a bypass now
/// rejects GPU-bearing evidence; unverified device claims are never emitted.
static SKIP_GPU_VERIFY_OVERRIDE: RwLock<Option<bool>> = RwLock::new(None);

/// `Some(true)` rejects GPU-bearing evidence. `Some(false)` and `None` require
/// normal verification, including any legacy environment flag.
pub fn set_skip_gpu_verify(skip: Option<bool>) {
    *SKIP_GPU_VERIFY_OVERRIDE.write().unwrap() = skip;
}

/// Default GPU-verify skip resolution when no override is injected (native):
/// the `TRUSTEE_SKIP_NVGPU_VERIFY` env var, opt-in. Wasm has no env and
/// defaults to `false` (verify) — see the wasm variant below.
#[cfg(not(all(
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
)))]
fn default_skip_gpu_verify() -> bool {
    env::var("TRUSTEE_SKIP_NVGPU_VERIFY")
        .map(|value| value.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Wasm has no environment; verification is required.
#[cfg(all(
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
))]
fn default_skip_gpu_verify() -> bool {
    false
}

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
pub struct Tdx {
    pub nvidia_config: crate::nvidia_config::NvidiaVerifierConfig,
}

#[cfg_attr(all(target_arch = "wasm32", target_vendor = "unknown", target_os = "unknown"), async_trait(?Send))]
#[cfg_attr(
    not(all(
        target_arch = "wasm32",
        target_vendor = "unknown",
        target_os = "unknown"
    )),
    async_trait
)]
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

        let claims = verify_evidence(
            expected_report_data,
            expected_init_data_hash,
            tdx_evidence,
            None,
            &self.nvidia_config,
        )
        .await
        .context("TDX verifier")?;

        Ok((claims, "cpu".to_string()))
    }

    /// Verify with attest-supplied DCAP collateral (skip PCCS fetch).
    #[cfg(feature = "tdx-dcap-rust")]
    async fn evaluate_with_collateral(
        &self,
        evidence: TeeEvidence,
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
        collateral: &serde_json::Value,
    ) -> Result<(TeeEvidenceParsedClaim, TeeClass)> {
        let tdx_evidence = serde_json::from_value::<TdxEvidence>(evidence).map_err(|source| {
            VerifierError::InvalidEvidenceFormat {
                field: "evidence",
                source: source.into(),
            }
        })?;
        let claims = verify_evidence(
            expected_report_data,
            expected_init_data_hash,
            tdx_evidence,
            Some(collateral),
            &self.nvidia_config,
        )
        .await
        .context("TDX verifier")?;
        Ok((claims, "cpu".to_string()))
    }
}

async fn verify_evidence(
    expected_report_data: &ReportData<'_>,
    expected_init_data_hash: &InitDataHash<'_>,
    evidence: TdxEvidence,
    collateral: Option<&serde_json::Value>,
    nvidia_config: &crate::nvidia_config::NvidiaVerifierConfig,
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
    let tcb_verification_result = {
        #[cfg(feature = "tdx-dcap-rust")]
        {
            ecdsa_quote_verification(quote_bin.as_slice(), collateral).await?
        }
        #[cfg(feature = "tdx-dcap-ffi")]
        {
            let _ = collateral;
            ecdsa_quote_verification(quote_bin.as_slice()).await?
        }
    };

    info!(
        "Quote DCAP check succeeded. TCB status: {}",
        tcb_verification_result.tcb_status
    );

    debug!("{quote}");

    if let ReportData::Value(expected_report_data) = expected_report_data {
        debug!("Check the binding of REPORT_DATA.");
        let expected_report_data = match &evidence.gpu_evidence {
            Some(gpus) => gpus.bound_report_data(expected_report_data)?,
            None => regularize_data(expected_report_data, 64, "REPORT_DATA", "TDX"),
        };
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
        ensure!(
            !default_skip_gpu_verify() && *SKIP_GPU_VERIFY_OVERRIDE.read().unwrap() != Some(true),
            "Skipping NVIDIA GPU verification is no longer supported"
        );
        let ReportData::Value(report_data) = expected_report_data else {
            bail!("GPU evidence requires expected report data");
        };
        let padded = regularize_data(report_data, 64, "REPORT_DATA", "TDX");
        let gpu_claims = gpu_evidence
            .evaluate(&gpu::gpu_nonce(&padded), nvidia_config)
            .await?;
        tdx_attestation_claims
            .as_object_mut()
            .ok_or_else(|| anyhow!("TDX claims must be an object"))?
            .extend(gpu_claims);
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

    /// evaluate_with_collateral uses the caller-supplied DCAP collateral
    /// (from test_data/tdx_collateral.json, fetched from PCCS for the
    /// prerecorded tdx_quote_4.dat) instead of contacting a PCCS.
    #[cfg(feature = "tdx-dcap-rust")]
    #[tokio::test]
    async fn evaluate_with_collateral_uses_supplied() {
        let quote_bin = std::fs::read("./test_data/tdx_quote_4.dat").expect("read quote");
        let quote_b64 = STANDARD.encode(&quote_bin);
        let collateral_json =
            std::fs::read("./test_data/tdx_collateral.json").expect("read collateral");
        let collateral: serde_json::Value =
            serde_json::from_slice(&collateral_json).expect("parse collateral");
        let result = Tdx::default()
            .evaluate_with_collateral(
                json!({ "quote": quote_b64 }),
                &ReportData::NotProvided,
                &InitDataHash::NotProvided,
                &collateral,
            )
            .await;
        assert!(
            result.is_ok(),
            "evaluate_with_collateral failed: {:?}",
            result.err()
        );
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
