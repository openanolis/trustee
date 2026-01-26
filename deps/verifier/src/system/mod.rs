use ::eventlog::{ccel::tcg_enum::TcgAlgorithm, CcEventLog, ReferenceMeasurement};
use log::{info, warn};
extern crate serde;
use self::serde::{Deserialize, Serialize};
use super::*;
use async_trait::async_trait;
use base64::Engine;
use kbs_types::HashAlgorithm;
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug)]
struct SystemEvidence {
    system_report: String,
    #[serde(default)]
    rtmr_register: Option<String>,
    #[serde(default)]
    cc_eventlog: Option<String>,
    environment: HashMap<String, String>,
    report_data: String,
}

#[derive(Debug, Default)]
pub struct SystemVerifier {}

#[async_trait]
impl Verifier for SystemVerifier {
    async fn evaluate(
        &self,
        evidence: TeeEvidence,
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<(TeeEvidenceParsedClaim, TeeClass)> {
        let evidence = serde_json::from_value::<SystemEvidence>(evidence)
            .context("Deserialize Quote failed.")?;

        verify_evidence(expected_report_data, expected_init_data_hash, &evidence)
            .await
            .context("Evidence's identity verification error.")?;

        info!(
            "Target System Evidence: {}",
            serde_json::to_string_pretty(&evidence)?
        );

        let claims = parse_evidence(&evidence)?;
        Ok((claims, "cpu".to_string()))
    }
}

async fn verify_evidence(
    expected_report_data: &ReportData<'_>,
    _expected_init_data_hash: &InitDataHash<'_>,
    evidence: &SystemEvidence,
) -> Result<()> {
    // Verify integrity of CC Eventlog against runtime measurement register.
    if let Some(rtmr_register) = &evidence.rtmr_register {
        let expected_alg = HashAlgorithm::Sha384;
        let measure_register = hex::decode(rtmr_register)
            .map_err(|e| anyhow!("Decode system runtime register hex: {e}"))?;
        if measure_register.len() != expected_alg.digest_len() {
            bail!(
                "System runtime register length {} is invalid, expected {}",
                measure_register.len(),
                expected_alg.digest_len()
            );
        }

        if let Some(el) = &evidence.cc_eventlog {
            let ccel_data = base64::engine::general_purpose::STANDARD
                .decode(el)
                .map_err(|e| anyhow!("Decode system CC Eventlog: {e}"))?;
            let ccel = CcEventLog::try_from(ccel_data)
                .map_err(|e| anyhow!("Parse CC Eventlog failed: {:?}", e))?;
            let compare_obj: Vec<ReferenceMeasurement> = vec![ReferenceMeasurement {
                index: 1,
                algorithm: TcgAlgorithm::Sha384,
                reference: measure_register,
            }];

            ccel.replay_and_match(compare_obj)?;
            info!("Eventlog integrity check succeeded for system evidence.");
        } else {
            warn!("No Eventlog included inside the system evidence.");
        }
    } else if evidence.cc_eventlog.is_some() {
        warn!("System evidence contains eventlog but no runtime register.");
    }

    // Emulate the report data.
    if let ReportData::Value(expected_report_data) = expected_report_data {
        debug!("Check the binding of REPORT_DATA.");
        let ev_report_data = base64::engine::general_purpose::STANDARD
            .decode(&evidence.report_data)
            .context("base64 decode report data for system evidence")?;
        if *expected_report_data != ev_report_data {
            bail!("REPORT_DATA is different from that in System Evidence");
        }
    }

    Ok(())
}

// Dump the TCB status from the quote.
#[allow(unused_assignments)]
fn parse_evidence(quote: &SystemEvidence) -> Result<TeeEvidenceParsedClaim> {
    let mut claims_map = serde_json::Map::new();

    let system_report: serde_json::Value = serde_json::from_str(&quote.system_report)?;
    let parsed_eventlog: Option<serde_json::Value> = if let Some(el) = &quote.cc_eventlog {
        let ccel_data = base64::engine::general_purpose::STANDARD
            .decode(el)
            .context("Decode system CC Eventlog when parsing claims")?;
        let ccel = CcEventLog::try_from(ccel_data)
            .map_err(|e| anyhow!("Parse CC Eventlog failed when parsing claims: {:?}", e))?;
        serde_json::to_value(ccel.log)
            .map(Some)
            .context("Serialize parsed CC Eventlog for claims")?
    } else {
        None
    };

    claims_map.insert("system_report".to_string(), system_report);
    claims_map.insert(
        "rtmr_register".to_string(),
        serde_json::to_value(&quote.rtmr_register)?,
    );
    if let Some(eventlog) = parsed_eventlog {
        claims_map.insert("uefi_event_logs".to_string(), eventlog);
    }
    claims_map.insert(
        "environment".to_string(),
        serde_json::to_value(&quote.environment)?,
    );
    claims_map.insert(
        "report_data".to_string(),
        serde_json::to_value(&quote.report_data)?,
    );

    Ok(serde_json::Value::Object(claims_map) as TeeEvidenceParsedClaim)
}
