use ::eventlog::{ccel::tcg_enum::TcgAlgorithm, CcEventLog, ReferenceMeasurement};
use anyhow::{anyhow, bail, Context, Result};
use log::{debug, warn};
extern crate serde;
use self::serde::{Deserialize, Serialize};
use super::*;
use async_trait::async_trait;
use base64::Engine;
use kbs_types::HashAlgorithm;
use serde_json::{json, Value};

#[derive(Serialize, Deserialize, Debug)]
struct SampleTeeEvidence {
    svn: String,

    #[serde(default = "String::default")]
    report_data: String,

    #[serde(default = "String::default")]
    measure_register: String,

    #[serde(default)]
    cc_eventlog: Option<String>,
}

#[derive(Debug, Default)]
pub struct Sample {}

#[async_trait]
impl Verifier for Sample {
    async fn evaluate(
        &self,
        evidence: TeeEvidence,
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<(TeeEvidenceParsedClaim, TeeClass)> {
        let tee_evidence = serde_json::from_value::<SampleTeeEvidence>(evidence)
            .context("Deserialize Quote failed.")?;

        verify_tee_evidence(expected_report_data, expected_init_data_hash, &tee_evidence)
            .await
            .context("Evidence's identity verification error.")?;

        debug!("TEE-Evidence<sample>: {:?}", tee_evidence);

        let claims = parse_tee_evidence(&tee_evidence)?;
        Ok((claims, "cpu".to_string()))
    }
}

async fn verify_tee_evidence(
    expected_report_data: &ReportData<'_>,
    expected_init_data_hash: &InitDataHash<'_>,
    evidence: &SampleTeeEvidence,
) -> Result<()> {
    // Verify the TEE Hardware signature. (Null for sample TEE)

    // Emulate the report data.
    if let ReportData::Value(expected_report_data) = expected_report_data {
        debug!("Check the binding of REPORT_DATA.");
        let ev_report_data = base64::engine::general_purpose::STANDARD
            .decode(&evidence.report_data)
            .context("base64 decode report data for sample evidence")?;
        if *expected_report_data != ev_report_data {
            bail!("REPORT_DATA is different from that in Sample Quote");
        }
    }

    if let InitDataHash::Value(_) = expected_init_data_hash {
        warn!("Sample does not support init data hash mechanism. skip.");
    }

    let expected_alg = HashAlgorithm::Sha256;
    let measure_register = hex::decode(&evidence.measure_register)
        .map_err(|e| anyhow!("Decode sample measure register hex: {e}"))?;
    if measure_register.len() != expected_alg.digest_len() {
        bail!(
            "Sample measure register length {} is invalid, expected {}",
            measure_register.len(),
            expected_alg.digest_len()
        );
    }

    if let Some(el) = &evidence.cc_eventlog {
        let ccel_data = base64::engine::general_purpose::STANDARD
            .decode(el)
            .map_err(|e| anyhow!("Decode sample CC Eventlog: {e}"))?;
        let ccel = CcEventLog::try_from(ccel_data)
            .map_err(|e| anyhow!("Parse CC Eventlog failed: {:?}", e))?;
        let compare_obj: Vec<ReferenceMeasurement> = vec![ReferenceMeasurement {
            index: 1,
            algorithm: TcgAlgorithm::Sha256,
            reference: measure_register,
        }];

        ccel.replay_and_match(compare_obj)?;
        debug!("Eventlog integrity check succeeded for sample evidence.");
    } else {
        warn!("No Eventlog included inside the sample evidence.");
    }

    Ok(())
}

// Dump the TCB status from the quote.
// Example: CPU SVN, RTMR, etc.
fn parse_tee_evidence(quote: &SampleTeeEvidence) -> Result<TeeEvidenceParsedClaim> {
    let parsed_eventlog: Option<Value> = if let Some(el) = &quote.cc_eventlog {
        let ccel_data = base64::engine::general_purpose::STANDARD
            .decode(el)
            .context("Decode sample CC Eventlog when parsing claims")?;
        let ccel = CcEventLog::try_from(ccel_data)
            .map_err(|e| anyhow!("Parse CC Eventlog failed when parsing claims: {:?}", e))?;
        serde_json::to_value(ccel)
            .map(Some)
            .context("Serialize parsed CC Eventlog for claims")?
    } else {
        None
    };

    let mut claims = serde_json::Map::new();
    claims.insert("svn".to_string(), json!(quote.svn));
    claims.insert("report_data".to_string(), json!(quote.report_data));
    claims.insert(
        "measure_register".to_string(),
        json!(quote.measure_register),
    );
    claims.insert(
        "cc_eventlog".to_string(),
        parsed_eventlog.unwrap_or(Value::Null),
    );

    Ok(Value::Object(claims) as TeeEvidenceParsedClaim)
}
