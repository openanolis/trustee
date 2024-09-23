use log::info;
extern crate serde;
use self::serde::{Deserialize, Serialize};
use super::*;
use async_trait::async_trait;
use base64::Engine;
use serde_json::json;
use sha2::{Digest, Sha384};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug)]
struct SystemEvidence {
    system_report: String,
    measurements: String,
    mr_register: String,
    report_data: String,
}

#[derive(Clone, Deserialize, Serialize, Default, Debug, PartialEq)]
pub struct MeasurementEntry {
    pub name: String,
    pub algorithm: String,
    pub digest: String,
}

#[derive(Debug, Default)]
pub struct SystemVerifier {}

#[async_trait]
impl Verifier for SystemVerifier {
    async fn evaluate(
        &self,
        evidence: &[u8],
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<TeeEvidenceParsedClaim> {
        let evidence = serde_json::from_slice::<SystemEvidence>(evidence)
            .context("Deserialize Quote failed.")?;

        verify_evidence(expected_report_data, expected_init_data_hash, &evidence)
            .await
            .context("Evidence's identity verification error.")?;

        info!(
            "Target System Evidence: {}",
            serde_json::to_string_pretty(&evidence)?
        );

        parse_evidence(&evidence)
    }
}

async fn verify_evidence(
    expected_report_data: &ReportData<'_>,
    _expected_init_data_hash: &InitDataHash<'_>,
    evidence: &SystemEvidence,
) -> Result<()> {
    // Verify the measurements with MR Register.
    let measurements: Vec<MeasurementEntry> = serde_json::from_str(&evidence.measurements)?;
    let mut tmp_mr = Vec::new();
    for entry in measurements.iter() {
        let mut hasher = Sha384::new();
        hasher.update(&tmp_mr);
        let digest = hex::decode(&entry.digest)?;
        hasher.update(&digest);
        tmp_mr = hasher.finalize().to_vec();
    }
    let rebuild_mr_register = hex::encode(&tmp_mr);
    if rebuild_mr_register != evidence.mr_register {
        bail!("Rebuilded MR Register is different from that in System Evidence");
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
    let mut claims_map = json!({});

    let mut measurements_map = HashMap::new();
    let measurements: Vec<MeasurementEntry> = serde_json::from_str(&quote.measurements)?;
    for entry in measurements.iter() {
        measurements_map.insert(entry.name.clone(), entry.digest.clone());
    }

    let system_report: serde_json::Value = serde_json::from_str(&quote.system_report)?;

    claims_map = json!({
        "system_report": system_report,
        "measurements": measurements_map,
        "mr_register": quote.mr_register,
        "report_data": quote.report_data,
    });

    Ok(claims_map as TeeEvidenceParsedClaim)
}
