use crate::TeeEvidenceParsedClaim;
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha384};

mod opaque_data;
mod report;
mod rim;

use report::AttestationReport;
use rim::{parse_rim_content, RimInfo};

/// Evidence list
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuEvidenceList {
    /// List of GPU evidence
    pub evidence_list: Vec<GpuEvidence>,
    /// Collection time
    pub collection_time: chrono::DateTime<chrono::Utc>,
}

/// GPU attestation evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuEvidence {
    /// Device index
    pub index: u32,
    /// Device UUID
    pub uuid: String,
    /// Device name
    pub name: String,
    /// Driver version
    pub driver_version: String,
    /// VBIOS version
    pub vbios_version: String,
    /// Attestation report (Base64 encoded)
    pub attestation_report: Option<String>,
    /// Certificate (Base64 encoded)
    pub certificate: Option<String>,
    /// Confidential computing status
    pub cc_enabled: bool,
}

impl GpuEvidence {
    pub async fn evaluate(&self) -> Result<TeeEvidenceParsedClaim> {
        let mut claim = Map::new();
        claim.insert("uuid".to_string(), Value::String(self.uuid.clone()));
        claim.insert("name".to_string(), Value::String(self.name.clone()));
        claim.insert(
            "driver_version".to_string(),
            Value::String(self.driver_version.clone()),
        );
        claim.insert(
            "vbios_version".to_string(),
            Value::String(self.vbios_version.clone()),
        );
        claim.insert("cc_enabled".to_string(), Value::Bool(self.cc_enabled));

        if let Some(attestation_report) = self.attestation_report.as_ref() {
            let report = general_purpose::STANDARD.decode(attestation_report)?;
            let attestation_report = AttestationReport::parse(&report)?;
            let opaque_data = &attestation_report.opaque_data;

            let driver_version = self.driver_version.clone();
            let vbios_version = self.vbios_version.clone();
            let project = opaque_data.get_string_field("PROJECT")?;
            let project_sku = opaque_data.get_string_field("PROJECT_SKU")?;
            let chip_sku = opaque_data.get_string_field("CHIP_SKU")?;

            // Parallel fetching of Driver and VBIOS RIMs
            info!("Fetching Driver and VBIOS RIMs in parallel...");
            let (driver_rim_result, vbios_rim_result) = tokio::join!(
                rim::get_driver_rim(&driver_version),
                rim::get_vbios_rim(&project, &project_sku, &chip_sku, &vbios_version)
            );

            let driver_rim_content = driver_rim_result
                .map_err(|e| anyhow!("Cannot get Driver RIM from RIM service: {}", e))?;
            let vbios_rim_content = vbios_rim_result
                .map_err(|e| anyhow!("Cannot get VBIOS RIM from RIM service: {}", e))?;

            let driver_rim = parse_rim_content(&driver_rim_content, "driver")?;
            let vbios_rim = parse_rim_content(&vbios_rim_content, "vbios")?;

            verify_measurements(&attestation_report, &driver_rim, &vbios_rim)?;

            // Calculate SHA384 hash of all measurements combined
            let mut hasher = Sha384::new();
            for (_, measurement) in &attestation_report.measurements {
                hasher.update(hex::decode(measurement)?);
            }
            let hash_result = hasher.finalize();
            let hash_hex = hex::encode(hash_result);

            claim.insert("measurement".to_string(), Value::String(hash_hex));
        }

        if let Some(certificate) = self.certificate.as_ref() {
            claim.insert(
                "certificate".to_string(),
                Value::String(certificate.clone()),
            );
        }

        Ok(Value::Object(claim) as TeeEvidenceParsedClaim)
    }
}

fn verify_measurements(
    attestation_report: &AttestationReport,
    driver_rim: &RimInfo,
    vbios_rim: &RimInfo,
) -> Result<()> {
    let runtime_measurements = &attestation_report.measurements;

    info!("Runtime measurement count: {}", runtime_measurements.len());

    let mut matches = 0;
    let mut mismatches = 0;

    // Verify driver measurements
    for (index, measurement) in &driver_rim.measurements {
        if measurement.active {
            if let Some(runtime_value) = runtime_measurements.get(index) {
                let mut found_match = false;
                for golden_value in &measurement.values {
                    if runtime_value == golden_value {
                        found_match = true;
                        break;
                    }
                }

                if found_match {
                    matches += 1;
                    debug!("Measurement index {} matches (Driver)", index);
                } else {
                    mismatches += 1;
                    warn!("Measurement index {} does not match (Driver)", index);
                    warn!("   Runtime value: {}", runtime_value);
                    warn!("   Expected values: {:?}", measurement.values);
                }
            }
        }
    }

    // Verify vbios measurements
    for (index, measurement) in &vbios_rim.measurements {
        if measurement.active {
            if let Some(runtime_value) = runtime_measurements.get(index) {
                let mut found_match = false;
                for golden_value in &measurement.values {
                    if runtime_value == golden_value {
                        found_match = true;
                        break;
                    }
                }

                if found_match {
                    matches += 1;
                    debug!("Measurement index {} matches (VBIOS)", index);
                } else {
                    mismatches += 1;
                    warn!("Measurement index {} does not match (VBIOS)", index);
                    warn!("   Runtime value: {}", runtime_value);
                    warn!("   Expected values: {:?}", measurement.values);
                }
            }
        }
    }

    info!("Measurement verification result:");
    info!("   Matches: {}", matches);
    info!("   Mismatches: {}", mismatches);

    if mismatches > 0 {
        error!("Measurement mismatch found! Device may be tampered with or using unsupported software version.");
        return Err(anyhow!("Measurement verification failed"));
    } else {
        info!("All measurements verified successfully!");
    }

    Ok(())
}
