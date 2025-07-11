// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This is a very simple format of provenance

use std::collections::HashMap;

use anyhow::*;
use base64::Engine;
use chrono::{Months, Timelike, Utc};
use log::warn;
use serde::{Deserialize, Serialize};

use crate::{
    reference_value::{HashValuePair, REFERENCE_VALUE_VERSION},
    ReferenceValue,
};

use super::Extractor;

#[derive(Serialize, Deserialize)]
pub struct Provenance {
    #[serde(flatten)]
    rvs: HashMap<String, Vec<String>>,
}

#[derive(Default)]
pub struct SampleExtractor;

/// Default reference value hash algorithm
const DEFAULT_ALG: &str = "sha384";

/// The reference value will be expired in the default time (months)
const MONTHS_BEFORE_EXPIRATION: u32 = 12;

impl Extractor for SampleExtractor {
    fn verify_and_extract(&self, provenance_base64: &str) -> Result<Vec<ReferenceValue>> {
        let provenance = base64::engine::general_purpose::STANDARD
            .decode(provenance_base64)
            .context("base64 decode")?;
        let payload: Provenance =
            serde_json::from_slice(&provenance).context("deseralize sample provenance")?;

        let res = payload
            .rvs
            .iter()
            .filter_map(|(name, rvalues)| {
                let rvs = rvalues
                    .iter()
                    .map(|rv| HashValuePair::new(DEFAULT_ALG.into(), rv.to_string()))
                    .collect();

                let time = Utc::now()
                    .with_nanosecond(0)
                    .and_then(|t| t.checked_add_months(Months::new(MONTHS_BEFORE_EXPIRATION)));

                match time {
                    Some(expiration) => Some(ReferenceValue {
                        version: REFERENCE_VALUE_VERSION.into(),
                        name: name.to_string(),
                        expiration,
                        hash_value: rvs,
                    }),
                    None => {
                        warn!("Expired time calculated overflowed for reference value of {name}.");
                        None
                    }
                }
            })
            .collect();

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use serde_json::json;

    #[test]
    fn test_verify_and_extract_valid_input() {
        // Create a sample extractor
        let extractor = SampleExtractor::default();

        // Create valid payload
        let payload = json!({
            "artifact1": ["hash1", "hash2"],
            "artifact2": ["hash3"]
        });

        // Encode payload to base64
        let base64_payload = base64::engine::general_purpose::STANDARD.encode(payload.to_string());

        // Test extraction
        let result = extractor.verify_and_extract(&base64_payload);
        assert!(result.is_ok(), "Extraction should succeed with valid input");

        let reference_values = result.unwrap();
        assert_eq!(
            reference_values.len(),
            2,
            "Should extract two reference values"
        );

        // Verify first reference value
        let rv1 = reference_values
            .iter()
            .find(|rv| rv.name == "artifact1")
            .expect("Should have artifact1");
        assert_eq!(
            rv1.hash_value.len(),
            2,
            "artifact1 should have two hash values"
        );
        assert_eq!(
            rv1.hash_value[0].alg(),
            DEFAULT_ALG,
            "Algorithm should be sha384"
        );
        assert_eq!(
            rv1.hash_value[0].value(),
            "hash1",
            "First hash value should be hash1"
        );
        assert_eq!(
            rv1.hash_value[1].alg(),
            DEFAULT_ALG,
            "Algorithm should be sha384"
        );
        assert_eq!(
            rv1.hash_value[1].value(),
            "hash2",
            "Second hash value should be hash2"
        );

        // Verify second reference value
        let rv2 = reference_values
            .iter()
            .find(|rv| rv.name == "artifact2")
            .expect("Should have artifact2");
        assert_eq!(
            rv2.hash_value.len(),
            1,
            "artifact2 should have one hash value"
        );
        assert_eq!(
            rv2.hash_value[0].alg(),
            DEFAULT_ALG,
            "Algorithm should be sha384"
        );
        assert_eq!(
            rv2.hash_value[0].value(),
            "hash3",
            "Hash value should be hash3"
        );
    }

    #[test]
    fn test_verify_and_extract_invalid_base64() {
        // Create a sample extractor
        let extractor = SampleExtractor::default();

        // Test with invalid base64
        let result = extractor.verify_and_extract("invalid-base64");
        assert!(
            result.is_err(),
            "Extraction should fail with invalid base64"
        );
        assert!(
            result.unwrap_err().to_string().contains("base64 decode"),
            "Error message should mention base64 decode failure"
        );
    }

    #[test]
    fn test_verify_and_extract_invalid_json() {
        // Create a sample extractor
        let extractor = SampleExtractor::default();

        // Create invalid JSON payload
        let invalid_json = "not a valid json";

        // Encode payload to base64
        let base64_payload = base64::engine::general_purpose::STANDARD.encode(invalid_json);

        // Test extraction
        let result = extractor.verify_and_extract(&base64_payload);
        assert!(result.is_err(), "Extraction should fail with invalid JSON");
        assert!(
            result.unwrap_err().to_string().contains("deseralize"),
            "Error message should mention deserialization failure"
        );
    }

    #[test]
    fn test_verify_and_extract_empty_payload() {
        // Create a sample extractor
        let extractor = SampleExtractor::default();

        // Create empty payload
        let payload = json!({});

        // Encode payload to base64
        let base64_payload = base64::engine::general_purpose::STANDARD.encode(payload.to_string());

        // Test extraction
        let result = extractor.verify_and_extract(&base64_payload);
        assert!(
            result.is_ok(),
            "Extraction should succeed with empty payload"
        );

        let reference_values = result.unwrap();
        assert_eq!(
            reference_values.len(),
            0,
            "Should extract zero reference values"
        );
    }
}
