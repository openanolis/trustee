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
use serde_json::Value;

use crate::{
    reference_value::{HashValuePair, REFERENCE_VALUE_VERSION},
    ReferenceValue,
};

use super::Extractor;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provenance {
    #[serde(flatten)]
    pub rvs: HashMap<String, Value>,
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
            .filter_map(|(name, policy_value)| {
                let time = Utc::now()
                    .with_nanosecond(0)
                    .and_then(|t| t.checked_add_months(Months::new(MONTHS_BEFORE_EXPIRATION)));

                match time {
                    Some(expiration) => {
                        let legacy_hashes = policy_value.as_array().and_then(|values| {
                            values
                                .iter()
                                .map(|value| value.as_str())
                                .collect::<Option<Vec<_>>>()
                        });

                        let (hash_value, value) = match legacy_hashes {
                            Some(values) => (
                                values
                                    .into_iter()
                                    .map(|value| {
                                        HashValuePair::new(DEFAULT_ALG.into(), value.to_string())
                                    })
                                    .collect(),
                                None,
                            ),
                            None => (Vec::new(), Some(policy_value.clone())),
                        };

                        Some(ReferenceValue {
                            version: REFERENCE_VALUE_VERSION.into(),
                            name: name.to_string(),
                            expiration,
                            hash_value,
                            value,
                            audit_proof: None,
                        })
                    }
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
