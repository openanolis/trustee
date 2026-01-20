// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod client;
pub mod config;
pub mod extractors;
pub mod pre_processor;
pub mod reference_value;
pub mod rvps_api;
pub mod server;
pub mod storage;

pub use config::Config;
pub use reference_value::{ReferenceValue, TrustedDigest};
pub use storage::ReferenceValueStorage;

use extractors::Extractors;
use pre_processor::{PreProcessor, PreProcessorAPI};

use anyhow::{bail, Context, Result};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Default version of Message
static MESSAGE_VERSION: &str = "0.1.0";

/// Message is an overall packet that Reference Value Provider Service
/// receives. It will contain payload (content of different provenance,
/// JSON format), provenance type (indicates the type of the payload)
/// and a version number (use to distinguish different version of
/// message, for extendability).
/// * `version`: version of this message.
/// * `payload`: content of the provenance, JSON encoded.
/// * `type`: provenance type of the payload.
#[derive(Serialize, Deserialize, Debug)]
pub struct Message {
    #[serde(default = "default_version")]
    version: String,
    payload: String,
    r#type: String,
}

/// Set the default version for Message
fn default_version() -> String {
    MESSAGE_VERSION.into()
}

/// The core of the RVPS, s.t. componants except communication componants.
pub struct Rvps {
    pre_processor: PreProcessor,
    extractors: Extractors,
    storage: Box<dyn ReferenceValueStorage + Send + Sync>,
}

fn merge_reference_values(old: ReferenceValue, new: ReferenceValue) -> ReferenceValue {
    // Keep the same name (should be identical). Prefer newer version string if differs.
    let mut merged = old.clone();
    merged.version = new.version;
    merged.name = new.name;

    // Expiration: keep the later one (more permissive, avoids accidentally expiring).
    merged.expiration = std::cmp::max(old.expiration, new.expiration);

    // Hashes: union (dedupe).
    for hv in new.hash_value.into_iter() {
        if !merged.hash_value.contains(&hv) {
            merged.hash_value.push(hv);
        }
    }

    // Audit proof: keep the newer one if present, otherwise preserve the old one.
    merged.audit_proof = new.audit_proof.or(old.audit_proof);

    merged
}

fn hash_set(rv: &ReferenceValue) -> HashSet<(String, String)> {
    rv.hash_value
        .iter()
        .map(|h| (h.alg().clone(), h.value().clone()))
        .collect()
}

impl Rvps {
    /// Instantiate a new RVPS
    pub fn new(config: Config) -> Result<Self> {
        let pre_processor = PreProcessor::default();
        let extractors = Extractors::default();
        let storage = config.storage.to_storage()?;

        Ok(Rvps {
            pre_processor,
            extractors,
            storage,
        })
    }

    /// Add Ware to the Core's Pre-Processor
    pub fn with_ware(&mut self, _ware: &str) -> &Self {
        // TODO: no wares implemented now.
        self
    }

    pub async fn verify_and_extract(&mut self, message: &str) -> Result<()> {
        let mut message: Message = serde_json::from_str(message).context("parse message")?;

        // Judge the version field
        if message.version != MESSAGE_VERSION {
            bail!(
                "Version unmatched! Need {}, given {}.",
                MESSAGE_VERSION,
                message.version
            );
        }

        self.pre_processor.process(&mut message)?;

        let rv = self.extractors.process(message)?;
        for v in rv.iter() {
            let name = v.name().to_string();
            if let Some(old) = self.storage.get(&name).await? {
                // Requirement: if hashes are identical, skip and do not replace.
                if hash_set(&old) == hash_set(v) {
                    info!(
                        "Reference value of {} unchanged (same hashes); skip update.",
                        name
                    );
                    continue;
                }

                let merged = merge_reference_values(old.clone(), v.clone());
                let _ = self.storage.set(name, merged).await?;
                info!(
                    "Reference value of {} is extended (hash list merged) instead of replaced.",
                    old.name()
                );
            } else {
                let _ = self.storage.set(name, v.clone()).await?;
                info!("Reference value of {} is added.", v.name());
            }
        }

        Ok(())
    }

    pub async fn get_digests(&self) -> Result<HashMap<String, Vec<String>>> {
        let mut rv_map = HashMap::new();
        let reference_values = self.storage.get_values().await?;

        for rv in reference_values {
            if rv.expired() {
                warn!("Reference value of {} is expired.", rv.name());
                continue;
            }

            let hash_values = rv
                .hash_values()
                .iter()
                .map(|pair| pair.value().to_owned())
                .collect();

            rv_map.insert(rv.name().to_string(), hash_values);
        }
        Ok(rv_map)
    }

    pub async fn delete_reference_value(&mut self, name: &str) -> Result<bool> {
        match self.storage.delete(name).await? {
            Some(deleted_rv) => {
                info!(
                    "Reference value {} deleted successfully.",
                    deleted_rv.name()
                );
                Ok(true)
            }
            None => {
                warn!("Reference value {} not found for deletion.", name);
                Ok(false)
            }
        }
    }
}
