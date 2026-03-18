// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod client;
pub mod config;
pub mod extractors;
pub mod pre_processor;
mod provenance_source;
pub mod reference_value;
mod rekor;
mod rv_list;
pub mod rvps_api;
pub mod server;
pub mod storage;

pub use config::Config;
pub use reference_value::{ReferenceValue, TrustedDigest};
pub use storage::ReferenceValueStorage;

use extractors::Extractors;
use pre_processor::{PreProcessor, PreProcessorAPI};

use anyhow::{bail, Context, Result};
use base64::Engine;
use chrono::{Months, Timelike, Utc};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Digest;
use std::collections::{HashMap, HashSet};

use provenance_source::{OciProvenanceFetcher, ProvenanceFetcher, ProvenanceSource};
use rv_list::{extract_slsa_digests, parse_reference_value_list, ReferenceValueOperation};

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

    pub async fn set_reference_value_list(&mut self, payload: &str) -> Result<()> {
        let request = parse_reference_value_list(payload)?;

        for item in request.rv_list {
            let operation = ReferenceValueOperation::parse(&item.operation_type)?;

            if item.provenance_info.provenance_type != "slsa-intoto-statements" {
                bail!(
                    "unsupported provenance_info.type `{}`",
                    item.provenance_info.provenance_type
                );
            }

            if item.id.is_empty() || item.version.is_empty() || item.rv_type.is_empty() {
                bail!("rv_list item has empty id/version/type");
            }

            let name = match &item.rv_name {
                Some(n) => {
                    let n = n.trim();
                    if n.is_empty() {
                        bail!("rv_list item rv_name cannot be empty or whitespace-only");
                    }
                    n.to_string()
                }
                None => format!("measurement.{}.{}", item.rv_type, item.id),
            };

            let slsa_docs = if let Some(source) = &item.provenance_source {
                let protocol = source.protocol.to_ascii_lowercase();
                let material = match protocol.as_str() {
                    "oci" => {
                        let fetcher = OciProvenanceFetcher::new();
                        let src = ProvenanceSource {
                            protocol: source.protocol.clone(),
                            uri: source.uri.clone(),
                            artifact: source.artifact.clone(),
                        };
                        fetcher
                            .fetch(&src)
                            .await
                            .with_context(|| format!("fetch provenance from OCI `{}`", src.uri))?
                    }
                    other => bail!("unsupported provenance_source.protocol `{other}`"),
                };
                parse_slsa_documents_from_material(&material.raw_bytes).with_context(|| {
                    format!(
                        "parse fetched provenance material for `{}` (media type: {:?})",
                        item.id, material.media_type
                    )
                })?
            } else {
                let lookup = format!("{}{}", item.id, item.version);
                let rekor_client = rekor::RekorClient::new(&item.provenance_info.rekor_url)?;
                rekor_client
                    .fetch_slsa_provenance_for_lookup(&lookup)
                    .await
                    .with_context(|| format!("fetch SLSA provenance for {}", item.id))?
            };

            let mut digest_set = HashSet::new();
            for doc in &slsa_docs {
                let doc_digests = extract_slsa_digests(doc, &item.id)?;
                for digest in doc_digests {
                    digest_set.insert(digest);
                }
            }

            if digest_set.is_empty() {
                bail!("no digest entries found for {}", item.id);
            }

            let expiration = Utc::now()
                .with_nanosecond(0)
                .and_then(|t| t.checked_add_months(Months::new(12)))
                .ok_or_else(|| anyhow::anyhow!("failed to compute expiration time"))?;

            let mut rv = ReferenceValue::new()?
                .set_version(reference_value::REFERENCE_VALUE_VERSION)
                .set_name(&name)
                .set_expiration(expiration);

            for (alg, value) in digest_set.iter() {
                rv = rv.add_hash_value_with_meta(
                    alg.clone(),
                    value.clone(),
                    Some(item.version.clone()),
                    None,
                );
            }

            if let Some(old) = self.storage.get(&name).await? {
                if hash_set(&old) == hash_set(&rv) {
                    info!("Reference value of {} unchanged; skip update.", name);
                    continue;
                }

                match operation {
                    ReferenceValueOperation::Add => {
                        let merged = merge_reference_values(old.clone(), rv.clone());
                        let _ = self.storage.set(name.clone(), merged).await?;
                        info!("Reference value of {} extended (add).", name);
                    }
                    ReferenceValueOperation::Refresh => {
                        let _ = self.storage.set(name.clone(), rv.clone()).await?;
                        info!("Reference value of {} refreshed.", name);
                    }
                }
            } else {
                let _ = self.storage.set(name.clone(), rv.clone()).await?;
                info!("Reference value of {} is added.", name);
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

fn parse_slsa_documents_from_material(raw_bytes: &[u8]) -> Result<Vec<String>> {
    let text = std::str::from_utf8(raw_bytes).context("provenance material is not UTF-8 text")?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        bail!("provenance material is empty");
    }

    if let Ok(json) = serde_json::from_str::<Value>(trimmed) {
        return parse_slsa_documents_from_json(&json);
    }

    // in-toto bundle is JSONL; parse line by line as DSSE envelopes.
    let mut docs = Vec::new();
    for line in trimmed.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(line).context("parse JSONL line as JSON")?;
        if let Some(statement) = dsse_payload_statement(&value)? {
            docs.push(statement);
        }
    }

    if docs.is_empty() {
        bail!("no SLSA statement found in provenance material");
    }

    Ok(unique_docs(docs))
}

fn parse_slsa_documents_from_json(value: &Value) -> Result<Vec<String>> {
    verify_rekor_v2_consistency(value)?;

    // Direct in-toto statement JSON.
    if is_statement_json(value) {
        return Ok(vec![value.to_string()]);
    }

    // DSSE envelope object.
    if let Some(statement) = dsse_payload_statement(value)? {
        return Ok(vec![statement]);
    }

    // Sigstore bundle: prefer dsseEnvelope payload when available.
    let mut docs = Vec::new();
    if let Some(dsse) = value.get("dsseEnvelope") {
        if let Some(statement) = dsse_payload_statement(dsse)? {
            docs.push(statement);
        }
    }
    if let Some(dsse) = value.pointer("/content/dsseEnvelope") {
        if let Some(statement) = dsse_payload_statement(dsse)? {
            docs.push(statement);
        }
    }
    if let Some(dsse) = value.pointer("/sourceBundle/dsseEnvelope") {
        if let Some(statement) = dsse_payload_statement(dsse)? {
            docs.push(statement);
        }
    }
    if let Some(dsse) = value.pointer("/sourceBundle/content/dsseEnvelope") {
        if let Some(statement) = dsse_payload_statement(dsse)? {
            docs.push(statement);
        }
    }

    // Array of envelopes/statements.
    if let Some(arr) = value.as_array() {
        for item in arr {
            if is_statement_json(item) {
                docs.push(item.to_string());
                continue;
            }
            if let Some(statement) = dsse_payload_statement(item)? {
                docs.push(statement);
            }
        }
    }

    if docs.is_empty() {
        bail!("unsupported provenance material JSON format");
    }
    Ok(unique_docs(docs))
}

fn dsse_payload_statement(value: &Value) -> Result<Option<String>> {
    let payload = value.get("payload").and_then(|v| v.as_str());
    let payload_type = value.get("payloadType").and_then(|v| v.as_str());
    let signatures = value.get("signatures").and_then(|v| v.as_array());
    if payload.is_none() || payload_type.is_none() || signatures.is_none() {
        return Ok(None);
    }

    let payload_type = payload_type.unwrap_or_default().to_ascii_lowercase();
    if !payload_type.starts_with("application/vnd.in-toto") {
        return Ok(None);
    }

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(payload.unwrap_or_default())
        .context("decode DSSE payload")?;
    let statement = String::from_utf8(decoded).context("DSSE payload is not UTF-8")?;
    let statement_json: Value =
        serde_json::from_str(&statement).context("parse DSSE payload as JSON")?;
    if !is_statement_json(&statement_json) {
        bail!("DSSE payload is not an in-toto statement");
    }

    Ok(Some(statement))
}

fn verify_rekor_v2_consistency(value: &Value) -> Result<()> {
    let dsse = value
        .get("dsseEnvelope")
        .or_else(|| value.pointer("/content/dsseEnvelope"))
        .or_else(|| value.pointer("/sourceBundle/dsseEnvelope"))
        .or_else(|| value.pointer("/sourceBundle/content/dsseEnvelope"));
    let tlog_entry = value
        .get("rekorEntryV2")
        .or_else(|| value.pointer("/verificationMaterial/tlogEntries/0"))
        .or_else(|| value.pointer("/sourceBundle/verificationMaterial/tlogEntries/0"));

    let (Some(dsse), Some(tlog_entry)) = (dsse, tlog_entry) else {
        return Ok(());
    };

    let payload_b64 = dsse
        .get("payload")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("dsseEnvelope.payload missing for Rekor v2 verification"))?;
    let payload_bytes = base64::engine::general_purpose::STANDARD
        .decode(payload_b64)
        .context("decode dsseEnvelope.payload for Rekor v2 verification")?;
    let payload_sha256 = sha2::Sha256::digest(payload_bytes);
    let payload_sha256_b64 = base64::engine::general_purpose::STANDARD.encode(payload_sha256);

    let canonicalized_body_b64 = tlog_entry
        .get("canonicalizedBody")
        .or_else(|| tlog_entry.get("canonicalized_body"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Rekor v2 tlog entry missing canonicalizedBody"))?;
    let canonicalized_body = base64::engine::general_purpose::STANDARD
        .decode(canonicalized_body_b64)
        .context("decode Rekor v2 canonicalizedBody")?;
    let canonicalized_json: Value = serde_json::from_slice(&canonicalized_body)
        .context("parse Rekor v2 canonicalizedBody JSON")?;

    let kind = canonicalized_json
        .get("kind")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if kind != "dsse" {
        bail!("Rekor v2 canonicalizedBody kind `{kind}` is not dsse");
    }

    let rekor_payload_digest = canonicalized_json
        .pointer("/spec/dsseV002/data/digest")
        .or_else(|| canonicalized_json.pointer("/spec/dsseV002/payloadHash/digest"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Rekor v2 canonicalizedBody missing dsse payload digest"))?;

    if rekor_payload_digest != payload_sha256_b64 {
        bail!(
            "Rekor v2 digest mismatch: rekor=`{}`, payload_sha256_b64=`{}`",
            rekor_payload_digest,
            payload_sha256_b64
        );
    }

    Ok(())
}

fn is_statement_json(value: &Value) -> bool {
    value
        .get("predicateType")
        .and_then(|v| v.as_str())
        .is_some()
        && value.get("_type").and_then(|v| v.as_str()).is_some()
}

fn unique_docs(docs: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for doc in docs {
        if seen.insert(doc.clone()) {
            out.push(doc);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_direct_statement() {
        let statement = r#"{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://slsa.dev/provenance/v1","subject":[],"predicate":{}}"#;
        let docs = parse_slsa_documents_from_material(statement.as_bytes()).unwrap();
        assert_eq!(docs.len(), 1);
    }

    #[test]
    fn parse_dsse_envelope() {
        let statement = r#"{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://slsa.dev/provenance/v1","subject":[],"predicate":{}}"#;
        let payload = base64::engine::general_purpose::STANDARD.encode(statement.as_bytes());
        let dsse = format!(
            r#"{{"payloadType":"application/vnd.in-toto+json","payload":"{payload}","signatures":[{{"sig":"abc"}}]}}"#
        );
        let docs = parse_slsa_documents_from_material(dsse.as_bytes()).unwrap();
        assert_eq!(docs.len(), 1);
        assert!(docs[0].contains("predicateType"));
    }
}
