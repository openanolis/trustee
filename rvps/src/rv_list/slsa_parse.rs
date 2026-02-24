use anyhow::{bail, Context, Result};
use base64::Engine;
use serde_json::Value;
use std::collections::HashSet;

pub fn extract_slsa_digests(provenance: &str) -> Result<Vec<(String, String)>> {
    let payload_json: Value = serde_json::from_str(provenance).or_else(|_| {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(provenance)
            .context("decode base64 provenance payload")?;
        serde_json::from_slice(&decoded).context("deserialize provenance payload")
    })?;

    let predicate_type = payload_json
        .get("predicateType")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if !predicate_type.to_lowercase().contains("slsa") {
        bail!("intoto predicateType `{predicate_type}` is not SLSA");
    }

    let mut digests = HashSet::new();
    for key in ["subject", "subjects"] {
        if let Some(arr) = payload_json.get(key).and_then(|v| v.as_array()) {
            for subject in arr {
                if let Some(obj) = subject.get("digest").and_then(|v| v.as_object()) {
                    for (alg, val) in obj {
                        if let Some(s) = val.as_str() {
                            digests.insert((alg.to_string(), s.to_string()));
                        }
                    }
                }
            }
        }
    }

    if digests.is_empty() {
        bail!("no digest entries found in SLSA provenance");
    }

    Ok(digests.into_iter().collect())
}
