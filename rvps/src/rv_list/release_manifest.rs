use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub const RV_RELEASE_PAYLOAD_TYPE: &str = "application/vnd.trustee.rv.release+json";

pub fn parse_release_manifest_documents_from_material(raw_bytes: &[u8]) -> Result<Vec<String>> {
    let text = std::str::from_utf8(raw_bytes).context("release manifest material is not UTF-8")?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        bail!("release manifest material is empty");
    }

    let value: Value =
        serde_json::from_str(trimmed).context("parse release manifest material as JSON")?;
    parse_release_manifest_documents_from_json(&value)
}

pub fn extract_release_manifest_digests(
    manifest: &str,
    expected_measurement: &str,
) -> Result<Vec<(String, String)>> {
    let payload_json: Value = serde_json::from_str(manifest).or_else(|_| {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(manifest)
            .context("decode base64 release manifest payload")?;
        serde_json::from_slice(&decoded).context("deserialize release manifest payload")
    })?;

    validate_release_manifest(&payload_json)?;
    let measurements = payload_json
        .get("measurements")
        .and_then(|v| v.as_object())
        .ok_or_else(|| anyhow!("release manifest missing measurements object"))?;

    let selected = measurements.get(expected_measurement).ok_or_else(|| {
        anyhow!("measurement `{expected_measurement}` not found in release manifest")
    })?;
    let algorithm = selected
        .get("algorithm")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("measurement `{expected_measurement}` missing algorithm"))?;
    let value = selected
        .get("value")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("measurement `{expected_measurement}` missing value"))?;

    validate_measurement(expected_measurement, algorithm, value)?;
    Ok(vec![(
        algorithm.to_ascii_lowercase(),
        value.to_ascii_lowercase(),
    )])
}

fn parse_release_manifest_documents_from_json(value: &Value) -> Result<Vec<String>> {
    verify_rekor_v1_consistency(value)?;
    verify_rekor_v2_consistency(value)?;

    if is_release_manifest(value) {
        return Ok(vec![value.to_string()]);
    }

    if let Some(release_payload) = value.get("releasePayload") {
        if is_release_manifest(release_payload) {
            return Ok(vec![release_payload.to_string()]);
        }
    }

    if let Some(manifest) = dsse_payload_release_manifest(value)? {
        return Ok(vec![manifest]);
    }

    let mut docs = Vec::new();
    for dsse in [
        value.get("dsseEnvelope"),
        value.pointer("/content/dsseEnvelope"),
        value.pointer("/sourceBundle/dsseEnvelope"),
        value.pointer("/sourceBundle/content/dsseEnvelope"),
    ]
    .into_iter()
    .flatten()
    {
        if let Some(manifest) = dsse_payload_release_manifest(dsse)? {
            docs.push(manifest);
        }
    }

    if let Some(arr) = value.as_array() {
        for item in arr {
            if is_release_manifest(item) {
                docs.push(item.to_string());
                continue;
            }
            if let Some(manifest) = dsse_payload_release_manifest(item)? {
                docs.push(manifest);
            }
        }
    }

    if docs.is_empty() {
        bail!("unsupported release manifest material JSON format");
    }

    Ok(unique_docs(docs))
}

fn dsse_payload_release_manifest(value: &Value) -> Result<Option<String>> {
    let payload = value.get("payload").and_then(|v| v.as_str());
    let payload_type = value.get("payloadType").and_then(|v| v.as_str());
    let signatures = value.get("signatures").and_then(|v| v.as_array());
    if payload.is_none() || payload_type.is_none() || signatures.is_none() {
        return Ok(None);
    }

    if payload_type.unwrap_or_default() != RV_RELEASE_PAYLOAD_TYPE {
        return Ok(None);
    }

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(payload.unwrap_or_default())
        .context("decode release manifest DSSE payload")?;
    let manifest = String::from_utf8(decoded).context("release manifest payload is not UTF-8")?;
    let manifest_json: Value =
        serde_json::from_str(&manifest).context("parse release manifest payload as JSON")?;
    validate_release_manifest(&manifest_json)?;

    Ok(Some(manifest))
}

fn validate_release_manifest(value: &Value) -> Result<()> {
    let schema_version = value
        .get("schemaVersion")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow!("release manifest missing schemaVersion"))?;
    if schema_version != 1 {
        bail!("unsupported release manifest schemaVersion `{schema_version}`");
    }

    let measurements = value
        .get("measurements")
        .and_then(|v| v.as_object())
        .ok_or_else(|| anyhow!("release manifest missing measurements object"))?;
    if measurements.is_empty() {
        bail!("release manifest measurements cannot be empty");
    }

    for (name, measurement) in measurements {
        let algorithm = measurement
            .get("algorithm")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("measurement `{name}` missing algorithm"))?;
        let digest = measurement
            .get("value")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("measurement `{name}` missing value"))?;
        validate_measurement(name, algorithm, digest)?;
    }

    Ok(())
}

fn validate_measurement(name: &str, algorithm: &str, value: &str) -> Result<()> {
    let algorithm = algorithm.to_ascii_lowercase();
    let expected_len = match algorithm.as_str() {
        "sha256" => 64,
        "sha384" => 96,
        other => bail!("measurement `{name}` uses unsupported algorithm `{other}`"),
    };

    if value.len() != expected_len || !value.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("measurement `{name}` value is not a valid {algorithm} lowercase hex digest");
    }
    if value.chars().any(|c| c.is_ascii_uppercase()) {
        bail!("measurement `{name}` value must be lowercase hex");
    }

    Ok(())
}

fn verify_rekor_v1_consistency(value: &Value) -> Result<()> {
    let dsse = value
        .get("dsseEnvelope")
        .or_else(|| value.pointer("/content/dsseEnvelope"))
        .or_else(|| value.pointer("/sourceBundle/dsseEnvelope"))
        .or_else(|| value.pointer("/sourceBundle/content/dsseEnvelope"));
    let rekor_entry = value
        .get("rekorEntryV1")
        .or_else(|| value.pointer("/verificationMaterial/tlogEntries/0"))
        .or_else(|| value.pointer("/sourceBundle/verificationMaterial/tlogEntries/0"));

    let (Some(dsse), Some(rekor_entry)) = (dsse, rekor_entry) else {
        return Ok(());
    };
    let payload_hash = payload_sha256_hex(dsse)?;

    let entry = unwrap_rekor_v1_entry(rekor_entry);
    let body_json = if let Some(body_b64) = entry.get("body").and_then(|v| v.as_str()) {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(body_b64)
            .context("decode Rekor v1 body")?;
        serde_json::from_slice::<Value>(&decoded).context("parse Rekor v1 body JSON")?
    } else {
        entry.clone()
    };

    let kind = body_json
        .get("kind")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if kind != "dsse" {
        bail!("Rekor v1 body kind `{kind}` is not dsse");
    }

    let rekor_payload_hash = body_json
        .pointer("/spec/payloadHash/value")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Rekor v1 dsse body missing payloadHash.value"))?;
    if rekor_payload_hash != payload_hash {
        bail!(
            "Rekor v1 payload hash mismatch: rekor=`{}`, payload_sha256=`{}`",
            rekor_payload_hash,
            payload_hash
        );
    }

    Ok(())
}

fn unwrap_rekor_v1_entry(value: &Value) -> &Value {
    if value.get("body").is_some() || value.get("kind").is_some() {
        return value;
    }
    value
        .as_object()
        .and_then(|obj| obj.values().next())
        .unwrap_or(value)
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

    let payload_sha256_b64 = payload_sha256_b64(dsse)?;
    let canonicalized_body_b64 = tlog_entry
        .get("canonicalizedBody")
        .or_else(|| tlog_entry.get("canonicalized_body"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Rekor v2 tlog entry missing canonicalizedBody"))?;
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
        .ok_or_else(|| anyhow!("Rekor v2 canonicalizedBody missing dsse payload digest"))?;

    if rekor_payload_digest != payload_sha256_b64 {
        bail!(
            "Rekor v2 digest mismatch: rekor=`{}`, payload_sha256_b64=`{}`",
            rekor_payload_digest,
            payload_sha256_b64
        );
    }

    Ok(())
}

fn payload_sha256_hex(dsse: &Value) -> Result<String> {
    let payload_b64 = dsse
        .get("payload")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("dsseEnvelope.payload missing"))?;
    let payload = base64::engine::general_purpose::STANDARD
        .decode(payload_b64)
        .context("decode dsseEnvelope.payload")?;
    Ok(format!("{:x}", Sha256::digest(payload)))
}

fn payload_sha256_b64(dsse: &Value) -> Result<String> {
    let payload_b64 = dsse
        .get("payload")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("dsseEnvelope.payload missing"))?;
    let payload = base64::engine::general_purpose::STANDARD
        .decode(payload_b64)
        .context("decode dsseEnvelope.payload")?;
    Ok(base64::engine::general_purpose::STANDARD.encode(Sha256::digest(payload)))
}

fn is_release_manifest(value: &Value) -> bool {
    value.get("schemaVersion").is_some() && value.get("measurements").is_some()
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
    fn parse_direct_release_manifest() {
        let manifest = r#"{"measurements":{"cvm_container_proxy":{"algorithm":"sha256","value":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},"schemaVersion":1}"#;
        let docs = parse_release_manifest_documents_from_material(manifest.as_bytes()).unwrap();
        assert_eq!(docs.len(), 1);
        let digests = extract_release_manifest_digests(&docs[0], "cvm_container_proxy").unwrap();
        assert_eq!(
            digests,
            vec![(
                "sha256".to_string(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()
            )]
        );
    }

    #[test]
    fn parse_dsse_release_manifest() {
        let manifest = r#"{"measurements":{"cvm_uki":{"algorithm":"sha384","value":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},"schemaVersion":1}"#;
        let payload = base64::engine::general_purpose::STANDARD.encode(manifest.as_bytes());
        let dsse = format!(
            r#"{{"payloadType":"{}","payload":"{payload}","signatures":[{{"sig":"abc"}}]}}"#,
            RV_RELEASE_PAYLOAD_TYPE
        );
        let docs = parse_release_manifest_documents_from_material(dsse.as_bytes()).unwrap();
        assert_eq!(docs.len(), 1);
        let digests = extract_release_manifest_digests(&docs[0], "cvm_uki").unwrap();
        assert_eq!(digests[0].0, "sha384");
    }

    #[test]
    fn parse_bundle_with_rekor_v1_uuid_map() {
        let manifest = r#"{"measurements":{"custom_name":{"algorithm":"sha256","value":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},"schemaVersion":1}"#;
        let payload = base64::engine::general_purpose::STANDARD.encode(manifest.as_bytes());
        let dsse = serde_json::json!({
            "payloadType": RV_RELEASE_PAYLOAD_TYPE,
            "payload": payload,
            "signatures": [{"sig": "abc"}]
        });
        let payload_sha = format!("{:x}", Sha256::digest(manifest.as_bytes()));
        let body = serde_json::json!({
            "kind": "dsse",
            "apiVersion": "0.0.1",
            "spec": {
                "payloadHash": {
                    "algorithm": "sha256",
                    "value": payload_sha
                }
            }
        });
        let body_b64 = base64::engine::general_purpose::STANDARD.encode(body.to_string());
        let bundle = serde_json::json!({
            "releasePayload": serde_json::from_str::<Value>(manifest).unwrap(),
            "dsseEnvelope": dsse,
            "rekorEntryV1": {
                "fake-uuid": {
                    "body": body_b64
                }
            }
        });

        let docs =
            parse_release_manifest_documents_from_material(bundle.to_string().as_bytes()).unwrap();
        let digests = extract_release_manifest_digests(&docs[0], "custom_name").unwrap();
        assert_eq!(
            digests[0].1,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
    }
}
