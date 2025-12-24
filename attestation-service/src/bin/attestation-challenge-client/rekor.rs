use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use log::{debug, warn};
use reqwest::Client;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub const DEFAULT_REKOR_URL: &str = "https://rekor.sigstore.dev";

pub struct RekorClient {
    base: String,
    http: Client,
}

impl RekorClient {
    pub fn new(base_url: &str) -> Result<Self> {
        let base = base_url.trim_end_matches('/').to_string();
        if !base.starts_with("http") {
            bail!("rekor url `{base}` is invalid; must start with http/https");
        }
        Ok(Self {
            base,
            http: Client::new(),
        })
    }

    pub async fn fetch_slsa_provenance(&self, artifact_name: &str) -> Result<Vec<String>> {
        let artifact_hash = sha256_hex(artifact_name);
        let uuids = self
            .search_by_hash(&artifact_hash)
            .await
            .with_context(|| format!("search Rekor index with hash {artifact_hash}"))?;

        if uuids.is_empty() {
            bail!("Rekor returned no entries for artifact `{artifact_name}`");
        }

        let bodies = self
            .retrieve_entries(&uuids)
            .await
            .context("retrieve Rekor entries by UUIDs")?;

        let mut slsa_docs = Vec::new();
        let mut seen = HashSet::new();
        let mut last_error: Option<anyhow::Error> = None;

        for entry in bodies {
            match extract_slsa_from_entry(&entry) {
                Ok(doc) => {
                    if seen.insert(doc.clone()) {
                        slsa_docs.push(doc);
                    }
                }
                Err(err) => {
                    warn!("skip Rekor entry: {err}");
                    last_error = Some(err);
                }
            }
        }

        if slsa_docs.is_empty() {
            if let Some(err) = last_error {
                bail!("no valid SLSA provenance found: {err}");
            }
            bail!("no valid SLSA provenance found");
        }

        Ok(slsa_docs)
    }

    async fn search_by_hash(&self, digest_hex: &str) -> Result<Vec<String>> {
        let url = format!("{}/api/v1/index/retrieve", self.base);
        let request_body = serde_json::json!({ "hash": format!("sha256:{digest_hex}") });

        let resp = self
            .http
            .post(url)
            .json(&request_body)
            .send()
            .await
            .context("send Rekor index search request")?;

        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            bail!("Rekor index query failed, HTTP {status}: {text}");
        }

        let parsed: Value = serde_json::from_str(&text).context("parse Rekor index response")?;
        parse_uuid_list(parsed)
    }

    async fn retrieve_entries(&self, uuids: &[String]) -> Result<Vec<Value>> {
        if uuids.is_empty() {
            return Ok(Vec::new());
        }

        debug!("Retrieving Rekor entries for uuids: {uuids:?}");

        let url = format!("{}/api/v1/log/entries/retrieve", self.base);
        let resp = self
            .http
            .post(url)
            // Rekor expects `entryUUIDs` in request body. Using the wrong field name (e.g. `uuids`)
            // may return `[]` with HTTP 200, which then fails parsing downstream.
            .json(&serde_json::json!({ "entryUUIDs": uuids }))
            .send()
            .await
            .context("send Rekor entries retrieve request")?;

        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            bail!("Rekor entries query failed, HTTP {status}: {text}");
        }

        debug!("Rekor entries response: {text}");

        let parsed: Value = serde_json::from_str(&text).context("parse Rekor entries response")?;
        // Rekor may return either:
        // - an object map: { "<uuid>": { ... }, ... }
        // - or an array of such objects: [ { "<uuid>": { ... } }, ... ]
        let entries_obj = if let Some(obj) = parsed.as_object() {
            obj.clone()
        } else if let Some(arr) = parsed.as_array() {
            let mut merged = serde_json::Map::new();
            for item in arr {
                let obj = item
                    .as_object()
                    .ok_or_else(|| anyhow!("unexpected Rekor entries response format"))?;
                for (k, v) in obj {
                    merged.insert(k.clone(), v.clone());
                }
            }
            merged
        } else {
            return Err(anyhow!("unexpected Rekor entries response format"));
        };

        let mut entries_out = Vec::new();
        for (_uuid, entry) in entries_obj {
            // Keep the full entry so we can parse either `attestation.data` or `body`.
            entries_out.push(entry);
        }

        Ok(entries_out)
    }
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    hex::encode(digest)
}

fn parse_uuid_list(value: Value) -> Result<Vec<String>> {
    if let Some(arr) = value.as_array() {
        return Ok(arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect());
    }

    if let Some(arr) = value.get("entries").and_then(|v| v.as_array()) {
        return Ok(arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect());
    }

    bail!("Failed to parse Rekor index response: {value}");
}

fn extract_slsa_from_entry(entry: &Value) -> Result<String> {
    // Newer Rekor responses may include the in-toto Statement directly in `attestation.data`.
    // This is base64(UTF-8 JSON). Prefer this path when present.
    if let Some(data_b64) = entry.pointer("/attestation/data").and_then(|v| v.as_str()) {
        let decoded = BASE64_STANDARD
            .decode(data_b64)
            .context("decode Rekor entry attestation.data")?;
        let payload_str =
            String::from_utf8(decoded).context("attestation.data is not valid UTF-8")?;
        let payload_json: Value =
            serde_json::from_str(&payload_str).context("parse attestation.data as json")?;
        validate_slsa_payload(&payload_json)?;
        return Ok(payload_str);
    }

    let body_b64 = entry
        .get("body")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Rekor entry missing body field"))?;

    let decoded = BASE64_STANDARD
        .decode(body_b64)
        .context("decode Rekor entry body")?;
    let body_json: Value = serde_json::from_slice(&decoded).context("parse Rekor entry body as json")?;

    let kind = body_json
        .get("kind")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_lowercase();
    if kind != "intoto" {
        bail!("Rekor entry kind `{kind}` is not intoto");
    }

    let payload_b64 = body_json
        .pointer("/spec/content/envelope/payload")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Rekor intoto entry missing DSSE payload"))?;

    let payload_bytes = BASE64_STANDARD
        .decode(payload_b64)
        .context("decode DSSE payload from Rekor entry")?;
    let payload_str =
        String::from_utf8(payload_bytes).context("intoto DSSE payload is not valid UTF-8")?;

    let payload_json: Value = serde_json::from_str(&payload_str).context("parse intoto payload as json")?;
    validate_slsa_payload(&payload_json)?;

    if let Some(statement_type) = payload_json.get("_type").and_then(|v| v.as_str()) {
        debug!("intoto statement type: {statement_type}");
    }

    Ok(payload_str)
}

fn validate_slsa_payload(payload_json: &Value) -> Result<()> {
    let predicate_type = payload_json
        .get("predicateType")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if !predicate_type.to_lowercase().contains("slsa") {
        bail!("intoto predicateType `{predicate_type}` is not SLSA");
    }
    Ok(())
}
