use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use log::debug;
use reqwest::header::{ACCEPT, AUTHORIZATION, WWW_AUTHENTICATE};
use reqwest::{Client, Response, StatusCode};
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Clone, Debug, Deserialize)]
pub struct ProvenanceSource {
    pub protocol: String,
    pub uri: String,
    #[serde(default)]
    pub artifact: Option<String>,
}

pub struct FetchedProvenanceMaterial {
    pub media_type: Option<String>,
    pub raw_bytes: Vec<u8>,
}

#[async_trait]
pub trait ProvenanceFetcher: Send + Sync {
    async fn fetch(&self, source: &ProvenanceSource) -> Result<FetchedProvenanceMaterial>;
}

pub struct OciProvenanceFetcher {
    http: Client,
}

impl OciProvenanceFetcher {
    pub fn new() -> Self {
        Self {
            http: Client::new(),
        }
    }
}

#[derive(Clone, Debug)]
struct OciReference {
    scheme: String,
    registry: String,
    repository: String,
    reference: String,
}

#[derive(Debug, Deserialize)]
struct OciManifest {
    #[serde(rename = "mediaType")]
    media_type: Option<String>,
    layers: Option<Vec<OciDescriptor>>,
    manifests: Option<Vec<OciDescriptor>>,
}

#[derive(Clone, Debug, Deserialize)]
struct OciDescriptor {
    #[serde(rename = "mediaType")]
    media_type: Option<String>,
    digest: String,
}

#[derive(Debug, Deserialize)]
struct BearerTokenResponse {
    token: Option<String>,
    access_token: Option<String>,
}

#[async_trait]
impl ProvenanceFetcher for OciProvenanceFetcher {
    async fn fetch(&self, source: &ProvenanceSource) -> Result<FetchedProvenanceMaterial> {
        let reference = parse_oci_reference(&source.uri)?;
        let manifest_url = format!(
            "{}://{}/v2/{}/manifests/{}",
            reference.scheme, reference.registry, reference.repository, reference.reference
        );

        let mut auth_header = None;
        let manifest_resp = self
            .get_with_bearer_retry(
                &manifest_url,
                Some(
                    "application/vnd.oci.image.manifest.v1+json,application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.v2+json",
                ),
                &mut auth_header,
            )
            .await
            .context("fetch OCI manifest")?;

        let manifest_text = manifest_resp
            .text()
            .await
            .context("read OCI manifest body")?;
        let manifest: OciManifest =
            serde_json::from_str(&manifest_text).context("parse OCI manifest JSON")?;
        debug!("OCI manifest media type: {:?}", manifest.media_type);

        let descriptor = select_provenance_descriptor(&manifest, source.artifact.as_deref())
            .with_context(|| {
                format!(
                    "select provenance descriptor from OCI manifest {}",
                    source.uri
                )
            })?;

        let blob_url = format!(
            "{}://{}/v2/{}/blobs/{}",
            reference.scheme, reference.registry, reference.repository, descriptor.digest
        );
        let blob_resp = self
            .get_with_bearer_retry(&blob_url, None, &mut auth_header)
            .await
            .context("fetch OCI blob")?;

        let blob_media_type = blob_resp
            .headers()
            .get("Content-Type")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_string())
            .or(descriptor.media_type.clone());
        let raw_bytes = blob_resp
            .bytes()
            .await
            .context("read OCI blob bytes")?
            .to_vec();

        Ok(FetchedProvenanceMaterial {
            media_type: blob_media_type,
            raw_bytes,
        })
    }
}

impl OciProvenanceFetcher {
    async fn get_with_bearer_retry(
        &self,
        url: &str,
        accept: Option<&str>,
        auth_header: &mut Option<String>,
    ) -> Result<Response> {
        let mut req = self.http.get(url);
        if let Some(accept_val) = accept {
            req = req.header(ACCEPT, accept_val);
        }
        if let Some(header_val) = auth_header.as_ref() {
            req = req.header(AUTHORIZATION, header_val);
        }
        let resp = req.send().await.with_context(|| format!("GET {url}"))?;

        if resp.status() != StatusCode::UNAUTHORIZED {
            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                bail!("request {url} failed with {status}: {text}");
            }
            return Ok(resp);
        }

        let challenge = resp
            .headers()
            .get(WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| anyhow!("OCI registry requires auth but WWW-Authenticate missing"))?;
        let token = self
            .fetch_bearer_token(challenge)
            .await
            .context("fetch OCI bearer token")?;
        let auth_value = format!("Bearer {token}");
        *auth_header = Some(auth_value.clone());

        let mut retry_req = self.http.get(url);
        if let Some(accept_val) = accept {
            retry_req = retry_req.header(ACCEPT, accept_val);
        }
        let retry_resp = retry_req
            .header(AUTHORIZATION, auth_value)
            .send()
            .await
            .with_context(|| format!("retry GET {url}"))?;
        if !retry_resp.status().is_success() {
            let status = retry_resp.status();
            let text = retry_resp.text().await.unwrap_or_default();
            bail!("request {url} failed after auth with {status}: {text}");
        }
        Ok(retry_resp)
    }

    async fn fetch_bearer_token(&self, challenge: &str) -> Result<String> {
        let params = parse_www_authenticate_bearer(challenge)?;
        let realm = params
            .get("realm")
            .cloned()
            .ok_or_else(|| anyhow!("bearer challenge missing realm"))?;

        let mut req = self.http.get(&realm);
        let mut query = Vec::new();
        if let Some(service) = params.get("service") {
            query.push(("service".to_string(), service.to_string()));
        }
        if let Some(scope) = params.get("scope") {
            query.push(("scope".to_string(), scope.to_string()));
        }
        if !query.is_empty() {
            req = req.query(&query);
        }

        let resp = req
            .send()
            .await
            .with_context(|| format!("GET bearer realm {realm}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            bail!("bearer token request failed with {status}: {text}");
        }

        let body: BearerTokenResponse = resp.json().await.context("parse bearer token JSON")?;
        body.token
            .or(body.access_token)
            .ok_or_else(|| anyhow!("token endpoint response missing token/access_token"))
    }
}

fn parse_oci_reference(uri: &str) -> Result<OciReference> {
    let without_scheme = uri
        .strip_prefix("oci://")
        .ok_or_else(|| anyhow!("unsupported OCI URI `{uri}`; expected prefix oci://"))?;
    let (host_and_repo, reference) = split_reference(without_scheme)?;
    let mut parts = host_and_repo.splitn(2, '/');
    let registry = parts
        .next()
        .ok_or_else(|| anyhow!("invalid OCI URI `{uri}`"))?
        .to_string();
    let repository = parts
        .next()
        .ok_or_else(|| anyhow!("invalid OCI URI `{uri}`: repository missing"))?
        .to_string();

    if registry.is_empty() || repository.is_empty() || reference.is_empty() {
        bail!("invalid OCI URI `{uri}`");
    }

    Ok(OciReference {
        scheme: infer_registry_scheme(&registry),
        registry,
        repository,
        reference,
    })
}

fn infer_registry_scheme(registry: &str) -> String {
    if registry.starts_with("127.0.0.1")
        || registry.starts_with("localhost")
        || std::env::var("TRUSTEE_OCI_INSECURE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    {
        "http".to_string()
    } else {
        "https".to_string()
    }
}

fn split_reference(path: &str) -> Result<(String, String)> {
    if let Some((left, digest)) = path.rsplit_once('@') {
        return Ok((left.to_string(), digest.to_string()));
    }

    let slash = path
        .rfind('/')
        .ok_or_else(|| anyhow!("invalid OCI reference `{path}`"))?;
    let suffix = &path[slash + 1..];
    if let Some(colon_pos) = suffix.rfind(':') {
        let left = format!("{}{}", &path[..slash + 1], &suffix[..colon_pos]);
        let tag = &suffix[colon_pos + 1..];
        return Ok((left, tag.to_string()));
    }

    Ok((path.to_string(), "latest".to_string()))
}

fn select_provenance_descriptor(
    manifest: &OciManifest,
    preferred_artifact: Option<&str>,
) -> Result<OciDescriptor> {
    let mut candidates = Vec::new();
    if let Some(layers) = &manifest.layers {
        candidates.extend(layers.clone());
    }
    if let Some(manifests) = &manifest.manifests {
        candidates.extend(manifests.clone());
    }
    if candidates.is_empty() {
        bail!("OCI manifest has no layers/manifests");
    }

    let want_bundle = preferred_artifact
        .map(|v| v.eq_ignore_ascii_case("bundle"))
        .unwrap_or(true);
    let want_provenance = preferred_artifact
        .map(|v| v.eq_ignore_ascii_case("provenance"))
        .unwrap_or(false);

    for c in &candidates {
        if let Some(mt) = &c.media_type {
            let lower = mt.to_ascii_lowercase();
            if want_bundle
                && (lower.contains("in-toto.bundle")
                    || lower.contains("dev.sigstore.bundle")
                    || lower.contains("jsonl"))
            {
                return Ok(c.clone());
            }
            if want_provenance
                && (lower.contains("in-toto")
                    || lower.contains("dsse.envelope")
                    || lower.contains("provenance"))
            {
                return Ok(c.clone());
            }
        }
    }

    for c in &candidates {
        if let Some(mt) = &c.media_type {
            let lower = mt.to_ascii_lowercase();
            if lower.contains("in-toto") || lower.contains("dsse.envelope") {
                return Ok(c.clone());
            }
        }
    }

    Ok(candidates[0].clone())
}

fn parse_www_authenticate_bearer(header: &str) -> Result<HashMap<String, String>> {
    let lower = header.to_ascii_lowercase();
    if !lower.starts_with("bearer ") {
        bail!("unsupported auth challenge `{header}`");
    }

    let kv = &header[7..];
    let mut map = HashMap::new();
    for part in kv.split(',') {
        let trimmed = part.trim();
        let Some((k, v)) = trimmed.split_once('=') else {
            continue;
        };
        map.insert(k.trim().to_string(), v.trim().trim_matches('"').to_string());
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_oci_reference_tag() {
        let r = parse_oci_reference("oci://registry.io/ns/repo:1.0.0").unwrap();
        assert_eq!(r.registry, "registry.io");
        assert_eq!(r.repository, "ns/repo");
        assert_eq!(r.reference, "1.0.0");
    }

    #[test]
    fn test_parse_oci_reference_digest() {
        let r = parse_oci_reference("oci://registry.io/ns/repo@sha256:abcd").unwrap();
        assert_eq!(r.reference, "sha256:abcd");
    }

    #[test]
    fn test_parse_www_authenticate() {
        let m = parse_www_authenticate_bearer(
            r#"Bearer realm="https://auth.example/token",service="registry.example",scope="repository:ns/repo:pull""#,
        )
        .unwrap();
        assert_eq!(m.get("realm").unwrap(), "https://auth.example/token");
        assert_eq!(m.get("service").unwrap(), "registry.example");
    }
}
