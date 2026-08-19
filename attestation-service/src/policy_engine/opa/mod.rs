// Copyright (c) 2026 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#[cfg(any(feature = "policy-rvps", feature = "policy-artifact-server"))]
use anyhow::{anyhow, bail};
use anyhow::{Context, Result};
use log::debug;
#[cfg(feature = "policy-rvps")]
use log::warn;
use regorus::Extension;
use sha2::Digest;
use std::collections::HashMap;
use std::sync::Arc;
#[cfg(feature = "policy-rvps")]
use std::time::Duration;

use crate::rvps::ReferenceValueResolver;

use super::{EvaluationResult, PolicyError};

#[cfg(feature = "fs")]
mod fs;
mod in_memory;

#[cfg(feature = "fs")]
pub use fs::OPA;
pub use in_memory::OPAInMemory;

#[cfg(all(feature = "policy-rvps", not(test)))]
const REFERENCE_QUERY_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(all(feature = "policy-rvps", test))]
const REFERENCE_QUERY_TIMEOUT: Duration = Duration::from_millis(100);

#[allow(dead_code)]
fn is_valid_policy_id(policy_id: &str) -> bool {
    policy_id
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
}

fn policy_uses_legacy_reference(policy: &str) -> Result<bool, PolicyError> {
    use regorus::unstable::{Lexer, Source, TokenKind};

    let source = Source::from_contents("policy.rego".to_string(), policy.to_string())
        .map_err(PolicyError::LoadPolicyFailed)?;
    let mut lexer = Lexer::new(&source);
    let mut tokens = Vec::new();

    loop {
        let token = lexer.next_token().map_err(PolicyError::LoadPolicyFailed)?;
        if token.0 == TokenKind::Eof {
            break;
        }
        tokens.push((token.0, token.1.text().to_string()));
    }

    let dotted = tokens.windows(3).any(|tokens| {
        tokens[0].0 == TokenKind::Ident
            && tokens[0].1 == "data"
            && tokens[1].0 == TokenKind::Symbol
            && tokens[1].1 == "."
            && tokens[2].0 == TokenKind::Ident
            && tokens[2].1 == "reference"
    });
    let indexed = tokens.windows(4).any(|tokens| {
        tokens[0].0 == TokenKind::Ident
            && tokens[0].1 == "data"
            && tokens[1].0 == TokenKind::Symbol
            && tokens[1].1 == "["
            && matches!(tokens[2].0, TokenKind::String | TokenKind::RawString)
            && tokens[2].1 == "reference"
            && tokens[3].0 == TokenKind::Symbol
            && tokens[3].1 == "]"
    });

    Ok(dotted || indexed)
}

#[cfg(feature = "policy-rvps")]
fn query_reference_value_extension(
    reference_value_resolver: Arc<ReferenceValueResolver>,
    runtime_handle: tokio::runtime::Handle,
) -> Box<dyn Extension> {
    Box::new(move |params: Vec<regorus::Value>| {
        if params.len() != 1 {
            bail!("query_reference_value requires exactly one parameter");
        }
        let reference_value_id = params[0]
            .as_string()
            .context("query_reference_value parameter must be a string")?
            .to_string();
        debug!("query reference value from RVPS: {reference_value_id}");

        let value = runtime_handle
            .block_on(async {
                tokio::time::timeout(
                    REFERENCE_QUERY_TIMEOUT,
                    reference_value_resolver.query_reference_value(&reference_value_id),
                )
                .await
                .map_err(|_| {
                    anyhow!(
                        "query_reference_value({reference_value_id:?}) timed out after {REFERENCE_QUERY_TIMEOUT:?}"
                    )
                })?
            })
            .map_err(|e| anyhow!("query_reference_value({reference_value_id:?}) failed: {e}"))?;

        match value {
            Some(value) => Ok(regorus::Value::from(value)),
            None => {
                warn!("No reference value found for id {reference_value_id:?}; returning null");
                Ok(regorus::Value::Null)
            }
        }
    })
}

#[cfg(feature = "policy-artifact-server")]
fn query_artifact_server_extension(
    client: Arc<artifact_resolve_sdk::Client>,
    runtime_handle: tokio::runtime::Handle,
) -> Box<dyn Extension> {
    Box::new(move |params: Vec<regorus::Value>| {
        use artifact_resolve_sdk::{Measurement, ReleaseManifest};

        if params.len() != 1 {
            bail!("query_artifact_server requires exactly one parameter");
        }
        let slices = params[0]
            .as_object()
            .context("query_artifact_server parameter must be an object")?;

        debug!("query artifact value from artifact server: {slices:?}");

        let measurements = slices
            .iter()
            .map(|(key, value)| -> Result<Measurement> {
                let key = key.as_string().context("key is not a string")?.to_string();
                let value = value
                    .as_string()
                    .context("value is not a string")?
                    .to_string();
                Ok(Measurement::text(key, value))
            })
            .collect::<Result<Vec<Measurement>>>()?;
        let resolve_request =
            artifact_resolve_sdk::ResolveRequest::new(ReleaseManifest::new(measurements));
        match runtime_handle.block_on(client.resolve(&resolve_request)) {
            Ok(resp) => {
                if resp.status != "resolved" {
                    bail!(
                        "query_artifact_server returned unexpected status {:?}",
                        resp.status
                    );
                }
                Ok(regorus::Value::Bool(true))
            }
            Err(err) if err.is_measurement_not_found() || err.is_measurement_revoked() => {
                debug!("query_artifact_server denied: {err}");
                Ok(regorus::Value::Bool(false))
            }
            Err(err) => Err(anyhow!("query_artifact_server failed: {err}")),
        }
    })
}

async fn common_evaluate(
    policy: String,
    input: String,
    policy_id: String,
    evaluation_rules: Vec<String>,
    reference_value_resolver: Arc<ReferenceValueResolver>,
    #[cfg(feature = "policy-artifact-server")] artifact_server_client: Arc<
        artifact_resolve_sdk::Client,
    >,
) -> Result<EvaluationResult, PolicyError> {
    let data = if policy_uses_legacy_reference(&policy)? {
        let reference_values = reference_value_resolver
            .get_reference_values()
            .await
            .map_err(|e| PolicyError::LoadReferenceDataFailed(e.into()))?;
        serde_json::json!({ "reference": reference_values }).to_string()
    } else {
        "{}".to_string()
    };

    #[cfg(any(feature = "policy-rvps", feature = "policy-artifact-server"))]
    let mut query_extensions = vec![];

    #[cfg(feature = "policy-rvps")]
    {
        let runtime_handle = tokio::runtime::Handle::current();
        query_extensions.push((
            "query_reference_value".to_string(),
            query_reference_value_extension(reference_value_resolver, runtime_handle),
        ));
    }

    #[cfg(feature = "policy-artifact-server")]
    {
        let runtime_handle = tokio::runtime::Handle::current();
        query_extensions.push((
            "query_artifact_server".to_string(),
            query_artifact_server_extension(artifact_server_client, runtime_handle),
        ));
    }

    #[cfg(any(feature = "policy-rvps", feature = "policy-artifact-server"))]
    {
        tokio::task::spawn_blocking(move || {
            evaluate_sync(
                policy,
                input,
                policy_id,
                evaluation_rules,
                data,
                query_extensions,
            )
        })
        .await
        .map_err(|e| {
            PolicyError::EvalPolicyFailed(anyhow!("Regorus blocking evaluation task failed: {e}"))
        })?
    }

    #[cfg(not(any(feature = "policy-rvps", feature = "policy-artifact-server")))]
    {
        evaluate_sync(policy, input, policy_id, evaluation_rules, data, vec![])
    }
}

fn evaluate_sync(
    policy: String,
    input: String,
    policy_id: String,
    evaluation_rules: Vec<String>,
    data: String,
    query_extensions: Vec<(String, Box<dyn Extension>)>,
) -> Result<EvaluationResult, PolicyError> {
    let mut engine = regorus::Engine::new();
    // regorus 0.11 defaults to rego.v1; keep accepting legacy `allow { ... }`
    // (rego.v0) policies that were saved before the rego.v1 migration.
    // `import rego.v1` policies still work under this mode.
    engine.set_rego_v0(true);

    let policy_hash = {
        let mut hasher = sha2::Sha384::new();
        hasher.update(&policy);
        hex::encode(hasher.finalize())
    };

    engine
        .add_policy(policy_id.clone(), policy)
        .map_err(PolicyError::LoadPolicyFailed)?;

    let data =
        regorus::Value::from_json_str(&data).map_err(PolicyError::JsonSerializationFailed)?;
    engine
        .add_data(data)
        .map_err(PolicyError::LoadReferenceDataFailed)?;

    engine
        .set_input_json(&input)
        .context("set input")
        .map_err(PolicyError::SetInputDataFailed)?;

    for (name, query_extension) in query_extensions {
        engine
            .add_extension(name, 1, query_extension)
            .map_err(PolicyError::EvalPolicyFailed)?;
    }

    let mut rules_result = HashMap::new();
    for rule in evaluation_rules {
        let whole_rule = format!("data.policy.{rule}");
        let claim_value = match engine.eval_rule(whole_rule) {
            Ok(value) => value,
            Err(error) if error.to_string().contains("not a valid rule path") => {
                debug!("Policy `{policy_id}` does not check {rule}");
                continue;
            }
            Err(error) => return Err(PolicyError::EvalPolicyFailed(error)),
        };

        let claim_value = claim_value
            .to_json_str()
            .map_err(PolicyError::JsonSerializationFailed)?;
        let claim_value =
            serde_json::from_str(&claim_value).map_err(PolicyError::SerdeJsonError)?;
        rules_result.insert(rule, claim_value);
    }

    Ok(EvaluationResult {
        rules_result,
        policy_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "policy-artifact-server")]
    use crate::policy_engine::PolicyEngine;
    #[cfg(feature = "policy-artifact-server")]
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread::JoinHandle,
        time::Duration,
    };

    #[test]
    fn detects_legacy_reference_without_comment_or_string_false_positives() {
        assert!(policy_uses_legacy_reference(
            "package policy\nallow { input.svn in data.reference.svn }"
        )
        .unwrap());
        assert!(policy_uses_legacy_reference(
            "package policy\nallow { input.svn in data[\"reference\"].svn }"
        )
        .unwrap());
        assert!(!policy_uses_legacy_reference(
            r#"package policy
               # data.reference.comment_only
               message := "data.reference.string_only"
               allow := true"#
        )
        .unwrap());
    }

    #[cfg(feature = "policy-artifact-server")]
    fn mock_artifact_server(
        status: u16,
        response_body: serde_json::Value,
    ) -> (String, JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();

            let mut request = Vec::new();
            loop {
                let mut buffer = [0; 4096];
                let bytes_read = stream.read(&mut buffer).unwrap();
                if bytes_read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..bytes_read]);

                if let Some(header_end) =
                    request.windows(4).position(|window| window == b"\r\n\r\n")
                {
                    let headers = String::from_utf8_lossy(&request[..header_end]);
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or_default();
                    if request.len() >= header_end + 4 + content_length {
                        break;
                    }
                }
            }

            let reason = match status {
                200 => "OK",
                404 => "Not Found",
                409 => "Conflict",
                500 => "Internal Server Error",
                _ => "Unknown",
            };
            let response_body = response_body.to_string();
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_body}",
                response_body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            request
        });

        (format!("http://{address}"), server)
    }

    #[cfg(feature = "policy-artifact-server")]
    async fn call_artifact_server_extension(base_url: String) -> Result<bool> {
        let http_client = reqwest::Client::builder().no_proxy().build()?;
        let client = Arc::new(
            artifact_resolve_sdk::Client::builder()
                .base_url(base_url)
                .http_client(http_client)
                .build()?,
        );
        let runtime_handle = tokio::runtime::Handle::current();

        tokio::task::spawn_blocking(move || {
            let mut extension = query_artifact_server_extension(client, runtime_handle);
            let argument = regorus::Value::from_json_str(r#"{"tdx.td-shim":"582f8ed2"}"#)?;
            let result = extension(vec![argument])?;
            Ok(*result
                .as_bool()
                .context("query_artifact_server result must be a boolean")?)
        })
        .await
        .context("query_artifact_server blocking task failed")?
    }

    #[cfg(feature = "policy-artifact-server")]
    fn request_json(request: &[u8]) -> serde_json::Value {
        let body_start = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap()
            + 4;
        serde_json::from_slice(&request[body_start..]).unwrap()
    }

    #[cfg(feature = "policy-artifact-server")]
    #[tokio::test(flavor = "multi_thread")]
    async fn artifact_server_policy_sends_text_measurement_and_returns_true() {
        let (base_url, server) = mock_artifact_server(
            200,
            serde_json::json!({
                "status": "resolved",
                "release_manifest": {
                    "schemaVersion": "1.0.0",
                    "measurements": [{
                        "type": "tdx.td-shim",
                        "value": "582f8ed2"
                    }]
                },
                "log_entries": []
            }),
        );

        let policy = r#"package policy
default allow = false
allow = query_artifact_server({"tdx.td-shim": "582f8ed2"})
"#;
        let engine =
            OPAInMemory::with_raw_default_policy(policy, "artifact.rego", &base_url).unwrap();
        let result = engine
            .evaluate(
                "{}",
                "artifact",
                vec!["allow".to_string()],
                crate::rvps::test_resolver(HashMap::new()),
            )
            .await
            .unwrap();
        assert!(result.rules_result.get("allow").unwrap().as_bool().unwrap());

        let request = server.join().unwrap();
        assert_eq!(
            request_json(&request),
            serde_json::json!({
                "release_manifest": {
                    "schemaVersion": "1.0.0",
                    "measurements": [{
                        "type": "tdx.td-shim",
                        "value": "582f8ed2"
                    }]
                }
            })
        );
    }

    #[cfg(feature = "policy-artifact-server")]
    #[tokio::test(flavor = "multi_thread")]
    async fn artifact_server_missing_or_revoked_measurement_returns_false() {
        for (status, error_code) in [(404, "measurement_not_found"), (409, "measurement_revoked")] {
            let (base_url, server) = mock_artifact_server(
                status,
                serde_json::json!({
                    "error_code": error_code,
                    "error_message": "measurement denied"
                }),
            );

            assert!(!call_artifact_server_extension(base_url).await.unwrap());
            server.join().unwrap();
        }
    }

    #[cfg(feature = "policy-artifact-server")]
    #[tokio::test(flavor = "multi_thread")]
    async fn artifact_server_infrastructure_error_is_propagated() {
        let (base_url, server) = mock_artifact_server(
            500,
            serde_json::json!({
                "error_code": "internal_error",
                "error_message": "server unavailable"
            }),
        );

        let error = call_artifact_server_extension(base_url)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("query_artifact_server failed"));
        assert!(error.contains("internal_error"));
        server.join().unwrap();
    }

    // regorus 0.11 defaults to rego.v1 (`Engine::new()` -> rego_v1 = true),
    // which rejects legacy `allow { ... }` (rego.v0) policies. The production
    // engine creation sites call `engine.set_rego_v0(true)` to keep those
    // pre-migration policies working. The four tests below pin the
    // compatibility behaviour of that mode for each policy shape.

    // Pins the full parse/eval matrix across both engine modes so that a
    // default-mode or v0-mode behavioural shift is caught. The v0-mode
    // columns are also asserted individually by the `rego_v0_mode_*` tests.
    #[test]
    fn rego_v0_v1_parse_compat_matrix() {
        let new_no_import = "package policy\nallow if { true }";
        let new_with_import = "package policy\nimport rego.v1\nallow if { true }";
        let old_no_import = "package policy\nallow { true }";
        let old_with_import = "package policy\nimport rego.v1\nallow { true }";

        let eval_allow = |policy: &str, v0_mode: bool| {
            let mut engine = regorus::Engine::new();
            if v0_mode {
                engine.set_rego_v0(true);
            }
            engine.add_policy("p.rego".to_string(), policy.to_string())?;
            let results = engine.eval_query("data.policy.allow".to_string(), false)?;
            Ok::<_, anyhow::Error>(
                results
                    .result
                    .first()
                    .and_then(|r| r.expressions.first())
                    .and_then(|e| e.value.as_bool().ok().copied())
                    == Some(true),
            )
        };

        // Default (rego.v1) engine: new dialect works with or without the import.
        assert!(eval_allow(new_no_import, false).unwrap());
        assert!(eval_allow(new_with_import, false).unwrap());
        // Legacy `allow { ... }` policies break under the default engine.
        assert!(eval_allow(old_no_import, false).is_err());
        assert!(eval_allow(old_with_import, false).is_err());

        // `set_rego_v0(true)` restores backward compatibility: legacy policies
        // parse again, and the new dialect still works (with or without import).
        assert!(eval_allow(old_no_import, true).unwrap());
        assert!(eval_allow(new_no_import, true).unwrap());
        assert!(eval_allow(new_with_import, true).unwrap());
        // Legacy body shape + `import rego.v1` stays invalid in either mode.
        assert!(eval_allow(old_with_import, true).is_err());
    }

    fn eval_allow_v0_mode(policy: &str) -> Result<bool, anyhow::Error> {
        let mut engine = regorus::Engine::new();
        engine.set_rego_v0(true);
        engine.add_policy("p.rego".to_string(), policy.to_string())?;
        let results = engine.eval_query("data.policy.allow".to_string(), false)?;
        Ok(results
            .result
            .first()
            .and_then(|r| r.expressions.first())
            .and_then(|e| e.value.as_bool().ok().copied())
            == Some(true))
    }

    #[test]
    fn rego_v0_mode_accepts_new_format_without_import() {
        // rego.v1 syntax (`allow if { ... }`) but without `import rego.v1`.
        // Accepted: the `if` keyword is recognised even in rego.v0 mode.
        let policy = "package policy\nallow if { true }";
        assert!(eval_allow_v0_mode(policy).unwrap());
    }

    #[test]
    fn rego_v0_mode_accepts_new_format_with_import() {
        // rego.v1 syntax with an explicit `import rego.v1`.
        let policy = "package policy\nimport rego.v1\nallow if { true }";
        assert!(eval_allow_v0_mode(policy).unwrap());
    }

    #[test]
    fn rego_v0_mode_accepts_legacy_format_without_import() {
        // Legacy rego.v0 `allow { ... }` body (no `if`). This is the
        // backward-compatibility case the v1 default would have broken.
        let policy = "package policy\nallow { true }";
        assert!(eval_allow_v0_mode(policy).unwrap());
    }

    #[test]
    fn rego_v0_mode_rejects_legacy_body_with_v1_import() {
        // Legacy `allow { ... }` body shape combined with `import rego.v1`
        // is self-contradictory: the import turns on rego.v1 for the module,
        // which then requires `if`. This stays a parse error in either mode.
        let policy = "package policy\nimport rego.v1\nallow { true }";
        assert!(eval_allow_v0_mode(policy).is_err());
    }
}
