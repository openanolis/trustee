// Copyright (c) 2026 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#[cfg(any(feature = "policy-rvps", feature = "policy-artifact-server"))]
use anyhow::bail;
use anyhow::{anyhow, Context, Result};
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
                        "query_reference_value({reference_value_id:?}) timed out after {:?}",
                        REFERENCE_QUERY_TIMEOUT
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
}
