// Copyright (c) 2026 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use log::debug;
use regorus::languages::rego::compiler::Compiler;
use regorus::rvm::vm::{ExecutionMode, ExecutionState, SuspendReason};
use regorus::{PolicyModule, Rc};
use sha2::Digest;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
#[cfg(all(
    feature = "policy-rvps",
    not(all(
        target_arch = "wasm32",
        target_vendor = "unknown",
        target_os = "unknown"
    ))
))]
use std::time::Duration;

use crate::rvps::ReferenceValueResolver;

use super::{EvaluationResult, PolicyError};

#[cfg(feature = "fs")]
mod fs;
mod in_memory;

#[cfg(feature = "fs")]
pub use fs::OPA;
pub use in_memory::OPAInMemory;

#[cfg(all(
    feature = "policy-rvps",
    not(test),
    not(all(
        target_arch = "wasm32",
        target_vendor = "unknown",
        target_os = "unknown"
    ))
))]
const REFERENCE_QUERY_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(all(
    feature = "policy-rvps",
    test,
    not(all(
        target_arch = "wasm32",
        target_vendor = "unknown",
        target_os = "unknown"
    ))
))]
const REFERENCE_QUERY_TIMEOUT: Duration = Duration::from_millis(100);

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

// On wasm32 the RVPS resolver returns `?Send` futures (single-threaded async,
// matching `RvpsApi`'s `async_trait(?Send)` cfg), so the host-await closure and
// its future drop the `Send` bound. Everywhere else `Send` is required because
// RegoVM runs on a multi-threaded tokio runtime.
#[cfg(all(
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
))]
type RegoVmHostAwaitFunction = Box<
    dyn Fn(
        regorus::Value,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<regorus::Value, PolicyError>>>>,
>;

#[cfg(not(all(
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
)))]
type RegoVmHostAwaitFunction = Box<
    dyn Fn(
            /* argument */ regorus::Value,
        )
            -> Pin<Box<dyn std::future::Future<Output = Result<regorus::Value, PolicyError>> + Send>>
        + Send
        + Sync,
>;

#[cfg(feature = "policy-rvps")]
fn query_reference_value_extension(
    reference_value_resolver: Arc<ReferenceValueResolver>,
) -> RegoVmHostAwaitFunction {
    Box::new(move |argument| {
        let reference_value_resolver = reference_value_resolver.clone();
        Box::pin(async move {
            let key = argument
                .as_string()
                .map_err(|e| {
                    PolicyError::EvalPolicyFailed(anyhow!(
                        "query_reference_value arg not a string: {e}"
                    ))
                })?
                .to_string();
            let fut = reference_value_resolver.query_reference_value(&key);
            let value = {
                #[cfg(not(all(
                    target_arch = "wasm32",
                    target_vendor = "unknown",
                    target_os = "unknown"
                )))]
                {
                    let timeout = REFERENCE_QUERY_TIMEOUT;
                    tokio::time::timeout(timeout, fut).await.map_err(|_| {
                        PolicyError::EvalPolicyFailed(anyhow!(
                            "query_reference_value({key:?}) timed out after {timeout:?}"
                        ))
                    })?
                }
                #[cfg(all(
                    target_arch = "wasm32",
                    target_vendor = "unknown",
                    target_os = "unknown"
                ))]
                {
                    // tokio::time::timeout in WASM is not supported
                    fut.await
                }
            }
            .map_err(|e| {
                PolicyError::EvalPolicyFailed(anyhow!("query_reference_value({key:?}) failed: {e}"))
            })?;
            Ok(match value {
                Some(v) => regorus::Value::from(v),
                None => regorus::Value::Null,
            })
        })
    })
}

#[cfg(feature = "policy-artifact-server")]
fn query_artifact_server_extension(
    artifact_server_client: Arc<artifact_resolve_sdk::Client>,
) -> RegoVmHostAwaitFunction {
    Box::new(move |argument| {
        let artifact_server_client = artifact_server_client.clone();
        Box::pin(async move {
            use artifact_resolve_sdk::{Measurement, ReleaseManifest};
            let slices = argument.as_object().map_err(|e| {
                PolicyError::EvalPolicyFailed(anyhow!(
                    "query_artifact_server argument must be an object: {e}"
                ))
            })?;

            debug!("query artifact value from artifact server: {slices:?}");

            let measurements = slices
                .iter()
                .map(|(key, value)| -> Result<Measurement> {
                    use anyhow::Context as _;

                    let key = key.as_string().context("key is not a string")?.to_string();
                    let value = value
                        .as_string()
                        .context("value is not a string")?
                        .to_string();
                    Ok(Measurement::text(key, value))
                })
                .collect::<Result<Vec<Measurement>>>()
                .map_err(PolicyError::EvalPolicyFailed)?;
            let resolve_request =
                artifact_resolve_sdk::ResolveRequest::new(ReleaseManifest::new(measurements));
            match artifact_server_client.resolve(&resolve_request).await {
                Ok(resp) => {
                    if resp.status != "resolved" {
                        Err(PolicyError::EvalPolicyFailed(anyhow!(
                            "query_artifact_server returned unexpected status {:?}",
                            resp.status
                        )))
                    } else {
                        Ok(regorus::Value::Bool(true))
                    }
                }
                Err(err) if err.is_measurement_not_found() || err.is_measurement_revoked() => {
                    debug!("query_artifact_server denied: {err}");
                    Ok(regorus::Value::Bool(false))
                }
                Err(err) => Err(PolicyError::EvalPolicyFailed(anyhow!(
                    "query_artifact_server failed: {err}"
                ))),
            }
        })
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
    // Legacy policies read reference values from data.reference; fetch them via
    // the resolver. All other policies get an empty data document.
    let data = if policy_uses_legacy_reference(&policy)? {
        let reference_values = reference_value_resolver
            .get_reference_values()
            .await
            .map_err(|e| PolicyError::LoadReferenceDataFailed(e.into()))?;
        serde_json::json!({ "reference": reference_values }).to_string()
    } else {
        "{}".to_string()
    };

    #[allow(unused_mut)]
    let mut regovm_host_await_functions = HashMap::<String, RegoVmHostAwaitFunction>::default();

    #[cfg(feature = "policy-rvps")]
    {
        regovm_host_await_functions.insert(
            "query_reference_value".to_string(),
            query_reference_value_extension(reference_value_resolver),
        );
    }

    #[cfg(feature = "policy-artifact-server")]
    {
        regovm_host_await_functions.insert(
            "query_artifact_server".to_string(),
            query_artifact_server_extension(artifact_server_client),
        );
    }

    evaluate_with_regovm(
        policy,
        input,
        policy_id,
        evaluation_rules,
        data,
        regovm_host_await_functions,
    )
    .await
}

async fn evaluate_with_regovm(
    policy: String,
    input: String,
    policy_id: String,
    evaluation_rules: Vec<String>,
    data: String,
    regovm_host_await_functions: HashMap<String, RegoVmHostAwaitFunction>,
) -> Result<EvaluationResult, PolicyError> {
    let policy_hash = {
        let mut hasher = sha2::Sha384::new();
        hasher.update(&policy);
        hex::encode(hasher.finalize())
    };

    // Append the host-await wrapper. regorus 0.11 requires `if` in rule bodies
    // regardless of dialect, so existing policies already use `if`; the wrapper's
    // fixed `:= v if { }` form composes with all of them.
    let full_policy = format!(
        "{policy}\n\n{}",
        build_extensions(&regovm_host_await_functions)
    );

    let data_value =
        regorus::Value::from_json_str(&data).map_err(PolicyError::JsonSerializationFailed)?;
    let input_value =
        regorus::Value::from_json_str(&input).map_err(PolicyError::SetInputDataFailed)?;

    let mut rules_result = std::collections::HashMap::new();
    for rule in &evaluation_rules {
        // regorus rejects a bare rule name with "not a valid rule path"; use the full data.policy path.
        let entry_point = format!("data.policy.{rule}");
        let cp = {
            let module = PolicyModule {
                id: Rc::from(policy_id.as_str()),
                content: Rc::from(full_policy.as_str()),
            };
            // compile_policy_with_entrypoint takes data as the compile-time data document.
            match regorus::compile_policy_with_entrypoint(
                data_value.clone(),
                &[module],
                Rc::from(entry_point.clone()),
            ) {
                Ok(cp) => cp,
                Err(e) if e.to_string().contains("not a valid rule path") => {
                    debug!("Policy `{policy_id}` does not check {rule}");
                    continue;
                }
                Err(e) => return Err(PolicyError::LoadPolicyFailed(e)),
            }
        };

        // Lower the CompiledPolicy to a Program, then load it onto a fresh VM.
        // RegoVM::new_with_policy stores the policy but never loads a program, so
        // execute() returns Undefined — do not use it.
        let program = Compiler::compile_from_policy(&cp, &[entry_point.as_str()])
            .map_err(|e| PolicyError::LoadPolicyFailed(e.into()))?;
        let mut vm = regorus::rvm::RegoVM::new();
        vm.load_program(program);
        vm.set_data(data_value.clone())
            .map_err(|e| PolicyError::LoadReferenceDataFailed(e.into()))?;
        vm.set_input(input_value.clone());
        vm.set_execution_mode(ExecutionMode::Suspendable);

        let _ = vm
            .execute()
            .map_err(|e| PolicyError::EvalPolicyFailed(e.into()))?;
        let result_value = loop {
            match vm.execution_state().clone() {
                ExecutionState::Suspended {
                    reason:
                        SuspendReason::HostAwait {
                            argument,
                            identifier,
                            ..
                        },
                    ..
                } => {
                    let v = dispatch(identifier, argument, &regovm_host_await_functions).await?;
                    vm.resume(Some(v))
                        .map_err(|e| PolicyError::EvalPolicyFailed(e.into()))?;
                }
                ExecutionState::Completed { result } => break result,
                ExecutionState::Error { error } => {
                    return Err(PolicyError::EvalPolicyFailed(anyhow!(
                        "RegoVM error: {error}"
                    )))
                }
                other => {
                    return Err(PolicyError::EvalPolicyFailed(anyhow!(
                        "unexpected VM state: {other:?}"
                    )))
                }
            }
        };

        let claim_value = serde_json::from_str(
            &result_value
                .to_json_str()
                .map_err(PolicyError::JsonSerializationFailed)?,
        )
        .map_err(PolicyError::SerdeJsonError)?;
        rules_result.insert(rule.clone(), claim_value);
    }

    Ok(EvaluationResult {
        rules_result,
        policy_hash,
    })
}

/// Route a suspended VM's argument to the matching async resolver, keyed by identifier.
async fn dispatch(
    identifier: regorus::Value,
    argument: regorus::Value,
    regovm_host_await_functions: &HashMap<String, RegoVmHostAwaitFunction>,
) -> Result<regorus::Value, PolicyError> {
    let id = identifier.as_string().map_err(|e| {
        PolicyError::EvalPolicyFailed(anyhow!("host await identifier not a string: {e}"))
    })?;

    match regovm_host_await_functions.get(id.as_ref()) {
        Some(function) => function(argument).await,
        None => Err(PolicyError::EvalPolicyFailed(anyhow!(
            "unknown host await identifier: {id}"
        ))),
    }
}

/// Host-await wrapper appended to every policy source. Dynamically generates
/// a Rego function for each registered host-await extension, rewriting the
/// friendly builtin name onto the native `__builtin_host_await`, which
/// suspends the VM so the host can run async I/O and resume it. Uses `if` +
/// `:=` (regorus 0.11 mandates `if` in rule bodies) and no `import rego.v1`
/// (imports must follow `package`; the wrapper sits at the module end).
fn build_extensions(
    regovm_host_await_functions: &HashMap<String, RegoVmHostAwaitFunction>,
) -> String {
    let mut ext = String::from(r#"# === trustee EXTENSIONS (generated) ==="#);
    for key in regovm_host_await_functions.keys() {
        ext.push_str(&format!(
            r#"
{key}(arg) := v if {{ v := __builtin_host_await(arg, "{key}") }}
"#,
        ));
    }
    ext
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

    #[cfg(feature = "policy-rvps")]
    #[tokio::test]
    async fn dispatch_routes_reference_value_lookup_and_returns_null_when_missing() {
        use crate::rvps::test_resolver;
        let rvps = test_resolver(std::collections::HashMap::from([]));
        let mut functions = HashMap::<String, RegoVmHostAwaitFunction>::new();
        functions.insert(
            "query_reference_value".to_string(),
            query_reference_value_extension(rvps),
        );
        let id = regorus::Value::String(regorus::Rc::from("query_reference_value"));
        let arg = regorus::Value::String(regorus::Rc::from("missing-key"));
        let v = dispatch(id, arg, &functions).await.unwrap();
        assert!(matches!(v, regorus::Value::Null));
    }

    #[tokio::test]
    async fn dispatch_unknown_identifier_errors() {
        let functions = HashMap::<String, RegoVmHostAwaitFunction>::new();
        let id = regorus::Value::String(regorus::Rc::from("nope"));
        let arg = regorus::Value::Null;
        assert!(dispatch(id, arg, &functions).await.is_err());
    }

    #[tokio::test]
    async fn dispatch_passes_argument_to_registered_function() {
        let mut functions = HashMap::<String, RegoVmHostAwaitFunction>::new();
        functions.insert(
            "echo".to_string(),
            Box::new(|argument| Box::pin(async move { Ok::<_, PolicyError>(argument) })),
        );
        let id = regorus::Value::String(regorus::Rc::from("echo"));
        let arg = regorus::Value::String(regorus::Rc::from("payload"));
        let v = dispatch(id, arg, &functions).await.unwrap();
        match v {
            regorus::Value::String(s) => assert_eq!(s.as_ref(), "payload"),
            other => panic!("expected string, got {other:?}"),
        }
    }

    #[test]
    fn build_extensions_empty_returns_only_header() {
        let functions = HashMap::<String, RegoVmHostAwaitFunction>::new();
        assert_eq!(
            build_extensions(&functions),
            "# === trustee EXTENSIONS (generated) ==="
        );
    }

    #[test]
    fn build_extensions_generates_host_await_wrapper_per_registered_key() {
        let make = || -> RegoVmHostAwaitFunction {
            Box::new(|_a: regorus::Value| {
                Box::pin(async { Ok::<_, PolicyError>(regorus::Value::Null) })
            })
        };
        let mut functions = HashMap::<String, RegoVmHostAwaitFunction>::new();
        functions.insert("alpha".to_string(), make());
        functions.insert("beta".to_string(), make());
        let ext = build_extensions(&functions);
        assert!(
            ext.contains(r#"alpha(arg) := v if { v := __builtin_host_await(arg, "alpha") }"#),
            "{ext}"
        );
        assert!(
            ext.contains(r#"beta(arg) := v if { v := __builtin_host_await(arg, "beta") }"#),
            "{ext}"
        );
    }

    // Host-await closure that always returns a fixed value, ignoring its argument.
    fn fixed_value_extension(value: regorus::Value) -> RegoVmHostAwaitFunction {
        Box::new(move |_argument| {
            let value = value.clone();
            Box::pin(async move { Ok(value) })
        })
    }

    // Host-await closure mapping a string argument to a number ("a"->1, "b"->2),
    // else null. Used to verify the VM forwards the policy argument to the host.
    fn lookup_extension() -> RegoVmHostAwaitFunction {
        Box::new(move |argument| {
            Box::pin(async move {
                let key = argument.as_string().map_err(|e| {
                    PolicyError::EvalPolicyFailed(anyhow!("lookup arg not a string: {e}"))
                })?;
                Ok(match key.as_ref() {
                    "a" => regorus::Value::from(serde_json::json!(1)),
                    "b" => regorus::Value::from(serde_json::json!(2)),
                    _ => regorus::Value::Null,
                })
            })
        })
    }

    // Host-await closure that always fails, to exercise error propagation from a
    // suspended host call back up through evaluate_with_regovm.
    fn failing_extension() -> RegoVmHostAwaitFunction {
        Box::new(move |_argument| {
            Box::pin(async move {
                Err(PolicyError::EvalPolicyFailed(anyhow!(
                    "async function failed"
                )))
            })
        })
    }

    #[tokio::test]
    async fn evaluate_with_regovm_async_builtin_drives_rule_true() {
        // A policy calls a host-await builtin whose returned value satisfies the
        // rule body, so the rule evaluates to true. Exercises the full
        // compile -> suspend -> host resume -> complete loop.
        let mut functions = HashMap::new();
        functions.insert(
            "my_async".to_string(),
            fixed_value_extension(regorus::Value::String(regorus::Rc::from("ok"))),
        );
        let policy = r#"package policy
import rego.v1
allow if {
    my_async("anything") == "ok"
}
"#;
        let result = evaluate_with_regovm(
            policy.to_string(),
            "{}".to_string(),
            "test".to_string(),
            vec!["allow".to_string()],
            "{}".to_string(),
            functions,
        )
        .await
        .unwrap();
        assert_eq!(
            result.rules_result.get("allow"),
            Some(&serde_json::Value::Bool(true))
        );
    }

    #[tokio::test]
    async fn evaluate_with_regovm_async_builtin_receives_policy_argument() {
        // The policy calls the same builtin twice with different arguments and
        // requires both to match. If the VM did not forward the policy argument to
        // the host, the second lookup would not return 2 and allow would be false.
        let mut functions = HashMap::new();
        functions.insert("lookup".to_string(), lookup_extension());
        let policy = r#"package policy
import rego.v1
allow if {
    lookup("a") == 1
    lookup("b") == 2
}
"#;
        let result = evaluate_with_regovm(
            policy.to_string(),
            "{}".to_string(),
            "test".to_string(),
            vec!["allow".to_string()],
            "{}".to_string(),
            functions,
        )
        .await
        .unwrap();
        assert_eq!(
            result.rules_result.get("allow"),
            Some(&serde_json::Value::Bool(true))
        );
    }

    #[tokio::test]
    async fn evaluate_with_regovm_async_builtin_null_satisfies_rule() {
        // A builtin returning null (unknown key) is compared against null in the
        // rule body and satisfies it. Exercises the Null return path end-to-end.
        let mut functions = HashMap::new();
        functions.insert("maybe".to_string(), lookup_extension());
        let policy = r#"package policy
import rego.v1
default allow = false
allow if {
    maybe("unknown") == null
}
"#;
        let result = evaluate_with_regovm(
            policy.to_string(),
            "{}".to_string(),
            "test".to_string(),
            vec!["allow".to_string()],
            "{}".to_string(),
            functions,
        )
        .await
        .unwrap();
        assert_eq!(
            result.rules_result.get("allow"),
            Some(&serde_json::Value::Bool(true))
        );
    }

    #[tokio::test]
    async fn evaluate_with_regovm_propagates_async_builtin_error() {
        // A failing host-await call must surface as a PolicyError from
        // evaluate_with_regovm, not panic or be silently swallowed.
        let mut functions = HashMap::new();
        functions.insert("failing".to_string(), failing_extension());
        let policy = r#"package policy
import rego.v1
allow if {
    failing("x") == 1
}
"#;
        let err = evaluate_with_regovm(
            policy.to_string(),
            "{}".to_string(),
            "test".to_string(),
            vec!["allow".to_string()],
            "{}".to_string(),
            functions,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("async function failed"), "{err}");
    }
}
