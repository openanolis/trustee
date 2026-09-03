// Copyright (c) 2026 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! OPA-style policy engine backed by [regorus].
//!
//! Exposes [`OPA`] (filesystem-backed) and [`OPAInMemory`] (fs-free) implementations of
//! [`PolicyEngine`](crate::policy_engine::PolicyEngine), the trait the attestation broker drives to
//! evaluate EAR appraisal rules against a `.rego` policy.
//!
//! # Execution backends
//!
//! Exactly one backend is selected by a mutually-exclusive Cargo feature, enforced by the
//! `compile_error!` guards below (enabling neither or both fails the build):
//!
//! - `regorus-interpreter` (default) — the stable path: a sync regorus [`Engine`](regorus::Engine)
//!   with host functions registered as regorus `Extension`s. Each extension call is an async
//!   [`ExtensionFunction`] closure adapted by `async_to_sync_extension` into a sync `Extension`
//!   that `block_on`s the closure's future on a `tokio::task::spawn_blocking` thread, so the
//!   `block_on` never nests the tokio runtime. Needs a multi-threaded runtime; unavailable on
//!   single-threaded wasm32 (its own `compile_error!`).
//! - `regorus-regovm` — the (still unstable) Regorus VM path: host functions are driven through
//!   the suspendable `__builtin_host_await` loop (`ExecutionMode::Suspendable`), which needs no
//!   tokio runtime and works on wasm32. Forwards regorus's `rvm` feature (the interpreter build
//!   compiles no `regorus::rvm` code).
//!
//! Both backends share the *same* async public type ([`ExtensionFunction`]), so a downstream crate
//! supplies one `Vec<(String, ExtensionFunction)>` regardless of the selected backend, and dotted
//! names resolve under either.
//!
//! # Performance (`regorus-regovm`)
//!
//! `evaluate_with_regovm` hoists `Engine` + policy/data load out of the per-rule loop and consults
//! a cross-evaluation program cache (the `ProgramCache` type, keyed by `policy_id` with the policy
//! content hash carried as a validation checksum) so a repeated appraisal of the same policy skips
//! parse/compile entirely, and a changed policy source invalidates just that entry instead of
//! accumulating stale versions. The cache plumbing is cfg-gated to `regorus-regovm`, so the
//! interpreter build carries no `regorus::rvm` types and no dead cache.

use anyhow::{anyhow, Result};
use log::debug;
#[cfg(feature = "regorus-regovm")]
use regorus::languages::rego::compiler::Compiler;
// The legacy interpreter backend exposes host functions through regorus's
// sync `Extension` trait; the RVM backend drives them through the suspendable
// host-call loop. Only the one compiled for the active backend is needed.
#[cfg(feature = "regorus-regovm")]
use regorus::rvm::vm::{ExecutionMode, ExecutionState, SuspendReason};
#[cfg(feature = "regorus-interpreter")]
use regorus::Extension;
#[cfg(feature = "regorus-regovm")]
use regorus::Rc;
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

// Exactly one policy execution backend must be enabled. The two are mutually
// exclusive and together exhaustive: `regorus-interpreter` is the stable legacy
// path (sync `Engine` + `Extension`s via `spawn_blocking`); `regorus-regovm`
// is the unstable Regorus VM suspendable host-call path. The public interface
// (`ExtensionFunction` / `with_extra_extension_functions`) is identical under
// either, so downstream code is unaffected by the choice.
#[cfg(all(feature = "regorus-regovm", feature = "regorus-interpreter"))]
compile_error!(
    "features `regorus-regovm` and `regorus-interpreter` are mutually exclusive; enable exactly one"
);
#[cfg(not(any(feature = "regorus-regovm", feature = "regorus-interpreter")))]
compile_error!("exactly one of `regorus-regovm` / `regorus-interpreter` must be enabled");
// The legacy interpreter backend relies on a multi-threaded tokio runtime
// (`Handle::current` + `spawn_blocking` + `block_on`) and cannot run on the
// single-threaded wasm32 target; there only `regorus-regovm` is available.
#[cfg(all(
    feature = "regorus-interpreter",
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
))]
compile_error!("`regorus-interpreter` backend is unavailable on wasm32; use `regorus-regovm`");

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

/// Rego reserved words a wrapper rule head may not use as a name segment.
/// Matches regorus's own keyword set (regular keywords `as`/`default`/`else`/
/// `import`/`package`/`not`/`some`/`with`, future keywords `contains`/`every`/
/// `if`/`in` which the wrapper module's `import rego.v1` activates, and the
/// literal tokens `true`/`false`/`null`). The wrapper module always enables
/// rego.v1, so these would fail to parse as a rule head — reject up front.
#[cfg(feature = "regorus-regovm")]
const REGO_KEYWORDS: &[&str] = &[
    "as", "default", "else", "import", "package", "not", "some", "with", "contains", "every", "if",
    "in", "true", "false", "null",
];

#[cfg(feature = "regorus-regovm")]
fn is_rego_keyword(segment: &str) -> bool {
    REGO_KEYWORDS.contains(&segment)
}

/// One segment of a Rego identifier, matching regorus's lexer `read_ident`
/// grammar: an ASCII letter or `_` followed by ASCII alphanumerics/`_`.
#[cfg(feature = "regorus-regovm")]
fn is_rego_ident_segment(segment: &str) -> bool {
    let mut chars = segment.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// A valid caller-supplied extension function name: a dotted path of Rego
/// identifiers.
///
/// Both backends accept exactly this shape: the regovm backend interpolates the
/// key into a ref-headed wrapper rule (`name(arg) := v if { ... }`) via
/// [`build_extensions`], and the interpreter backend registers it as a dotted
/// builtin path through `Engine::add_extension`. Anything outside this set is
/// rejected here — before any source interpolation — so a key carrying a
/// newline, comment, quote, brace, or operator (the `build_extensions` source-
/// injection vector) never reaches Rego. Dotted names are accepted because
/// regorus's rego.v1 parser admits a ref-headed function definition and both
/// backends resolve them (see `regovm_accepts_dotted_wrapper_function_name` and
/// `interpreter_accepts_dotted_extension_name`).
#[cfg(feature = "regorus-regovm")]
pub(crate) fn is_valid_rego_extension_name(name: &str) -> bool {
    if name.is_empty() || name.starts_with('.') || name.ends_with('.') || name.contains("..") {
        return false;
    }
    name.split('.')
        .all(|seg| !seg.is_empty() && is_rego_ident_segment(seg) && !is_rego_keyword(seg))
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

/// A host-supplied function callable from rego policy under either execution
/// backend. The caller provides `Vec<(String, ExtensionFunction)>` via
/// [`OPAInMemory::with_extra_extension_functions`](in_memory::OPAInMemory::with_extra_extension_functions);
/// each pair registers a rego function named after the key that policy can call
/// to perform work regorus does not ship built-in (e.g. an RVPS lookup, an
/// artifact-server resolve, or any downstream host function). The same async
/// closure type serves both backends:
/// - `regorus-regovm`: the VM suspends on `__builtin_host_await` and the host
///   resumes it with the closure's result;
/// - `regorus-interpreter`: the closure is wrapped in a sync regorus `Extension`
///   that `block_on`s it on a blocking thread.
// On wasm32 the RVPS resolver returns `?Send` futures (single-threaded async,
// matching `RvpsApi`'s `async_trait(?Send)` cfg), so the closure and its
// future drop the `Send` bound. Everywhere else `Send` is required because
// the multi-threaded tokio runtime (interpreter) or the VM (regovm) needs it.
#[cfg(all(
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
))]
pub type ExtensionFunction = Arc<
    dyn Fn(
            regorus::Value,
        )
            -> Pin<Box<dyn std::future::Future<Output = Result<regorus::Value, PolicyError>>>>
        + Send
        + Sync,
>;

#[cfg(not(all(
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
)))]
pub type ExtensionFunction = Arc<
    dyn Fn(
            /* argument */ regorus::Value,
        )
            -> Pin<Box<dyn std::future::Future<Output = Result<regorus::Value, PolicyError>> + Send>>
        + Send
        + Sync,
>;

/// Compiled RVM programs for one policy, keyed by rule name. Only rules the
/// policy actually defines are present (undefined rules are skipped at compile
/// time, preserving origin/main's `not a valid rule path` -> skip contract).
#[cfg(feature = "regorus-regovm")]
type RulePrograms = HashMap<String, Arc<regorus::rvm::Program>>;

/// One policy's cached compilation: the content hash it was compiled against
/// (a validation checksum — if the policy source changed, this entry is stale)
/// plus the per-rule compiled programs. Fields are private so only `mod.rs`
/// can construct or read an entry; the type is named only because it is the
/// value type of the `pub` `ProgramCache` alias.
#[cfg(feature = "regorus-regovm")]
#[derive(Clone)]
pub struct CachedPolicy {
    hash: String,
    rules: RulePrograms,
}

/// Cross-evaluation program cache, keyed by `policy_id`. Each entry carries
/// the policy content hash it was compiled against as a validation checksum:
/// a lookup is a hit only when the `policy_id` is present AND the stored hash
/// matches the current policy source. This bounds the cache to one entry per
/// policy and evicts stale versions automatically — a changed policy source
/// (whether via `set_policy` or, for the fs-backed `OPA`, an external file
/// overwrite) produces a hash mismatch, so that slot is overwritten in place
/// on the next miss and old versions never accumulate. The cached `Program`
/// excludes per-eval `data`/`input` (set on the VM at run time) and the
/// host-await wrapper is constant per engine instance, so the (id, hash) pair
/// is a sufficient key.
#[cfg(feature = "regorus-regovm")]
pub type ProgramCache = tokio::sync::RwLock<HashMap<String, CachedPolicy>>;

#[cfg(feature = "policy-rvps")]
fn query_reference_value_extension(
    reference_value_resolver: Arc<ReferenceValueResolver>,
) -> ExtensionFunction {
    Arc::new(move |argument| {
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
) -> ExtensionFunction {
    Arc::new(move |argument| {
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

// Up to eight parameters (policy source, input, id, rule list, RVPS resolver,
// optional artifact client, caller-injected extension functions,
// cross-evaluation program cache), each a distinct concern; the artifact
// client and program cache are feature-gated, so the effective count ranges
// 6-8 depending on the feature set. Bundling would obscure the call sites
// rather than clarify them.
#[allow(clippy::too_many_arguments)]
async fn common_evaluate(
    policy: String,
    input: String,
    policy_id: String,
    evaluation_rules: Vec<String>,
    reference_value_resolver: Arc<ReferenceValueResolver>,
    #[cfg(feature = "policy-artifact-server")] artifact_server_client: Arc<
        artifact_resolve_sdk::Client,
    >,
    extra_extension_functions: Option<Vec<(String, ExtensionFunction)>>,
    #[cfg(feature = "regorus-regovm")] program_cache: &ProgramCache,
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
    let mut extension_functions = HashMap::<String, ExtensionFunction>::default();

    #[cfg(feature = "policy-rvps")]
    {
        extension_functions.insert(
            "query_reference_value".to_string(),
            query_reference_value_extension(reference_value_resolver),
        );
    }

    #[cfg(feature = "policy-artifact-server")]
    {
        extension_functions.insert(
            "query_artifact_server".to_string(),
            query_artifact_server_extension(artifact_server_client),
        );
    }

    // Merge caller-injected functions after the built-ins. This is the generic
    // extension point that lets a downstream crate supply arbitrary host
    // functions callable from rego that regorus does not ship built-in. User
    // functions are inserted last so a key colliding with a built-in is
    // overridden by the caller's explicit choice.
    if let Some(extras) = extra_extension_functions {
        for (key, function) in extras {
            extension_functions.insert(key, function);
        }
    }

    // Dispatch to the selected backend. Exactly one of the two features is on
    // (enforced by the compile_error guards at the top of this file), so only
    // one branch is compiled. `program_cache` exists only under
    // `regorus-regovm` (it caches compiled `regorus::rvm::Program`s, which the
    // interpreter path never touches), so the param itself is cfg-gated above.
    #[cfg(feature = "regorus-regovm")]
    return evaluate_with_regovm(
        policy,
        input,
        policy_id,
        evaluation_rules,
        data,
        extension_functions,
        program_cache,
    )
    .await;
    #[cfg(feature = "regorus-interpreter")]
    return evaluate_with_interpreter(
        policy,
        input,
        policy_id,
        evaluation_rules,
        data,
        extension_functions,
    )
    .await;
}

#[cfg(feature = "regorus-regovm")]
async fn evaluate_with_regovm(
    policy: String,
    input: String,
    policy_id: String,
    evaluation_rules: Vec<String>,
    data: String,
    extension_functions: HashMap<String, ExtensionFunction>,
    program_cache: &ProgramCache,
) -> Result<EvaluationResult, PolicyError> {
    let policy_hash = {
        let mut hasher = sha2::Sha384::new();
        hasher.update(&policy);
        hex::encode(hasher.finalize())
    };

    // Emit the extension wrappers as a *separate* rego.v1 module (see
    // [`build_extensions_module`]) rather than concatenating them onto the
    // user policy. This keeps legacy rego.v0 policies parseable: the user
    // module (no `import rego.v1`) parses in v0 mode while the wrapper module
    // parses in v1 mode. Skip it when no extension functions are registered.
    let wrapper_module = if extension_functions.is_empty() {
        None
    } else {
        Some(build_extensions_module(&extension_functions)?)
    };

    let data_value =
        regorus::Value::from_json_str(&data).map_err(PolicyError::JsonSerializationFailed)?;
    let input_value =
        regorus::Value::from_json_str(&input).map_err(PolicyError::SetInputDataFailed)?;

    // Resolve the per-rule RVM programs for this evaluation, reusing the
    // cross-evaluation cache and compiling only rules it does not already hold.
    // See [`resolve_programs`] for the hit / full-miss / partial-miss policy.
    let programs: RulePrograms = resolve_programs(
        program_cache,
        &policy_id,
        &policy_hash,
        &policy,
        &data_value,
        &evaluation_rules,
        &wrapper_module,
    )
    .await?;

    let mut rules_result = std::collections::HashMap::new();
    for rule in &evaluation_rules {
        // Rules absent from `programs` were skipped (policy does not define
        // them) — preserve origin/main's skip behavior on cache hits too.
        let Some(program) = programs.get(rule) else {
            continue;
        };

        // Lower the CompiledPolicy to a Program, then load it onto a fresh VM.
        // RegoVM::new_with_policy stores the policy but never loads a program,
        // so execute() returns Undefined — do not use it.
        let mut vm = regorus::rvm::RegoVM::new();
        vm.load_program(program.clone());
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
                    let v = dispatch(identifier, argument, &extension_functions).await?;
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

/// Resolve the per-rule RVM programs needed for an evaluation, populating the
/// cross-evaluation cache.
///
/// The cache is keyed by `policy_id`. A lookup is a hit when this policy was
/// compiled before AND its stored content hash matches the current source — a
/// hit reuses the previously compiled per-rule programs and skips `Engine`
/// construction, policy parsing and compilation entirely, so only the per-rule
/// VM runs.
///
/// Two kinds of miss:
/// - full miss: no entry (first appraisal) or a changed source whose hash no
///   longer matches — start from an empty rule map.
/// - partial miss: a hit, but this request asks for a rule the cached entry
///   did not compile (a previous request used a different rule set). The cached
///   map is reused and only the missing rules are compiled and merged in —
///   otherwise a rule absent from the *first* request would be wrongly skipped
///   as "not defined" on every later request.
///
/// In both miss cases the `Engine` is built once for the whole evaluation
/// (hoisted out of the per-rule compile loop) and only the missing rules are
/// compiled. Keying by id (not by hash) bounds the cache to one entry per
/// policy and makes a changed source overwrite the stale slot in place, so old
/// versions never accumulate — important for the fs-backed `OPA`, which reads
/// the policy file fresh on every `evaluate` and would otherwise leak a cache
/// entry per content version when the file is overwritten on disk.
///
/// Rules the policy does not define are skipped: regorus reports them as `not
/// a valid rule path`, which origin/main already treated as "skip this rule";
/// a skipped rule is absent from the returned map, so a later request for it
/// re-attempts the compile (cheaply) and skips again.
#[cfg(feature = "regorus-regovm")]
async fn resolve_programs(
    program_cache: &ProgramCache,
    policy_id: &str,
    policy_hash: &str,
    policy: &str,
    data_value: &regorus::Value,
    evaluation_rules: &[String],
    wrapper_module: &Option<String>,
) -> Result<RulePrograms, PolicyError> {
    // Start from the cached entry for this policy when its hash matches;
    // otherwise an empty map (full miss — first appraisal or a changed source).
    let mut programs: RulePrograms = {
        let cached = program_cache.read().await.get(policy_id).cloned();
        match cached {
            Some(c) if c.hash == policy_hash => c.rules,
            _ => HashMap::new(),
        }
    };

    // Rules requested but not yet compiled (full miss, or a later request for
    // rules the cached entry didn't include). Compile only these, then merge
    // into the map and persist so the next appraisal finds them warm.
    let missing: Vec<String> = evaluation_rules
        .iter()
        .filter(|rule| !programs.contains_key(*rule))
        .cloned()
        .collect();
    if !missing.is_empty() {
        let mut engine = regorus::Engine::new();
        engine.set_rego_v0(true);
        engine
            .add_data(data_value.clone())
            .map_err(PolicyError::LoadPolicyFailed)?;
        engine
            .add_policy(policy_id.to_string(), policy.to_string())
            .map_err(PolicyError::LoadPolicyFailed)?;
        if let Some(wrapper) = wrapper_module {
            engine
                .add_policy(EXTENSIONS_WRAPPER_MODULE_ID.to_string(), wrapper.clone())
                .map_err(PolicyError::LoadPolicyFailed)?;
        }
        for rule in &missing {
            // regorus rejects a bare rule name with "not a valid rule path";
            // use the full data.policy path. See [`common_evaluate`].
            let entry_point = format!("data.policy.{rule}");
            let cp = match engine.compile_with_entrypoint(&Rc::from(entry_point.clone())) {
                Ok(cp) => cp,
                Err(e) if e.to_string().contains("not a valid rule path") => {
                    debug!("Policy `{policy_id}` does not check {rule}");
                    continue;
                }
                Err(e) => return Err(PolicyError::LoadPolicyFailed(e)),
            };
            let program = Compiler::compile_from_policy(&cp, &[entry_point.as_str()])
                .map_err(|e| PolicyError::LoadPolicyFailed(e.into()))?;
            programs.insert(rule.clone(), program);
        }
        // Persist the merged map (hash unchanged on a partial miss).
        program_cache.write().await.insert(
            policy_id.to_string(),
            CachedPolicy {
                hash: policy_hash.to_string(),
                rules: programs.clone(),
            },
        );
    }

    Ok(programs)
}

#[cfg(feature = "regorus-interpreter")]
async fn evaluate_with_interpreter(
    policy: String,
    input: String,
    policy_id: String,
    evaluation_rules: Vec<String>,
    data: String,
    extension_functions: HashMap<String, ExtensionFunction>,
) -> Result<EvaluationResult, PolicyError> {
    // Captured on the async thread, then moved onto a blocking-pool thread so
    // the extensions' `block_on` never runs inside a runtime context guard.
    let runtime_handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        evaluate_sync(
            policy,
            input,
            policy_id,
            evaluation_rules,
            data,
            extension_functions,
            runtime_handle,
        )
    })
    .await
    .map_err(|e| {
        PolicyError::EvalPolicyFailed(anyhow!("Regorus blocking evaluation task failed: {e}"))
    })?
}

#[cfg(feature = "regorus-interpreter")]
fn evaluate_sync(
    policy: String,
    input: String,
    policy_id: String,
    evaluation_rules: Vec<String>,
    data: String,
    extension_functions: HashMap<String, ExtensionFunction>,
    runtime_handle: tokio::runtime::Handle,
) -> Result<EvaluationResult, PolicyError> {
    let policy_hash = {
        let mut hasher = sha2::Sha384::new();
        hasher.update(&policy);
        hex::encode(hasher.finalize())
    };

    let mut engine = regorus::Engine::new();
    // regorus 0.11 defaults to rego.v1; keep accepting legacy `allow { ... }`
    // (rego.v0) policies saved before the rego.v1 migration. `import rego.v1`
    // policies still work.
    engine.set_rego_v0(true);
    engine
        .add_policy(policy_id.clone(), policy)
        .map_err(PolicyError::LoadPolicyFailed)?;
    let data_value =
        regorus::Value::from_json_str(&data).map_err(PolicyError::JsonSerializationFailed)?;
    engine
        .add_data(data_value)
        .map_err(PolicyError::LoadReferenceDataFailed)?;
    engine
        .set_input_json(&input)
        .map_err(PolicyError::SetInputDataFailed)?;

    for (name, function) in &extension_functions {
        engine
            .add_extension(
                name.clone(),
                1,
                async_to_sync_extension(function.clone(), runtime_handle.clone()),
            )
            .map_err(PolicyError::EvalPolicyFailed)?;
    }

    let mut rules_result = std::collections::HashMap::new();
    for rule in evaluation_rules {
        // regorus rejects a bare rule name with "not a valid rule path"; use
        // the full data.policy path.
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

/// Bridge an async [`ExtensionFunction`] into the sync `regorus::Extension`
/// the interpreter backend expects: drive the closure's future to completion
/// on the captured tokio runtime handle. Called from a `spawn_blocking`
/// thread, so `block_on` does not nest the runtime.
#[cfg(feature = "regorus-interpreter")]
fn async_to_sync_extension(
    function: ExtensionFunction,
    runtime_handle: tokio::runtime::Handle,
) -> Box<dyn Extension> {
    Box::new(move |params: Vec<regorus::Value>| {
        if params.len() != 1 {
            return Err(anyhow!(
                "extension expects exactly 1 argument, got {}",
                params.len()
            ));
        }
        let argument = params[0].clone();
        let future = function(argument);
        runtime_handle.block_on(future).map_err(anyhow::Error::new)
    })
}
/// Dispatch a host-await call to the matching extension function, identified
/// by the string the VM passed to `__builtin_host_await`.
#[cfg(feature = "regorus-regovm")]
async fn dispatch(
    identifier: regorus::Value,
    argument: regorus::Value,
    extension_functions: &HashMap<String, ExtensionFunction>,
) -> Result<regorus::Value, PolicyError> {
    let id = identifier.as_string().map_err(|e| {
        PolicyError::EvalPolicyFailed(anyhow!("extension identifier not a string: {e}"))
    })?;

    match extension_functions.get(id.as_ref()) {
        Some(function) => function(argument).await,
        None => Err(PolicyError::EvalPolicyFailed(anyhow!(
            "unknown extension function: {id}"
        ))),
    }
}

/// Per-key rego wrappers appended to the policy source on the regovm backend.
/// Dynamically generates a rego function for each registered extension,
/// forwarding the friendly name onto regorus's native `__builtin_host_await`
/// primitive, which suspends the VM so the host can run async I/O and resume it.
/// Uses `if` + `:=` (rego.v1 syntax) and no `import rego.v1` -- see
/// [`build_extensions_module`], which wraps these definitions in their own
/// rego.v1 module.
#[cfg(feature = "regorus-regovm")]
fn build_extensions(
    extension_functions: &HashMap<String, ExtensionFunction>,
) -> Result<String, PolicyError> {
    // Validate every key before interpolation. Each key is spliced raw into a
    // Rego rule head (`{key}(arg) := v if { ... }`) AND into a string literal
    // (`"{key}"`); a key carrying a newline, comment, quote, or brace would
    // inject Rego source — append `allow := true` and flip a
    // `default allow := false`. This is the unbypassable gate: every path that
    // generates wrapper source goes through here. See
    // [`is_valid_rego_extension_name`].
    if let Some(bad) = extension_functions
        .keys()
        .find(|key| !is_valid_rego_extension_name(key))
    {
        return Err(PolicyError::EvalPolicyFailed(anyhow!(
            "invalid extension function name `{bad}`: must be a dotted path of Rego identifiers"
        )));
    }
    let mut ext = String::from(r#"# === trustee EXTENSIONS (generated) ==="#);
    for key in extension_functions.keys() {
        ext.push_str(&format!(
            r#"
{key}(arg) := v if {{ v := __builtin_host_await(arg, "{key}") }}
"#,
        ));
    }
    Ok(ext)
}

/// Module id under which the generated extension wrappers are loaded, so they
/// form a distinct module from the user-supplied policy.
#[cfg(feature = "regorus-regovm")]
const EXTENSIONS_WRAPPER_MODULE_ID: &str = "__trustee_extensions__.rego";

/// Wrap the generated extension function definitions in their own rego.v1
/// module (own `package` + `import rego.v1`). Keeping them separate from the
/// user policy lets a legacy rego.v0 policy (no `import rego.v1`) parse in v0
/// mode while the wrappers still parse in v1 mode: the regorus parser picks
/// the dialect per module (auto-enabling v1 when it sees `import rego.v1`),
/// but a single shared module cannot mix dialects, so concatenating v1-syntax
/// wrappers onto a v0 policy would force the whole module into v1 and reject
/// legacy `allow { ... }` bodies.
#[cfg(feature = "regorus-regovm")]
fn build_extensions_module(
    extension_functions: &HashMap<String, ExtensionFunction>,
) -> Result<String, PolicyError> {
    Ok(format!(
        "package policy\nimport rego.v1\n\n{}",
        build_extensions(extension_functions)?
    ))
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
        use anyhow::Context as _;

        let http_client = reqwest::Client::builder().no_proxy().build()?;
        let client = Arc::new(
            artifact_resolve_sdk::Client::builder()
                .base_url(base_url)
                .http_client(http_client)
                .build()?,
        );

        let extension = query_artifact_server_extension(client);
        let argument = regorus::Value::from_json_str(r#"{"tdx.td-shim":"582f8ed2"}"#)?;
        let result = extension(argument).await?;
        Ok(*result
            .as_bool()
            .context("query_artifact_server result must be a boolean")?)
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

    #[cfg(all(feature = "policy-rvps", feature = "regorus-regovm"))]
    #[tokio::test]
    async fn dispatch_routes_reference_value_lookup_and_returns_null_when_missing() {
        use crate::rvps::test_resolver;
        let rvps = test_resolver(std::collections::HashMap::from([]));
        let mut functions = HashMap::<String, ExtensionFunction>::new();
        functions.insert(
            "query_reference_value".to_string(),
            query_reference_value_extension(rvps),
        );
        let id = regorus::Value::String(regorus::Rc::from("query_reference_value"));
        let arg = regorus::Value::String(regorus::Rc::from("missing-key"));
        let v = dispatch(id, arg, &functions).await.unwrap();
        assert!(matches!(v, regorus::Value::Null));
    }

    #[cfg(feature = "regorus-regovm")]
    #[tokio::test]
    async fn dispatch_unknown_identifier_errors() {
        let functions = HashMap::<String, ExtensionFunction>::new();
        let id = regorus::Value::String(regorus::Rc::from("nope"));
        let arg = regorus::Value::Null;
        assert!(dispatch(id, arg, &functions).await.is_err());
    }

    #[cfg(feature = "regorus-regovm")]
    #[tokio::test]
    async fn dispatch_passes_argument_to_registered_function() {
        let mut functions = HashMap::<String, ExtensionFunction>::new();
        functions.insert(
            "echo".to_string(),
            Arc::new(|argument| Box::pin(async move { Ok::<_, PolicyError>(argument) })),
        );
        let id = regorus::Value::String(regorus::Rc::from("echo"));
        let arg = regorus::Value::String(regorus::Rc::from("payload"));
        let v = dispatch(id, arg, &functions).await.unwrap();
        match v {
            regorus::Value::String(s) => assert_eq!(s.as_ref(), "payload"),
            other => panic!("expected string, got {other:?}"),
        }
    }

    #[cfg(feature = "regorus-regovm")]
    #[test]
    fn build_extensions_empty_returns_only_header() {
        let functions = HashMap::<String, ExtensionFunction>::new();
        assert_eq!(
            build_extensions(&functions).unwrap(),
            "# === trustee EXTENSIONS (generated) ==="
        );
    }

    #[cfg(feature = "regorus-regovm")]
    #[test]
    fn build_extensions_generates_wrapper_per_registered_key() {
        let make = || -> ExtensionFunction {
            Arc::new(|_a: regorus::Value| {
                Box::pin(async { Ok::<_, PolicyError>(regorus::Value::Null) })
            })
        };
        let mut functions = HashMap::<String, ExtensionFunction>::new();
        functions.insert("alpha".to_string(), make());
        functions.insert("beta".to_string(), make());
        let ext = build_extensions(&functions).unwrap();
        assert!(
            ext.contains(r#"alpha(arg) := v if { v := __builtin_host_await(arg, "alpha") }"#),
            "{ext}"
        );
        assert!(
            ext.contains(r#"beta(arg) := v if { v := __builtin_host_await(arg, "beta") }"#),
            "{ext}"
        );
    }
    // The regovm backend generates a per-extension Rego wrapper rule whose
    // head *is* the extension key. A dotted key is a legitimate, working
    // wrapper name: regorus's rego.v1 parser accepts a ref-headed function
    // definition, so the generated module compiles and the wrapper resolves at
    // call time. This characterizes that contract so a future `build_extensions`
    // change does not silently break the dotted extension path.
    #[cfg(feature = "regorus-regovm")]
    #[tokio::test]
    async fn regovm_accepts_dotted_wrapper_function_name() {
        let mut functions = HashMap::new();
        functions.insert(
            "crypto.sha256".to_string(),
            fixed_value_extension(regorus::Value::String(regorus::Rc::from("ok"))),
        );

        // The generated wrapper module must parse as rego.v1.
        let wrapper = build_extensions_module(&functions).expect("wrapper must build");
        assert!(
            wrapper.contains(
                r#"crypto.sha256(arg) := v if { v := __builtin_host_await(arg, "crypto.sha256") }"#
            ),
            "{wrapper}"
        );
        let mut eng = regorus::Engine::new();
        eng.set_rego_v0(true);
        eng.add_policy(EXTENSIONS_WRAPPER_MODULE_ID.to_string(), wrapper)
            .expect("dotted wrapper module must compile");

        // End to end: a policy calling the dotted extension resolves through
        // the host-await wrapper to the registered function.
        let policy = r#"package policy
import rego.v1
allow if { crypto.sha256("abc") == "ok" }
"#;
        let result = evaluate_with_regovm(
            policy.to_string(),
            "{}".to_string(),
            "test".to_string(),
            vec!["allow".to_string()],
            "{}".to_string(),
            functions,
            &fresh_program_cache(),
        )
        .await
        .expect("regovm eval must succeed with a dotted wrapper name");
        assert_eq!(
            result.rules_result.get("allow"),
            Some(&serde_json::Value::Bool(true))
        );
    }

    // The interpreter backend registers caller extensions through
    // `regorus::Engine::add_extension`. A dotted name is a legitimate extension
    // path: it registers and resolves at the policy call site. This
    // characterizes that contract so a future identifier validator on
    // the registration path does not silently reject dotted names.
    #[cfg(feature = "regorus-interpreter")]
    #[test]
    fn interpreter_accepts_dotted_extension_name() {
        let mut engine = regorus::Engine::new();
        engine.set_rego_v0(true);
        engine
            .add_policy(
                "test".to_string(),
                r#"package policy
import rego.v1
result := crypto.sha256("abc")
"#
                .to_string(),
            )
            .expect("policy must compile");
        engine
            .add_extension(
                "crypto.sha256".to_string(),
                1,
                Box::new(|mut params: Vec<regorus::Value>| {
                    let _ = params.remove(0);
                    Ok(regorus::Value::String(regorus::Rc::from("ok")))
                }),
            )
            .expect("add_extension must accept a dotted name");
        engine.set_input_json("{}").expect("set input");
        let value = engine
            .eval_rule("data.policy.result".to_string())
            .expect("eval_rule must resolve the dotted extension call");
        match value {
            regorus::Value::String(s) => assert_eq!(s.as_ref(), "ok"),
            other => panic!("expected string \"ok\", got {other:?}"),
        }
    }

    // The dotted-identifier contract that both backends accept, and the
    // injection vectors that must be rejected (the `build_extensions`
    // source-injection attack surface).
    #[cfg(feature = "regorus-regovm")]
    #[test]
    fn is_valid_rego_extension_name_accepts_dotted_identifiers() {
        // Plain and dotted names both backends resolve.
        assert!(is_valid_rego_extension_name("crypto.sha256"));
        assert!(is_valid_rego_extension_name("query_reference_value"));
        assert!(is_valid_rego_extension_name("query_artifact_server"));
        assert!(is_valid_rego_extension_name("my_async"));
        assert!(is_valid_rego_extension_name("a.b.c"));
        assert!(is_valid_rego_extension_name("_leading_underscore"));
        assert!(is_valid_rego_extension_name("sha256"));
    }

    #[cfg(feature = "regorus-regovm")]
    #[test]
    fn is_valid_rego_extension_name_rejects_injection_vectors() {
        let rejects = [
            // empty / dot-only
            "",
            ".",
            ".crypto.sha256",
            "crypto.sha256.",
            "crypto..sha256",
            // the reviewer's attack: a name with a newline + comment that
            // would append `allow := true` to the generated module
            "foo(arg) := v if { v := true }\nallow := true",
            // string-literal breakout (second interpolation site)
            r#"foo","evil")"#,
            // spaces / operators / braces / quotes — none appear in a dotted
            // identifier path
            "has space",
            "tab\there",
            "with#comment",
            "semi;colon",
            "brace{",
            "quote\"",
            "backslash\\",
            "dash-name",
            "star*",
            // a leading digit is a Rego number, not an identifier
            "1abc",
            "crypto.1abc",
            // reserved keywords as a segment (the wrapper module enables
            // rego.v1, so these would fail to parse as a rule head)
            "if",
            "in",
            "contains",
            "crypto.if",
            "true",
            "package",
        ];
        for name in rejects {
            assert!(
                !is_valid_rego_extension_name(name),
                "expected `{name}` to be rejected"
            );
        }
    }

    // The reviewer's injection must be blocked at the regovm entry, before
    // `build_extensions` ever interpolates the name into Rego source. A policy
    // with `default allow := false` must stay false even when a malicious
    // extension name is registered.
    #[cfg(feature = "regorus-regovm")]
    #[tokio::test]
    async fn regovm_rejects_injection_extension_name() {
        let mut functions = HashMap::new();
        functions.insert(
            // Newline + comment that, if interpolated raw, would append
            // `allow := true` to the wrapper module.
            "foo\nallow := true #".to_string(),
            fixed_value_extension(regorus::Value::Bool(true)),
        );
        let policy = r#"package policy
import rego.v1
default allow := false
"#;
        let result = evaluate_with_regovm(
            policy.to_string(),
            "{}".to_string(),
            "test".to_string(),
            vec!["allow".to_string()],
            "{}".to_string(),
            functions,
            &fresh_program_cache(),
        )
        .await;
        let err = result.expect_err("malformed extension name must be rejected");
        assert!(
            err.to_string().contains("invalid extension function name"),
            "expected an invalid-name error, got: {err}"
        );
        assert!(
            err.to_string().contains("allow := true"),
            "error should name the offending key: {err}"
        );
    }

    // A fresh, empty program cache for `evaluate_with_regovm` tests. Each test
    // gets its own so cached programs never leak across cases.
    #[cfg(feature = "regorus-regovm")]
    fn fresh_program_cache() -> ProgramCache {
        ProgramCache::default()
    }

    // Extension closure that always returns a fixed value, ignoring its argument.
    #[cfg(feature = "regorus-regovm")]
    fn fixed_value_extension(value: regorus::Value) -> ExtensionFunction {
        Arc::new(move |_argument| {
            let value = value.clone();
            Box::pin(async move { Ok(value) })
        })
    }

    // Extension closure mapping a string argument to a number ("a"->1, "b"->2),
    // else null. Used to verify the VM forwards the policy argument to the host.
    #[cfg(feature = "regorus-regovm")]
    fn lookup_extension() -> ExtensionFunction {
        Arc::new(move |argument| {
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

    // Extension closure that always fails, to exercise error propagation from a
    // suspended host call back up through evaluate_with_regovm.
    #[cfg(feature = "regorus-regovm")]
    fn failing_extension() -> ExtensionFunction {
        Arc::new(move |_argument| {
            Box::pin(async move {
                Err(PolicyError::EvalPolicyFailed(anyhow!(
                    "async function failed"
                )))
            })
        })
    }

    #[cfg(feature = "regorus-regovm")]
    #[tokio::test]
    async fn evaluate_with_regovm_async_builtin_drives_rule_true() {
        // A policy calls an extension whose returned value satisfies the rule
        // body, so the rule evaluates to true. Exercises the full
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
            &fresh_program_cache(),
        )
        .await
        .unwrap();
        assert_eq!(
            result.rules_result.get("allow"),
            Some(&serde_json::Value::Bool(true))
        );
    }

    #[cfg(feature = "regorus-regovm")]
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
            &fresh_program_cache(),
        )
        .await
        .unwrap();
        assert_eq!(
            result.rules_result.get("allow"),
            Some(&serde_json::Value::Bool(true))
        );
    }

    #[cfg(feature = "regorus-regovm")]
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
            &fresh_program_cache(),
        )
        .await
        .unwrap();
        assert_eq!(
            result.rules_result.get("allow"),
            Some(&serde_json::Value::Bool(true))
        );
    }

    #[cfg(feature = "regorus-regovm")]
    #[tokio::test]
    async fn evaluate_with_regovm_propagates_async_builtin_error() {
        // A failing extension call must surface as a PolicyError from
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
            &fresh_program_cache(),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("async function failed"), "{err}");
    }

    // Pins origin/main's "skip missing rule" contract: a policy that defines
    // only some of the requested rules must evaluate successfully, with the
    // undefined rules simply ABSENT from the result — not a hard error. Both
    // the old interpreter (`eval_rule` + catch `not a valid rule path`) and the
    // current `evaluate_with_regovm` preserve this; any optimization of
    // `evaluate_with_regovm` (hoist, program cache, etc.) MUST preserve it too.
    // See the `eval_bench` module for why multi-entry compile was rejected: it
    // would turn this skip into a whole-compile failure.
    #[cfg(all(feature = "regorus-regovm", feature = "policy-rvps"))]
    #[tokio::test]
    async fn evaluate_skips_rules_not_defined_in_policy() {
        let policy = r#"package policy
import rego.v1
default executables := 3
default hardware := 2
"#;
        let mut functions = HashMap::<String, ExtensionFunction>::default();
        functions.insert(
            "query_reference_value".to_string(),
            query_reference_value_extension(crate::rvps::test_resolver(
                std::collections::HashMap::new(),
            )),
        );
        let result = evaluate_with_regovm(
            policy.to_string(),
            "{}".to_string(),
            "partial".to_string(),
            vec![
                "executables".to_string(),
                "hardware".to_string(),
                "configuration".to_string(), // not defined -> must be skipped
                "file_system".to_string(),   // not defined -> must be skipped
            ],
            "{}".to_string(),
            functions,
            &fresh_program_cache(),
        )
        .await
        .expect("partial policy must evaluate, skipping undefined rules");

        let present: std::collections::HashSet<&str> =
            result.rules_result.keys().map(|k| k.as_str()).collect();
        assert_eq!(
            present,
            ["executables", "hardware"]
                .into_iter()
                .collect::<std::collections::HashSet<&str>>(),
            "only defined rules should be present; undefined ones skipped"
        );
        assert_eq!(
            result.rules_result.get("executables").unwrap(),
            &serde_json::json!(3)
        );
        assert_eq!(
            result.rules_result.get("hardware").unwrap(),
            &serde_json::json!(2)
        );
    }
}

