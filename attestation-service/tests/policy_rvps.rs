// Copyright (c) 2026 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

#![cfg(all(feature = "fs", feature = "policy-rvps"))]

use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::time::Duration;

use attestation_service::config::Config;
use attestation_service::rvps::{grpc::RvpsRemoteConfig, RvpsConfig, RvpsCrateConfig};
use attestation_service::token::{simple, AttestationTokenConfig};
use attestation_service::{AttestationService, HashAlgorithm, Tee, VerificationRequest};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use reference_value_provider_service::client;
use reference_value_provider_service::server;
use reference_value_provider_service::storage::{in_memory, ReferenceValueStorageConfig};
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::task::JoinHandle;

const MEASUREMENT: &str = "1111111111111111111111111111111111111111111111111111111111111111";

const QUERY_POLICY: &str = r#"
package policy

import future.keywords.if
import future.keywords.in

default allow := false

allow if {
    input["sample.svn"] == query_reference_value("minimum_svn")
    input["sample.measure_register"] in query_reference_value("allowed_measurements")
    query_reference_value("constraints").debug == false
    query_reference_value("missing") == null
}
"#;

const LEGACY_POLICY: &str = r#"
package policy

import future.keywords.if
import future.keywords.in

default allow := false

allow if {
    input["sample.svn"] == data.reference["minimum_svn"]
    input["sample.measure_register"] in data.reference["allowed_measurements"]
}
"#;

struct RvpsServerGuard(JoinHandle<anyhow::Result<()>>);

impl Drop for RvpsServerGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn in_memory_rvps_config() -> RvpsCrateConfig {
    RvpsCrateConfig {
        storage: ReferenceValueStorageConfig::InMemory(in_memory::Config::default()),
    }
}

fn as_config(work_dir: &Path, rvps_config: RvpsConfig) -> Config {
    Config {
        work_dir: work_dir.join("work"),
        rvps_config,
        attestation_token_broker: AttestationTokenConfig::Simple(simple::Configuration {
            settings: simple::TokenBrokerSettings {
                duration_min: 5,
                issuer_name: "policy-rvps-e2e".to_string(),
            },
            signer: None,
            policy_dir: work_dir.join("policies").to_string_lossy().into_owned(),
            ..Default::default()
        }),
        challenge_key_path: None,
        artifact_server_address: attestation_service::config::DEFAULT_ARTIFACT_SERVER_ADDRESS
            .to_string(),
    }
}

fn sample_message(minimum_svn: &str) -> String {
    let payload = json!({
        "minimum_svn": minimum_svn,
        "allowed_measurements": [MEASUREMENT],
        "constraints": {
            "debug": false,
            "products": ["alpha", "beta"]
        }
    });

    json!({
        "version": "0.1.0",
        "type": "sample",
        "payload": STANDARD.encode(payload.to_string())
    })
    .to_string()
}

fn sample_request() -> VerificationRequest {
    VerificationRequest {
        evidence: json!({
            "svn": "7",
            "report_data": "",
            "measure_register": MEASUREMENT,
            "cc_eventlog": null
        }),
        tee: Tee::Sample,
        runtime_data: None,
        runtime_data_hash_algorithm: HashAlgorithm::Sha384,
        init_data: None,
        additional_data: None,
    }
}

async fn set_policy(service: &mut AttestationService, id: &str, policy: &str) {
    service
        .set_policy(id.to_string(), URL_SAFE_NO_PAD.encode(policy))
        .await
        .unwrap();
}

fn assert_token(token: &str, policy_id: &str) {
    let segments: Vec<_> = token.split('.').collect();
    assert_eq!(segments.len(), 3);

    let claims = URL_SAFE_NO_PAD.decode(segments[1]).unwrap();
    let claims: Value = serde_json::from_slice(&claims).unwrap();
    assert_eq!(claims["iss"], "policy-rvps-e2e");
    let tcb_status: Value = serde_json::from_str(claims["tcb-status"].as_str().unwrap()).unwrap();
    assert_eq!(tcb_status["sample.measure_register"], MEASUREMENT);
    assert!(claims["evaluation-reports"]
        .as_array()
        .unwrap()
        .iter()
        .any(|report| report["policy-id"] == policy_id));
}

async fn exercise_query_and_legacy_policies(service: &mut AttestationService) {
    service
        .register_reference_value(&sample_message("7"))
        .await
        .unwrap();

    set_policy(service, "query", QUERY_POLICY).await;
    let token = service
        .evaluate(vec![sample_request()], vec!["query".to_string()])
        .await
        .unwrap();
    assert_token(&token, "query");

    set_policy(service, "legacy", LEGACY_POLICY).await;
    let token = service
        .evaluate(vec![sample_request()], vec!["legacy".to_string()])
        .await
        .unwrap();
    assert_token(&token, "legacy");

    service
        .register_reference_value(&sample_message("8"))
        .await
        .unwrap();
    let error = service
        .evaluate(vec![sample_request()], vec!["query".to_string()])
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("Reject by policy query"), "{error}");
}

fn unused_local_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    address
}

async fn start_remote_rvps() -> (RvpsServerGuard, String) {
    let address = unused_local_address();
    let endpoint = format!("http://{address}");
    let handle = tokio::spawn(server::start(address, in_memory_rvps_config()));
    let guard = RvpsServerGuard(handle);

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if tokio::net::TcpStream::connect(address).await.is_ok() {
                break;
            }
            assert!(!guard.0.is_finished(), "RVPS server stopped during startup");
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("RVPS server did not become ready");

    (guard, endpoint)
}

#[tokio::test]
async fn builtin_rvps_supports_query_and_legacy_policies_end_to_end() {
    let temp_dir = TempDir::new().unwrap();
    let mut service = AttestationService::new(as_config(
        temp_dir.path(),
        RvpsConfig::BuiltIn(in_memory_rvps_config()),
    ))
    .await
    .unwrap();

    exercise_query_and_legacy_policies(&mut service).await;
}

#[tokio::test]
async fn remote_rvps_supports_new_and_old_protocols_end_to_end() {
    let (_server, endpoint) = start_remote_rvps().await;
    let temp_dir = TempDir::new().unwrap();
    let mut service = AttestationService::new(as_config(
        temp_dir.path(),
        RvpsConfig::GrpcRemote(RvpsRemoteConfig {
            address: endpoint.clone(),
        }),
    ))
    .await
    .unwrap();

    service
        .register_reference_value(&sample_message("7"))
        .await
        .unwrap();

    assert_eq!(
        client::query_by_id(endpoint.clone(), "minimum_svn".to_string())
            .await
            .unwrap(),
        Some("\"7\"".to_string())
    );
    assert_eq!(
        client::query_by_id(endpoint.clone(), "missing".to_string())
            .await
            .unwrap(),
        None
    );

    // Empty-key query is the exact wire behavior of pre-change Anolis clients.
    let bulk: Value =
        serde_json::from_str(&client::query(endpoint.clone()).await.unwrap()).unwrap();
    assert_eq!(bulk["minimum_svn"], "7");
    assert_eq!(bulk["allowed_measurements"], json!([MEASUREMENT]));

    set_policy(&mut service, "query", QUERY_POLICY).await;
    let token = service
        .evaluate(vec![sample_request()], vec!["query".to_string()])
        .await
        .unwrap();
    assert_token(&token, "query");

    set_policy(&mut service, "legacy", LEGACY_POLICY).await;
    let token = service
        .evaluate(vec![sample_request()], vec!["legacy".to_string()])
        .await
        .unwrap();
    assert_token(&token, "legacy");
}
