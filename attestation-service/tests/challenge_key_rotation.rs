// Copyright (c) 2026 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "fs")]

use std::io::Write;
use std::path::Path;

use attestation_service::config::Config;
use attestation_service::rvps::{RvpsConfig, RvpsCrateConfig};
use attestation_service::token::{simple, AttestationTokenConfig};
use attestation_service::{
    AttestationService, HashAlgorithm, RuntimeData, Tee, VerificationRequest,
};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use canon_json::CanonicalFormatter;
use reference_value_provider_service::storage::{in_memory, ReferenceValueStorageConfig};
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::RsaPrivateKey;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha384};

const MEASUREMENT: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn config(work_dir: &Path, challenge_key_path: &Path) -> Config {
    Config {
        work_dir: work_dir.join("work"),
        rvps_config: RvpsConfig::BuiltIn(RvpsCrateConfig {
            storage: ReferenceValueStorageConfig::InMemory(in_memory::Config::default()),
        }),
        attestation_token_broker: AttestationTokenConfig::Simple(simple::Configuration {
            settings: simple::TokenBrokerSettings {
                duration_min: 5,
                issuer_name: "challenge-key-rotation-e2e".to_string(),
            },
            signer: None,
            policy_dir: work_dir.join("policies").to_string_lossy().into_owned(),
        }),
        challenge_key_path: Some(challenge_key_path.to_path_buf()),
    }
}

fn request_for_challenge(challenge: &str) -> VerificationRequest {
    let challenge: Value = serde_json::from_str(challenge).unwrap();
    let runtime_data = json!({
        "challenge_token": challenge["extra-params"]["jwt"]
    });

    let mut canonical = Vec::new();
    let mut serializer =
        serde_json::Serializer::with_formatter(&mut canonical, CanonicalFormatter::new());
    runtime_data.serialize(&mut serializer).unwrap();
    let report_data = Sha384::digest(canonical);

    VerificationRequest {
        evidence: json!({
            "svn": "1",
            "report_data": STANDARD.encode(report_data),
            "measure_register": MEASUREMENT,
            "cc_eventlog": null
        }),
        tee: Tee::Sample,
        runtime_data: Some(RuntimeData::Structured(runtime_data)),
        runtime_data_hash_algorithm: HashAlgorithm::Sha384,
        init_data: None,
        additional_data: None,
    }
}

fn replace_key_atomically(key_path: &Path) {
    let mut rng = rand::rngs::OsRng;
    let key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let pem = key.to_pkcs8_pem(LineEnding::LF).unwrap();

    let mut temporary = tempfile::NamedTempFile::new_in(key_path.parent().unwrap()).unwrap();
    temporary.write_all(pem.as_bytes()).unwrap();
    temporary.as_file_mut().sync_all().unwrap();
    temporary.persist(key_path).unwrap();
}

#[tokio::test]
async fn service_reloads_challenge_key_across_full_attestation_flow() {
    let temp_dir = tempfile::tempdir().unwrap();
    let key_path = temp_dir.path().join("challenge/key.pem");
    let service = AttestationService::new(config(temp_dir.path(), &key_path))
        .await
        .unwrap();

    assert!(
        !key_path.exists(),
        "service construction must leave challenge key creation lazy"
    );

    let first_challenge = service.generate_challenge(None, None).await.unwrap();
    assert!(key_path.exists(), "first challenge creates the key");
    service
        .evaluate(vec![request_for_challenge(&first_challenge)], vec![])
        .await
        .expect("first challenge-to-attestation flow succeeds");

    replace_key_atomically(&key_path);

    let second_challenge = service.generate_challenge(None, None).await.unwrap();
    service
        .evaluate(vec![request_for_challenge(&second_challenge)], vec![])
        .await
        .expect("same service observes rotated key without restart");

    service
        .evaluate(vec![request_for_challenge(&first_challenge)], vec![])
        .await
        .expect_err("an outstanding JWT signed by the old key is invalid after rotation");
}
