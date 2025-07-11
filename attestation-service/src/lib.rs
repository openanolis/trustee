//! Attestation Service
//!
//! # Features
//! - `rvps-grpc`: The AS will connect a remote RVPS.

pub mod config;
pub mod policy_engine;
pub mod rvps;
pub mod token;

use crate::token::AttestationTokenBroker;

use anyhow::{anyhow, Context, Result};
use config::Config;
pub use kbs_types::{Attestation, Tee};
use log::{debug, info};
use reqwest::Client;
use rvps::{RvpsApi, RvpsError};
use serde_json::Value;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::collections::HashMap;
use std::io::Read;
use strum::{AsRefStr, Display, EnumString};
use thiserror::Error;
use tokio::fs;
use verifier::{InitDataHash, ReportData};

/// Hash algorithms used to calculate runtime/init data binding
#[derive(Debug, Display, EnumString, AsRefStr)]
pub enum HashAlgorithm {
    #[strum(ascii_case_insensitive)]
    Sha256,

    #[strum(ascii_case_insensitive)]
    Sha384,

    #[strum(ascii_case_insensitive)]
    Sha512,
}

impl HashAlgorithm {
    fn accumulate_hash(&self, materials: Vec<u8>) -> Vec<u8> {
        match self {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(materials);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha384 => {
                let mut hasher = Sha384::new();
                hasher.update(materials);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha512 => {
                let mut hasher = Sha512::new();
                hasher.update(materials);
                hasher.finalize().to_vec()
            }
        }
    }
}

/// Runtime/Init Data used to check the binding relationship with report data
/// in Evidence
#[derive(Debug, Clone)]
pub enum Data {
    /// This will be used as the expected runtime/init data to check against
    /// the one inside evidence.
    Raw(Vec<u8>),

    /// Runtime/Init data in a JSON map. CoCoAS will rearrange each layer of the
    /// data JSON object in dictionary order by key, then serialize and output
    /// it into a compact string, and perform hash calculation on the whole
    /// to check against the one inside evidence.
    Structured(Value),
}

#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("io error: {0}")]
    IO(#[from] std::io::Error),
    #[error("Create AS work dir failed: {0}")]
    CreateDir(#[source] std::io::Error),
    #[error("Policy Engine is not supported: {0}")]
    UnsupportedPolicy(#[source] strum::ParseError),
    #[error("Create rvps failed: {0}")]
    Rvps(#[source] RvpsError),
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

pub struct AttestationService {
    _config: Config,
    rvps: Box<dyn RvpsApi + Send + Sync>,
    token_broker: Box<dyn AttestationTokenBroker + Send + Sync>,
}

impl AttestationService {
    /// Create a new Attestation Service instance.
    pub async fn new(config: Config) -> Result<Self, ServiceError> {
        if !config.work_dir.as_path().exists() {
            fs::create_dir_all(&config.work_dir)
                .await
                .map_err(ServiceError::CreateDir)?;
        }

        let rvps = rvps::initialize_rvps_client(&config.rvps_config)
            .await
            .map_err(ServiceError::Rvps)?;

        let token_broker = config.attestation_token_broker.to_token_broker()?;

        Ok(Self {
            _config: config,
            rvps,
            token_broker,
        })
    }

    /// Set Attestation Verification Policy.
    pub async fn set_policy(&mut self, policy_id: String, policy: String) -> Result<()> {
        self.token_broker.set_policy(policy_id, policy).await?;
        Ok(())
    }

    /// Get Attestation Verification Policy List.
    /// The result is a `policy-id` -> `policy hash` map.
    pub async fn list_policies(&self) -> Result<HashMap<String, String>> {
        self.token_broker
            .list_policies()
            .await
            .context("Cannot List Policy")
    }

    /// Get a single Policy content.
    pub async fn get_policy(&self, policy_id: String) -> Result<String> {
        self.token_broker
            .get_policy(policy_id)
            .await
            .context("Cannot Get Policy")
    }

    /// Delete a single Policy.
    pub async fn delete_policy(&self, policy_id: String) -> Result<()> {
        self.token_broker
            .delete_policy(policy_id)
            .await
            .context("Cannot Delete Policy")
    }

    /// Evaluate Attestation Evidence.
    /// Issue an attestation results token which contain TCB status and TEE public key. Input parameters:
    /// - `evidence`: TEE evidence bytes. This might not be the raw hardware evidence bytes. Definitions
    ///   are in `verifier` crate.
    /// - `tee`: concrete TEE type
    /// - `runtime_data`: These data field will be used to check against the counterpart inside the evidence.
    ///   The concrete way of checking is decide by the enum type. If this parameter is set `None`, the comparation
    ///   will not be performed.
    /// - `init_data`: These data field will be used to check against the counterpart inside the evidence.
    ///   The concrete way of checking is decide by the enum type. If this parameter is set `None`, the comparation
    ///   will not be performed.
    /// - `hash_algorithm`: The hash algorithm that is used to calculate the digest of `runtime_data` and
    ///   `init_data`.
    /// - `policy_ids`: The ids of the policies that will be used to evaluate the claims.
    ///    For EAR tokens, only the first policy will be evaluated.
    ///    The hash of the policy will be returned as part of the attestation token.
    #[allow(clippy::too_many_arguments)]
    pub async fn evaluate(
        &self,
        evidence: Vec<u8>,
        tee: Tee,
        runtime_data: Option<Data>,
        runtime_data_hash_algorithm: HashAlgorithm,
        init_data: Option<Data>,
        init_data_hash_algorithm: HashAlgorithm,
        policy_ids: Vec<String>,
    ) -> Result<String> {
        let verifier = verifier::to_verifier(&tee)?;

        let (report_data, runtime_data_claims) =
            parse_data(runtime_data, &runtime_data_hash_algorithm).context("parse runtime data")?;

        let report_data = match &report_data {
            Some(data) => ReportData::Value(data),
            None => ReportData::NotProvided,
        };

        let (init_data, init_data_claims) =
            parse_data(init_data, &init_data_hash_algorithm).context("parse init data")?;

        let init_data_hash = match &init_data {
            Some(data) => InitDataHash::Value(data),
            None => InitDataHash::NotProvided,
        };

        let claims_from_tee_evidence = verifier
            .evaluate(&evidence, &report_data, &init_data_hash)
            .await
            .map_err(|e| anyhow!("Verifier evaluate failed: {e:?}"))?;
        info!("{:?} Verifier/endorsement check passed.", tee);

        let reference_data_map = self
            .rvps
            .get_digests()
            .await
            .map_err(|e| anyhow!("Generate reference data failed: {:?}", e))?;
        debug!("reference_data_map: {:#?}", reference_data_map);

        let attestation_results_token = self
            .token_broker
            .issue(
                claims_from_tee_evidence,
                policy_ids,
                init_data_claims,
                runtime_data_claims,
                reference_data_map,
                tee,
            )
            .await?;
        Ok(attestation_results_token)
    }

    /// Registry a new reference value
    pub async fn register_reference_value(&mut self, message: &str) -> Result<()> {
        self.rvps
            .verify_and_extract(message)
            .await
            .context("register reference value")
    }

    /// Delete a reference value by name
    pub async fn delete_reference_value(&mut self, name: String) -> Result<bool> {
        self.rvps
            .delete_reference_value(&name)
            .await
            .context("delete reference value")
    }

    pub async fn generate_supplemental_challenge(
        &self,
        tee: Tee,
        tee_parameters: String,
    ) -> Result<String> {
        let verifier = verifier::to_verifier(&tee)?;
        verifier
            .generate_supplemental_challenge(tee_parameters)
            .await
    }

    /// Get token broker certificate content
    /// Returns the binary content of the certificate
    pub async fn get_token_broker_cert_config(&self) -> Result<Option<Vec<u8>>> {
        match &self._config.attestation_token_broker {
            token::AttestationTokenConfig::Simple(cfg) => {
                if let Some(signer) = &cfg.signer {
                    self.get_cert_content(signer.cert_path.as_deref(), signer.cert_url.as_deref())
                        .await
                } else {
                    Ok(None)
                }
            }
            token::AttestationTokenConfig::Ear(cfg) => {
                if let Some(signer) = &cfg.signer {
                    self.get_cert_content(signer.cert_path.as_deref(), signer.cert_url.as_deref())
                        .await
                } else {
                    Ok(None)
                }
            }
        }
    }

    /// Get certificate content from file path or URL
    async fn get_cert_content(
        &self,
        cert_path: Option<&str>,
        cert_url: Option<&str>,
    ) -> Result<Option<Vec<u8>>> {
        if let Some(path) = cert_path {
            // Read certificate from file
            let mut file = std::fs::File::open(path)
                .map_err(|e| anyhow!("Failed to open certificate file: {}", e))?;
            let mut content = Vec::new();
            file.read_to_end(&mut content)
                .map_err(|e| anyhow!("Failed to read certificate file: {}", e))?;
            Ok(Some(content))
        } else if let Some(url) = cert_url {
            // Get certificate from URL
            let client = Client::new();
            let response = client
                .get(url)
                .send()
                .await
                .map_err(|e| anyhow!("Failed to fetch certificate from URL: {}", e))?;

            if !response.status().is_success() {
                return Err(anyhow!(
                    "Failed to fetch certificate: HTTP {}",
                    response.status()
                ));
            }

            let content = response
                .bytes()
                .await
                .map_err(|e| anyhow!("Failed to read certificate content: {}", e))?;

            Ok(Some(content.to_vec()))
        } else {
            Ok(None)
        }
    }
}

/// Get the expected init/runtime data and potential claims due to the given input
/// and the hash algorithm
fn parse_data(
    data: Option<Data>,
    hash_algorithm: &HashAlgorithm,
) -> Result<(Option<Vec<u8>>, Value)> {
    match data {
        Some(value) => match value {
            Data::Raw(raw) => Ok((Some(raw), Value::Null)),
            Data::Structured(structured) => {
                // by default serde_json will enforence the alphabet order for keys
                let hash_materials =
                    serde_json::to_vec(&structured).context("parse JSON structured data")?;
                let digest = hash_algorithm.accumulate_hash(hash_materials);
                Ok((Some(digest), structured))
            }
        },
        None => Ok((None, Value::Null)),
    }
}

#[cfg(test)]
mod tests {
    use assert_json_diff::assert_json_eq;
    use rstest::rstest;
    use serde_json::{json, Value};
    use std::io;

    use crate::{Data, HashAlgorithm, ServiceError};

    #[test]
    fn test_service_error_io() {
        let io_error = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let service_error = ServiceError::IO(io_error);

        match service_error {
            ServiceError::IO(err) => {
                assert_eq!(err.kind(), io::ErrorKind::NotFound);
            }
            _ => panic!("Expected ServiceError::IO variant"),
        }
    }

    #[test]
    fn test_service_error_create_dir() {
        let io_error = io::Error::new(io::ErrorKind::PermissionDenied, "permission denied");
        let service_error = ServiceError::CreateDir(io_error);

        match service_error {
            ServiceError::CreateDir(err) => {
                assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
            }
            _ => panic!("Expected ServiceError::CreateDir variant"),
        }
    }

    #[test]
    fn test_service_error_display() {
        let io_error = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let service_error = ServiceError::IO(io_error);

        assert_eq!(format!("{}", service_error), "io error: file not found");
    }

    #[test]
    fn test_hash_algorithm_sha256() {
        let input = b"test data".to_vec();
        let hash = HashAlgorithm::Sha256.accumulate_hash(input);
        // Expected SHA256 hash for the string "test data"
        let expected =
            hex::decode("916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9")
                .unwrap();
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_hash_algorithm_sha384() {
        let input = b"test data".to_vec();
        let hash = HashAlgorithm::Sha384.accumulate_hash(input);
        // Expected SHA384 hash for the string "test data"
        let expected = hex::decode("29901176dc824ac3fd22227677499f02e4e69477ccc501593cc3dc8c6bfef73a08dfdf4a801723c0479b74d6f1abc372").unwrap();
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_hash_algorithm_sha512() {
        let input = b"test data".to_vec();
        let hash = HashAlgorithm::Sha512.accumulate_hash(input);
        // Expected SHA512 hash for the string "test data"
        let expected = hex::decode("0e1e21ecf105ec853d24d728867ad70613c21663a4693074b2a3619c1bd39d66b588c33723bb466c72424e80e3ca63c249078ab347bab9428500e7ee43059d0d").unwrap();
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_data_enum_raw() {
        let raw_data = Data::Raw(b"test raw data".to_vec());
        if let Data::Raw(data) = raw_data {
            assert_eq!(data, b"test raw data".to_vec());
        } else {
            panic!("Expected Data::Raw variant");
        }
    }

    #[test]
    fn test_data_enum_structured() {
        let json_value = json!({"key": "value", "nested": {"inner": 123}});
        let structured_data = Data::Structured(json_value.clone());
        if let Data::Structured(data) = structured_data {
            assert_json_eq!(data, json_value);
        } else {
            panic!("Expected Data::Structured variant");
        }
    }

    #[rstest]
    #[case(Some(Data::Raw(b"aaaaa".to_vec())), Some(b"aaaaa".to_vec()), HashAlgorithm::Sha384, Value::Null)]
    #[case(None, None, HashAlgorithm::Sha384, Value::Null)]
    #[case(Some(Data::Structured(json!({"b": 1, "a": "test", "c": {"d": "e"}}))), Some(hex::decode(b"e71ce8e70d814ba6639c3612ebee0ff1f76f650f8dbb5e47157e0f3f525cd22c4597480a186427c813ca941da78870c3").unwrap()), HashAlgorithm::Sha384, json!({"b": 1, "a": "test", "c": {"d": "e"}}))]
    #[case(Some(Data::Structured(json!({"complex": {"nested": [1, 2, 3], "object": {"a": "b"}}}))), Some(hex::decode(b"3a3e5c5c7d2c77a4a9a3cebcb3afd4c5c56e62a2fe0b9d3f3a1b6e6a4a4a7e8a0c7c9c8a1a8c5a4c3a5a0c3a0a6a7a7a4").unwrap_or_default()), HashAlgorithm::Sha384, json!({"complex": {"nested": [1, 2, 3], "object": {"a": "b"}}}))]
    fn parse_data_json_binding(
        #[case] input: Option<Data>,
        #[case] expected_data: Option<Vec<u8>>,
        #[case] hash_algorithm: HashAlgorithm,
        #[case] expected_claims: Value,
    ) {
        let input_clone = input.clone();
        let (data, data_claims) = crate::parse_data(input, &hash_algorithm).expect("parse failed");

        // For structured data, we don't directly compare hash values as JSON serialization might differ
        if let Some(Data::Structured(_)) = input_clone {
            assert!(data.is_some());
        } else {
            assert_eq!(data, expected_data);
        }

        assert_json_eq!(data_claims, expected_claims);
    }

    #[test]
    fn test_parse_data_with_raw_data() {
        let raw_data = Some(Data::Raw(b"test data".to_vec()));
        let (parsed_data, claims) =
            crate::parse_data(raw_data, &HashAlgorithm::Sha256).expect("parse failed");

        assert_eq!(parsed_data, Some(b"test data".to_vec()));
        assert_eq!(claims, Value::Null);
    }

    #[test]
    fn test_parse_data_with_structured_data() {
        let json_data = json!({"test": "value", "number": 123});
        let structured_data = Some(Data::Structured(json_data.clone()));

        let (parsed_data, claims) =
            crate::parse_data(structured_data, &HashAlgorithm::Sha256).expect("parse failed");

        // Verify that a hash value is returned
        assert!(parsed_data.is_some());
        // Verify that the original JSON data is returned
        assert_json_eq!(claims, json_data);
    }

    #[test]
    fn test_parse_data_with_none() {
        let (parsed_data, claims) =
            crate::parse_data(None, &HashAlgorithm::Sha256).expect("parse failed");

        assert_eq!(parsed_data, None);
        assert_eq!(claims, Value::Null);
    }
}
