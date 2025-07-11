// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! reference value for RVPS

use anyhow::{anyhow, Result};
use chrono::{DateTime, NaiveDateTime, Timelike, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use std::time::SystemTime;

/// Default version of ReferenceValue
pub const REFERENCE_VALUE_VERSION: &str = "0.1.0";

/// A HashValuePair stores a hash algorithm name
/// and relative artifact's hash value due to
/// the algorithm.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct HashValuePair {
    alg: String,
    value: String,
}

impl HashValuePair {
    pub fn new(alg: String, value: String) -> Self {
        Self { alg, value }
    }

    pub fn alg(&self) -> &String {
        &self.alg
    }

    pub fn value(&self) -> &String {
        &self.value
    }
}

/// Helper to deserialize an expired time
fn primitive_date_time_from_str<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<DateTime<Utc>, D::Error> {
    let s = <Option<&str>>::deserialize(d)?
        .ok_or_else(|| serde::de::Error::invalid_length(0, &"<TIME>"))?;

    let ndt = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%SZ")
        .map_err(|err| serde::de::Error::custom::<String>(err.to_string()))?;

    Ok(DateTime::from_naive_utc_and_offset(ndt, Utc))
}

/// Define Reference Value stored inside RVPS.
/// This Reference Value is not the same as that in IETF's RATS.
/// Here, ReferenceValue is stored inside RVPS. Its format MAY be modified.
/// * `version`: version of the reference value format.
/// * `name`: name of the artifact related to this reference value.
/// * `expiration`: Time after which refrence valid is invalid
/// * `hash_value`: A set of key-value pairs, each indicates a hash
///   algorithm and its relative hash value for the artifact.
///   The actual struct deliver from RVPS to AS is
///   [`TrustedDigest`], whose simple structure is easy
///   for AS to handle.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ReferenceValue {
    #[serde(default = "default_version")]
    pub version: String,
    pub name: String,
    #[serde(deserialize_with = "primitive_date_time_from_str")]
    pub expiration: DateTime<Utc>,
    #[serde(rename = "hash-value")]
    pub hash_value: Vec<HashValuePair>,
}

/// Set the default version for ReferenceValue
fn default_version() -> String {
    REFERENCE_VALUE_VERSION.into()
}

impl ReferenceValue {
    /// Create a new `ReferenceValue`, the `expiration`
    /// field's nanosecond will be set to 0. This avoid
    /// a rare bug that when the nanosecond of the time
    /// is not 0, the test case will fail.
    pub fn new() -> Result<Self> {
        Ok(ReferenceValue {
            version: REFERENCE_VALUE_VERSION.into(),
            name: String::new(),
            expiration: Utc::now()
                .with_nanosecond(0)
                .ok_or_else(|| anyhow!("set nanosecond failed."))?,
            hash_value: Vec::new(),
        })
    }

    /// Set version of the ReferenceValue.
    pub fn set_version(mut self, version: &str) -> Self {
        self.version = version.into();
        self
    }

    /// Get version of the ReferenceValue.
    pub fn version(&self) -> &String {
        &self.version
    }

    /// Set expired time of the ReferenceValue.
    pub fn set_expiration(mut self, expiration: DateTime<Utc>) -> Self {
        self.expiration = expiration
            .with_nanosecond(0)
            .expect("Set nanosecond failed.");
        self
    }

    /// Check whether reference value is expired
    pub fn expired(&self) -> bool {
        let now: DateTime<Utc> = DateTime::from(SystemTime::now());

        now > self.expiration
    }

    /// Set hash value of the ReferenceValue.
    pub fn add_hash_value(mut self, alg: String, value: String) -> Self {
        self.hash_value.push(HashValuePair::new(alg, value));
        self
    }

    /// Get hash value of the ReferenceValue.
    pub fn hash_values(&self) -> &Vec<HashValuePair> {
        &self.hash_value
    }

    /// Set artifact name for Reference Value
    pub fn set_name(mut self, name: &str) -> Self {
        self.name = name.into();
        self
    }

    /// Get artifact name of the ReferenceValue.
    pub fn name(&self) -> &String {
        &self.name
    }
}

/// Trusted Digest is what RVPS actually delivered to
/// AS, it will include:
/// * `name`: The name of the artifact, e.g., `linux-1.1.1`
/// * `hash_values`: digests that have been verified and can
///   be trusted, so we can refer them as `trusted digests`.
#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq, Eq)]
pub struct TrustedDigest {
    /// The resource name.
    pub name: String,
    /// The reference hash values, base64 coded.
    pub hash_values: Vec<String>,
}

#[cfg(test)]
mod test {
    use chrono::{TimeZone, Utc};
    use serde_json::json;

    use super::{HashValuePair, ReferenceValue, TrustedDigest};

    #[test]
    fn reference_value_serialize() {
        let rv = ReferenceValue::new()
            .expect("create ReferenceValue failed.")
            .set_version("1.0.0")
            .set_name("artifact")
            .set_expiration(Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap())
            .add_hash_value("sha512".into(), "123".into());

        assert_eq!(rv.version(), "1.0.0");

        let rv_json = json!({
            "expiration": "1970-01-01T00:00:00Z",
            "name": "artifact",
            "version": "1.0.0",
            "hash-value": [{
                "alg": "sha512",
                "value": "123"
            }]
        });

        let serialized_rf = serde_json::to_value(&rv).unwrap();
        assert_eq!(serialized_rf, rv_json);
    }

    #[test]
    fn reference_value_deserialize() {
        let rv = ReferenceValue::new()
            .expect("create ReferenceValue failed.")
            .set_version("1.0.0")
            .set_name("artifact")
            .set_expiration(Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap())
            .add_hash_value("sha512".into(), "123".into());

        assert_eq!(rv.version(), "1.0.0");
        let rv_json = r#"{
            "expiration": "1970-01-01T00:00:00Z",
            "name": "artifact",
            "version": "1.0.0",
            "hash-value": [{
                "alg": "sha512",
                "value": "123"
            }]
        }"#;
        let deserialized_rf: ReferenceValue = serde_json::from_str(&rv_json).unwrap();
        assert_eq!(deserialized_rf, rv);
    }

    #[test]
    fn test_hash_value_pair_getters() {
        let pair = HashValuePair::new("sha256".to_string(), "abcdef".to_string());
        assert_eq!(pair.alg(), "sha256");
        assert_eq!(pair.value(), "abcdef");
    }

    #[test]
    fn test_reference_value_new() {
        let rv = ReferenceValue::new().expect("Failed to create ReferenceValue");
        assert_eq!(rv.version, crate::reference_value::REFERENCE_VALUE_VERSION);
        assert_eq!(rv.name, "");
        assert!(rv.hash_value.is_empty());
    }

    #[test]
    fn test_reference_value_set_version() {
        let rv = ReferenceValue::new()
            .expect("Failed to create ReferenceValue")
            .set_version("2.0.0");
        assert_eq!(rv.version(), "2.0.0");
    }

    #[test]
    fn test_reference_value_set_name() {
        let rv = ReferenceValue::new()
            .expect("Failed to create ReferenceValue")
            .set_name("test_artifact");
        assert_eq!(rv.name(), "test_artifact");
    }

    #[test]
    fn test_reference_value_set_expiration() {
        let expiration = Utc.with_ymd_and_hms(2025, 12, 31, 23, 59, 59).unwrap();
        let rv = ReferenceValue::new()
            .expect("Failed to create ReferenceValue")
            .set_expiration(expiration);
        assert_eq!(rv.expiration, expiration);
    }

    #[test]
    fn test_reference_value_expired() {
        // Create a reference value that is already expired
        let past = Utc::now() - chrono::Duration::days(1);
        let rv_expired = ReferenceValue::new()
            .expect("Failed to create ReferenceValue")
            .set_expiration(past);
        assert!(rv_expired.expired(), "Reference value should be expired");

        // Create a reference value that is not yet expired
        let future = Utc::now() + chrono::Duration::days(1);
        let rv_valid = ReferenceValue::new()
            .expect("Failed to create ReferenceValue")
            .set_expiration(future);
        assert!(!rv_valid.expired(), "Reference value should not be expired");
    }

    #[test]
    fn test_reference_value_add_hash_value() {
        let rv = ReferenceValue::new()
            .expect("Failed to create ReferenceValue")
            .add_hash_value("sha256".to_string(), "abc123".to_string())
            .add_hash_value("sha384".to_string(), "def456".to_string());

        assert_eq!(rv.hash_values().len(), 2);
        assert_eq!(rv.hash_values()[0].alg(), "sha256");
        assert_eq!(rv.hash_values()[0].value(), "abc123");
        assert_eq!(rv.hash_values()[1].alg(), "sha384");
        assert_eq!(rv.hash_values()[1].value(), "def456");
    }

    #[test]
    fn test_reference_value_deserialize_invalid_date() {
        // Test with invalid date format
        let invalid_date_json = r#"{
            "expiration": "not-a-date",
            "name": "artifact",
            "version": "1.0.0",
            "hash-value": []
        }"#;

        let result: Result<ReferenceValue, _> = serde_json::from_str(invalid_date_json);
        assert!(result.is_err(), "Should fail to deserialize invalid date");
    }

    #[test]
    fn test_reference_value_deserialize_missing_date() {
        // Test with missing date
        let missing_date_json = r#"{
            "name": "artifact",
            "version": "1.0.0",
            "hash-value": []
        }"#;

        let result: Result<ReferenceValue, _> = serde_json::from_str(missing_date_json);
        assert!(result.is_err(), "Should fail to deserialize missing date");
    }

    #[test]
    fn test_trusted_digest() {
        let digest = TrustedDigest {
            name: "test_artifact".to_string(),
            hash_values: vec!["hash1".to_string(), "hash2".to_string()],
        };

        assert_eq!(digest.name, "test_artifact");
        assert_eq!(digest.hash_values.len(), 2);
        assert_eq!(digest.hash_values[0], "hash1");
        assert_eq!(digest.hash_values[1], "hash2");
    }

    #[test]
    fn test_trusted_digest_default() {
        let digest = TrustedDigest::default();
        assert_eq!(digest.name, "");
        assert!(digest.hash_values.is_empty());
    }

    #[test]
    fn test_trusted_digest_serialize_deserialize() {
        let digest = TrustedDigest {
            name: "test_artifact".to_string(),
            hash_values: vec!["hash1".to_string(), "hash2".to_string()],
        };

        let serialized = serde_json::to_string(&digest).expect("Failed to serialize");
        let deserialized: TrustedDigest =
            serde_json::from_str(&serialized).expect("Failed to deserialize");

        assert_eq!(deserialized.name, digest.name);
        assert_eq!(deserialized.hash_values, digest.hash_values);
    }
}
