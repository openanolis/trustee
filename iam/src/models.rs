//! Core IAM data models and request/response payloads.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{self, Deserialize, Serialize};
use uuid::Uuid;

pub type AccountId = String;
pub type PrincipalId = String;
pub type RoleId = String;
pub type ResourceArn = String;

/// Logical tenant boundary that owns principals and resources.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Account {
    pub id: AccountId,
    pub name: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    pub created_at: DateTime<Utc>,
}

/// Security principal (human, workload, service, etc.).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Principal {
    pub id: PrincipalId,
    pub account_id: AccountId,
    pub name: String,
    pub principal_type: PrincipalType,
    #[serde(default, skip_serializing_if = "Attributes::is_empty")]
    pub attributes: Attributes,
    pub created_at: DateTime<Utc>,
}

/// Known principal persona categories.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PrincipalType {
    Human,
    Service,
    Runtime,
    External,
    Unknown,
}

impl Default for PrincipalType {
    fn default() -> Self {
        Self::Unknown
    }
}

/// Resource registration metadata (maps to ARN).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Resource {
    pub arn: ResourceArn,
    pub owner_account_id: AccountId,
    pub resource_type: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tags: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Attributes::is_empty")]
    pub attributes: Attributes,
    pub created_at: DateTime<Utc>,
}

/// Role combines trust/access policies and metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Role {
    pub id: RoleId,
    pub name: String,
    pub description: Option<String>,
    pub trust_policy: PolicyDocument,
    pub access_policy: PolicyDocument,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    pub created_at: DateTime<Utc>,
}

/// IAM policy document (trust or access).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyDocument {
    #[serde(default = "default_policy_version")]
    pub version: String,
    #[serde(default)]
    pub statements: Vec<Statement>,
}

impl Default for PolicyDocument {
    fn default() -> Self {
        Self {
            version: default_policy_version(),
            statements: Vec::new(),
        }
    }
}

/// Individual statement within a policy document.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Statement {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    pub effect: Effect,
    pub actions: Vec<String>,
    pub resources: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Effect {
    #[serde(rename = "Allow")]
    Allow,
    #[serde(rename = "Deny")]
    Deny,
}

/// Condition expression using a single operator/key/value-set.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Condition {
    pub operator: ConditionOperator,
    pub key: String,
    pub values: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ConditionOperator {
    StringEquals,
    StringLike,
    Bool,
}

/// Free-form metadata container stored alongside principals/resources.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Attributes {
    #[serde(default)]
    pub values: serde_json::Map<String, serde_json::Value>,
}

impl Attributes {
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

impl From<serde_json::Map<String, serde_json::Value>> for Attributes {
    fn from(values: serde_json::Map<String, serde_json::Value>) -> Self {
        Self { values }
    }
}

/// Request payload for creating an account.
#[derive(Debug, Deserialize)]
pub struct CreateAccountRequest {
    pub name: String,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

/// Response wrapper for account creation/read APIs.
#[derive(Debug, Serialize)]
pub struct AccountResponse {
    pub account: Account,
}

/// Request payload for creating a principal under an account.
#[derive(Debug, Deserialize)]
pub struct CreatePrincipalRequest {
    pub name: String,
    #[serde(default)]
    pub principal_type: PrincipalType,
    #[serde(default)]
    pub attributes: Attributes,
}

/// Response wrapper for principal APIs.
#[derive(Debug, Serialize)]
pub struct PrincipalResponse {
    pub principal: Principal,
}

/// Request payload for resource registration.
#[derive(Debug, Deserialize)]
pub struct RegisterResourceRequest {
    pub owner_account_id: AccountId,
    pub resource_type: String,
    #[serde(default)]
    pub tags: BTreeMap<String, String>,
    #[serde(default)]
    pub attributes: Attributes,
}

/// Response wrapper for resource operations.
#[derive(Debug, Serialize)]
pub struct ResourceResponse {
    pub resource: Resource,
}

/// Request payload for creating a role.
#[derive(Debug, Deserialize)]
pub struct CreateRoleRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub trust_policy: PolicyDocument,
    pub access_policy: PolicyDocument,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

/// Response wrapper for role operations.
#[derive(Debug, Serialize)]
pub struct RoleResponse {
    pub role: Role,
}

/// Request payload for AssumeRole/STSlike exchange.
#[derive(Debug, Deserialize)]
pub struct AssumeRoleRequest {
    pub principal_id: PrincipalId,
    pub role_id: RoleId,
    #[serde(default)]
    pub requested_duration_seconds: Option<u64>,
    #[serde(default)]
    pub session_name: Option<String>,
    #[serde(default)]
    pub attestation_token: Option<String>,
    #[serde(default)]
    pub context: Option<serde_json::Map<String, serde_json::Value>>,
}

/// STS response containing the opaque signed token.
#[derive(Debug, Serialize)]
pub struct AssumeRoleResponse {
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

/// Authorization evaluation request (used by proxies/services).
#[derive(Debug, Deserialize)]
pub struct EvaluateRequest {
    pub token: String,
    pub action: String,
    pub resource: ResourceArn,
    #[serde(default)]
    pub context: Option<serde_json::Map<String, serde_json::Value>>,
}

/// Result of authorization evaluation.
#[derive(Debug, Serialize)]
pub struct EvaluateResponse {
    pub allowed: bool,
}

/// JWT claims embedded inside every IAM session token.
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionClaims {
    pub sub: PrincipalId,
    pub tenant: AccountId,
    pub role: RoleId,
    pub iss: String,
    pub iat: i64,
    pub exp: i64,
    #[serde(default)]
    pub session_name: Option<String>,
    #[serde(default)]
    pub env: serde_json::Map<String, serde_json::Value>,
    #[serde(default)]
    pub custom: serde_json::Map<String, serde_json::Value>,
}

impl SessionClaims {
    /// Convert the numeric expiry into `DateTime`.
    pub fn expires_at(&self) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(self.exp, 0)
            .unwrap_or_else(|| DateTime::<Utc>::from_timestamp(0, 0).expect("unix epoch is valid"))
    }
}

/// Generate a random identifier with a stable prefix.
pub fn generate_id(prefix: &str) -> String {
    format!("{}-{}", prefix, Uuid::new_v4())
}

fn default_policy_version() -> String {
    "2025-01-01".to_string()
}
