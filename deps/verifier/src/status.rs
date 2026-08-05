use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Runtime status of an external dependency used by an evidence verifier.
///
/// The shape is intentionally verifier-agnostic so additional dependencies
/// (KDS, registrar, RIM services, and so on) can expose status without adding
/// transport-specific APIs.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DependencyStatus {
    /// Stable dependency kind, for example `tdx-collateral-cache`.
    pub kind: String,
    /// Stable instance identifier within the dependency kind.
    pub name: String,
    /// Machine-readable state such as `ready`, `degraded`, or `unhealthy`.
    pub status: String,
    /// Human-readable summary suitable for health dashboards.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Dependency-specific values. Values remain typed on REST responses and
    /// are JSON-encoded when bridged to the protobuf status API.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub details: BTreeMap<String, Value>,
}

impl DependencyStatus {
    pub fn is_unhealthy(&self) -> bool {
        self.status == "unhealthy"
    }

    pub fn is_degraded(&self) -> bool {
        self.status == "degraded"
    }
}
