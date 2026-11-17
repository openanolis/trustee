//! NVIDIA verifier settings shared by native AS, built-in KBS and library users.
use anyhow::{anyhow, ensure, Result};
use serde::Deserialize;
use std::sync::RwLock;

static LEGACY_RIM_URL: RwLock<Option<String>> = RwLock::new(None);

pub(crate) fn set_legacy_rim_url(url: Option<String>) {
    *LEGACY_RIM_URL.write().unwrap() = url;
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NvidiaVerificationMode {
    #[default]
    #[serde(alias = "local", alias = "Rim", alias = "Local")]
    Rim,
    #[serde(alias = "remote", alias = "Nras", alias = "Remote")]
    Nras,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct NvidiaVerifierConfig {
    pub mode: NvidiaVerificationMode,
    pub rim_url: String,
    pub ocsp_url: String,
    pub nras_url: String,
    pub nras_jwks_url: String,
    /// Trusted NVIDIA NVAT 2.x CLI, invoked directly without a shell.
    pub local_verifier_path: String,
    pub tls_ca_cert: Option<String>,
}

impl Default for NvidiaVerifierConfig {
    fn default() -> Self {
        Self {
            mode: NvidiaVerificationMode::Rim,
            rim_url: "https://rim.attestation.nvidia.com".into(),
            ocsp_url: "https://ocsp.ndis.nvidia.com".into(),
            nras_url: "https://nras.attestation.nvidia.com/v4/attest/gpu".into(),
            nras_jwks_url: "https://nras.attestation.nvidia.com/.well-known/jwks.json".into(),
            local_verifier_path: "/usr/bin/nvattest".into(),
            tls_ca_cert: None,
        }
    }
}

impl NvidiaVerifierConfig {
    /// Environment settings override the optional file configuration. Invalid
    /// overrides fail closed rather than silently selecting another mode.
    pub fn resolve(&self) -> Result<Self> {
        self.resolve_with(|name| {
            #[cfg(not(target_arch = "wasm32"))]
            {
                std::env::var(name).ok()
            }
            #[cfg(target_arch = "wasm32")]
            {
                let _ = name;
                None
            }
        })
    }

    fn resolve_with(&self, env: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let mut config = self.clone();
        if config.rim_url == Self::default().rim_url {
            if let Some(url) = LEGACY_RIM_URL.read().unwrap().clone() {
                config.rim_url = url;
            }
        }
        if let Some(url) = env("NV_RIM_URL") {
            config.rim_url = url.trim_end_matches('/').trim_end_matches("/v1/rim").into();
        }
        if let Some(mode) = env("TRUSTEE_NVIDIA_VERIFIER_MODE") {
            config.mode = match mode.to_ascii_lowercase().as_str() {
                "rim" | "local" => NvidiaVerificationMode::Rim,
                "nras" | "remote" => NvidiaVerificationMode::Nras,
                _ => {
                    return Err(anyhow!(
                        "Invalid TRUSTEE_NVIDIA_VERIFIER_MODE; expected rim or nras"
                    ))
                }
            };
        }
        for (name, field) in [
            ("TRUSTEE_NVIDIA_RIM_URL", &mut config.rim_url),
            ("TRUSTEE_NVIDIA_OCSP_URL", &mut config.ocsp_url),
            ("TRUSTEE_NVIDIA_NRAS_URL", &mut config.nras_url),
            ("TRUSTEE_NVIDIA_NRAS_JWKS_URL", &mut config.nras_jwks_url),
        ] {
            if let Some(value) = env(name) {
                *field = value;
            }
            ensure!(
                field.starts_with("https://"),
                "NVIDIA service URL must use HTTPS: {name}"
            );
        }
        if let Some(value) = env("TRUSTEE_NVIDIA_LOCAL_VERIFIER_PATH") {
            config.local_verifier_path = value;
        }
        ensure!(
            config.local_verifier_path.starts_with('/'),
            "NVIDIA local verifier path must be absolute"
        );
        if let Some(value) = env("TRUSTEE_NVIDIA_TLS_CA_CERT") {
            config.tls_ca_cert = Some(value);
        }
        if let Some(path) = &config.tls_ca_cert {
            ensure!(path.starts_with('/'), "NVIDIA TLS CA path must be absolute");
        }
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_is_local_rim() {
        let config: NvidiaVerifierConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(
            config.resolve_with(|_| None).unwrap().mode,
            NvidiaVerificationMode::Rim
        );
    }
    #[test]
    fn environment_overrides_file_in_both_directions() {
        for (file, env, expected) in [
            ("nras", "rim", NvidiaVerificationMode::Rim),
            ("rim", "nras", NvidiaVerificationMode::Nras),
        ] {
            let config: NvidiaVerifierConfig = serde_json::from_value(
                serde_json::json!({"mode": file, "rim_url": "https://file.example"}),
            )
            .unwrap();
            let config = config
                .resolve_with(|key| match key {
                    "TRUSTEE_NVIDIA_VERIFIER_MODE" => Some(env.into()),
                    "TRUSTEE_NVIDIA_RIM_URL" => Some("https://environment.example".into()),
                    _ => None,
                })
                .unwrap();
            assert_eq!(config.mode, expected);
            assert_eq!(config.rim_url, "https://environment.example");
        }
    }
    #[test]
    fn invalid_override_does_not_downgrade() {
        assert!(NvidiaVerifierConfig::default()
            .resolve_with(|_| Some("invalid".into()))
            .is_err());
    }
}
