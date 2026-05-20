// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use super::backend::{ResourceDesc, StorageBackend};
use anyhow::{anyhow, Context, Result};
use derivative::Derivative;
use kms::{plugins::aliyun::AliyunKmsClient, Annotations, Getter};
use log::info;
use serde::Deserialize;
use std::{env, fmt::Display, str::FromStr};

const ENV_ALIYUN_CLIENT_KEY: &str = "KBS_RESOURCE_STORAGE_ALIYUN_CLIENT_KEY";
const ENV_ALIYUN_KMS_INSTANCE_ID: &str = "KBS_RESOURCE_STORAGE_ALIYUN_KMS_INSTANCE_ID";
const ENV_ALIYUN_PASSWORD: &str = "KBS_RESOURCE_STORAGE_ALIYUN_PASSWORD";
const ENV_ALIYUN_CERT_PEM: &str = "KBS_RESOURCE_STORAGE_ALIYUN_CERT_PEM";
const ENV_ALIYUN_ACCESS_KEY_ID: &str = "KBS_RESOURCE_STORAGE_ALIYUN_ACCESS_KEY_ID";
const ENV_ALIYUN_ACCESS_KEY_SECRET: &str = "KBS_RESOURCE_STORAGE_ALIYUN_ACCESS_KEY_SECRET";
const ENV_ALIYUN_REGION_ID: &str = "KBS_RESOURCE_STORAGE_ALIYUN_REGION_ID";
const ENV_ALIYUN_ENDPOINT: &str = "KBS_RESOURCE_STORAGE_ALIYUN_ENDPOINT";
const ENV_ALIYUN_INSECURE_SKIP_TLS_VERIFY: &str =
    "KBS_RESOURCE_STORAGE_ALIYUN_INSECURE_SKIP_TLS_VERIFY";

#[derive(Derivative, Deserialize, Clone, PartialEq)]
#[derivative(Debug)]
pub struct AliyunKmsBackendConfig {
    #[derivative(Debug = "ignore")]
    client_key: Option<String>,
    kms_instance_id: Option<String>,
    #[derivative(Debug = "ignore")]
    password: Option<String>,
    cert_pem: Option<String>,
    #[derivative(Debug = "ignore")]
    access_key_id: Option<String>,
    #[derivative(Debug = "ignore")]
    access_key_secret: Option<String>,
    region_id: Option<String>,
    endpoint: Option<String>,
    #[serde(default)]
    insecure_skip_tls_verify: bool,
}

impl Default for AliyunKmsBackendConfig {
    fn default() -> Self {
        Self {
            client_key: None,
            kms_instance_id: None,
            password: None,
            cert_pem: None,
            access_key_id: None,
            access_key_secret: None,
            region_id: None,
            endpoint: None,
            insecure_skip_tls_verify: false,
        }
    }
}

impl AliyunKmsBackendConfig {
    pub(crate) fn env_overrides_present() -> bool {
        [
            ENV_ALIYUN_CLIENT_KEY,
            ENV_ALIYUN_KMS_INSTANCE_ID,
            ENV_ALIYUN_PASSWORD,
            ENV_ALIYUN_CERT_PEM,
            ENV_ALIYUN_ACCESS_KEY_ID,
            ENV_ALIYUN_ACCESS_KEY_SECRET,
            ENV_ALIYUN_REGION_ID,
            ENV_ALIYUN_ENDPOINT,
            ENV_ALIYUN_INSECURE_SKIP_TLS_VERIFY,
        ]
        .into_iter()
        .any(|name| env::var_os(name).is_some())
    }

    pub(crate) fn apply_env_overrides(&mut self) -> Result<()> {
        set_optional_string_from_env(&mut self.client_key, ENV_ALIYUN_CLIENT_KEY)?;
        set_optional_string_from_env(&mut self.kms_instance_id, ENV_ALIYUN_KMS_INSTANCE_ID)?;
        set_optional_string_from_env(&mut self.password, ENV_ALIYUN_PASSWORD)?;
        set_optional_string_from_env(&mut self.cert_pem, ENV_ALIYUN_CERT_PEM)?;
        set_optional_string_from_env(&mut self.access_key_id, ENV_ALIYUN_ACCESS_KEY_ID)?;
        set_optional_string_from_env(&mut self.access_key_secret, ENV_ALIYUN_ACCESS_KEY_SECRET)?;
        set_optional_string_from_env(&mut self.region_id, ENV_ALIYUN_REGION_ID)?;
        set_optional_string_from_env(&mut self.endpoint, ENV_ALIYUN_ENDPOINT)?;

        if let Some(insecure_skip_tls_verify) = env_parse(ENV_ALIYUN_INSECURE_SKIP_TLS_VERIFY)? {
            self.insecure_skip_tls_verify = insecure_skip_tls_verify;
        }

        Ok(())
    }
}

fn set_optional_string_from_env(target: &mut Option<String>, name: &str) -> Result<()> {
    if let Some(value) = env_string(name)? {
        *target = Some(value);
    }

    Ok(())
}

fn env_string(name: &str) -> Result<Option<String>> {
    match env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(err) => Err(anyhow!("read environment variable {name}: {err}")),
    }
}

fn env_parse<T>(name: &str) -> Result<Option<T>>
where
    T: FromStr,
    T::Err: Display,
{
    env_string(name)?
        .map(|value| {
            value
                .parse::<T>()
                .map_err(|err| anyhow!("parse environment variable {name}: {err}"))
        })
        .transpose()
}

pub struct AliyunKmsBackend {
    client: AliyunKmsClient,
}

#[async_trait::async_trait]
impl StorageBackend for AliyunKmsBackend {
    async fn read_secret_resource(&self, resource_desc: ResourceDesc) -> Result<Vec<u8>> {
        info!(
            "Use aliyun KMS backend. Ignore {}/{}",
            resource_desc.repository_name, resource_desc.resource_type
        );
        let name = resource_desc.resource_tag;
        let resource_bytes = self
            .client
            .get_secret(&name, &Annotations::default())
            .await
            .context("failed to get resource from aliyun KMS")?;
        Ok(resource_bytes)
    }

    async fn write_secret_resource(
        &self,
        _resource_desc: ResourceDesc,
        _data: &[u8],
    ) -> Result<()> {
        todo!("Does not support!")
    }

    async fn delete_secret_resource(&self, _resource_desc: ResourceDesc) -> Result<()> {
        todo!("Does not support!")
    }

    async fn list_secret_resources(&self) -> Result<Vec<ResourceDesc>> {
        todo!("Does not support!")
    }
}

impl AliyunKmsBackend {
    pub fn new(repo_desc: &AliyunKmsBackendConfig) -> Result<Self> {
        let has_client_key = repo_desc
            .client_key
            .as_ref()
            .map(|v| !v.is_empty())
            .unwrap_or(false);
        let has_instance_id = repo_desc
            .kms_instance_id
            .as_ref()
            .map(|v| !v.is_empty())
            .unwrap_or(false);
        let has_password = repo_desc
            .password
            .as_ref()
            .map(|v| !v.is_empty())
            .unwrap_or(false);
        let has_cert = repo_desc
            .cert_pem
            .as_ref()
            .map(|v| !v.is_empty())
            .unwrap_or(false);
        let has_endpoint = repo_desc
            .endpoint
            .as_ref()
            .map(|v| !v.is_empty())
            .unwrap_or(false);
        let has_access_key_id = repo_desc
            .access_key_id
            .as_ref()
            .map(|v| !v.is_empty())
            .unwrap_or(false);
        let has_access_key_secret = repo_desc
            .access_key_secret
            .as_ref()
            .map(|v| !v.is_empty())
            .unwrap_or(false);
        let has_region_id = repo_desc
            .region_id
            .as_ref()
            .map(|v| !v.is_empty())
            .unwrap_or(false);

        let client = if has_client_key
            && has_instance_id
            && has_password
            && (has_cert || repo_desc.insecure_skip_tls_verify)
        {
            AliyunKmsClient::new_client_key_client_with_options(
                repo_desc.client_key.as_ref().expect("checked"),
                repo_desc.kms_instance_id.as_ref().expect("checked"),
                repo_desc.password.as_ref().expect("checked"),
                repo_desc.cert_pem.as_deref(),
                has_endpoint.then(|| repo_desc.endpoint.as_ref().expect("checked").as_str()),
                repo_desc.insecure_skip_tls_verify,
            )
            .context("create aliyun KMS backend with AAP client key")?
        } else {
            if has_access_key_id != has_access_key_secret {
                return Err(anyhow!(
                    "access_key_id and access_key_secret must be configured together"
                ));
            }

            let access_key_id = if has_access_key_id {
                repo_desc.access_key_id.as_ref().expect("checked").clone()
            } else {
                env::var("ALIYUN_KMS_ACCESS_KEY_ID").map_err(|_| {
                    anyhow!(
                        "missing ALIYUN_KMS_ACCESS_KEY_ID env var and AAP client key config is incomplete"
                    )
                })?
            };
            let access_key_secret = if has_access_key_secret {
                repo_desc
                    .access_key_secret
                    .as_ref()
                    .expect("checked")
                    .clone()
            } else {
                env::var("ALIYUN_KMS_ACCESS_KEY_SECRET").map_err(|_| {
                    anyhow!(
                        "missing ALIYUN_KMS_ACCESS_KEY_SECRET env var and AAP client key config is incomplete"
                    )
                })?
            };
            let region_id = if has_region_id {
                repo_desc.region_id.as_ref().expect("checked").clone()
            } else {
                env::var("ALIYUN_KMS_REGION_ID").map_err(|_| {
                    anyhow!(
                        "missing ALIYUN_KMS_REGION_ID env var and AAP client key config is incomplete"
                    )
                })?
            };

            AliyunKmsClient::new_access_key_client_with_options(
                &access_key_id,
                &access_key_secret,
                &region_id,
                has_endpoint.then(|| repo_desc.endpoint.as_ref().expect("checked").as_str()),
                repo_desc.cert_pem.as_deref(),
                repo_desc.insecure_skip_tls_verify,
            )
            .context("create aliyun KMS backend with AccessKey")?
        };
        Ok(Self { client })
    }
}

#[cfg(test)]
mod tests {
    use super::AliyunKmsBackendConfig;

    #[test]
    fn parse_access_key_private_cloud_config() {
        let config: AliyunKmsBackendConfig = toml::from_str(
            r#"
            access_key_id = "ak"
            access_key_secret = "sk"
            region_id = "cn-test"
            endpoint = "kms-intranet.cn-test.example.com"
            cert_pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
            insecure_skip_tls_verify = false
            "#,
        )
        .unwrap();

        assert_eq!(config.access_key_id.as_deref(), Some("ak"));
        assert_eq!(config.access_key_secret.as_deref(), Some("sk"));
        assert_eq!(config.region_id.as_deref(), Some("cn-test"));
        assert_eq!(
            config.endpoint.as_deref(),
            Some("kms-intranet.cn-test.example.com")
        );
        assert!(!config.insecure_skip_tls_verify);
    }

    #[test]
    fn default_tls_verify_is_enabled() {
        let config: AliyunKmsBackendConfig = toml::from_str(
            r#"
            access_key_id = "ak"
            access_key_secret = "sk"
            region_id = "cn-test"
            "#,
        )
        .unwrap();

        assert!(!config.insecure_skip_tls_verify);
    }
}
