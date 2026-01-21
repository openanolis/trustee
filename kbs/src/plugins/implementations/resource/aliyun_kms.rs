// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use super::backend::{ResourceDesc, StorageBackend};
use anyhow::{anyhow, Context, Result};
use derivative::Derivative;
use kms::{plugins::aliyun::AliyunKmsClient, Annotations, Getter};
use log::info;
use serde::Deserialize;
use std::env;

#[derive(Derivative, Deserialize, Clone, PartialEq)]
#[derivative(Debug)]
pub struct AliyunKmsBackendConfig {
    #[derivative(Debug = "ignore")]
    client_key: Option<String>,
    kms_instance_id: Option<String>,
    #[derivative(Debug = "ignore")]
    password: Option<String>,
    cert_pem: Option<String>,
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

        let client = if has_client_key && has_instance_id && has_password && has_cert {
            AliyunKmsClient::new(
                repo_desc.client_key.as_ref().expect("checked"),
                repo_desc.kms_instance_id.as_ref().expect("checked"),
                repo_desc.password.as_ref().expect("checked"),
                repo_desc.cert_pem.as_ref().expect("checked"),
            )
            .context("create aliyun KMS backend with AAP client key")?
        } else {
            let access_key_id = env::var("ALIYUN_KMS_ACCESS_KEY_ID").map_err(|_| {
                anyhow!(
                    "missing ALIYUN_KMS_ACCESS_KEY_ID env var and AAP client key config is incomplete"
                )
            })?;
            let access_key_secret = env::var("ALIYUN_KMS_ACCESS_KEY_SECRET").map_err(|_| {
                anyhow!(
                    "missing ALIYUN_KMS_ACCESS_KEY_SECRET env var and AAP client key config is incomplete"
                )
            })?;
            let region_id = env::var("ALIYUN_KMS_REGION_ID").map_err(|_| {
                anyhow!(
                    "missing ALIYUN_KMS_REGION_ID env var and AAP client key config is incomplete"
                )
            })?;
            AliyunKmsClient::new_access_key_client(&access_key_id, &access_key_secret, &region_id)
                .context("create aliyun KMS backend with AccessKey")?
        };
        Ok(Self { client })
    }
}
