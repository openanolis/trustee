// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

pub mod local_fs;

#[cfg(feature = "aliyun")]
pub mod aliyun_kms;

use actix_web::http::Method;
use anyhow::{bail, Context, Result};

pub mod backend;
pub use backend::*;

use super::super::plugin_manager::ClientPlugin;

#[async_trait::async_trait]
impl ClientPlugin for ResourceStorage {
    async fn handle(
        &self,
        body: &[u8],
        _query: &str,
        path: &str,
        method: &Method,
    ) -> Result<Vec<u8>> {
        let resource_desc = path
            .strip_prefix('/')
            .context("accessed path is illegal, should start with `/`")?;
        match method.as_str() {
            "POST" => {
                let resource_description = ResourceDesc::try_from(resource_desc)?;
                self.set_secret_resource(resource_description, body).await?;
                Ok(vec![])
            }
            "GET" => {
                // Check if this is a list request based on path pattern
                if resource_desc == "resources" {
                    let resources = self.list_secret_resources().await?;
                    let json_response = serde_json::to_vec(&resources)
                        .context("Failed to serialize resource list")?;
                    Ok(json_response)
                } else {
                    // Handle single resource request
                    let resource_description = ResourceDesc::try_from(resource_desc)?;
                    let resource = self.get_secret_resource(resource_description).await?;
                    Ok(resource)
                }
            }
            _ => bail!("Illegal HTTP method. Only supports `GET` and `POST`"),
        }
    }

    async fn validate_auth(
        &self,
        _body: &[u8],
        _query: &str,
        _path: &str,
        method: &Method,
    ) -> Result<bool> {
        if method.as_str() == "POST" {
            return Ok(true);
        }

        Ok(false)
    }

    async fn encrypted(
        &self,
        _body: &[u8],
        _query: &str,
        _path: &str,
        method: &Method,
    ) -> Result<bool> {
        if method.as_str() == "GET" {
            return Ok(true);
        }

        Ok(false)
    }
}
