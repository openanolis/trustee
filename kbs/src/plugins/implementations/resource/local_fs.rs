// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use super::{ResourceDesc, StorageBackend};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::{
    boxed::Box,
    fs,
    path::{Path, PathBuf},
    pin::Pin,
};
use tokio::fs as async_fs;

pub const DEFAULT_REPO_DIR_PATH: &str = "/opt/confidential-containers/kbs/repository";

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct LocalFsRepoDesc {
    #[serde(default)]
    pub dir_path: String,
}

impl Default for LocalFsRepoDesc {
    fn default() -> Self {
        Self {
            dir_path: DEFAULT_REPO_DIR_PATH.into(),
        }
    }
}

pub struct LocalFs {
    pub repo_dir_path: String,
}

#[async_trait::async_trait]
impl StorageBackend for LocalFs {
    async fn read_secret_resource(&self, resource_desc: ResourceDesc) -> Result<Vec<u8>> {
        let mut resource_path = PathBuf::from(&self.repo_dir_path);

        let ref_resource_path = format!(
            "{}/{}/{}",
            resource_desc.repository_name, resource_desc.resource_type, resource_desc.resource_tag
        );
        resource_path.push(ref_resource_path);

        let resource_byte = tokio::fs::read(&resource_path)
            .await
            .context("read resource from local fs")?;
        Ok(resource_byte)
    }

    async fn write_secret_resource(&self, resource_desc: ResourceDesc, data: &[u8]) -> Result<()> {
        let mut resource_path = PathBuf::from(&self.repo_dir_path);
        resource_path.push(resource_desc.repository_name);
        resource_path.push(resource_desc.resource_type);

        if !Path::new(&resource_path).exists() {
            tokio::fs::create_dir_all(&resource_path)
                .await
                .context("create new resource path")?;
        }

        resource_path.push(resource_desc.resource_tag);

        // Note that the local fs does not handle synchronization conditions
        // because it is only for test use case and we assume the write request
        // will not happen togetherly with reads.
        // If it is to be used in productive scenarios, it is recommended that
        // the storage is marked as read-only and written out-of-band.
        tokio::fs::write(resource_path, data)
            .await
            .context("write local fs")
    }

    async fn list_secret_resources(&self) -> Result<Vec<ResourceDesc>> {
        let base_path = PathBuf::from(&self.repo_dir_path);
        let results = Self::scan_directory(&base_path, Vec::new()).await?;
        Ok(results)
    }
}

impl LocalFs {
    fn scan_directory(
        path: &Path,
        path_components: Vec<String>,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<Vec<ResourceDesc>>> + Send + '_>> {
        Box::pin(async move {
            let mut results = Vec::new();

            let mut entries = match async_fs::read_dir(path).await {
                Ok(entries) => entries,
                Err(_) => return Ok(results),
            };
            while let Ok(Some(entry)) = entries.next_entry().await {
                let metadata = match entry.metadata().await {
                    Ok(metadata) => metadata,
                    Err(_) => continue,
                };

                let entry_name = match entry.file_name().to_str() {
                    Some(name) => name.to_string(),
                    None => continue,
                };

                let mut current_path_components = path_components.clone();
                current_path_components.push(entry_name);

                if metadata.is_dir() && current_path_components.len() < 3 {
                    let sub_results =
                        Self::scan_directory(&entry.path(), current_path_components).await?;
                    results.extend(sub_results);
                } else if metadata.is_file() && current_path_components.len() == 3 {
                    results.push(ResourceDesc {
                        repository_name: current_path_components[0].clone(),
                        resource_type: current_path_components[1].clone(),
                        resource_tag: current_path_components[2].clone(),
                    });
                }
            }

            Ok(results)
        })
    }

    pub fn new(repo_desc: &LocalFsRepoDesc) -> anyhow::Result<Self> {
        // Create repository dir.
        if !Path::new(&repo_desc.dir_path).exists() {
            fs::create_dir_all(&repo_desc.dir_path)?;
        }
        // Create default repo.
        if !Path::new(&format!("{}/default", &repo_desc.dir_path)).exists() {
            fs::create_dir_all(format!("{}/default", &repo_desc.dir_path))?;
        }

        Ok(Self {
            repo_dir_path: repo_desc.dir_path.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        local_fs::{LocalFs, LocalFsRepoDesc},
        ResourceDesc, StorageBackend,
    };

    const TEST_DATA: &[u8] = b"testdata";

    #[tokio::test]
    async fn write_and_read_resource() {
        let tmp_dir = tempfile::tempdir().expect("create temp dir failed");
        let repo_desc = LocalFsRepoDesc {
            dir_path: tmp_dir.path().to_string_lossy().to_string(),
        };

        let local_fs = LocalFs::new(&repo_desc).expect("create local fs failed");
        let resource_desc = ResourceDesc {
            repository_name: "default".into(),
            resource_type: "test".into(),
            resource_tag: "test".into(),
        };

        local_fs
            .write_secret_resource(resource_desc.clone(), TEST_DATA)
            .await
            .expect("write secret resource failed");
        let data = local_fs
            .read_secret_resource(resource_desc)
            .await
            .expect("read secret resource failed");

        assert_eq!(&data[..], TEST_DATA);
    }
}
