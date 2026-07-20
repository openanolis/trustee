// Copyright (c) 2026 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Regression test for initializing EncryptedDb through the production plugin
//! manager while already running inside the KBS async runtime.

#![cfg(feature = "encrypted-db")]

use std::io::Write;

use kbs::plugins::implementations::resource::encrypted_db::{
    DatabaseConfig, EncryptedDbBackendConfig,
};
use kbs::plugins::{PluginManager, PluginsConfig, RepositoryConfig};
use tempfile::NamedTempFile;

#[tokio::test]
async fn initializes_encrypted_db_through_plugin_manager() {
    let mut secret = NamedTempFile::new().expect("create master secret");
    secret
        .write_all(b"plugin-manager-runtime-regression")
        .expect("write master secret");
    secret.flush().expect("flush master secret");

    let config = EncryptedDbBackendConfig {
        master_secret_path: secret.path().to_string_lossy().into_owned(),
        database: DatabaseConfig {
            kind: "sqlite".to_string(),
            path: ":memory:".to_string(),
            ..Default::default()
        },
        ..Default::default()
    };

    let manager = PluginManager::new(vec![PluginsConfig::ResourceStorage(
        RepositoryConfig::EncryptedDb(config),
    )])
    .await
    .expect("EncryptedDb must initialize on the existing async runtime");

    assert!(manager.get("resource").is_some());
}
