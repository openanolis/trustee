// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//
use serde::Deserialize;

use crate::storage::ReferenceValueStorageConfig;

#[derive(Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Config {
    #[serde(default)]
    pub storage: ReferenceValueStorageConfig,
}

#[cfg(feature = "bin")]
use anyhow::{Context, Result};

impl Config {
    /// Load config from a file. Only the `rvps` binary uses this; the library
    /// core (and library consumers like attestation-service/kbs) construct
    /// `Config` directly, so this is gated behind the `bin` feature to keep the
    /// `config` crate out of the library's dependency closure.
    #[cfg(feature = "bin")]
    pub fn from_file(config_path: &str) -> Result<Self> {
        let c = config::Config::builder()
            .add_source(config::File::with_name(config_path))
            .build()?;

        let res = c.try_deserialize().context("invalid config")?;
        Ok(res)
    }
}
