// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "nebula-ca-plugin")]
pub mod nebula_ca;
#[cfg(feature = "pkcs11")]
pub mod pkcs11;
#[cfg(feature = "tpm-pca")]
pub mod tpm_pca;

pub mod resource;
pub mod sample;

#[cfg(feature = "nebula-ca-plugin")]
pub use nebula_ca::{NebulaCaPlugin, NebulaCaPluginConfig};
#[cfg(feature = "pkcs11")]
pub use pkcs11::{Pkcs11Backend, Pkcs11Config};
#[cfg(feature = "tpm-pca")]
pub use tpm_pca::{TpmCaConfig, TpmCaPlugin};

pub use resource::{RepositoryConfig, ResourceStorage};
pub use sample::{Sample, SampleConfig};
