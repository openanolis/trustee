// Copyright (c) 2026 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

pub(super) const ALG_RSA_OAEP_256: &str = "RSA-OAEP-256";

/// Wire format shared by EncryptedLocalFs and EncryptedDb.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub(super) struct Envelope {
    pub alg: String,
    pub enc_key: String,
    pub iv: String,
    pub ciphertext: String,
    pub tag: String,
}

impl Envelope {
    pub(super) fn validate_algorithm(&self) -> Result<()> {
        if self.alg != ALG_RSA_OAEP_256 {
            bail!(
                "unsupported resource envelope alg `{}`; use RSA-OAEP-256",
                self.alg
            );
        }
        Ok(())
    }

    pub(super) fn validate_new_write(data: &[u8]) -> Result<()> {
        if let Ok(envelope) = serde_json::from_slice::<Self>(data) {
            envelope.validate_algorithm()?;
        }
        Ok(())
    }
}
