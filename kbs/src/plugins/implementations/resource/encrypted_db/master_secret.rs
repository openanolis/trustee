// Copyright (c) 2026 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Master secret loading + Argon2id KDF for the `EncryptedDb` backend. Real
//! implementation lands in commit 2 (this scaffold only exposes the type so
//! the surrounding module compiles).

/// Reads the master passphrase from a file (typically a Kubernetes Secret
/// mounted as a tmpfs file at `/run/trustee/master.passphrase`).
pub struct FileMasterSecretProvider {
    _path: String,
}

impl FileMasterSecretProvider {
    pub fn new(path: &str) -> Self {
        Self {
            _path: path.to_string(),
        }
    }
}
