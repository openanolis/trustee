// Copyright (c) 2026 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

pub type Result<T> = std::result::Result<T, StorageError>;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("invalid storage configuration: {message}")]
    InvalidConfiguration { message: String },

    #[error("invalid storage namespace `{namespace}`")]
    InvalidNamespace { namespace: String },

    #[error("invalid storage key `{key}`")]
    InvalidKey { key: String },

    #[error("storage backend does not support {capability}")]
    UnsupportedCapability { capability: &'static str },

    #[error("storage backend operation failed: {message}")]
    Backend { message: String },

    #[cfg(feature = "mysql")]
    #[error("storage backend operation failed: {message}")]
    Database {
        code: Option<String>,
        message: String,
    },
}

#[cfg(feature = "mysql")]
impl StorageError {
    pub(crate) fn is_retryable_mysql_transaction(&self) -> bool {
        matches!(
            self,
            Self::Database {
                code: Some(code),
                ..
            } if matches!(code.as_str(), "1205" | "1213" | "40001")
        )
    }
}

#[cfg(feature = "mysql")]
impl From<sqlx::Error> for StorageError {
    fn from(value: sqlx::Error) -> Self {
        let code = match &value {
            sqlx::Error::Database(error) => error.code().map(|code| code.into_owned()),
            _ => None,
        };
        Self::Database {
            code,
            message: value.to_string(),
        }
    }
}
