// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! This Error type helps to work with Actix-web

use std::fmt::Write;

use actix_web::{body::BoxBody, HttpResponse, ResponseError};
use kbs_types::ErrorInformation;
use log::error;
use strum::AsRefStr;
use thiserror::Error;

const ERROR_TYPE_PREFIX: &str = "https://github.com/confidential-containers/kbs/errors";

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, AsRefStr, Debug)]
pub enum Error {
    #[error("Admin auth error: {0}")]
    AdminAuth(#[from] crate::admin::Error),

    #[cfg(feature = "as")]
    #[error("Attestation error: {0}")]
    AttestationError(#[from] crate::attestation::Error),

    #[error("HTTP initialization failed")]
    HTTPFailed {
        #[source]
        source: anyhow::Error,
    },

    #[error("HTTPS initialization failed")]
    HTTPSFailed {
        #[source]
        source: anyhow::Error,
    },

    #[error("Request path {path} is invalid")]
    InvalidRequestPath { path: String },

    #[error("JWE failed")]
    JweError {
        #[source]
        source: anyhow::Error,
    },

    #[error("PluginManager initialization failed")]
    PluginManagerInitialization {
        #[source]
        source: anyhow::Error,
    },

    #[error("Plugin {plugin_name} not found")]
    PluginNotFound { plugin_name: String },

    #[error("Plugin internal error")]
    PluginInternalError {
        #[source]
        source: anyhow::Error,
    },

    #[error("Access denied by policy")]
    PolicyDeny,

    #[error("Policy engine error")]
    PolicyEngine(#[from] crate::policy_engine::KbsPolicyEngineError),

    #[error("Serialize/Deserialize failed")]
    SerdeError(#[from] serde_json::Error),

    #[error("Attestation Token not found")]
    TokenNotFound,

    #[error("Token Verifier error")]
    TokenVerifierError(#[from] crate::token::Error),
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        let mut detail = String::new();

        // The write macro here will only raise error when OOM of the string.
        write!(&mut detail, "{}", self).expect("Failed to write error");
        let info = ErrorInformation {
            error_type: format!("{ERROR_TYPE_PREFIX}/{}", self.as_ref()),
            detail,
        };

        // All the fields inside the ErrorInfo are printable characters, so this
        // error cannot happen.
        // A test covering all the possible error types are given to ensure this.
        let body = serde_json::to_string(&info).expect("Failed to serialize error");

        // Map errors to appropriate HTTP status codes based on their nature
        let mut res = match self {
            // 400 Bad Request - Client request errors
            Error::JweError { .. } | Error::SerdeError(_) => HttpResponse::BadRequest(),

            // 401 Unauthorized - Authentication/authorization errors
            Error::AdminAuth(_) | Error::TokenNotFound | Error::TokenVerifierError(_) => {
                HttpResponse::Unauthorized()
            }

            // 403 Forbidden - Access denied by policy
            Error::PolicyDeny => HttpResponse::Forbidden(),

            // 404 Not Found - Resource not found
            Error::InvalidRequestPath { .. } | Error::PluginNotFound { .. } => {
                HttpResponse::NotFound()
            }

            // 500 Internal Server Error - Server-side failures
            Error::HTTPFailed { .. }
            | Error::HTTPSFailed { .. }
            | Error::PluginManagerInitialization { .. }
            | Error::PluginInternalError { .. }
            | Error::PolicyEngine(_) => HttpResponse::InternalServerError(),

            #[cfg(feature = "as")]
            Error::AttestationError(e) => {
                use crate::attestation::Error as AttestationError;
                match e {
                    // Initialization problems are server-side
                    AttestationError::AttestationServiceInitialization { .. } => {
                        HttpResponse::InternalServerError()
                    }
                    // Client provided invalid/unsupported claims or inputs
                    AttestationError::ExtractTeePubKeyFailed { .. } => HttpResponse::BadRequest(),
                    // Upstream handshake failures → treat as Bad Gateway to indicate dependency issue
                    AttestationError::RcarAuthFailed { .. }
                    | AttestationError::RcarAttestFailed { .. } => HttpResponse::BadGateway(),
                    // Policy ops errors are usually due to bad input or illegal state
                    AttestationError::SetPolicy { .. }
                    | AttestationError::GetPolicy { .. }
                    | AttestationError::ListPolicies { .. }
                    | AttestationError::DeletePolicy { .. } => HttpResponse::BadRequest(),
                }
            }
        };

        error!("{self:?}");

        res.body(BoxBody::new(body))
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::Error;

    #[rstest]
    #[case(Error::InvalidRequestPath{path: "test".into()})]
    #[case(Error::PluginNotFound{plugin_name: "test".into()})]
    fn into_error_response(#[case] err: Error) {
        let _ = actix_web::ResponseError::error_response(&err);
    }
}
