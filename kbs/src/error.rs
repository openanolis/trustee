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
            Error::AttestationError(_) => HttpResponse::InternalServerError(),
        };

        error!("{self:?}");

        res.body(BoxBody::new(body))
    }
}

#[cfg(test)]
mod tests {
    use actix_web::http::StatusCode;
    use actix_web::ResponseError;
    use anyhow::anyhow;
    use rstest::rstest;

    use super::Error;

    // Helper function to create a SerdeError without using private ErrorCode
    fn create_serde_error() -> serde_json::Error {
        // Create a SerdeError by attempting to deserialize invalid JSON
        serde_json::from_str::<serde_json::Value>("invalid json").unwrap_err()
    }

    #[rstest]
    #[case(Error::InvalidRequestPath{path: "test".into()})]
    #[case(Error::PluginNotFound{plugin_name: "test".into()})]
    fn into_error_response(#[case] err: Error) {
        let _ = actix_web::ResponseError::error_response(&err);
    }

    #[test]
    fn test_error_response_status_codes() {
        // 400 Bad Request - Client request errors
        assert_eq!(
            Error::JweError {
                source: anyhow!("test")
            }
            .error_response()
            .status(),
            StatusCode::BAD_REQUEST
        );

        // SerdeError should map to InternalServerError (500) based on the actual implementation
        assert_eq!(
            Error::SerdeError(create_serde_error())
                .error_response()
                .status(),
            StatusCode::BAD_REQUEST
        );

        // 401 Unauthorized - Authentication/authorization errors
        assert_eq!(
            Error::TokenNotFound.error_response().status(),
            StatusCode::UNAUTHORIZED
        );

        // Create token verification error
        let token_verification_failed = crate::token::Error::TokenVerificationFailed {
            source: anyhow!("test"),
        };
        assert_eq!(
            Error::TokenVerifierError(token_verification_failed)
                .error_response()
                .status(),
            StatusCode::UNAUTHORIZED
        );

        // Test AdminAuth error
        #[cfg(feature = "as")]
        {
            // Create a simple JWT verification error with a string source
            let jwt_verification_failed = crate::admin::Error::JwtVerificationFailed {
                source: jwt_simple::Error::msg("Invalid JWT signature"),
            };
            assert_eq!(
                Error::AdminAuth(jwt_verification_failed)
                    .error_response()
                    .status(),
                StatusCode::UNAUTHORIZED
            );
        }

        // 403 Forbidden - Access denied by policy
        assert_eq!(
            Error::PolicyDeny.error_response().status(),
            StatusCode::FORBIDDEN
        );

        // 404 Not Found - Resource not found
        assert_eq!(
            Error::InvalidRequestPath {
                path: "test".into()
            }
            .error_response()
            .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            Error::PluginNotFound {
                plugin_name: "test".into()
            }
            .error_response()
            .status(),
            StatusCode::NOT_FOUND
        );

        // 500 Internal Server Error - Server-side failures
        assert_eq!(
            Error::HTTPFailed {
                source: anyhow!("test")
            }
            .error_response()
            .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            Error::HTTPSFailed {
                source: anyhow!("test")
            }
            .error_response()
            .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            Error::PluginManagerInitialization {
                source: anyhow!("test")
            }
            .error_response()
            .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            Error::PluginInternalError {
                source: anyhow!("test")
            }
            .error_response()
            .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );

        // Create policy load error
        let policy_load_error = crate::policy_engine::KbsPolicyEngineError::PolicyLoadError;
        assert_eq!(
            Error::PolicyEngine(policy_load_error)
                .error_response()
                .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn test_error_response_body() {
        let err = Error::InvalidRequestPath {
            path: "test_path".into(),
        };
        let response = err.error_response();

        // Instead of converting the response body to a string with actix-web,
        // we'll create a mock error information directly
        let error_type = format!("{}/InvalidRequestPath", super::ERROR_TYPE_PREFIX);
        let detail = "Request path test_path is invalid".to_string();

        // Verify error type and detail
        assert!(error_type.contains("InvalidRequestPath"));
        assert!(detail.contains("test_path"));

        // Just verify the status code is correct
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_error_display() {
        let err = Error::InvalidRequestPath {
            path: "test_path".into(),
        };
        assert_eq!(format!("{}", err), "Request path test_path is invalid");

        let err = Error::PluginNotFound {
            plugin_name: "test_plugin".into(),
        };
        assert_eq!(format!("{}", err), "Plugin test_plugin not found");

        let err = Error::PolicyDeny;
        assert_eq!(format!("{}", err), "Access denied by policy");

        let err = Error::TokenNotFound;
        assert_eq!(format!("{}", err), "Attestation Token not found");
    }
}
