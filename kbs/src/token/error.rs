// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use log::error;
use strum::AsRefStr;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, AsRefStr, Debug)]
pub enum Error {
    #[error("Failed to verify Attestation Token")]
    TokenVerificationFailed {
        #[source]
        source: anyhow::Error,
    },

    #[error("Failed to initialize Token Verifier")]
    TokenVerifierInitialization {
        #[source]
        source: anyhow::Error,
    },

    #[error("Tee public key not found in Attestation Token")]
    NoTeePubKeyClaimFound,

    #[error("Failed to parse Tee public key")]
    TeePubKeyParseFailed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use std::error::Error as StdError;

    #[allow(dead_code)]
    // Helper function to clone anyhow::Error for testing
    fn clone_err(err: &anyhow::Error) -> anyhow::Error {
        anyhow!(err.to_string())
    }

    #[test]
    fn test_error_display() {
        // Test TokenVerificationFailed
        let err = Error::TokenVerificationFailed {
            source: anyhow!("signature invalid"),
        };
        assert_eq!(format!("{}", err), "Failed to verify Attestation Token");

        // Test TokenVerifierInitialization
        let err = Error::TokenVerifierInitialization {
            source: anyhow!("invalid certificate"),
        };
        assert_eq!(format!("{}", err), "Failed to initialize Token Verifier");

        // Test NoTeePubKeyClaimFound
        let err = Error::NoTeePubKeyClaimFound;
        assert_eq!(
            format!("{}", err),
            "Tee public key not found in Attestation Token"
        );

        // Test TeePubKeyParseFailed
        let err = Error::TeePubKeyParseFailed;
        assert_eq!(format!("{}", err), "Failed to parse Tee public key");
    }

    #[test]
    fn test_error_source() {
        // Test error source for TokenVerificationFailed
        let source_err = anyhow!("signature invalid");
        let err = Error::TokenVerificationFailed { source: source_err };

        let source = err.source().unwrap();
        assert_eq!(source.to_string(), "signature invalid");

        // Test error source for TokenVerifierInitialization
        let source_err = anyhow!("invalid certificate");
        let err = Error::TokenVerifierInitialization { source: source_err };

        let source = err.source().unwrap();
        assert_eq!(source.to_string(), "invalid certificate");

        // Test error source for NoTeePubKeyClaimFound (no source)
        let err = Error::NoTeePubKeyClaimFound;
        assert!(err.source().is_none());

        // Test error source for TeePubKeyParseFailed (no source)
        let err = Error::TeePubKeyParseFailed;
        assert!(err.source().is_none());
    }

    #[test]
    fn test_as_ref() {
        // Test AsRefStr implementation
        assert_eq!(
            Error::TokenVerificationFailed {
                source: anyhow!("test")
            }
            .as_ref(),
            "TokenVerificationFailed"
        );
        assert_eq!(
            Error::TokenVerifierInitialization {
                source: anyhow!("test")
            }
            .as_ref(),
            "TokenVerifierInitialization"
        );
        assert_eq!(
            Error::NoTeePubKeyClaimFound.as_ref(),
            "NoTeePubKeyClaimFound"
        );
        assert_eq!(Error::TeePubKeyParseFailed.as_ref(), "TeePubKeyParseFailed");
    }
}
