use anyhow::Error as AnyhowError;
use thiserror::Error;

/// Stable error categories emitted by evidence verifiers.
///
/// Verifiers still use [`anyhow::Error`] internally for rich context, but input,
/// verification, and dependency failures must be classified at the point where
/// their semantics are known. Transport layers can then map these categories
/// without inspecting human-readable error strings.
#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid evidence format in `{field}`")]
    InvalidEvidenceFormat {
        field: &'static str,
        #[source]
        source: AnyhowError,
    },

    #[error("invalid evidence encoding in `{field}`")]
    InvalidEvidenceEncoding {
        field: &'static str,
        #[source]
        source: AnyhowError,
    },

    #[error("invalid quote in `{field}`")]
    InvalidQuote {
        field: &'static str,
        #[source]
        source: AnyhowError,
    },

    #[error("evidence verification failed")]
    VerificationFailed {
        #[source]
        source: AnyhowError,
    },

    #[error("evidence binding mismatch in `{field}`")]
    BindingMismatch {
        field: &'static str,
        #[source]
        source: AnyhowError,
    },

    #[error("dependency `{dependency}` returned an invalid response")]
    DependencyBadResponse {
        dependency: &'static str,
        #[source]
        source: AnyhowError,
    },

    #[error("dependency `{dependency}` is unavailable")]
    DependencyUnavailable {
        dependency: &'static str,
        #[source]
        source: AnyhowError,
    },

    #[error("verifier internal error")]
    Internal {
        #[source]
        source: AnyhowError,
    },
}
