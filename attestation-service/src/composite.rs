// Copyright (c) 2026 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Verification of relationships between otherwise independent TEE evidence.

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::Value;
use std::collections::HashMap;
use verifier::VerifierError;

use crate::{AttestationError, RuntimeData, Tee, VerificationRequest};

const ADDITIONAL_EVIDENCE: &str = "additional-evidence";

/// Verify bindings which span more than one [`VerificationRequest`].
///
/// A request list represents one TCB. For an SNP guest with an SVSM vTPM, the
/// TPM evidence must therefore be the same evidence covered by the SNP runtime
/// data, use the same base runtime data, and identify the EK carried in the
/// VMPL0 SVSM manifest.
pub(crate) fn verify_composite_bindings(requests: &[VerificationRequest]) -> Result<()> {
    let snp = requests
        .iter()
        .enumerate()
        .filter(|(_, request)| request.tee == Tee::Snp)
        .collect::<Vec<_>>();
    let tpm = requests
        .iter()
        .enumerate()
        .filter(|(_, request)| request.tee == Tee::Tpm)
        .collect::<Vec<_>>();

    // Standalone SNP and standalone TPM evidence remain valid. The binding is
    // required only when both are combined into one attestation result.
    if snp.is_empty() || tpm.is_empty() {
        return Ok(());
    }

    if snp.len() != 1 || tpm.len() != 1 {
        return Err(invalid_request(
            None,
            "verification_requests",
            "an SNP/SVSM vTPM attestation requires exactly one SNP and one TPM request",
        ));
    }

    verify_snp_svsm_vtpm_binding(snp[0], tpm[0])
}

fn verify_snp_svsm_vtpm_binding(
    (snp_index, snp): (usize, &VerificationRequest),
    (tpm_index, tpm): (usize, &VerificationRequest),
) -> Result<()> {
    let primary_runtime = structured_runtime(snp_index, snp)?;
    let additional_evidence = primary_runtime
        .get(ADDITIONAL_EVIDENCE)
        .and_then(Value::as_str)
        .filter(|evidence| !evidence.is_empty())
        .ok_or_else(|| {
            invalid_request(
                Some(snp_index),
                "runtime_data",
                "SNP runtime data does not contain TPM additional evidence",
            )
        })?;
    let additional: HashMap<Tee, Value> =
        serde_json::from_str(additional_evidence).map_err(|e| {
            invalid_request(
                Some(snp_index),
                "runtime_data",
                format!("cannot parse SNP additional evidence: {e}"),
            )
        })?;
    let bound_tpm = additional.get(&Tee::Tpm).ok_or_else(|| {
        invalid_request(
            Some(snp_index),
            "runtime_data",
            "SNP runtime data does not contain TPM additional evidence",
        )
    })?;

    if bound_tpm != &tpm.evidence {
        return Err(binding_mismatch(
            tpm_index,
            Tee::Tpm,
            "evidence",
            "TPM evidence differs from the evidence bound by the SNP report",
        ));
    }

    let mut base_runtime = primary_runtime.clone();
    base_runtime.remove(ADDITIONAL_EVIDENCE);
    if &base_runtime != structured_runtime(tpm_index, tpm)? {
        return Err(invalid_request(
            Some(tpm_index),
            "runtime_data",
            "SNP and TPM evidence do not use the same base runtime data",
        ));
    }

    let manifest = evidence_string(snp_index, Tee::Snp, &snp.evidence, "svsm_manifest")?;
    let ek_public = evidence_string(tpm_index, Tee::Tpm, &tpm.evidence, "ek_pubkey")?;
    let manifest = decode_evidence(snp_index, Tee::Snp, "svsm_manifest", manifest)?;
    let ek_public = decode_evidence(tpm_index, Tee::Tpm, "ek_pubkey", ek_public)?;

    if manifest.is_empty() || manifest != ek_public {
        return Err(binding_mismatch(
            tpm_index,
            Tee::Tpm,
            "ek_pubkey",
            "TPM EK public key does not match the vTPM manifest bound by the VMPL0 SNP report",
        ));
    }

    Ok(())
}

fn structured_runtime(
    index: usize,
    request: &VerificationRequest,
) -> Result<&serde_json::Map<String, Value>> {
    match &request.runtime_data {
        Some(RuntimeData::Structured(Value::Object(runtime))) => Ok(runtime),
        _ => Err(invalid_request(
            Some(index),
            "runtime_data",
            "SNP/SVSM vTPM composite evidence requires structured runtime data",
        )),
    }
}

fn evidence_string<'a>(
    index: usize,
    tee: Tee,
    evidence: &'a Value,
    field: &'static str,
) -> Result<&'a str> {
    evidence.get(field).and_then(Value::as_str).ok_or_else(|| {
        verification_error(
            index,
            tee,
            VerifierError::InvalidEvidenceFormat {
                field,
                source: anyhow!("required field is missing or is not a string"),
            },
        )
    })
}

fn decode_evidence(index: usize, tee: Tee, field: &'static str, value: &str) -> Result<Vec<u8>> {
    STANDARD.decode(value).map_err(|source| {
        verification_error(
            index,
            tee,
            VerifierError::InvalidEvidenceEncoding {
                field,
                source: source.into(),
            },
        )
    })
}

fn invalid_request(
    request_index: Option<usize>,
    field: &'static str,
    message: impl Into<String>,
) -> anyhow::Error {
    AttestationError::InvalidRequest {
        request_index,
        field,
        source: anyhow!("{}", message.into()),
    }
    .into()
}

fn binding_mismatch(
    request_index: usize,
    tee: Tee,
    field: &'static str,
    message: impl Into<String>,
) -> anyhow::Error {
    verification_error(
        request_index,
        tee,
        VerifierError::BindingMismatch {
            field,
            source: anyhow!("{}", message.into()),
        },
    )
}

fn verification_error(request_index: usize, tee: Tee, source: VerifierError) -> anyhow::Error {
    AttestationError::Verification {
        request_index,
        tee,
        source: source.into(),
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HashAlgorithm;
    use serde_json::json;

    fn request(tee: Tee, evidence: Value, runtime_data: Value) -> VerificationRequest {
        VerificationRequest {
            tee,
            evidence,
            runtime_data: Some(RuntimeData::Structured(runtime_data)),
            runtime_data_hash_algorithm: HashAlgorithm::Sha384,
            init_data: None,
            additional_data: None,
        }
    }

    fn composite_requests(manifest: &[u8]) -> Vec<VerificationRequest> {
        let ek = STANDARD.encode(manifest);
        let tpm_evidence = json!({
            "ek_pubkey": ek,
            "ak_pubkey": "ak",
            "quote": {"SHA256": "quote"}
        });
        let additional =
            serde_json::to_string(&HashMap::from([(Tee::Tpm, tpm_evidence.clone())])).unwrap();
        let base_runtime = json!({"nonce": "challenge", "tee-pubkey": "key"});
        let primary_runtime = json!({
            "nonce": "challenge",
            "tee-pubkey": "key",
            (ADDITIONAL_EVIDENCE): additional,
        });

        vec![
            request(
                Tee::Snp,
                json!({"svsm_manifest": STANDARD.encode(manifest)}),
                primary_runtime,
            ),
            request(Tee::Tpm, tpm_evidence, base_runtime),
        ]
    }

    #[test]
    fn accepts_bound_snp_svsm_vtpm_evidence() {
        verify_composite_bindings(&composite_requests(b"ek-public")).unwrap();
    }

    #[test]
    fn rejects_manifest_ek_mismatch() {
        let mut requests = composite_requests(b"ek-public");
        requests[0].evidence["svsm_manifest"] = json!(STANDARD.encode(b"another-ek"));

        let error = verify_composite_bindings(&requests).unwrap_err();
        assert!(format!("{error:#}").contains("TPM EK public key does not match"));
    }

    #[test]
    fn rejects_tpm_evidence_splicing() {
        let mut requests = composite_requests(b"ek-public");
        requests[1].evidence["quote"] = json!({"SHA256": "another-quote"});

        let error = verify_composite_bindings(&requests).unwrap_err();
        assert!(format!("{error:#}").contains("TPM evidence differs"));
    }

    #[test]
    fn rejects_snp_tpm_pair_without_svsm_manifest() {
        let mut requests = composite_requests(b"ek-public");
        requests[0].evidence = json!({});

        let error = verify_composite_bindings(&requests).unwrap_err();
        assert!(format!("{error:#}").contains("svsm_manifest"));
    }

    #[test]
    fn rejects_different_runtime_data() {
        let mut requests = composite_requests(b"ek-public");
        requests[1].runtime_data = Some(RuntimeData::Structured(
            json!({"nonce": "another-challenge", "tee-pubkey": "key"}),
        ));

        let error = verify_composite_bindings(&requests).unwrap_err();
        assert!(format!("{error:#}").contains("same base runtime data"));
    }

    #[test]
    fn leaves_independent_evidence_unchanged() {
        let snp = request(Tee::Snp, json!({}), json!({"nonce": "challenge"}));
        verify_composite_bindings(&[snp]).unwrap();
    }

    #[test]
    fn accepts_plain_snp_with_empty_additional_evidence() {
        let snp = request(
            Tee::Snp,
            json!({}),
            json!({
                "nonce": "challenge",
                (ADDITIONAL_EVIDENCE): "",
            }),
        );

        verify_composite_bindings(&[snp]).unwrap();
    }
}
