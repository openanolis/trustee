//! DCAP-QVL (Intel `libsgx_dcap_quoteverify`) backend for TDX quote
//! verification. Selected by the `tdx-dcap-ffi` feature.
//!
//! This is the historical behaviour: quote verification is delegated to the
//! Intel DCAP Quote Verification Library through the
//! `intel-tee-quote-verification-rs` FFI bindings, which link against the
//! `libsgx_dcap_quoteverify` shared object at run time and dynamically load
//! the platform quote provider (PCCS collateral) and, optionally, the QvE.

use anyhow::{anyhow, bail, Result};
use log::{debug, warn};
use std::mem;
use std::time::{Duration, SystemTime};

use intel_tee_quote_verification_rs as qvl;
use qvl::{
    quote3_error_t, sgx_ql_qv_result_t, sgx_ql_qv_supplemental_t, sgx_ql_request_policy_t,
    sgx_qv_set_enclave_load_policy, tee_get_supplemental_data_version_and_size,
    tee_qv_get_collateral, tee_supp_data_descriptor_t, tee_verify_quote,
};

use crate::tdx::quote::TcbVerificationResult;

/// Human-readable TCB verification status string.
fn qv_result_to_str(result: sgx_ql_qv_result_t) -> &'static str {
    match result {
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OK => "UpToDate",
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_NEEDED => "ConfigurationNeeded",
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE => "OutOfDate",
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED => {
            "OutOfDateConfigurationNeeded"
        }
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_SW_HARDENING_NEEDED => "SWHardeningNeeded",
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED => {
            "ConfigurationAndSWHardeningNeeded"
        }
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_INVALID_SIGNATURE => "InvalidSignature",
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_REVOKED => "Revoked",
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_UNSPECIFIED => "Unspecified",
        _ => "Unknown",
    }
}

pub async fn ecdsa_quote_verification(quote: &[u8]) -> Result<TcbVerificationResult> {
    let mut supp_data: sgx_ql_qv_supplemental_t = Default::default();
    let mut supp_data_desc = tee_supp_data_descriptor_t {
        major_version: 0,
        data_size: 0,
        p_data: &mut supp_data as *mut sgx_ql_qv_supplemental_t as *mut u8,
    };

    // Call DCAP quote verify library to set QvE loading policy to multi-thread
    // We only need to set the policy once; otherwise, it will return the error code 0xe00c (SGX_QL_UNSUPPORTED_LOADING_POLICY)
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        match sgx_qv_set_enclave_load_policy(
            sgx_ql_request_policy_t::SGX_QL_PERSISTENT_QVE_MULTI_THREAD,
        ) {
            quote3_error_t::SGX_QL_SUCCESS => {
                debug!("Info: sgx_qv_set_enclave_load_policy successfully returned.")
            }
            err => warn!(
                "Error: sgx_qv_set_enclave_load_policy failed: {:#04x}",
                err as u32
            ),
        }
    });

    match tee_get_supplemental_data_version_and_size(quote) {
        Ok((supp_ver, supp_size)) => {
            if supp_size == mem::size_of::<sgx_ql_qv_supplemental_t>() as u32 {
                debug!("tee_get_quote_supplemental_data_version_and_size successfully returned.");
                debug!(
                    "Info: latest supplemental data major version: {}, minor version: {}, size: {}",
                    u16::from_be_bytes(supp_ver.to_be_bytes()[..2].try_into()?),
                    u16::from_be_bytes(supp_ver.to_be_bytes()[2..].try_into()?),
                    supp_size,
                );
                supp_data_desc.data_size = supp_size;
            } else {
                warn!("Quote supplemental data size is different between DCAP QVL and QvE, please make sure you installed DCAP QVL and QvE from same release.")
            }
        }
        Err(e) => bail!(
            "tee_get_quote_supplemental_data_size failed: {:#04x}",
            e as u32
        ),
    }

    // get collateral
    let collateral = match tee_qv_get_collateral(quote) {
        Ok(c) => {
            debug!("tee_qv_get_collateral successfully returned.");
            Some(c)
        }
        Err(e) => {
            warn!("tee_qv_get_collateral failed: {:#04x}", e as u32);
            None
        }
    };

    // set current time. This is only for sample purposes, in production mode a trusted time should be used.
    //
    let current_time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64;

    let p_supplemental_data = match supp_data_desc.data_size {
        0 => None,
        _ => Some(&mut supp_data_desc),
    };

    // call DCAP quote verify library for quote verification
    let (collateral_expiration_status, quote_verification_result) = tee_verify_quote(
        quote,
        collateral.as_ref(),
        current_time,
        None,
        p_supplemental_data,
    )
    .map_err(|e| anyhow!("tee_verify_quote failed: {:#04x}", e as u32))?;

    debug!("tee_verify_quote successfully returned.");

    // check verification result
    match quote_verification_result {
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OK => {
            // check verification collateral expiration status
            // this value should be considered in your own attestation/verification policy
            if collateral_expiration_status == 0 {
                debug!("Verification completed successfully.");
            } else {
                warn!("Verification completed, but collateral is out of date based on 'expiration_check_date' you provided.");
            }
        }
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_NEEDED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_SW_HARDENING_NEEDED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED => {
            warn!(
                "Verification completed with Non-terminal result: {:x}",
                quote_verification_result as u32
            );
        }
        _ => {
            bail!(
                "Verification completed with Terminal result: {:x}",
                quote_verification_result as u32
            );
        }
    }

    // Extract advisory IDs from supplemental data (null-terminated C string).
    // sa_list is [c_char; 320] (i8 on Linux), containing comma-separated advisory IDs.
    let advisory_ids = {
        let sa_bytes: Vec<u8> = supp_data
            .sa_list
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| b as u8)
            .collect();
        String::from_utf8_lossy(&sa_bytes).to_string()
    };

    let result = TcbVerificationResult {
        tcb_status: qv_result_to_str(quote_verification_result).to_string(),
        tcb_status_code: quote_verification_result as u32,
        collateral_expired: collateral_expiration_status != 0,
        earliest_issue_date: supp_data.earliest_issue_date,
        latest_issue_date: supp_data.latest_issue_date,
        earliest_expiration_date: supp_data.earliest_expiration_date,
        tcb_level_date_tag: supp_data.tcb_level_date_tag,
        tcb_eval_ref_num: supp_data.tcb_eval_ref_num,
        advisory_ids,
        tee_type: supp_data.tee_type,
    };

    debug!("TCB verification result: {:?}", result);

    Ok(result)
}
