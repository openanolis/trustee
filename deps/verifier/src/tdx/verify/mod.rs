//! TDX quote verification backends.
//!
//! The actual ECDSA quote verification can be provided by one of two
//! mutually-exclusive, compile-time-selected backends:
//!
//! * [`tdx-dcap-ffi`](ffi) — the default. Delegates to the Intel DCAP Quote
//!   Verification Library through FFI, linking the `libsgx_dcap_quoteverify`
//!   shared object at run time. This is the historical behaviour and is what
//!   every default build (`all-verifier`) uses.
//!
//! * `tdx-dcap-rust` — a backend built on the `dcap-qvl` crate that removes the
//!   dependency on any external DCAP shared library. It is opt-in; with it
//!   disabled the default (FFI) build is unaffected. It builds on the same Rust
//!   toolchain as the default build (see the crate-level docs).
//!
//! Both backends expose the same entry point:
//!
//! ```ignore
//! pub async fn ecdsa_quote_verification(quote: &[u8]) -> Result<TcbVerificationResult>
//! ```
//!
//! and return the same [`TcbVerificationResult`](crate::tdx::quote::TcbVerificationResult),
//! so nothing above this module needs to know which backend is compiled in.

#[cfg(all(feature = "tdx-dcap-ffi", feature = "tdx-dcap-rust"))]
compile_error!(
    "features `tdx-dcap-ffi` and `tdx-dcap-rust` are mutually exclusive: \
     enable exactly one TDX quote-verification backend"
);

#[cfg(not(any(feature = "tdx-dcap-ffi", feature = "tdx-dcap-rust")))]
compile_error!(
    "the `tdx-verifier` feature requires a backend: enable either \
     `tdx-dcap-ffi` (Intel DCAP shared library, the default) or \
     `tdx-dcap-rust` (dcap-qvl, no external DCAP library)"
);

#[cfg(feature = "tdx-dcap-ffi")]
mod ffi;
#[cfg(feature = "tdx-dcap-ffi")]
pub(crate) use ffi::ecdsa_quote_verification;

#[cfg(feature = "tdx-dcap-rust")]
mod native;
#[cfg(feature = "tdx-dcap-rust")]
pub(crate) use native::ecdsa_quote_verification;

#[cfg(test)]
mod tests {
    use super::ecdsa_quote_verification;
    use rstest::rstest;
    use std::fs;

    /// Test to verify the TDX quote, both in v4 and v5 format.
    ///
    /// This test is backend-agnostic: it exercises whichever backend
    /// (`tdx-dcap-ffi` or `tdx-dcap-rust`) is compiled in. Both must produce
    /// the same [`TcbVerificationResult`](crate::tdx::quote::TcbVerificationResult)
    /// for a given quote.
    ///
    /// It is `#[ignore]`d because it needs network access to a PCCS to fetch
    /// verification collateral (TCB info, QE identity, CRLs). With the
    /// `tdx-dcap-ffi` backend it additionally requires `libsgx-dcap-quote-verify`
    /// and the `libsgx-dcap-default-qpl` quote provider to be installed and
    /// `/etc/sgx_default_qcnl.conf` to point at a reachable PCCS, e.g.:
    ///
    /// ```json
    /// {"pccs_url" :"https://sgx-dcap-server.cn-beijing.aliyuncs.com/sgx/certification/v4/"}
    /// ```
    ///
    /// With the `tdx-dcap-rust` backend, collateral is fetched over HTTPS
    /// directly, so only network access to the configured PCCS is required.
    ///
    /// DCAP only ships packages on x86-64, thus we only run this on x86-64.
    #[cfg(target_arch = "x86_64")]
    #[rstest]
    #[ignore]
    #[tokio::test]
    #[case("./test_data/tdx_quote_4.dat")]
    #[ignore]
    #[tokio::test]
    #[case("./test_data/tdx_quote_5.dat")]
    async fn test_verify_tdx_quote(#[case] quote: &str) {
        let quote_bin = fs::read(quote).unwrap();
        let res = ecdsa_quote_verification(quote_bin.as_slice()).await;
        assert!(res.is_ok(), "{res:?}");
        let tcb_result = res.unwrap();
        println!(
            "TCB status: {}, advisory_ids: {}, tcb_level_date_tag: {}",
            tcb_result.tcb_status, tcb_result.advisory_ids, tcb_result.tcb_level_date_tag
        );
    }
}
