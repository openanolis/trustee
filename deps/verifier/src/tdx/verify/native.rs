//! Pure-Rust TDX quote verification backend. Selected by the `tdx-dcap-rust`
//! feature.
//!
//! This backend removes the dependency on the Intel DCAP shared library
//! (`libsgx_dcap_quoteverify`) and its dynamically loaded quote provider. The
//! ECDSA quote signature, PCK certificate chain, TCB info and QE identity are
//! all verified in Rust via the [`dcap_qvl`] crate; verification collateral is
//! fetched over HTTPS from a PCCS using the verifier's own `reqwest` stack (we
//! deliberately do *not* enable `dcap-qvl`'s `report` feature, which would pull
//! in `reqwest` 0.13 / `aws-lc-sys`).
//!
//! Toolchain: `dcap-qvl`'s dependency tree requires a newer Rust toolchain
//! (>= 1.86) than the default (FFI) build. This does not affect the default
//! build: the `tdx-dcap-rust` feature is opt-in, and with it disabled Cargo
//! prunes this whole subtree.
//!
//! Scope: the collateral fetch currently supports quotes whose certification
//! data embeds the PCK certificate chain (PCK cert type 5), which is what cloud
//! TDX quotes use. Other certification data types return a clear error.
//!
//! The [`TcbVerificationResult`] returned here is populated to match the fields
//! the DCAP QVL (FFI) backend exposes, including `tcb_level_date_tag`, which is
//! reproduced by re-running Intel QVL's TCB-level matching over the platform TCB
//! (SGX TCB components + PCE SVN from the PCK certificate, TDX TEE TCB SVN from
//! the TD report).

use anyhow::{anyhow, bail, Context, Result};
use asn1_rs::{Any, FromDer, Oid};
use dcap_qvl::tcb_info::{TcbComponents, TcbInfo, TcbLevel};
use dcap_qvl::verify::{QuoteVerifier, VerifiedReport};
use dcap_qvl::QuoteCollateralV3;
use log::debug;
use std::time::{SystemTime, UNIX_EPOCH};
use x509_parser::pem::Pem;
use x509_parser::prelude::*;

use crate::tdx::quote::{parse_tdx_quote, TcbVerificationResult};

/// Default PCCS base URL. Matches the Alibaba Cloud PCCS the FFI backend's
/// quote provider is normally configured against (`/etc/sgx_default_qcnl.conf`).
/// Overridable at run time with the `PCCS_URL` environment variable.
const DEFAULT_PCCS_URL: &str = "https://sgx-dcap-server.cn-beijing.aliyuncs.com";

/// TEE type for TDX, matching the value the FFI backend reports in
/// `TcbVerificationResult::tee_type`.
const TEE_TYPE_TDX: u32 = 0x0000_0081;

/// Intel SGX extension OID (`1.2.840.113741.1.13.1`) and the sub-OIDs used here.
const OID_SGX_EXTENSION: &[u64] = &[1, 2, 840, 113741, 1, 13, 1];
const OID_SGX_TCB: &[u64] = &[1, 2, 840, 113741, 1, 13, 1, 2];
const OID_SGX_PCESVN: &[u64] = &[1, 2, 840, 113741, 1, 13, 1, 2, 17];
const OID_SGX_FMSPC: &[u64] = &[1, 2, 840, 113741, 1, 13, 1, 4];

pub async fn ecdsa_quote_verification(quote: &[u8]) -> Result<TcbVerificationResult> {
    let pccs_url = std::env::var("PCCS_URL")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_PCCS_URL.to_string());

    // The PCK certificate chain is embedded in the quote's certification data
    // (PCK cert type 5). Extract it and derive FMSPC / CA type for collateral.
    let pck_chain = extract_pck_chain_pem(quote)
        .context("failed to extract embedded PCK certificate chain from quote")?;
    let leaf_der = first_cert_der(&pck_chain)?;
    let (fmspc, ca) = extract_fmspc_and_ca(&leaf_der)?;
    debug!("dcap-qvl backend: fmspc={fmspc}, ca={ca}, pccs={pccs_url}");

    let collateral = fetch_collateral(&pccs_url, &fmspc, ca, pck_chain.clone()).await?;

    let real_now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let dates = CollateralDates::parse(&collateral)?;
    let collateral_expired = real_now >= dates.earliest_expiration_date;
    debug!(
        "dcap-qvl backend: fmspc={fmspc} now={real_now} tcb_next={} expired={collateral_expired}",
        dates.tcb_info.next_update
    );

    // The FFI (DCAP QVL) backend treats debug-mode TDs and service TDs as
    // non-fatal, deferring to the policy engine. Match that here so the reported
    // claims (not this backend) drive those decisions.
    //
    // One intentional difference remains: dcap-qvl rejects *expired* collateral
    // (TCB info / QE identity past its `nextUpdate`) as a hard error, whereas the
    // FFI backend reports it via the `collateral_expired` flag and continues. We
    // keep dcap-qvl's stricter behaviour (verifying against year-old collateral
    // is unsafe) and still surface `collateral_expired` for policies that check
    // it. In practice this only differs when the configured PCCS serves stale
    // collateral for a platform's FMSPC; point `PCCS_URL` at an up-to-date PCCS
    // (or Intel PCS) if you hit it.
    let report = QuoteVerifier::new_prod()
        .allow_debug(true)
        .allow_service_td(true)
        .verify(quote, &collateral, real_now as u64)
        .map_err(|e| anyhow!("dcap-qvl quote verification failed: {e:#}"))?;

    build_result(quote, &leaf_der, &report, &dates, collateral_expired)
}

// ---------------------------------------------------------------------------
// PCK chain / certificate parsing
// ---------------------------------------------------------------------------

/// Extract the PEM PCK certificate chain embedded in the quote's certification
/// data (PCK cert type 5). We locate it by scanning for the PEM boundaries,
/// which avoids re-parsing the whole ECDSA signature structure.
fn extract_pck_chain_pem(quote: &[u8]) -> Result<String> {
    const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
    const END: &[u8] = b"-----END CERTIFICATE-----";
    let start = find_sub(quote, BEGIN)
        .context("no PEM certificate found in quote (unsupported PCK cert type?)")?;
    let end =
        rfind_sub(quote, END).context("malformed PEM certificate chain in quote")? + END.len();
    let pem = std::str::from_utf8(&quote[start..end])
        .context("PCK certificate chain is not valid UTF-8")?;
    Ok(pem.to_string())
}

/// DER of the leaf (first) certificate in a PEM chain.
fn first_cert_der(pem_chain: &str) -> Result<Vec<u8>> {
    for pem in Pem::iter_from_buffer(pem_chain.as_bytes()) {
        let pem = pem.context("failed to parse PEM block in PCK chain")?;
        return Ok(pem.contents);
    }
    bail!("PCK certificate chain contains no certificate")
}

/// Extract FMSPC (hex, upper-case) and CA type ("platform"/"processor") from
/// the leaf PCK certificate.
fn extract_fmspc_and_ca(leaf_der: &[u8]) -> Result<(String, &'static str)> {
    let (_, cert) =
        X509Certificate::from_der(leaf_der).context("failed to parse PCK leaf certificate")?;

    let sgx_ext = sgx_extension(&cert)?;
    let entries = parse_der_seq_of_pairs(sgx_ext).context("failed to parse Intel SGX extension")?;
    let fmspc_val = entries
        .iter()
        .find(|(oid, _)| oid == &arcs_str(OID_SGX_FMSPC))
        .map(|(_, v)| v)
        .context("SGX extension is missing FMSPC")?;
    let fmspc_bytes = der_octet_string(fmspc_val).context("FMSPC is not an OCTET STRING")?;
    let fmspc = hex::encode_upper(fmspc_bytes);

    // CA type is derived from the issuer common name.
    let issuer = cert.issuer().to_string();
    let ca = if issuer.contains("Platform") {
        "platform"
    } else if issuer.contains("Processor") {
        "processor"
    } else {
        // Default matches Intel/Phala behaviour when the CN is unexpected.
        "processor"
    };

    Ok((fmspc, ca))
}

/// Extract the platform SGX TCB: 16 component SVNs and the PCE SVN, from the
/// PCK certificate's SGX extension. Needed to reproduce TCB-level matching.
fn extract_platform_sgx_tcb(leaf_der: &[u8]) -> Result<([u8; 16], u16)> {
    let (_, cert) =
        X509Certificate::from_der(leaf_der).context("failed to parse PCK leaf certificate")?;
    let sgx_ext = sgx_extension(&cert)?;
    let entries = parse_der_seq_of_pairs(sgx_ext)?;

    let tcb_val = entries
        .iter()
        .find(|(oid, _)| oid == &arcs_str(OID_SGX_TCB))
        .map(|(_, v)| v)
        .context("SGX extension is missing the TCB entry")?;
    // The TCB value is itself a SEQUENCE of (OID, value) pairs.
    let tcb_entries = parse_der_seq_of_pairs(tcb_val).context("failed to parse SGX TCB entry")?;

    let mut comps = [0u8; 16];
    for (n, comp) in comps.iter_mut().enumerate() {
        // Component OIDs are 1.2.840.113741.1.13.1.2.<n+1> for n in 0..16.
        let mut oid = OID_SGX_TCB.to_vec();
        oid.push((n + 1) as u64);
        let v = tcb_entries
            .iter()
            .find(|(o, _)| o == &arcs_str(&oid))
            .map(|(_, v)| v)
            .with_context(|| format!("SGX TCB component {} missing", n + 1))?;
        *comp = der_integer_u64(v)? as u8;
    }
    let pcesvn_val = tcb_entries
        .iter()
        .find(|(o, _)| o == &arcs_str(OID_SGX_PCESVN))
        .map(|(_, v)| v)
        .context("SGX TCB PCESVN missing")?;
    let pcesvn = der_integer_u64(pcesvn_val)? as u16;

    Ok((comps, pcesvn))
}

fn sgx_extension<'a>(cert: &'a X509Certificate<'a>) -> Result<&'a [u8]> {
    cert.extensions()
        .iter()
        .find(|e| e.oid.to_id_string() == arcs_str(OID_SGX_EXTENSION))
        .map(|e| e.value)
        .context("PCK certificate is missing the Intel SGX extension")
}

// ---------------------------------------------------------------------------
// Collateral fetch (PCCS)
// ---------------------------------------------------------------------------

async fn fetch_collateral(
    pccs_url: &str,
    fmspc: &str,
    ca: &str,
    pck_chain: String,
) -> Result<QuoteCollateralV3> {
    let base = pccs_url
        .trim_end_matches('/')
        .trim_end_matches("/sgx/certification/v4")
        .trim_end_matches("/tdx/certification/v4")
        .to_string();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .context("failed to build HTTP client for PCCS")?;

    // PCK CRL (always under the sgx path).
    let pckcrl_url = format!("{base}/sgx/certification/v4/pckcrl?ca={ca}&encoding=der");
    let (pck_crl_issuer_chain, pck_crl) =
        get_with_header(&client, &pckcrl_url, "SGX-PCK-CRL-Issuer-Chain").await?;

    // TCB info (tdx path for TDX).
    let tcb_url = format!("{base}/tdx/certification/v4/tcb?fmspc={fmspc}");
    let (tcb_info_issuer_chain, tcb_body) =
        get_with_header(&client, &tcb_url, "TCB-Info-Issuer-Chain").await?;
    let tcb_json: serde_json::Value =
        serde_json::from_slice(&tcb_body).context("TCB info is not valid JSON")?;
    let tcb_info = tcb_json
        .get("tcbInfo")
        .context("TCB info response missing tcbInfo")?
        .to_string();
    let tcb_info_signature = hex::decode(
        tcb_json
            .get("signature")
            .and_then(|v| v.as_str())
            .context("TCB info response missing signature")?,
    )
    .context("TCB info signature is not valid hex")?;

    // QE identity (tdx path for TDX).
    let qe_url = format!("{base}/tdx/certification/v4/qe/identity?update=standard");
    let (qe_identity_issuer_chain, qe_body) =
        get_with_header(&client, &qe_url, "SGX-Enclave-Identity-Issuer-Chain").await?;
    let qe_json: serde_json::Value =
        serde_json::from_slice(&qe_body).context("QE identity is not valid JSON")?;
    let qe_identity = qe_json
        .get("enclaveIdentity")
        .context("QE identity response missing enclaveIdentity")?
        .to_string();
    let qe_identity_signature = hex::decode(
        qe_json
            .get("signature")
            .and_then(|v| v.as_str())
            .context("QE identity response missing signature")?,
    )
    .context("QE identity signature is not valid hex")?;

    // Root CA CRL. PCCS serves it hex-encoded under the sgx path.
    let rootcacrl_url = format!("{base}/sgx/certification/v4/rootcacrl");
    let root_ca_crl_raw = client
        .get(&rootcacrl_url)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .context("failed to fetch root CA CRL")?
        .bytes()
        .await
        .context("failed to read root CA CRL body")?;
    let root_ca_crl = match std::str::from_utf8(&root_ca_crl_raw)
        .ok()
        .and_then(|s| hex::decode(s.trim()).ok())
    {
        Some(der) => der,
        None => root_ca_crl_raw.to_vec(),
    };

    Ok(QuoteCollateralV3 {
        pck_crl_issuer_chain,
        root_ca_crl,
        pck_crl,
        tcb_info_issuer_chain,
        tcb_info,
        tcb_info_signature,
        qe_identity_issuer_chain,
        qe_identity,
        qe_identity_signature,
        pck_certificate_chain: Some(pck_chain),
    })
}

/// GET a URL, returning (url-decoded issuer-chain header value, body bytes).
async fn get_with_header(
    client: &reqwest::Client,
    url: &str,
    header: &str,
) -> Result<(String, Vec<u8>)> {
    let resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("failed to GET {url}"))?
        .error_for_status()
        .with_context(|| format!("PCCS returned an error for {url}"))?;
    let hdr = resp
        .headers()
        .get(header)
        .with_context(|| format!("PCCS response for {url} missing header {header}"))?
        .to_str()
        .context("issuer-chain header is not valid ASCII")?
        .to_string();
    let hdr = urlencoding::decode(&hdr)
        .context("failed to url-decode issuer-chain header")?
        .into_owned();
    let body = resp
        .bytes()
        .await
        .with_context(|| format!("failed to read body of {url}"))?
        .to_vec();
    Ok((hdr, body))
}

// ---------------------------------------------------------------------------
// Result mapping (including TCB-level matching for tcb_level_date_tag)
// ---------------------------------------------------------------------------

/// Collateral issue/expiration dates (union of TCB info and QE identity),
/// parsed once so they can be used both to clamp the verification timestamp and
/// to populate the result.
struct CollateralDates {
    tcb_info: TcbInfo,
    earliest_issue_date: i64,
    latest_issue_date: i64,
    earliest_expiration_date: i64,
}

impl CollateralDates {
    fn parse(collateral: &QuoteCollateralV3) -> Result<Self> {
        let tcb_info: TcbInfo =
            serde_json::from_str(&collateral.tcb_info).context("failed to parse tcb_info JSON")?;
        let qe_identity: serde_json::Value = serde_json::from_str(&collateral.qe_identity)
            .context("failed to parse qe_identity JSON")?;

        let tcb_issue = parse_iso8601(&tcb_info.issue_date)?;
        let tcb_next = parse_iso8601(&tcb_info.next_update)?;
        let qe_issue = qe_identity
            .get("issueDate")
            .and_then(|v| v.as_str())
            .map(parse_iso8601)
            .transpose()?;
        let qe_next = qe_identity
            .get("nextUpdate")
            .and_then(|v| v.as_str())
            .map(parse_iso8601)
            .transpose()?;

        Ok(Self {
            earliest_issue_date: qe_issue.map_or(tcb_issue, |q| tcb_issue.min(q)),
            latest_issue_date: qe_issue.map_or(tcb_issue, |q| tcb_issue.max(q)),
            earliest_expiration_date: qe_next.map_or(tcb_next, |q| tcb_next.min(q)),
            tcb_info,
        })
    }
}

fn build_result(
    quote: &[u8],
    leaf_der: &[u8],
    report: &VerifiedReport,
    dates: &CollateralDates,
    collateral_expired: bool,
) -> Result<TcbVerificationResult> {
    // Reproduce Intel QVL TCB-level matching to recover the matched level's
    // tcb_date (`tcb_level_date_tag`).
    let tcb_level_date_tag = match matched_tcb_level(quote, leaf_der, &dates.tcb_info) {
        Ok(level) => parse_iso8601(&level.tcb_date)?,
        Err(e) => {
            debug!("dcap-qvl backend: could not resolve matched TCB level: {e:#}");
            0
        }
    };

    Ok(TcbVerificationResult {
        tcb_status: report.status.clone(),
        tcb_status_code: status_to_code(&report.status),
        collateral_expired,
        earliest_issue_date: dates.earliest_issue_date,
        latest_issue_date: dates.latest_issue_date,
        earliest_expiration_date: dates.earliest_expiration_date,
        tcb_level_date_tag,
        tcb_eval_ref_num: dates.tcb_info.tcb_evaluation_data_number,
        advisory_ids: report.advisory_ids.join(","),
        tee_type: TEE_TYPE_TDX,
    })
}

/// Find the TCB level the platform is at, mirroring Intel QVL: canonically
/// sort the levels (highest TCB first) and return the first level the platform
/// satisfies component-wise.
fn matched_tcb_level<'a>(
    quote: &[u8],
    leaf_der: &[u8],
    tcb_info: &'a TcbInfo,
) -> Result<&'a TcbLevel> {
    let (sgx_comps, pcesvn) = extract_platform_sgx_tcb(leaf_der)?;
    let is_tdx = tcb_info.version >= 3 && tcb_info.id == "TDX";

    // Platform TDX TEE TCB SVN from the TD report.
    let tdx_svn: [u8; 16] = if is_tdx {
        let parsed = parse_tdx_quote(quote)?;
        parsed
            .tcb_svn()
            .try_into()
            .map_err(|_| anyhow!("unexpected TDX TEE TCB SVN length"))?
    } else {
        [0u8; 16]
    };

    // Canonical order: SGX components desc, then PCE SVN desc, then TDX
    // components desc (matches Intel QVL / dcap-qvl `canonicalize_tcb_levels`).
    let mut levels: Vec<&TcbLevel> = tcb_info.tcb_levels.iter().collect();
    levels.sort_by(|a, b| {
        svns(&b.tcb.sgx_components)
            .cmp(&svns(&a.tcb.sgx_components))
            .then(b.tcb.pce_svn.cmp(&a.tcb.pce_svn))
            .then(svns(&b.tcb.tdx_components).cmp(&svns(&a.tcb.tdx_components)))
    });

    for level in levels {
        if platform_meets(level, &sgx_comps, pcesvn, &tdx_svn, is_tdx) {
            return Ok(level);
        }
    }
    bail!("no TCB level matched the platform")
}

fn platform_meets(
    level: &TcbLevel,
    sgx_comps: &[u8; 16],
    pcesvn: u16,
    tdx_svn: &[u8; 16],
    is_tdx: bool,
) -> bool {
    for (i, c) in level.tcb.sgx_components.iter().enumerate() {
        if sgx_comps.get(i).copied().unwrap_or(0) < c.svn {
            return false;
        }
    }
    if pcesvn < level.tcb.pce_svn {
        return false;
    }
    if is_tdx {
        for (i, c) in level.tcb.tdx_components.iter().enumerate() {
            if tdx_svn.get(i).copied().unwrap_or(0) < c.svn {
                return false;
            }
        }
    }
    true
}

fn svns(comps: &[TcbComponents]) -> Vec<u8> {
    comps.iter().map(|c| c.svn).collect()
}

/// Map a TCB status string to the numeric code the FFI backend reports in
/// `TcbVerificationResult::tcb_status_code` (the `sgx_ql_qv_result_t` values).
fn status_to_code(status: &str) -> u32 {
    match status {
        "UpToDate" => 0x0000_0000,
        "ConfigurationNeeded" => 0x0000_A001,
        "OutOfDate" => 0x0000_A002,
        "OutOfDateConfigurationNeeded" => 0x0000_A003,
        "InvalidSignature" => 0x0000_A004,
        "Revoked" => 0x0000_A005,
        "Unspecified" => 0x0000_A006,
        "SWHardeningNeeded" => 0x0000_A007,
        "ConfigurationAndSWHardeningNeeded" => 0x0000_A008,
        _ => 0x0000_A006, // Unspecified
    }
}

// ---------------------------------------------------------------------------
// small DER / date helpers
// ---------------------------------------------------------------------------

fn parse_iso8601(s: &str) -> Result<i64> {
    // PCS timestamps are RFC 3339, e.g. "2024-03-13T00:00:00Z".
    let dt = chrono::DateTime::parse_from_rfc3339(s)
        .or_else(|_| chrono::DateTime::parse_from_rfc3339(&format!("{s}Z")))
        .with_context(|| format!("invalid timestamp: {s}"))?;
    Ok(dt.timestamp())
}

/// Dotted-decimal string for an OID given as numeric arcs.
fn arcs_str(arcs: &[u64]) -> String {
    arcs.iter()
        .map(|a| a.to_string())
        .collect::<Vec<_>>()
        .join(".")
}

/// Parse a DER `SEQUENCE OF SEQUENCE { OID, value }` into (dotted-OID, raw value
/// DER) pairs. `value` is the raw DER of whatever followed the OID.
fn parse_der_seq_of_pairs(der: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    let (_, top) = Any::from_der(der).map_err(|e| anyhow!("DER parse error: {e}"))?;
    let mut content = top.data;
    let mut out = Vec::new();
    while !content.is_empty() {
        let (rest, entry) = Any::from_der(content).map_err(|e| anyhow!("DER parse error: {e}"))?;
        let (after_oid, oid) =
            Oid::from_der(entry.data).map_err(|e| anyhow!("DER OID parse error: {e}"))?;
        out.push((oid.to_id_string(), after_oid.to_vec()));
        content = rest;
    }
    Ok(out)
}

/// Interpret a raw DER value as an OCTET STRING and return its bytes.
fn der_octet_string(der: &[u8]) -> Result<Vec<u8>> {
    let (_, any) = Any::from_der(der).map_err(|e| anyhow!("DER parse error: {e}"))?;
    Ok(any.data.to_vec())
}

/// Interpret a raw DER value as an INTEGER and return it as u64.
fn der_integer_u64(der: &[u8]) -> Result<u64> {
    let (_, any) = Any::from_der(der).map_err(|e| anyhow!("DER parse error: {e}"))?;
    let mut v: u64 = 0;
    for &b in any.data {
        v = (v << 8) | b as u64;
    }
    Ok(v)
}

fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn rfind_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).rposition(|w| w == needle)
}
