use anyhow::anyhow;
use base64::Engine;
use log::{debug, warn};
extern crate serde;
use self::serde::{Deserialize, Serialize};
use super::*;
use asn1_rs::{oid, Integer, OctetString, Oid};
use async_trait::async_trait;
use openssl::{
    ec::EcKey,
    ecdsa,
    nid::Nid,
    pkey::{PKey, Public},
    sha::sha384,
    x509::{self, X509},
};
use serde_json::json;
use sev::firmware::guest::AttestationReport;
use sev::firmware::host::{CertTableEntry, CertType};
#[cfg(test)]
use std::sync::OnceLock;
use x509_parser::prelude::*;

#[derive(Serialize, Deserialize)]
pub struct SnpEvidence {
    attestation_report: AttestationReport,
    cert_chain: Option<Vec<CertTableEntry>>,
}

const HW_ID_OID: Oid<'static> = oid!(1.3.6 .1 .4 .1 .3704 .1 .4);
const UCODE_SPL_OID: Oid<'static> = oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .8);
const SNP_SPL_OID: Oid<'static> = oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .3);
const TEE_SPL_OID: Oid<'static> = oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .2);
const LOADER_SPL_OID: Oid<'static> = oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .1);
const FMC_SPL_OID: Oid<'static> = oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .9);

// AMD Key Distribution Service, used to fetch the VCEK on-demand when the
// attester did not embed a cert chain in the evidence (e.g. the host does not
// provision the VCEK cert table in the extended report).
const KDS_CERT_SITE: &str = "https://kdsintf.amd.com";
const KDS_VCEK: &str = "/vcek/v1";

// Supported report versions. v2 has no CPUID fields (legacy, assumed Milan);
// v3..=5 carry CPUID family/model so the processor generation can be derived.
const REPORT_VERSION_MIN: u32 = 2;
const REPORT_VERSION_MAX: u32 = 5;

// Offsets inside the 1184-byte ATTESTATION_REPORT (stable across v2..=5).
const OFF_REPORTED_TCB: usize = 0x180;
const OFF_CPUID_FAM: usize = 0x188;
const OFF_CPUID_MOD: usize = 0x189;

/// AMD EPYC processor generations whose AMD root keys we trust.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProcessorGeneration {
    Milan,
    Genoa,
    Turin,
}

impl std::fmt::Display for ProcessorGeneration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ProcessorGeneration::Milan => "Milan",
            ProcessorGeneration::Genoa => "Genoa",
            ProcessorGeneration::Turin => "Turin",
        };
        write!(f, "{s}")
    }
}

impl ProcessorGeneration {
    fn pem(&self) -> &'static [u8] {
        match self {
            ProcessorGeneration::Milan => include_bytes!("milan_ask_ark_asvk.pem"),
            ProcessorGeneration::Genoa => include_bytes!("genoa_ask_ark_asvk.pem"),
            ProcessorGeneration::Turin => include_bytes!("turin_ask_ark_asvk.pem"),
        }
    }
}

/// reported_tcb SPLs read straight from the raw report bytes. The byte order of
/// TCB_VERSION changed on Turin (a FMC byte was prepended), so the `sev` 4.x
/// `report.reported_tcb` fields are wrong on Turin; we read the raw bytes with a
/// generation-aware layout instead.
struct ReportedTcb {
    fmc: Option<u8>,
    bootloader: u8,
    tee: u8,
    snp: u8,
    microcode: u8,
}

fn read_reported_tcb(raw: &[u8], gen: ProcessorGeneration) -> Result<ReportedTcb> {
    let t = raw
        .get(OFF_REPORTED_TCB..OFF_REPORTED_TCB + 8)
        .context("report too short for REPORTED_TCB")?;
    Ok(match gen {
        // Turin: [fmc, bootloader, tee, snp, _, _, _, microcode]
        ProcessorGeneration::Turin => ReportedTcb {
            fmc: Some(t[0]),
            bootloader: t[1],
            tee: t[2],
            snp: t[3],
            microcode: t[7],
        },
        // Milan/Genoa: [bootloader, tee, _, _, _, _, snp, microcode]
        _ => ReportedTcb {
            fmc: None,
            bootloader: t[0],
            tee: t[1],
            snp: t[6],
            microcode: t[7],
        },
    })
}

/// Derive the processor generation from the CPUID family/model bytes (report
/// v3+). v2 reports have no CPUID data and are treated as Milan for backwards
/// compatibility.
fn get_processor_generation(raw: &[u8], version: u32) -> Result<ProcessorGeneration> {
    if version < 3 {
        return Ok(ProcessorGeneration::Milan);
    }
    let cpu_fam = *raw
        .get(OFF_CPUID_FAM)
        .context("report too short for CPUID")?;
    let cpu_mod = *raw
        .get(OFF_CPUID_MOD)
        .context("report too short for CPUID")?;
    match cpu_fam {
        0x19 => match cpu_mod {
            0x0..=0xF => Ok(ProcessorGeneration::Milan),
            0x10..=0x1F | 0xA0..=0xAF => Ok(ProcessorGeneration::Genoa),
            _ => bail!("Unsupported SNP processor model {cpu_mod:#x} for family 0x19"),
        },
        0x1A => match cpu_mod {
            0x0..=0x11 => Ok(ProcessorGeneration::Turin),
            _ => bail!("Unsupported SNP processor model {cpu_mod:#x} for family 0x1A"),
        },
        _ => bail!("Unsupported SNP processor family {cpu_fam:#x}"),
    }
}

fn load_cert_chain_for(gen: ProcessorGeneration) -> Result<VendorCertificates> {
    let certs = X509::stack_from_pem(gen.pem())?;
    if certs.len() != 3 {
        bail!("Malformed {gen} ASK/ARK/ASVK");
    }
    Ok(VendorCertificates {
        ask: certs[0].clone(),
        ark: certs[1].clone(),
        asvk: certs[2].clone(),
    })
}

/// Fetch the VCEK (DER) from the AMD KDS for the given report and generation.
async fn fetch_vcek_from_kds(
    raw: &[u8],
    gen: ProcessorGeneration,
    chip_id: &[u8],
) -> Result<Vec<u8>> {
    if chip_id.iter().all(|b| *b == 0) {
        bail!("Hardware ID is all-zero; cannot request VCEK from KDS (MASK_CHIP_ID set?)");
    }
    let tcb = read_reported_tcb(raw, gen)?;
    // Turin uses an 8-byte hwID in the KDS URL; earlier generations use 64 bytes.
    let hw_id = match gen {
        ProcessorGeneration::Turin => hex::encode(&chip_id[0..8]),
        _ => hex::encode(chip_id),
    };
    let url = match gen {
        ProcessorGeneration::Turin => {
            let fmc = tcb.fmc.context("Turin report missing FMC TCB value")?;
            format!(
                "{KDS_CERT_SITE}{KDS_VCEK}/{gen}/{hw_id}?fmcSPL={:02}&blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
                fmc, tcb.bootloader, tcb.tee, tcb.snp, tcb.microcode
            )
        }
        _ => format!(
            "{KDS_CERT_SITE}{KDS_VCEK}/{gen}/{hw_id}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
            tcb.bootloader, tcb.tee, tcb.snp, tcb.microcode
        ),
    };
    debug!("Fetching VCEK from KDS: {url}");
    let client = reqwest::Client::builder()
        .build()
        .context("Failed to build KDS HTTP client")?;
    let resp = client
        .get(&url)
        .send()
        .await
        .context("Failed to send VCEK request to KDS")?;
    if !resp.status().is_success() {
        bail!("KDS returned status {} for {url}", resp.status());
    }
    let der = resp
        .bytes()
        .await
        .context("Failed to read VCEK body from KDS")?
        .to_vec();
    Ok(der)
}

#[derive(Debug, Default)]
pub struct Snp {}

#[cfg(test)]
pub(crate) fn load_milan_cert_chain() -> &'static Result<VendorCertificates> {
    static MILAN_CERT_CHAIN: OnceLock<Result<VendorCertificates>> = OnceLock::new();
    MILAN_CERT_CHAIN.get_or_init(|| {
        let certs = X509::stack_from_pem(include_bytes!("milan_ask_ark_asvk.pem"))?;
        if certs.len() != 3 {
            bail!("Malformed Milan ASK/ARK/ASVK");
        }

        let vendor_certs = VendorCertificates {
            ask: certs[0].clone(),
            ark: certs[1].clone(),
            asvk: certs[2].clone(),
        };
        Ok(vendor_certs)
    })
}

impl Snp {
    pub fn new() -> Result<Self> {
        Ok(Self {})
    }
}

#[derive(Clone, Debug)]
pub(crate) struct VendorCertificates {
    ask: X509,
    ark: X509,
    asvk: X509,
}

#[async_trait]
impl Verifier for Snp {
    async fn evaluate(
        &self,
        evidence: TeeEvidence,
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<(TeeEvidenceParsedClaim, TeeClass)> {
        let SnpEvidence {
            attestation_report: report,
            cert_chain,
        } = serde_json::from_value(evidence).context("Deserialize Quote failed.")?;

        // Faithful raw bytes of the report; sev 4.x round-trips v2..=5 reports
        // byte-for-byte, so we use these for offset-based parsing of fields the
        // 4.x struct does not expose correctly (CPUID, Turin TCB layout).
        let raw = bincode::serialize(&report).context("Failed to serialize report")?;

        if report.version < REPORT_VERSION_MIN || report.version > REPORT_VERSION_MAX {
            return Err(anyhow!(
                "Unexpected report version {} (supported {REPORT_VERSION_MIN}..={REPORT_VERSION_MAX})",
                report.version
            ));
        }

        let proc_gen = get_processor_generation(&raw, report.version)?;
        let vendor_certs = load_cert_chain_for(proc_gen)?;

        // Use the cert chain embedded in the evidence, or fetch the VCEK from the
        // AMD KDS when the attester did not provide one.
        let cert_chain = match cert_chain {
            Some(cc) if !cc.is_empty() => cc,
            _ => {
                let vcek = fetch_vcek_from_kds(&raw, proc_gen, &report.chip_id).await?;
                vec![CertTableEntry::new(CertType::VCEK, vcek)]
            }
        };

        verify_report_signature(&report, &raw, &cert_chain, &vendor_certs, proc_gen)?;

        if report.vmpl != 0 {
            return Err(anyhow!("VMPL Check Failed"));
        }

        if let ReportData::Value(expected_report_data) = expected_report_data {
            debug!("Check the binding of REPORT_DATA.");
            let expected_report_data =
                regularize_data(expected_report_data, 64, "REPORT_DATA", "SNP");

            if expected_report_data != report.report_data {
                warn!(
                    "Report data mismatch. Given: {}, Expected: {}",
                    hex::encode(report.report_data),
                    hex::encode(expected_report_data)
                );
                bail!("Report Data Mismatch");
            }
        };

        if let InitDataHash::Value(expected_init_data_hash) = expected_init_data_hash {
            debug!("Check the binding of HOST_DATA.");
            let expected_init_data_hash =
                regularize_data(expected_init_data_hash, 32, "HOST_DATA", "SNP");
            if expected_init_data_hash != report.host_data {
                bail!("Host Data Mismatch");
            }
        }

        let claims_map = parse_tee_evidence(&report, &raw, proc_gen)?;
        let json = json!(claims_map);
        Ok((json, "cpu".to_string()))
    }
}

fn get_oid_octets<const N: usize>(
    vcek: &x509_parser::certificate::TbsCertificate,
    oid: Oid,
) -> Result<[u8; N]> {
    let val = vcek
        .get_extension_unique(&oid)?
        .ok_or_else(|| anyhow!("Oid not found"))?
        .value;

    // Previously, the hwID extension hasn't been encoded as DER octet string.
    // In this case, the value of the extension is the hwID itself (64 byte long),
    // and we can just return the value.
    if val.len() == N {
        return Ok(val.try_into().unwrap());
    }

    // Parse the value as DER encoded octet string.
    let (_, val_octet) = OctetString::from_der(val)?;
    val_octet
        .as_ref()
        .try_into()
        .context("Unexpected data size")
}

fn get_oid_int(cert: &x509_parser::certificate::TbsCertificate, oid: Oid) -> Result<u8> {
    let val = cert
        .get_extension_unique(&oid)?
        .ok_or_else(|| anyhow!("Oid not found"))?
        .value;

    let (_, val_int) = Integer::from_der(val)?;
    val_int.as_u8().context("Unexpected data size")
}

pub(crate) fn verify_report_signature(
    report: &AttestationReport,
    raw: &[u8],
    cert_chain: &[CertTableEntry],
    vendor_certs: &VendorCertificates,
    proc_gen: ProcessorGeneration,
) -> Result<()> {
    // check cert chain
    let VendorCertificates { ask, ark, asvk } = vendor_certs;

    // verify VCEK or VLEK cert chain
    // the key can be either VCEK or VLEK
    let endorsement_key = verify_cert_chain(cert_chain, ask, ark, asvk)?;

    // OpenSSL bindings do not expose custom extensions
    // Parse the key using x509_parser
    let endorsement_key_der = &endorsement_key.to_der()?;
    let parsed_endorsement_key = X509Certificate::from_der(endorsement_key_der)?
        .1
        .tbs_certificate;

    let common_name =
        get_common_name(&endorsement_key).context("No common name found in certificate")?;

    // reported_tcb read from the raw bytes with a generation-aware layout
    // (the sev 4.x struct misreads Turin's TCB which has a prepended FMC byte).
    let tcb = read_reported_tcb(raw, proc_gen)?;

    // if the common name is "VCEK", then the key is a VCEK, so check the chip id.
    // Turin VCEKs carry an 8-byte HWID extension; earlier generations carry 64.
    if common_name == "VCEK" {
        match proc_gen {
            ProcessorGeneration::Turin => {
                let hwid = get_oid_octets::<8>(&parsed_endorsement_key, HW_ID_OID)?;
                if hwid[..] != report.chip_id[0..8] {
                    bail!("Chip ID mismatch");
                }
            }
            _ => {
                if get_oid_octets::<64>(&parsed_endorsement_key, HW_ID_OID)? != report.chip_id {
                    bail!("Chip ID mismatch");
                }
            }
        }
    }

    // tcb version
    // these integer extensions are 3 bytes with the last byte as the data
    if get_oid_int(&parsed_endorsement_key, UCODE_SPL_OID)? != tcb.microcode {
        return Err(anyhow!("Microcode version mismatch"));
    }

    if get_oid_int(&parsed_endorsement_key, SNP_SPL_OID)? != tcb.snp {
        return Err(anyhow!("SNP version mismatch"));
    }

    if get_oid_int(&parsed_endorsement_key, TEE_SPL_OID)? != tcb.tee {
        return Err(anyhow!("TEE version mismatch"));
    }

    if get_oid_int(&parsed_endorsement_key, LOADER_SPL_OID)? != tcb.bootloader {
        return Err(anyhow!("Boot loader version mismatch"));
    }

    // FMC is a Turin+ TCB component.
    if let Some(fmc) = tcb.fmc {
        if get_oid_int(&parsed_endorsement_key, FMC_SPL_OID)? != fmc {
            return Err(anyhow!("FMC version mismatch"));
        }
    }

    // verify report signature
    let sig = ecdsa::EcdsaSig::try_from(&report.signature)?;
    let data = &raw[..=0x29f];

    let pub_key = EcKey::try_from(endorsement_key.public_key()?)?;
    let signed = sig.verify(&sha384(data), &pub_key)?;
    if !signed {
        return Err(anyhow!("Signature validation failed."));
    }

    Ok(())
}

fn verify_signature(cert: &X509, issuer: &X509, name: &str) -> Result<()> {
    cert.verify(&(issuer.public_key()? as PKey<Public>))?
        .then_some(())
        .ok_or_else(|| anyhow!("Invalid {name} signature"))
}

fn verify_cert_chain(
    cert_chain: &[CertTableEntry],
    ask: &X509,
    ark: &X509,
    asvk: &X509,
) -> Result<X509> {
    // get endorsement keys (VLEK or VCEK)
    let endorsement_keys: Vec<&CertTableEntry> = cert_chain
        .iter()
        .filter(|e| e.cert_type == CertType::VCEK || e.cert_type == CertType::VLEK)
        .collect();

    let &[key] = endorsement_keys.as_slice() else {
        bail!("Could not find either VCEK or VLEK in cert chain")
    };

    let decoded_key =
        x509::X509::from_der(key.data()).context("Failed to decode endorsement key")?;

    match key.cert_type {
        CertType::VCEK => {
            // Chain: ARK -> ARK -> ASK -> VCEK
            verify_signature(ark, ark, "ARK")?;
            verify_signature(ask, ark, "ASK")?;
            verify_signature(&decoded_key, ask, "VCEK")?;
        }
        CertType::VLEK => {
            // Chain: ARK -> ARK -> ASVK -> VLEK
            verify_signature(ark, ark, "ARK")?;
            verify_signature(asvk, ark, "ASVK")?;
            verify_signature(&decoded_key, asvk, "VLEK")?;
        }
        _ => bail!("Certificate not of type versioned endorsement key (VLEK or VCEK)"),
    }

    Ok(decoded_key)
}

pub(crate) fn parse_tee_evidence(
    report: &AttestationReport,
    raw: &[u8],
    proc_gen: ProcessorGeneration,
) -> Result<TeeEvidenceParsedClaim> {
    // generation-aware reported_tcb (see read_reported_tcb)
    let tcb = read_reported_tcb(raw, proc_gen)?;
    let claims_map = json!({
        // policy fields
        "policy_abi_major": format!("{}",report.policy.abi_major()),
        "policy_abi_minor": format!("{}", report.policy.abi_minor()),
        "policy_smt_allowed": format!("{}", report.policy.smt_allowed()),
        "policy_migrate_ma": format!("{}", report.policy.migrate_ma_allowed()),
        "policy_debug_allowed": format!("{}", report.policy.debug_allowed()),
        "policy_single_socket": format!("{}", report.policy.single_socket_required()),

        // versioning info
        "reported_tcb_bootloader": format!("{}", tcb.bootloader),
        "reported_tcb_tee": format!("{}", tcb.tee),
        "reported_tcb_snp": format!("{}", tcb.snp),
        "reported_tcb_microcode": format!("{}", tcb.microcode),

        // platform info
        "platform_tsme_enabled": format!("{}", report.plat_info.tsme_enabled()),
        "platform_smt_enabled": format!("{}", report.plat_info.smt_enabled()),

        // measurement
        "measurement": format!("{}", base64::engine::general_purpose::STANDARD.encode(report.measurement)),
    });

    Ok(claims_map as TeeEvidenceParsedClaim)
}

fn get_common_name(cert: &x509::X509) -> Result<String> {
    let mut entries = cert.subject_name().entries_by_nid(Nid::COMMONNAME);
    let Some(e) = entries.next() else {
        bail!("No CN found");
    };

    if entries.count() != 0 {
        bail!("No CN found");
    }

    Ok(e.data().as_utf8()?.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VCEK: &[u8; 1360] = include_bytes!("../../test_data/snp/test-vcek.der");
    const VCEK_LEGACY: &[u8; 1361] =
        include_bytes!("../../test_data/snp/test-vcek-invalid-legacy.der");
    const VCEK_NEW: &[u8; 1362] = include_bytes!("../../test_data/snp/test-vcek-invalid-new.der");
    const VCEK_REPORT: &[u8; 1184] = include_bytes!("../../test_data/snp/test-report.bin");

    const VLEK: &[u8; 1329] = include_bytes!("../../test_data/snp/test-vlek.der");
    const VLEK_REPORT: &[u8; 1184] = include_bytes!("../../test_data/snp/test-vlek-report.bin");

    // Real AMD EPYC 9xx5 "Turin" (Zen5) v5 attestation report and the matching
    // VCEK fetched from the AMD KDS.
    const TURIN_REPORT: &[u8; 1184] = include_bytes!("../../test_data/snp/turin-report.bin");
    const TURIN_VCEK: &[u8; 1289] = include_bytes!("../../test_data/snp/turin-vcek.der");

    #[test]
    fn check_milan_certificates() {
        let VendorCertificates { ask, ark, asvk } = load_milan_cert_chain().as_ref().unwrap();
        assert_eq!(get_common_name(ark).unwrap(), "ARK-Milan");
        assert_eq!(get_common_name(ask).unwrap(), "SEV-Milan");
        assert_eq!(get_common_name(asvk).unwrap(), "SEV-VLEK-Milan");

        assert!(ark
            .verify(&(ark.public_key().unwrap() as PKey<Public>))
            .context("Invalid ARK Signature")
            .unwrap());

        assert!(ask
            .verify(&(ark.public_key().unwrap() as PKey<Public>))
            .context("Invalid ASK Signature")
            .unwrap());

        assert!(asvk
            .verify(&(ark.public_key().unwrap() as PKey<Public>))
            .context("Invalid ASVK Signature")
            .unwrap());
    }

    fn check_oid_ints(cert: &TbsCertificate) {
        let oids = vec![UCODE_SPL_OID, SNP_SPL_OID, TEE_SPL_OID, LOADER_SPL_OID];
        for oid in oids {
            get_oid_int(&cert, oid).unwrap();
        }
    }

    #[test]
    fn check_vlek_parsing() {
        let parsed_vlek = X509Certificate::from_der(VLEK).unwrap().1.tbs_certificate;

        check_oid_ints(&parsed_vlek);
    }

    #[test]
    fn check_vcek_parsing() {
        let parsed_vcek = X509Certificate::from_der(VCEK).unwrap().1.tbs_certificate;

        get_oid_octets::<64>(&parsed_vcek, HW_ID_OID).unwrap();

        check_oid_ints(&parsed_vcek);
    }

    #[test]
    fn check_vcek_parsing_legacy() {
        let parsed_vcek = X509Certificate::from_der(VCEK_LEGACY)
            .unwrap()
            .1
            .tbs_certificate;

        get_oid_octets::<64>(&parsed_vcek, HW_ID_OID).unwrap();

        check_oid_ints(&parsed_vcek);
    }

    #[test]
    fn check_vcek_parsing_new() {
        let parsed_vcek = X509Certificate::from_der(VCEK_NEW)
            .unwrap()
            .1
            .tbs_certificate;

        get_oid_octets::<64>(&parsed_vcek, HW_ID_OID).unwrap();

        check_oid_ints(&parsed_vcek);
    }

    #[test]
    fn check_vcek_signature_verification() {
        let cert_table = vec![CertTableEntry::new(CertType::VCEK, VCEK.to_vec())];
        let VendorCertificates { ask, ark, asvk } = load_milan_cert_chain().as_ref().unwrap();
        verify_cert_chain(&cert_table, ask, ark, asvk).unwrap();
    }

    #[test]
    fn check_vcek_signature_failure() {
        let mut vcek = VCEK.clone();

        // corrupt some byte, while it should remain a valid cert
        vcek[42] += 1;
        X509::from_der(&vcek).expect("failed to parse der");

        let cert_table = vec![CertTableEntry::new(CertType::VCEK, vcek.to_vec())];
        let VendorCertificates { ask, ark, asvk } = load_milan_cert_chain().as_ref().unwrap();
        verify_cert_chain(&cert_table, ask, ark, asvk).unwrap_err();
    }

    #[test]
    fn check_vlek_signature_verification() {
        let cert_table = vec![CertTableEntry::new(CertType::VLEK, VLEK.to_vec())];
        let VendorCertificates { ask, ark, asvk } = load_milan_cert_chain().as_ref().unwrap();
        verify_cert_chain(&cert_table, ask, ark, asvk).unwrap();
    }

    #[test]
    fn check_vlek_signature_failure() {
        let mut vlek = VLEK.clone();

        // corrupt some byte, while it should remain a valid cert
        vlek[42] += 1;
        X509::from_der(&vlek).expect("failed to parse der");

        let cert_table = vec![CertTableEntry::new(CertType::VLEK, vlek.to_vec())];
        let VendorCertificates { ask, ark, asvk } = load_milan_cert_chain().as_ref().unwrap();
        verify_cert_chain(&cert_table, ask, ark, asvk).unwrap_err();
    }

    #[test]
    fn check_milan_chain_signature_failure() {
        let cert_table = vec![CertTableEntry::new(CertType::VCEK, VCEK.to_vec())];
        let VendorCertificates { ask, ark, asvk } = load_milan_cert_chain().as_ref().unwrap();

        // toggle ark <=> ask
        verify_cert_chain(&cert_table, ark, ask, asvk).unwrap_err();
    }

    #[test]
    fn check_report_signature() {
        let attestation_report =
            bincode::deserialize::<AttestationReport>(VCEK_REPORT.as_slice()).unwrap();
        let cert_chain = vec![CertTableEntry::new(CertType::VCEK, VCEK.to_vec())];
        let vendor_certs = load_milan_cert_chain().as_ref().unwrap();
        verify_report_signature(
            &attestation_report,
            &bincode::serialize(&attestation_report).unwrap(),
            &cert_chain,
            vendor_certs,
            ProcessorGeneration::Milan,
        )
        .unwrap();
    }

    #[test]
    fn check_vlek_report_signature() {
        let attestation_report =
            bincode::deserialize::<AttestationReport>(VLEK_REPORT.as_slice()).unwrap();
        let cert_chain = vec![CertTableEntry::new(CertType::VLEK, VLEK.to_vec())];
        let vendor_certs = load_milan_cert_chain().as_ref().unwrap();
        verify_report_signature(
            &attestation_report,
            &bincode::serialize(&attestation_report).unwrap(),
            &cert_chain,
            vendor_certs,
            ProcessorGeneration::Milan,
        )
        .unwrap();
    }

    #[test]
    fn check_report_signature_failure() {
        let mut bytes = VCEK_REPORT.clone();

        // corrupt some byte
        bytes[42] += 1;

        let attestation_report = bincode::deserialize::<AttestationReport>(&bytes).unwrap();
        let cert_chain = vec![CertTableEntry::new(CertType::VCEK, VCEK.to_vec())];
        let vendor_certs = load_milan_cert_chain().as_ref().unwrap();
        verify_report_signature(
            &attestation_report,
            &bincode::serialize(&attestation_report).unwrap(),
            &cert_chain,
            vendor_certs,
            ProcessorGeneration::Milan,
        )
        .unwrap_err();
    }

    #[test]
    fn check_vlek_report_signature_failure() {
        let mut bytes = VLEK_REPORT.clone();

        // corrupt some byte
        bytes[42] += 1;

        let attestation_report = bincode::deserialize::<AttestationReport>(&bytes).unwrap();
        let cert_chain = vec![CertTableEntry::new(CertType::VLEK, VLEK.to_vec())];
        let vendor_certs = load_milan_cert_chain().as_ref().unwrap();
        verify_report_signature(
            &attestation_report,
            &bincode::serialize(&attestation_report).unwrap(),
            &cert_chain,
            vendor_certs,
            ProcessorGeneration::Milan,
        )
        .unwrap_err();
    }

    #[test]
    fn check_turin_generation_and_tcb() {
        let report = bincode::deserialize::<AttestationReport>(TURIN_REPORT.as_slice()).unwrap();
        let raw = bincode::serialize(&report).unwrap();
        assert_eq!(report.version, 5);
        assert_eq!(
            get_processor_generation(&raw, report.version).unwrap(),
            ProcessorGeneration::Turin
        );
        // The sev 4.x struct misreads Turin's FMC-shifted TCB; the raw reader fixes it.
        let tcb = read_reported_tcb(&raw, ProcessorGeneration::Turin).unwrap();
        assert_eq!(
            (tcb.bootloader, tcb.tee, tcb.snp, tcb.microcode),
            (3, 2, 5, 97)
        );
        assert_eq!(tcb.fmc, Some(1));
    }

    #[test]
    fn check_turin_report_signature() {
        let report = bincode::deserialize::<AttestationReport>(TURIN_REPORT.as_slice()).unwrap();
        let raw = bincode::serialize(&report).unwrap();
        let vendor_certs = load_cert_chain_for(ProcessorGeneration::Turin).unwrap();
        let cert_chain = vec![CertTableEntry::new(CertType::VCEK, TURIN_VCEK.to_vec())];
        verify_report_signature(
            &report,
            &raw,
            &cert_chain,
            &vendor_certs,
            ProcessorGeneration::Turin,
        )
        .unwrap();
    }

    #[test]
    fn check_turin_report_signature_failure() {
        let mut bytes = *TURIN_REPORT;
        bytes[0x90] ^= 0x01; // corrupt the measurement
        let report = bincode::deserialize::<AttestationReport>(&bytes).unwrap();
        let raw = bincode::serialize(&report).unwrap();
        let vendor_certs = load_cert_chain_for(ProcessorGeneration::Turin).unwrap();
        let cert_chain = vec![CertTableEntry::new(CertType::VCEK, TURIN_VCEK.to_vec())];
        verify_report_signature(
            &report,
            &raw,
            &cert_chain,
            &vendor_certs,
            ProcessorGeneration::Turin,
        )
        .unwrap_err();
    }
}
