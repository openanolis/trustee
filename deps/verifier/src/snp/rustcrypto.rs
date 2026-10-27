//! Crypto backend only. Parsing, chip/TCB binding, REPORT_DATA, HOST_DATA and
//! SVSM checks remain in the common SNP verifier.
use anyhow::{bail, Context, Result};
use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use rsa::{pkcs1::RsaPssParams, pkcs8::DecodePublicKey};
use sev::firmware::guest::AttestationReport;
use sha2::Sha384;
use x509_cert::{
    der::{Decode, Encode},
    Certificate as X509,
};
use x509_parser::prelude::*;

#[derive(Clone, Debug)]
pub(super) struct Certificate(Vec<u8>);

impl Certificate {
    pub(super) fn from_der(bytes: &[u8]) -> Result<Self> {
        X509::from_der(bytes).context("Invalid DER certificate")?;
        Ok(Self(bytes.to_vec()))
    }

    pub(super) fn stack_from_pem(bytes: &[u8]) -> Result<Vec<Self>> {
        ::pem::parse_many(bytes)?
            .into_iter()
            .map(|pem| {
                if pem.tag() != "CERTIFICATE" {
                    bail!("Expected a certificate PEM block");
                }
                Self::from_der(pem.contents())
            })
            .collect()
    }

    pub(super) fn to_der(&self) -> Result<Vec<u8>> {
        Ok(self.0.clone())
    }
}

pub(super) fn get_common_name(cert: &Certificate) -> Result<String> {
    let (_, cert) =
        X509Certificate::from_der(&cert.0).map_err(|_| anyhow::anyhow!("Invalid certificate"))?;
    let mut names = cert.subject().iter_common_name();
    let name = names.next().context("No CN found")?.as_str()?.to_owned();
    if names.next().is_some() {
        bail!("Multiple certificate common names");
    }
    Ok(name)
}

pub(super) fn verify_signature(cert: &Certificate, issuer: &Certificate, name: &str) -> Result<()> {
    let cert = X509::from_der(&cert.0)?;
    let issuer = X509::from_der(&issuer.0)?;
    // AMD endorsement chains use RSA-PSS/SHA-384, MGF1/SHA-384 and 48-byte
    // salt. Check both AlgorithmIdentifiers and parameters; accepting only the
    // OID silently ignores attacker-selected PSS parameters.
    if cert.signature_algorithm != cert.tbs_certificate.signature
        || cert.signature_algorithm.oid.to_string() != "1.2.840.113549.1.1.10"
    {
        bail!("Unsupported {name} certificate signature algorithm");
    }
    let parameters = cert
        .signature_algorithm
        .parameters
        .as_ref()
        .context("Missing PSS parameters")?
        .to_der()?;
    let parameters = RsaPssParams::from_der(&parameters)?;
    let expected = RsaPssParams::new::<Sha384>(48);
    let mask = parameters
        .mask_gen
        .parameters
        .context("Missing PSS mask hash")?;
    let null_or_absent = |value: Option<x509_cert::der::asn1::AnyRef<'_>>| {
        value.is_none_or(|p| p == x509_cert::der::asn1::AnyRef::NULL)
    };
    if parameters.hash.oid != expected.hash.oid
        || !null_or_absent(parameters.hash.parameters)
        || parameters.mask_gen.oid != expected.mask_gen.oid
        || mask.oid != expected.hash.oid
        || !null_or_absent(mask.parameters)
        || parameters.salt_len != 48
        || parameters.trailer_field != expected.trailer_field
    {
        bail!("Unsupported {name} certificate signature parameters");
    }
    if cert.tbs_certificate.issuer != issuer.tbs_certificate.subject {
        bail!("Invalid {name} issuer");
    }
    let key = rsa::RsaPublicKey::from_public_key_der(
        &issuer.tbs_certificate.subject_public_key_info.to_der()?,
    )?;
    let signature = rsa::pss::Signature::try_from(cert.signature.raw_bytes())?;
    rsa::pss::VerifyingKey::<Sha384>::new(key)
        .verify(&cert.tbs_certificate.to_der()?, &signature)
        .with_context(|| format!("Invalid {name} signature"))
}

pub(super) fn verify_report(
    report: &AttestationReport,
    raw: &[u8],
    cert: &Certificate,
) -> Result<()> {
    let cert = X509::from_der(&cert.0)?;
    let spki = &cert.tbs_certificate.subject_public_key_info;
    if report.sig_algo != 1
        || spki.algorithm.oid.to_string() != "1.2.840.10045.2.1"
        || spki
            .algorithm
            .parameters
            .as_ref()
            .context("Missing EC curve")?
            .decode_as::<x509_cert::der::asn1::ObjectIdentifier>()?
            .to_string()
            != "1.3.132.0.34"
    {
        bail!("SNP requires an ECDSA P-384 report signature");
    }
    let r = report.signature.r();
    let s = report.signature.s();
    if r[48..].iter().chain(&s[48..]).any(|byte| *byte != 0) {
        bail!("Non-canonical SNP signature scalar");
    }
    let mut signature = [0u8; 96];
    for index in 0..48 {
        signature[index] = r[47 - index];
        signature[index + 48] = s[47 - index];
    }
    let signature = Signature::from_slice(&signature)?;
    let key = VerifyingKey::from_sec1_bytes(spki.subject_public_key.raw_bytes())?;
    key.verify(
        raw.get(..0x2a0).context("Truncated SNP report")?,
        &signature,
    )
    .context("SNP report signature validation failed")
}
