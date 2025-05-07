// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use actix_web::http::Method;
use anyhow::*;
use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    rsa::Rsa,
    x509::{
        extension::{BasicConstraints, KeyUsage},
        X509Builder, X509NameBuilder, X509,
    },
};
use serde::Deserialize;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use super::super::plugin_manager::ClientPlugin;

// Default RSA Key Bits
const RSA_KEY_BITS: u32 = 2048;
// Default TPM private CA name
const DEFAULT_TPM_CA_NAME: &str = "Trustee TPM Private CA";
// Default organization Name
const DEFAULT_ORGANIZATION_NAME: &str = "Trustee";
// Default CA signing key file name
const SIGNING_KEY_NAME: &str = "ca.key";
// Default CA cert file name
const CA_CERT_NAME: &str = "ca.crt";
// Default workdir
const DEFAULT_WORK_DIR: &str = "/opt/confidential-containers/kbs/tpm-pca";
// Default CA self-signed certificate duration (365d)
const DEFAULT_CA_CERT_DURATION: &str = "365d";

#[derive(Deserialize, Clone, Debug, PartialEq)]
pub struct TpmCaConfig {
    signing_key_path: Option<String>,
    cert_chain_path: Option<String>,
    work_dir: Option<String>,
    tpm_self_signed_ca_config: Option<SelfSignedTpmCaConfig>,
}

#[allow(dead_code)]
pub struct TpmCaPlugin {
    /// PEM format signing key path
    signing_key_path: PathBuf,
    /// PEM format cert chain
    cert_chain_path: PathBuf,
    /// Work dir
    work_dir: PathBuf,
}

impl TryFrom<TpmCaConfig> for TpmCaPlugin {
    type Error = anyhow::Error;

    fn try_from(config: TpmCaConfig) -> anyhow::Result<Self> {
        let work_dir_path_str = &config.work_dir.unwrap_or(DEFAULT_WORK_DIR.to_string());
        let work_dir_path = Path::new(work_dir_path_str);
        std::fs::create_dir_all(work_dir_path)?;

        let mut signing_key_path = PathBuf::from(config.signing_key_path.unwrap_or_default());
        let mut cert_chain_path = PathBuf::from(config.cert_chain_path.unwrap_or_default());

        // If singing key not exists, generate a new key pair and a self-signed CA cert.
        if signing_key_path.as_os_str().is_empty() {
            if !cert_chain_path.as_os_str().is_empty() {
                bail!("Miss private key of CA certificate, `signing_key_path` must be specified when `cert_chain_path` is specified");
            }

            log::warn!("Generate self signed Root CA");

            signing_key_path.extend(vec![work_dir_path, Path::new(SIGNING_KEY_NAME)]);

            if !signing_key_path.as_path().exists() {
                let signing_key = Rsa::generate(RSA_KEY_BITS)?;

                let mut file = std::fs::File::create(&signing_key_path)?;
                file.write_all(&signing_key.private_key_to_pem()?)?;
            }
        }

        if cert_chain_path.as_os_str().is_empty() {
            cert_chain_path.extend(vec![work_dir_path, Path::new(CA_CERT_NAME)]);

            if !cert_chain_path.as_path().exists() {
                let signing_key_pem = std::fs::read(&signing_key_path)
                    .map_err(|e| anyhow!("Read TPM CA Signing key failed: {:?}", e))?;
                let signing_key = Rsa::private_key_from_pem(&signing_key_pem)?;
                let pkey = PKey::from_rsa(signing_key)?;

                let mut name_builder = X509NameBuilder::new()?;

                let ca_config = match config.tpm_self_signed_ca_config {
                    Some(ref c) => c.clone(),
                    None => SelfSignedTpmCaConfig::default(),
                };

                name_builder.append_entry_by_nid(
                    Nid::COMMONNAME,
                    &ca_config.name.unwrap_or(DEFAULT_TPM_CA_NAME.to_string()),
                )?;
                name_builder.append_entry_by_nid(Nid::COUNTRYNAME, "CN")?;
                name_builder.append_entry_by_nid(
                    Nid::ORGANIZATIONNAME,
                    &ca_config
                        .organization
                        .unwrap_or(DEFAULT_ORGANIZATION_NAME.to_string()),
                )?;
                let name = name_builder.build();

                let mut builder = X509::builder()?;
                builder.set_version(2)?;
                builder.set_subject_name(&name)?;
                builder.set_issuer_name(&name)?;
                builder.set_pubkey(&pkey)?;

                let duration = ca_config
                    .duration
                    .unwrap_or(DEFAULT_CA_CERT_DURATION.to_string());

                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                let not_before =
                    Asn1Time::from_unix(now).context("Failed to set not_before time")?;
                let duration_seconds = parse_duration(&duration)
                    .context("Failed to parse duration of self-signed CA cert")?;
                let not_after = Asn1Time::from_unix(now + duration_seconds)
                    .context("Failed to set not_after time")?;
                builder.set_not_before(not_before.as_ref())?;
                builder.set_not_after(not_after.as_ref())?;

                builder.sign(&pkey, MessageDigest::sha256())?;

                let certificate = builder.build();

                let mut file = std::fs::File::create(&cert_chain_path)?;
                file.write_all(&certificate.to_pem()?)?;
            }
        }

        if !signing_key_path.as_path().exists() || !cert_chain_path.as_path().exists() {
            bail!("CA key or certificate not found");
        }

        Ok(Self {
            signing_key_path,
            cert_chain_path,
            work_dir: PathBuf::from(work_dir_path),
        })
    }
}

/// Root CA configuration
///
/// These properties can be provided in the KBS config
/// under [plugins.self_signed_ca]. They are optional.
#[derive(Clone, Debug, Default, serde::Deserialize, PartialEq)]
struct SelfSignedTpmCaConfig {
    /// Name of the certificate authority
    name: Option<String>,
    /// Name of the certificate organization
    organization: Option<String>,
    /// Amount of time the certificate should be valid for. Valid time units are: <hours>"h"<minutes>"m"<seconds>"s"
    duration: Option<String>,
    /// Comma separated list of groups. This will limit which groups subordinate certs can use
    groups: Option<String>,
}

/// Credential service parameters
///
/// They are provided in the request via URL query string.
#[derive(Debug, PartialEq, serde::Deserialize)]
pub struct AkCredentialParams {
    /// Required: name of the cert, usually AK name (HEX encode)
    name: String,
    /// Optional: how long the cert should be valid for.
    /// The default is 1 second before the signing cert expires.
    /// Valid time units are seconds: "s", minutes: "m", hours: "h".
    duration: Option<String>,
    /// AK public key (PEM format).
    ak_pubkey: String,
    /// EK cert.
    ek_cert: Option<String>,
}

impl TryFrom<&str> for AkCredentialParams {
    type Error = Error;

    fn try_from(query: &str) -> Result<Self> {
        let params: AkCredentialParams = serde_qs::from_str(query)?;
        Ok(params)
    }
}

#[async_trait::async_trait]
impl ClientPlugin for TpmCaPlugin {
    async fn handle(
        &self,
        _body: &[u8],
        query: &str,
        path: &str,
        method: &Method,
    ) -> Result<Vec<u8>> {
        let sub_path = path
            .strip_prefix('/')
            .context("accessed path is illegal, should start with `/`")?;
        if method.as_str() != "GET" {
            bail!("Illegal HTTP method. Only GET is supported");
        }

        // The TPM CA plugin is stateless, so none of request types below should
        // store state.
        match sub_path {
            // Create AK credential for the provided parameters.
            "ak-credential" => {
                let params = AkCredentialParams::try_from(query)
                    .map_err(|e| anyhow!("Parse AK ceredential request params failed: {e}"))?;

                let credential = self.create_ak_credential(&params).await?;

                Ok(serde_json::to_vec(&credential)?)
            }
            // Get CA certificate chain
            "certificate" => {
                let cert = std::fs::read_to_string(&self.cert_chain_path.as_path())
                    .map_err(|e| anyhow!("Failed to read CA certificate chain: {e}"))?;

                Ok(cert.into_bytes())
            }
            _ => Err(anyhow!("{} not supported", sub_path))?,
        }
    }

    async fn validate_auth(
        &self,
        _body: &[u8],
        _query: &str,
        _path: &str,
        _method: &Method,
    ) -> Result<bool> {
        Ok(true)
    }

    /// Whether the body needs to be encrypted via TEE key pair.
    /// If returns `Ok(true)`, the KBS server will encrypt the whole body
    /// with TEE key pair and use KBS protocol's Response format.
    async fn encrypted(
        &self,
        _body: &[u8],
        _query: &str,
        _path: &str,
        _method: &Method,
    ) -> Result<bool> {
        Ok(false)
    }
}

impl TpmCaPlugin {
    async fn create_ak_credential(&self, params: &AkCredentialParams) -> Result<Vec<u8>> {
        // 1. Load CA private key and certificate
        let ca_key = PKey::private_key_from_pem(
            &std::fs::read(&self.signing_key_path).with_context(|| {
                format!(
                    "Failed to read CA key from {:?}",
                    self.signing_key_path.as_os_str()
                )
            })?,
        )
        .with_context(|| "Failed to parse CA private key")?;

        let ca_cert = X509::from_pem(&std::fs::read(&self.cert_chain_path).with_context(|| {
            format!(
                "Failed to read CA cert from {:?}",
                self.cert_chain_path.as_os_str()
            )
        })?)
        .with_context(|| "Failed to parse CA certificate")?;

        // 2. Parse AK public key
        let ak_pubkey = PKey::public_key_from_pem(params.ak_pubkey.as_bytes())
            .with_context(|| "Failed to parse AK public key")?;

        // 3. Build certificate
        let mut cert_builder = X509Builder::new().context("Failed to create X509 builder")?;

        // Set version (X509v3)
        cert_builder.set_version(2)?; // Note: 2 corresponds to X509v3

        // Generate random serial number
        let serial = {
            let mut bn = BigNum::new()?;
            bn.rand(128, MsbOption::MAYBE_ZERO, false)?; // Generate 128-bit random number
            bn.to_asn1_integer()?
        };
        cert_builder.set_serial_number(&serial)?;

        // Handle validity period
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Parse duration parameter
        let duration_seconds = match &params.duration {
            Some(d) => parse_duration(d)?,
            None => {
                // Default to CA certificate validity minus 1 second
                let epoch_asn1_time = Asn1Time::from_unix(0)?;
                let ca_not_after = ca_cert.not_after().diff(epoch_asn1_time.as_ref())?.secs as i64;
                ca_not_after - now - 1
            }
        };

        let not_before = Asn1Time::from_unix(now)?;
        cert_builder.set_not_before(not_before.as_ref())?;
        let not_after = Asn1Time::from_unix(now + duration_seconds)?;
        cert_builder.set_not_after(not_after.as_ref())?;

        // Build subject name
        let mut subject_builder = X509NameBuilder::new()?;
        subject_builder
            .append_entry_by_nid(Nid::COMMONNAME, &params.name)
            .context("Failed to set common name")?;
        let subject = subject_builder.build();
        cert_builder.set_subject_name(&subject)?;

        // Set issuer name (from CA certificate)
        cert_builder.set_issuer_name(ca_cert.issuer_name())?;

        // Set public key
        cert_builder.set_pubkey(&ak_pubkey)?;

        // Add extensions
        // Basic constraints (non-CA)
        let basic_constraints = BasicConstraints::new()
            .critical()
            .ca()
            .build()
            .context("Failed to create basic constraints")?;
        cert_builder.append_extension(basic_constraints)?;

        // Key usage
        let key_usage = KeyUsage::new()
            .critical()
            .digital_signature()
            .build()
            .context("Failed to create key usage")?;
        cert_builder.append_extension(key_usage)?;

        // 4. Sign with CA private key
        cert_builder
            .sign(&ca_key, MessageDigest::sha256())
            .context("Failed to sign certificate")?;

        // 5. Generate final certificate
        let cert = cert_builder.build();

        // 6. Build certificate chain (new certificate + CA certificate)
        let mut pem = cert.to_pem().context("Failed to encode certificate")?;
        pem.extend_from_slice(
            &ca_cert
                .to_pem()
                .context("Failed to encode CA certificate")?,
        );

        Ok(pem)
    }
}

/// Parse duration string into seconds
fn parse_duration(time_string: &str) -> Result<i64> {
    // Match the string against the pattern: digits followed by a time unit
    let re = regex::Regex::new(r"^(\d+)([smhd])$")
        .map_err(|e| anyhow!("Failed to compile regex: {}", e))?;

    // Try to capture the groups
    if let Some(captures) = re.captures(time_string) {
        // Get the number as a string and parse it to i64
        let number = captures
            .get(1)
            .unwrap()
            .as_str()
            .parse::<i64>()
            .map_err(|e| anyhow!("Failed to parse number: {}", e))?;

        // Get the unit string
        let unit = captures.get(2).unwrap().as_str();

        // Calculate seconds based on the unit
        let seconds = match unit {
            "s" => number,
            "m" => number * 60,
            "h" => number * 3600,
            "d" => number * 86400,
            _ => bail!("Unknown time unit"),
        };

        Ok(seconds)
    } else {
        bail!("Invalid Format")
    }
}
