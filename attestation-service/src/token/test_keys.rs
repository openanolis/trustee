// Copyright (c) 2026 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{extension::BasicConstraints, X509Name, X509},
};
use tempfile::NamedTempFile;

pub(super) fn rsa_signer_files() -> (NamedTempFile, NamedTempFile) {
    let ca_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let ca = certificate("Trustee test root", 1, &ca_key, None);
    let leaf_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let leaf = certificate("Trustee test signer", 2, &leaf_key, Some((&ca, &ca_key)));

    let key_file = NamedTempFile::new().unwrap();
    std::fs::write(&key_file, leaf_key.private_key_to_pem_pkcs8().unwrap()).unwrap();
    let chain_file = NamedTempFile::new().unwrap();
    let mut chain = leaf.to_pem().unwrap();
    chain.extend(ca.to_pem().unwrap());
    std::fs::write(&chain_file, chain).unwrap();
    (key_file, chain_file)
}

fn certificate(
    common_name: &str,
    serial: u32,
    key: &PKey<Private>,
    issuer: Option<(&X509, &PKey<Private>)>,
) -> X509 {
    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_text("CN", common_name).unwrap();
    let name = name.build();
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    let serial = BigNum::from_u32(serial).unwrap().to_asn1_integer().unwrap();
    cert.set_serial_number(&serial).unwrap();
    cert.set_subject_name(&name).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    cert.set_pubkey(key).unwrap();
    match issuer {
        Some((ca, ca_key)) => {
            cert.set_issuer_name(ca.subject_name()).unwrap();
            cert.sign(ca_key, MessageDigest::sha256()).unwrap();
        }
        None => {
            cert.set_issuer_name(&name).unwrap();
            cert.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
                .unwrap();
            cert.sign(key, MessageDigest::sha256()).unwrap();
        }
    }
    cert.build()
}
