use crate::config::{build_default_config, DEFAULT_WORK_DIR};
use crate::data::{load_init_data, parse_runtime_hash_alg, parse_tee, read_evidence};
use aes_gcm::{
    aead::{generic_array::GenericArray, AeadMutInPlace},
    Aes256Gcm, KeyInit, Nonce,
};
use aes_kw::{Kek, KekAes256};
use anyhow::{anyhow, bail, Context, Result};
use attestation_service::{AttestationService, VerificationRequest};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use kbs_types::{ProtectedHeader, Response as EncryptedResponse, TeePubKey};
use p256::{
    ecdh::EphemeralSecret, elliptic_curve::sec1::FromEncodedPoint, EncodedPoint, PublicKey,
};
use rand::{rngs::OsRng, Rng, RngCore};
use reqwest::Client;
use rsa::{sha2::Sha256, BigUint, Oaep, RsaPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::path::PathBuf;

const RSA_OAEP256_ALGORITHM: &str = "RSA-OAEP-256";
const ECDH_ES_A256KW: &str = "ECDH-ES+A256KW";
const EC_KTY: &str = "EC";
const P256_CURVE: &str = "P-256";
const AES_GCM_256_ALGORITHM: &str = "A256GCM";
const AES_GCM_256_KEY_BITS: u32 = 256;
const RESOURCE_INJECTION_RUNTIME_HASH_ALGORITHM: &str = "sha384";

#[derive(Debug, Deserialize)]
struct PrepareResponse {
    session_id: String,
    nonce: String,
    tee_pubkey: Value,
    evidence: String,
}

#[derive(Debug, Serialize)]
struct PrepareRequest {
    nonce: String,
}

#[derive(Debug, Serialize)]
struct CommitRequest {
    session_id: String,
    encrypted_resource: Value,
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    api_url: String,
    resource_path: String,
    resource_file: PathBuf,
    tee_text: String,
    nonce: Option<String>,
    init_data_digest: Option<String>,
    init_data_toml: Option<PathBuf>,
    policies: Vec<String>,
) -> Result<()> {
    let (repository, r#type, tag) = parse_resource_path(&resource_path)?;
    let nonce = nonce.unwrap_or_else(generate_nonce);
    let base = api_url.trim_end_matches('/');
    let prepare_url = format!(
        "{base}/cdh/resource-injection/prepare/{repository}/{}/{tag}",
        r#type
    );
    let commit_url = format!(
        "{base}/cdh/resource-injection/commit/{repository}/{}/{tag}",
        r#type
    );

    let client = Client::new();
    let prepare_resp = client
        .post(prepare_url)
        .json(&PrepareRequest {
            nonce: nonce.clone(),
        })
        .send()
        .await
        .context("send prepare injection request")?;
    if !prepare_resp.status().is_success() {
        bail!(
            "prepare injection request failed with status {}",
            prepare_resp.status()
        );
    }
    let prepare: PrepareResponse = prepare_resp
        .json()
        .await
        .context("parse prepare response body")?;
    if prepare.nonce != nonce {
        bail!("prepare response nonce mismatch");
    }

    verify_evidence(
        prepare.evidence,
        &tee_text,
        init_data_digest,
        init_data_toml,
        policies,
        prepare.nonce.clone(),
        prepare.tee_pubkey.clone(),
    )
    .await?;

    let resource_plaintext = std::fs::read(&resource_file)
        .with_context(|| format!("read resource file {}", resource_file.display()))?;
    let tee_pubkey: TeePubKey =
        serde_json::from_value(prepare.tee_pubkey).context("parse TEE public key from prepare")?;
    let encrypted = encrypt_for_tee(tee_pubkey, resource_plaintext)?;
    let encrypted_resource =
        serde_json::to_value(encrypted).context("serialize encrypted resource")?;

    let commit_resp = client
        .post(commit_url)
        .json(&CommitRequest {
            session_id: prepare.session_id,
            encrypted_resource,
        })
        .send()
        .await
        .context("send commit injection request")?;
    if !commit_resp.status().is_success() {
        bail!(
            "commit injection request failed with status {}",
            commit_resp.status()
        );
    }

    println!("resource injected successfully to {resource_path}");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn verify_evidence(
    evidence_b64: String,
    tee_text: &str,
    init_data_digest: Option<String>,
    init_data_toml: Option<PathBuf>,
    policies: Vec<String>,
    nonce: String,
    tee_pubkey: Value,
) -> Result<()> {
    let evidence_raw = base64::engine::general_purpose::STANDARD
        .decode(evidence_b64)
        .context("decode base64 evidence from prepare response")?;
    let evidence_text =
        String::from_utf8(evidence_raw).context("prepare response evidence is not valid utf-8")?;
    let mut evidence_file = tempfile::NamedTempFile::new().context("create temporary evidence")?;
    std::io::Write::write_all(&mut evidence_file, evidence_text.as_bytes())
        .context("write temporary evidence")?;

    let work_dir = PathBuf::from(DEFAULT_WORK_DIR);
    let config = build_default_config(&work_dir)?;
    let attestation_service = AttestationService::new(config)
        .await
        .context("initialize attestation service")?;

    let evidence = read_evidence(evidence_file.path())?;
    let tee = parse_tee(tee_text)?;
    let runtime_hash_algorithm = parse_runtime_hash_alg(RESOURCE_INJECTION_RUNTIME_HASH_ALGORITHM)?;
    let runtime_data = Some(attestation_service::RuntimeData::Structured(json!({
        "nonce": nonce,
        "tee-pubkey": tee_pubkey,
    })));
    let init_data = load_init_data(init_data_digest, init_data_toml)?;
    let policy_ids = if policies.is_empty() {
        vec!["default".into()]
    } else {
        policies
    };

    let request = VerificationRequest {
        evidence,
        tee,
        runtime_data,
        runtime_data_hash_algorithm: runtime_hash_algorithm,
        init_data,
        additional_data: None,
    };

    attestation_service
        .evaluate(vec![request], policy_ids)
        .await
        .context("verify challenge evidence before injection")?;

    Ok(())
}

fn parse_resource_path(resource_path: &str) -> Result<(&str, &str, &str)> {
    let mut parts = resource_path.split('/');
    let repository = parts.next().ok_or_else(|| {
        anyhow!("invalid resource_path, expected format: <repository>/<type>/<tag>")
    })?;
    let r#type = parts.next().ok_or_else(|| {
        anyhow!("invalid resource_path, expected format: <repository>/<type>/<tag>")
    })?;
    let tag = parts.next().ok_or_else(|| {
        anyhow!("invalid resource_path, expected format: <repository>/<type>/<tag>")
    })?;
    if parts.next().is_some() || repository.is_empty() || r#type.is_empty() || tag.is_empty() {
        bail!("invalid resource_path, expected format: <repository>/<type>/<tag>");
    }
    Ok((repository, r#type, tag))
}

fn generate_nonce() -> String {
    let mut bytes = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn encrypt_for_tee(tee_pub_key: TeePubKey, payload_data: Vec<u8>) -> Result<EncryptedResponse> {
    match tee_pub_key {
        TeePubKey::RSA { alg, k_mod, k_exp } => match &alg[..] {
            RSA_OAEP256_ALGORITHM => rsa_oaep256(k_mod, k_exp, payload_data),
            others => bail!("unsupported tee public key algorithm: {others}"),
        },
        TeePubKey::EC { crv, alg, x, y } => match (&crv[..], &alg[..]) {
            (P256_CURVE, ECDH_ES_A256KW) => ecdh_es_a256kw_p256(x, y, payload_data),
            (crv, alg) => bail!("unsupported tee public key curve {crv} and algorithm {alg}"),
        },
    }
}

fn rsa_oaep256(
    k_mod: String,
    k_exp: String,
    mut payload_data: Vec<u8>,
) -> Result<EncryptedResponse> {
    let mut rng = rand::thread_rng();
    let aes_sym_key = Aes256Gcm::generate_key(&mut OsRng);
    let mut cipher = Aes256Gcm::new(&aes_sym_key);
    let iv = rng.gen::<[u8; 12]>();
    let nonce = Nonce::from_slice(&iv);
    let protected = ProtectedHeader {
        alg: RSA_OAEP256_ALGORITHM.to_string(),
        enc: AES_GCM_256_ALGORITHM.to_string(),
        other_fields: Map::new(),
    };

    let aad = protected.generate_aad().context("generate JWE AAD")?;
    let tag = cipher
        .encrypt_in_place_detached(nonce, &aad, &mut payload_data)
        .map_err(|e| anyhow!("AES encrypt resource payload failed: {e}"))?;

    let k_mod = URL_SAFE_NO_PAD
        .decode(k_mod)
        .context("base64 decode k_mod failed")?;
    let n = BigUint::from_bytes_be(&k_mod);
    let k_exp = URL_SAFE_NO_PAD
        .decode(k_exp)
        .context("base64 decode k_exp failed")?;
    let e = BigUint::from_bytes_be(&k_exp);
    let rsa_pub_key = RsaPublicKey::new(n, e).context("build RSA public key failed")?;
    let encrypted_key = rsa_pub_key
        .encrypt(&mut rng, Oaep::new::<Sha256>(), aes_sym_key.as_slice())
        .context("RSA OAEP encrypt CEK failed")?;

    Ok(EncryptedResponse {
        protected,
        encrypted_key,
        iv: iv.into(),
        ciphertext: payload_data,
        aad: None,
        tag: tag.to_vec(),
    })
}

fn ecdh_es_a256kw_p256(
    x: String,
    y: String,
    mut payload_data: Vec<u8>,
) -> Result<EncryptedResponse> {
    let mut rng = rand::thread_rng();
    let cek = Aes256Gcm::generate_key(&mut rng);

    let x: [u8; 32] = URL_SAFE_NO_PAD
        .decode(x)
        .context("base64 decode x failed")?
        .try_into()
        .map_err(|_| anyhow!("invalid bytes length of coordinate x"))?;
    let y: [u8; 32] = URL_SAFE_NO_PAD
        .decode(y)
        .context("base64 decode y failed")?
        .try_into()
        .map_err(|_| anyhow!("invalid bytes length of coordinate y"))?;
    let client_point = EncodedPoint::from_affine_coordinates(
        &GenericArray::from(x),
        &GenericArray::from(y),
        false,
    );
    let public_key = PublicKey::from_encoded_point(&client_point)
        .into_option()
        .ok_or(anyhow!("invalid TEE public key"))?;

    let encrypter_secret = EphemeralSecret::random(&mut rng);
    let z = encrypter_secret
        .diffie_hellman(&public_key)
        .raw_secret_bytes()
        .to_vec();
    let mut key_derivation_materials = Vec::new();
    key_derivation_materials.extend_from_slice(&(ECDH_ES_A256KW.len() as u32).to_be_bytes());
    key_derivation_materials.extend_from_slice(ECDH_ES_A256KW.as_bytes());
    key_derivation_materials.extend_from_slice(&(0_u32).to_be_bytes());
    key_derivation_materials.extend_from_slice(&(0_u32).to_be_bytes());
    key_derivation_materials.extend_from_slice(&AES_GCM_256_KEY_BITS.to_be_bytes());

    let mut wrapping_key = vec![0; 32];
    concat_kdf::derive_key_into::<rsa::sha2::Sha256>(
        &z,
        &key_derivation_materials,
        &mut wrapping_key,
    )
    .map_err(|e| anyhow!("derive ECDH wrapping key failed: {e:?}"))?;
    let wrapping_key: [u8; 32] = wrapping_key
        .try_into()
        .map_err(|_| anyhow!("invalid bytes length of wrapping key"))?;
    let wrapping_key: KekAes256 = Kek::new(&GenericArray::from(wrapping_key));
    let cek = cek.to_vec();
    let mut encrypted_key = vec![0; 40];
    wrapping_key
        .wrap(&cek, &mut encrypted_key)
        .map_err(|e| anyhow!("AES key wrap failed: {e:?}"))?;

    let point = EncodedPoint::from(encrypter_secret.public_key());
    let epk_x = URL_SAFE_NO_PAD.encode(
        point
            .x()
            .ok_or(anyhow!("invalid ephemeral key: missing x"))?,
    );
    let epk_y = URL_SAFE_NO_PAD.encode(
        point
            .y()
            .ok_or(anyhow!("invalid ephemeral key: missing y"))?,
    );
    let protected = ProtectedHeader {
        alg: ECDH_ES_A256KW.to_string(),
        enc: AES_GCM_256_ALGORITHM.to_string(),
        other_fields: json!({
            "epk": {
                "crv": P256_CURVE,
                "kty": EC_KTY,
                "x": epk_x,
                "y": epk_y
            }
        })
        .as_object()
        .expect("epk must be object")
        .clone(),
    };

    let mut cek_cipher = Aes256Gcm::new(GenericArray::from_slice(&cek));
    let iv = rand::thread_rng().gen::<[u8; 12]>();
    let nonce = Nonce::from_slice(&iv);
    let aad = protected.generate_aad().context("generate JWE AAD")?;
    let tag = cek_cipher
        .encrypt_in_place_detached(nonce, &aad, &mut payload_data)
        .map_err(|e| anyhow!("AES encrypt resource payload failed: {e}"))?;

    Ok(EncryptedResponse {
        protected,
        encrypted_key,
        iv: iv.into(),
        ciphertext: payload_data,
        aad: None,
        tag: tag.to_vec(),
    })
}
