use std::{collections::HashMap, sync::Arc};

use actix_web::{body::BoxBody, web, HttpRequest, HttpResponse, Responder, ResponseError};
use anyhow::{anyhow, bail, Context};
use attestation_service::{
    AttestationService, HashAlgorithm, InitDataInput as InnerInitDataInput,
    RuntimeData as InnerRuntimeData, VerificationRequest,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use kbs_types::{ErrorInformation, Tee};
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use strum::AsRefStr;
use thiserror::Error;
use tokio::sync::RwLock;

const ERROR_TYPE_PREFIX: &str =
    "https://github.com/confidential-containers/attestation-service/errors";

#[derive(Error, Debug, AsRefStr)]
#[allow(dead_code)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[error("Bad request: {0}")]
    BadRequest(#[source] anyhow::Error),

    #[error("Unauthorized: {0}")]
    Unauthorized(#[source] anyhow::Error),

    #[error("Forbidden: {0}")]
    Forbidden(#[source] anyhow::Error),

    #[error("Not found: {0}")]
    NotFound(#[source] anyhow::Error),

    #[error("Conflict: {0}")]
    Conflict(#[source] anyhow::Error),

    #[error("Unprocessable entity: {0}")]
    UnprocessableEntity(#[source] anyhow::Error),

    #[error("An internal error occured: {0}")]
    InternalError(#[from] anyhow::Error),
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        // 统一的错误信息结构
        let detail = format!("{}", self);
        let info = ErrorInformation {
            error_type: format!("{}/{}", ERROR_TYPE_PREFIX, self.as_ref()),
            detail,
        };

        let body = serde_json::to_string(&info).unwrap_or_else(|_| "{}".to_string());

        let mut res = match self {
            Error::BadRequest(_) => HttpResponse::BadRequest(),
            Error::Unauthorized(_) => HttpResponse::Unauthorized(),
            Error::Forbidden(_) => HttpResponse::Forbidden(),
            Error::NotFound(_) => HttpResponse::NotFound(),
            Error::Conflict(_) => HttpResponse::Conflict(),
            Error::UnprocessableEntity(_) => HttpResponse::UnprocessableEntity(),
            Error::InternalError(_) => HttpResponse::InternalServerError(),
        };

        res.body(BoxBody::new(body))
    }
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Deserialize)]
pub struct AttestationRequest {
    verification_requests: Vec<IndividualAttestationRequest>,
    policy_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct IndividualAttestationRequest {
    tee: String,
    evidence: String,
    runtime_data: Option<RuntimeData>,
    init_data: Option<InitDataInput>,
    runtime_data_hash_algorithm: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeRequest {
    // ChallengeRequest uses HashMap to pass variables like:
    // tee, tee_params etc
    #[serde(flatten)]
    inner: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RuntimeData {
    Raw(String),
    Structured(Value),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum InitDataInput {
    InitDataDigest(String),
    InitDataToml(String),
}

fn to_tee(tee: &str) -> anyhow::Result<Tee> {
    let res = match tee {
        "azsnpvtpm" => Tee::AzSnpVtpm,
        "sev" => Tee::Sev,
        "sgx" => Tee::Sgx,
        "snp" => Tee::Snp,
        "tdx" => Tee::Tdx,
        // "cca" => Tee::Cca,
        "csv" => Tee::Csv,
        "sample" => Tee::Sample,
        "sampledevice" => Tee::SampleDevice,
        "aztdxvtpm" => Tee::AzTdxVtpm,
        "system" => Tee::System,
        "se" => Tee::Se,
        "tpm" => Tee::Tpm,
        "hygondcu" => Tee::HygonDcu,
        other => bail!("tee `{other} not supported`"),
    };

    Ok(res)
}

fn parse_runtime_data(data: RuntimeData) -> Result<InnerRuntimeData> {
    let res = match data {
        RuntimeData::Raw(raw) => {
            let data = URL_SAFE_NO_PAD
                .decode(raw)
                .map_err(|e| Error::BadRequest(anyhow!("base64 decode raw runtime data: {e}")))?;
            InnerRuntimeData::Raw(data)
        }
        RuntimeData::Structured(structured) => InnerRuntimeData::Structured(structured),
    };

    Ok(res)
}

fn parse_init_data(data: InitDataInput) -> Result<InnerInitDataInput> {
    let res = match data {
        InitDataInput::InitDataDigest(raw) => {
            let data = URL_SAFE_NO_PAD
                .decode(raw)
                .map_err(|e| Error::BadRequest(anyhow!("base64 decode raw init data: {e}")))?;
            InnerInitDataInput::Digest(data)
        }
        InitDataInput::InitDataToml(structured) => InnerInitDataInput::Toml(structured),
    };

    Ok(res)
}

/// This handler uses json extractor
pub async fn attestation(
    request: web::Json<AttestationRequest>,
    cocoas: web::Data<Arc<RwLock<AttestationService>>>,
) -> Result<HttpResponse> {
    info!("Attestation API called.");

    let request = request.into_inner();
    debug!("attestation: {request:#?}");

    let mut verification_requests: Vec<VerificationRequest> = vec![];
    for attestation_request in request.verification_requests {
        let evidence = URL_SAFE_NO_PAD
            .decode(&attestation_request.evidence)
            .map_err(|e| Error::BadRequest(anyhow!("base64 decode evidence: {e}")))?;

        let evidence = serde_json::from_slice(&evidence)
            .map_err(|e| Error::BadRequest(anyhow!("failed to parse evidence as JSON: {e}")))?;

        let tee = to_tee(&attestation_request.tee)
            .map_err(|e| Error::BadRequest(anyhow!("invalid tee: {e}")))?;

        let runtime_data = attestation_request
            .runtime_data
            .map(parse_runtime_data)
            .transpose()?;

        let init_data = attestation_request
            .init_data
            .map(parse_init_data)
            .transpose()?;

        let runtime_data_hash_algorithm = match attestation_request.runtime_data_hash_algorithm {
            Some(alg) => HashAlgorithm::try_from(&alg[..]).map_err(|e| {
                Error::BadRequest(anyhow!("parse runtime data HashAlgorithm failed: {e}"))
            })?,
            None => {
                info!("No Runtime Data Hash Algorithm provided, use `sha384` by default.");
                HashAlgorithm::Sha384
            }
        };

        verification_requests.push(VerificationRequest {
            evidence,
            tee,
            runtime_data,
            runtime_data_hash_algorithm,
            init_data,
        });
    }

    let policy_ids = if request.policy_ids.is_empty() {
        info!("no policy specified. `default` will be used");
        vec!["default".into()]
    } else {
        request.policy_ids
    };

    let token = cocoas
        .read()
        .await
        .evaluate(verification_requests, policy_ids)
        .await
        .map_err(|e| Error::InternalError(anyhow!("attestation report evaluate: {e}")))?;
    Ok(HttpResponse::Ok().body(token))
}

#[derive(Deserialize, Debug)]
pub struct SetPolicyInput {
    policy_id: String,
    policy: String,
}

/// This handler uses json extractor with limit
pub async fn set_policy(
    input: web::Json<SetPolicyInput>,
    cocoas: web::Data<Arc<RwLock<AttestationService>>>,
) -> Result<HttpResponse> {
    info!("Set Policy API called.");
    let input = input.into_inner();

    debug!("set policy: {input:#?}");
    cocoas
        .write()
        .await
        .set_policy(input.policy_id, input.policy)
        .await
        .context("set policy")?;

    Ok(HttpResponse::Ok().body(""))
}

/// This handler uses json extractor
pub async fn get_challenge(
    request: web::Json<ChallengeRequest>,
    cocoas: web::Data<Arc<RwLock<AttestationService>>>,
) -> Result<HttpResponse> {
    info!("get_challenge API called.");
    let request: ChallengeRequest = request.into_inner();

    debug!("get_challenge: {request:#?}");
    let inner_tee = request
        .inner
        .get("tee")
        .as_ref()
        .map(|s| s.as_str())
        .ok_or_else(|| Error::BadRequest(anyhow!("Failed to get inner tee")))?;
    let tee_params = request
        .inner
        .get("tee_params")
        .ok_or_else(|| Error::BadRequest(anyhow!("Failed to get inner tee_params")))?;

    let tee = to_tee(inner_tee).map_err(|e| Error::BadRequest(anyhow!("invalid tee: {e}")))?;
    let challenge = cocoas
        .read()
        .await
        .generate_supplemental_challenge(tee, tee_params.to_string())
        .await
        .map_err(|e| Error::InternalError(anyhow!("generate challenge: {e}")))?;
    Ok(HttpResponse::Ok().body(challenge))
}

/// GET /policy
/// GET /policy/{policy_id}
///
/// The returned body would look like
/// ```json
/// [
///     {"policy-id": <id-1>, "policy-hash": <hash-1>},
///     {"policy-id": <id-2>, "policy-hash": <hash-2>},
///     ...
/// ]
/// ```
pub async fn get_policies(
    request: HttpRequest,
    cocoas: web::Data<Arc<RwLock<AttestationService>>>,
) -> Result<HttpResponse> {
    info!("get policy.");

    match request.match_info().get("policy_id") {
        Some(policy_id) => {
            let policy = cocoas
                .read()
                .await
                .get_policy(policy_id.to_string())
                .await
                .context("get policy")?;

            Ok(HttpResponse::Ok().body(policy))
        }
        None => {
            let policy_list = cocoas
                .read()
                .await
                .list_policies()
                .await
                .context("get policies")?
                .into_iter()
                .map(|(id, digest)| json!({"policy-id": id, "policy-hash": digest}))
                .collect::<Vec<_>>();

            let policy_list =
                serde_json::to_string(&policy_list).context("serialize response body")?;

            Ok(HttpResponse::Ok().body(policy_list))
        }
    }
}

/// DELETE /policy/{policy_id}
pub async fn delete_policy(
    request: HttpRequest,
    cocoas: web::Data<Arc<RwLock<AttestationService>>>,
) -> Result<HttpResponse> {
    info!("delete policy API called.");

    let policy_id = request
        .match_info()
        .get("policy_id")
        .ok_or_else(|| anyhow!("Policy ID is required"))?;

    debug!("delete policy: {policy_id}");

    cocoas
        .write()
        .await
        .delete_policy(policy_id.to_string())
        .await
        .context("delete policy")?;

    Ok(HttpResponse::Ok().body(""))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RemovePolicyRequest {
    pub policy_ids: Vec<String>,
}

/// Handler for getting token broker certificate
pub async fn get_certificate(
    attestation_service: web::Data<Arc<RwLock<AttestationService>>>,
) -> impl Responder {
    let service = attestation_service.read().await;
    match service.get_token_broker_cert_config().await {
        Ok(Some(cert_content)) => {
            // Return certificate content
            HttpResponse::Ok()
                .content_type("application/x-pem-file")
                .body(cert_content)
        }
        Ok(None) => {
            // No certificate configured
            HttpResponse::NotFound().json(serde_json::json!({
                "error": "No certificate configured"
            }))
        }
        Err(e) => {
            error!("Failed to get certificate: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to get certificate: {}", e)
            }))
        }
    }
}
