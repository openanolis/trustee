use std::{collections::HashMap, sync::Arc};

use actix_web::{http::StatusCode, web, HttpRequest, HttpResponse, Responder, ResponseError};
use anyhow::{anyhow, bail, Context};
use attestation_service::challenge::verify_challenge_and_extract_nonce_b64url;
use attestation_service::{
    AttestationError, AttestationService, HashAlgorithm, InitDataInput as InnerInitDataInput,
    RuntimeData as InnerRuntimeData, VerificationRequest,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use kbs_types::Tee;
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;
use tokio::sync::RwLock;

const ERROR_TYPE_PREFIX: &str =
    "https://github.com/confidential-containers/attestation-service/errors";

#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
enum ErrorKind {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    UnprocessableEntity,
    BadGateway,
    ServiceUnavailable,
    InternalError,
}

impl ErrorKind {
    fn status(self) -> StatusCode {
        match self {
            Self::BadRequest => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Conflict => StatusCode::CONFLICT,
            Self::UnprocessableEntity => StatusCode::UNPROCESSABLE_ENTITY,
            Self::BadGateway => StatusCode::BAD_GATEWAY,
            Self::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn type_name(self) -> &'static str {
        match self {
            Self::BadRequest => "BadRequest",
            Self::Unauthorized => "Unauthorized",
            Self::Forbidden => "Forbidden",
            Self::NotFound => "NotFound",
            Self::Conflict => "Conflict",
            Self::UnprocessableEntity => "UnprocessableEntity",
            Self::BadGateway => "BadGateway",
            Self::ServiceUnavailable => "ServiceUnavailable",
            Self::InternalError => "InternalError",
        }
    }
}

#[derive(Debug, Error)]
#[error("{code}: {source:#}")]
pub struct Error {
    kind: ErrorKind,
    code: &'static str,
    title: &'static str,
    detail: String,
    retryable: bool,
    field: Option<String>,
    #[source]
    source: anyhow::Error,
}

#[derive(Debug, Serialize, Deserialize)]
struct ProblemDetails {
    #[serde(rename = "type")]
    error_type: String,
    title: String,
    status: u16,
    code: String,
    detail: String,
    retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    field: Option<String>,
}

impl Error {
    fn new(
        kind: ErrorKind,
        code: &'static str,
        title: &'static str,
        detail: impl Into<String>,
        retryable: bool,
        field: Option<String>,
        source: anyhow::Error,
    ) -> Self {
        Self {
            kind,
            code,
            title,
            detail: detail.into(),
            retryable,
            field,
            source,
        }
    }

    fn bad_request(
        code: &'static str,
        title: &'static str,
        detail: impl Into<String>,
        field: impl Into<String>,
        source: anyhow::Error,
    ) -> Self {
        Self::new(
            ErrorKind::BadRequest,
            code,
            title,
            detail,
            false,
            Some(field.into()),
            source,
        )
    }

    fn unauthorized(
        code: &'static str,
        title: &'static str,
        detail: impl Into<String>,
        source: anyhow::Error,
    ) -> Self {
        Self::new(
            ErrorKind::Unauthorized,
            code,
            title,
            detail,
            false,
            None,
            source,
        )
    }

    fn internal(source: anyhow::Error) -> Self {
        Self::new(
            ErrorKind::InternalError,
            "AS.INTERNAL.ERROR",
            "Internal server error",
            "The attestation service encountered an internal error.",
            false,
            None,
            source,
        )
    }

    fn from_attestation_evaluation(source: anyhow::Error) -> Self {
        let request_index =
            source
                .chain()
                .find_map(|cause| match cause.downcast_ref::<AttestationError>() {
                    Some(AttestationError::Verification { request_index, .. }) => {
                        Some(*request_index)
                    }
                    _ => None,
                });

        let specification = source.chain().find_map(|cause| {
            let error = cause.downcast_ref::<AttestationError>()?;
            match error {
                AttestationError::InvalidRequest {
                    request_index,
                    field,
                    ..
                } => {
                    let field = request_field(*request_index, field);
                    Some((
                        ErrorKind::BadRequest,
                        "AS.REQUEST.INVALID_ARGUMENT",
                        "Invalid request argument",
                        format!("Attestation request field `{field}` is invalid."),
                        false,
                        Some(field),
                    ))
                }
                AttestationError::UnsupportedTee { request_index, .. } => Some((
                    ErrorKind::BadRequest,
                    "AS.REQUEST.UNSUPPORTED_TEE",
                    "Unsupported TEE",
                    "The requested TEE type is not enabled by this attestation service."
                        .to_string(),
                    false,
                    Some(format!("verification_requests[{request_index}].tee")),
                )),
                AttestationError::Verification { .. } => None,
            }
        });

        let specification = specification.or_else(|| {
            source.chain().find_map(|cause| {
                let error = cause.downcast_ref::<verifier::VerifierError>()?;
                let evidence_field =
                    |field| request_index.map(|index| evidence_field(index, field));
                Some(match error {
                    verifier::VerifierError::InvalidEvidenceFormat { field, .. } => (
                        ErrorKind::BadRequest,
                        "AS.EVIDENCE.INVALID_FORMAT",
                        "Invalid evidence format",
                        "The evidence structure is invalid.".to_string(),
                        false,
                        evidence_field(field),
                    ),
                    verifier::VerifierError::InvalidEvidenceEncoding { field, .. } => (
                        ErrorKind::BadRequest,
                        "AS.EVIDENCE.INVALID_ENCODING",
                        "Invalid evidence encoding",
                        "An evidence field uses an invalid encoding.".to_string(),
                        false,
                        evidence_field(field),
                    ),
                    verifier::VerifierError::InvalidQuote { field, .. } => (
                        ErrorKind::UnprocessableEntity,
                        "AS.EVIDENCE.INVALID_QUOTE",
                        "Invalid attestation quote",
                        "The attestation quote is malformed or unsupported.".to_string(),
                        false,
                        evidence_field(field),
                    ),
                    verifier::VerifierError::VerificationFailed { .. } => (
                        ErrorKind::UnprocessableEntity,
                        "AS.EVIDENCE.VERIFICATION_FAILED",
                        "Evidence verification failed",
                        "The evidence could not be cryptographically verified.".to_string(),
                        false,
                        None,
                    ),
                    verifier::VerifierError::BindingMismatch { field, .. } => (
                        ErrorKind::UnprocessableEntity,
                        "AS.EVIDENCE.BINDING_MISMATCH",
                        "Evidence binding mismatch",
                        "The evidence is not bound to the expected data.".to_string(),
                        false,
                        evidence_field(field),
                    ),
                    verifier::VerifierError::DependencyBadResponse { .. } => (
                        ErrorKind::BadGateway,
                        "AS.DEPENDENCY.BAD_RESPONSE",
                        "Invalid dependency response",
                        "An attestation dependency returned an invalid response.".to_string(),
                        true,
                        None,
                    ),
                    verifier::VerifierError::DependencyUnavailable { .. } => (
                        ErrorKind::ServiceUnavailable,
                        "AS.DEPENDENCY.UNAVAILABLE",
                        "Dependency unavailable",
                        "An attestation dependency is temporarily unavailable.".to_string(),
                        true,
                        None,
                    ),
                    verifier::VerifierError::Internal { .. } => (
                        ErrorKind::InternalError,
                        "AS.INTERNAL.ERROR",
                        "Internal server error",
                        "The attestation service encountered an internal error.".to_string(),
                        false,
                        None,
                    ),
                })
            })
        });

        match specification {
            Some((kind, code, title, detail, retryable, field)) => {
                Self::new(kind, code, title, detail, retryable, field, source)
            }
            None => Self::internal(source),
        }
    }
}

impl From<anyhow::Error> for Error {
    fn from(source: anyhow::Error) -> Self {
        Self::internal(source)
    }
}

impl ResponseError for Error {
    fn status_code(&self) -> StatusCode {
        self.kind.status()
    }

    fn error_response(&self) -> HttpResponse {
        let status = self.status_code();
        error!(
            "code={} status={} error={:#}",
            self.code,
            status.as_u16(),
            self.source
        );

        let problem = ProblemDetails {
            error_type: format!("{}/{}", ERROR_TYPE_PREFIX, self.kind.type_name()),
            title: self.title.to_string(),
            status: status.as_u16(),
            code: self.code.to_string(),
            detail: self.detail.clone(),
            retryable: self.retryable,
            field: self.field.clone(),
        };

        HttpResponse::build(status)
            .content_type("application/problem+json")
            .json(problem)
    }
}

fn request_field(request_index: Option<usize>, field: &str) -> String {
    match request_index {
        Some(index) => format!("verification_requests[{index}].{field}"),
        None => field.to_string(),
    }
}

fn evidence_field(request_index: usize, field: &str) -> String {
    let base = format!("verification_requests[{request_index}].evidence");
    match field {
        "evidence" => base,
        field => format!("{base}.{field}"),
    }
}

pub fn json_config() -> web::JsonConfig {
    web::JsonConfig::default().error_handler(|source, _request| {
        Error::bad_request(
            "AS.REQUEST.INVALID_JSON",
            "Invalid JSON request",
            "The request body is not valid JSON for this endpoint.",
            "body",
            source.into(),
        )
        .into()
    })
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
    additional_data: Option<String>,
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
        "hygontpm" => Tee::HygonTpm,
        "hygondcu" => Tee::HygonDcu,
        other => bail!("tee `{other} not supported`"),
    };

    Ok(res)
}

fn parse_runtime_data(data: RuntimeData) -> Result<InnerRuntimeData> {
    let res = match data {
        RuntimeData::Raw(raw) => {
            let data = URL_SAFE_NO_PAD.decode(raw).map_err(|source| {
                Error::bad_request(
                    "AS.EVIDENCE.INVALID_ENCODING",
                    "Invalid runtime data encoding",
                    "Runtime data uses an invalid encoding.",
                    "runtime_data.raw",
                    source.into(),
                )
            })?;
            InnerRuntimeData::Raw(data)
        }
        RuntimeData::Structured(structured) => InnerRuntimeData::Structured(structured),
    };

    Ok(res)
}

fn parse_init_data(data: InitDataInput) -> Result<InnerInitDataInput> {
    let res = match data {
        InitDataInput::InitDataDigest(raw) => {
            let data = URL_SAFE_NO_PAD.decode(raw).map_err(|source| {
                Error::bad_request(
                    "AS.EVIDENCE.INVALID_ENCODING",
                    "Invalid init data encoding",
                    "Init data uses an invalid encoding.",
                    "init_data.init_data_digest",
                    source.into(),
                )
            })?;
            InnerInitDataInput::Digest(data)
        }
        InitDataInput::InitDataToml(structured) => InnerInitDataInput::Toml(structured),
    };

    Ok(res)
}

/// Return transport-neutral AS and verifier dependency status. This endpoint
/// does not contact PCCS; it only snapshots the in-process state.
pub async fn get_status(cocoas: web::Data<Arc<RwLock<AttestationService>>>) -> impl Responder {
    let status = cocoas.read().await.status().await;
    web::Json(status)
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
    for (request_index, attestation_request) in
        request.verification_requests.into_iter().enumerate()
    {
        let evidence = URL_SAFE_NO_PAD
            .decode(&attestation_request.evidence)
            .map_err(|source| {
                Error::bad_request(
                    "AS.EVIDENCE.INVALID_ENCODING",
                    "Invalid evidence encoding",
                    "The evidence uses an invalid encoding.",
                    evidence_field(request_index, "evidence"),
                    source.into(),
                )
            })?;

        let evidence = serde_json::from_slice(&evidence).map_err(|source| {
            Error::bad_request(
                "AS.EVIDENCE.INVALID_FORMAT",
                "Invalid evidence format",
                "The decoded evidence is not valid JSON.",
                evidence_field(request_index, "evidence"),
                source.into(),
            )
        })?;

        let tee = to_tee(&attestation_request.tee).map_err(|source| {
            Error::bad_request(
                "AS.REQUEST.UNSUPPORTED_TEE",
                "Unsupported TEE",
                "The requested TEE type is unsupported.",
                format!("verification_requests[{request_index}].tee"),
                source,
            )
        })?;

        let runtime_data = match attestation_request.runtime_data {
            Some(RuntimeData::Structured(v)) => {
                if let Some(jwt) = v.get("challenge_token").and_then(|x| x.as_str()) {
                    // 验证 token，但不修改 runtime_data 内容
                    let challenge_key_path = cocoas.read().await.challenge_key_path();
                    let _ = verify_challenge_and_extract_nonce_b64url(jwt, &challenge_key_path)
                        .map_err(|source| {
                            Error::unauthorized(
                                "AS.CHALLENGE.INVALID_TOKEN",
                                "Invalid challenge token",
                                "The challenge token is invalid or expired.",
                                source,
                            )
                        })?;
                }
                Some(parse_runtime_data(RuntimeData::Structured(v))?)
            }
            Some(RuntimeData::Raw(raw)) => Some(parse_runtime_data(RuntimeData::Raw(raw))?),
            None => None,
        };

        let init_data = attestation_request
            .init_data
            .map(parse_init_data)
            .transpose()?;

        let runtime_data_hash_algorithm = match attestation_request.runtime_data_hash_algorithm {
            Some(alg) => HashAlgorithm::try_from(&alg[..]).map_err(|e| {
                Error::bad_request(
                    "AS.REQUEST.INVALID_ARGUMENT",
                    "Invalid request argument",
                    "The runtime data hash algorithm is unsupported.",
                    format!("verification_requests[{request_index}].runtime_data_hash_algorithm"),
                    e.into(),
                )
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
            additional_data: attestation_request.additional_data,
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
        .map_err(|source| {
            Error::from_attestation_evaluation(source.context("attestation report evaluate"))
        })?;
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
    let tee_opt = match request.inner.get("tee") {
        Some(s) => Some(to_tee(s).map_err(|source| {
            Error::bad_request(
                "AS.REQUEST.UNSUPPORTED_TEE",
                "Unsupported TEE",
                "The requested TEE type is unsupported.",
                "tee",
                source,
            )
        })?),
        None => None,
    };
    let tee_params_opt = request.inner.get("tee_params").cloned();
    let challenge = cocoas
        .read()
        .await
        .generate_challenge(tee_opt, tee_params_opt)
        .await
        .map_err(|source| Error::internal(source.context("generate challenge")))?;
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

pub async fn get_jwks(
    attestation_service: web::Data<Arc<RwLock<AttestationService>>>,
) -> impl Responder {
    let service = attestation_service.read().await;
    match service.get_token_broker_public_key().await {
        Ok(Some(public_key_content)) => {
            // Return certificate content
            HttpResponse::Ok()
                .content_type("application/json")
                .body(public_key_content)
        }
        Ok(None) => {
            // No certificate configured
            HttpResponse::NotFound().json(serde_json::json!({
                "error": "No public key configured"
            }))
        }
        Err(e) => {
            error!("Failed to get public key: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to get public key: {}", e)
            }))
        }
    }
}

pub async fn get_openid_configuration(
    attestation_service: web::Data<Arc<RwLock<AttestationService>>>,
) -> impl Responder {
    let service = attestation_service.read().await;
    match service.get_token_broker_oid_config().await {
        Ok(Some(oid_config_content)) => {
            // Return certificate content
            HttpResponse::Ok()
                .content_type("application/json")
                .body(oid_config_content)
        }
        Ok(None) => {
            // No certificate configured
            HttpResponse::NotFound().json(serde_json::json!({
                "error": "No OpenId config configured"
            }))
        }
        Err(e) => {
            error!("Failed to get OpenID config: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to get OpenID config: {}", e)
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{body::to_bytes, http::header, test, App};

    async fn problem(error: Error) -> (HttpResponse, ProblemDetails) {
        let response = error.error_response();
        let status = response.status();
        let headers = response.headers().clone();
        assert!(headers.get("x-request-id").is_none());
        let body = to_bytes(response.into_body()).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert!(body.get("request_id").is_none());
        let problem: ProblemDetails = serde_json::from_value(body).unwrap();
        let mut response = HttpResponse::build(status).finish();
        *response.headers_mut() = headers;
        (response, problem)
    }

    fn evaluation_error(error: verifier::VerifierError) -> Error {
        let source = AttestationError::Verification {
            request_index: 0,
            tee: Tee::Tdx,
            source: error.into(),
        };
        Error::from_attestation_evaluation(anyhow::Error::new(source))
    }

    #[actix_web::test]
    async fn invalid_inner_quote_encoding_returns_stable_problem_details() {
        let source_detail = "Invalid byte 95, offset 5";
        let error = evaluation_error(verifier::VerifierError::InvalidEvidenceEncoding {
            field: "quote",
            source: anyhow!(source_detail),
        });

        let (response, problem) = problem(error).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/problem+json"
        );
        assert_eq!(problem.code, "AS.EVIDENCE.INVALID_ENCODING");
        assert_eq!(problem.title, "Invalid evidence encoding");
        assert_eq!(
            problem.field.as_deref(),
            Some("verification_requests[0].evidence.quote")
        );
        assert!(!problem.retryable);
        assert!(!problem.detail.contains(source_detail));
    }

    #[actix_web::test]
    async fn invalid_quote_and_dependency_errors_have_distinct_statuses() {
        let (_, invalid_quote) = problem(evaluation_error(verifier::VerifierError::InvalidQuote {
            field: "quote",
            source: anyhow!("short quote"),
        }))
        .await;
        assert_eq!(invalid_quote.status, 422);
        assert_eq!(invalid_quote.code, "AS.EVIDENCE.INVALID_QUOTE");
        assert!(!invalid_quote.retryable);

        let (_, unavailable) = problem(evaluation_error(
            verifier::VerifierError::DependencyUnavailable {
                dependency: "PCCS",
                source: anyhow!("connection timed out"),
            },
        ))
        .await;
        assert_eq!(unavailable.status, 503);
        assert_eq!(unavailable.code, "AS.DEPENDENCY.UNAVAILABLE");
        assert!(unavailable.retryable);
    }

    #[actix_web::test]
    async fn malformed_request_json_uses_the_same_contract() {
        async fn handler(_request: web::Json<AttestationRequest>) -> HttpResponse {
            HttpResponse::Ok().finish()
        }

        let app = test::init_service(
            App::new()
                .app_data(json_config())
                .route("/attestation", web::post().to(handler)),
        )
        .await;
        let request = test::TestRequest::post()
            .uri("/attestation")
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .set_payload("{")
            .to_request();
        let response = test::call_service(&app, request).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().get("x-request-id").is_none());
        let body: Value = test::read_body_json(response).await;
        assert!(body.get("request_id").is_none());
        let problem: ProblemDetails = serde_json::from_value(body).unwrap();
        assert_eq!(problem.code, "AS.REQUEST.INVALID_JSON");
        assert_eq!(problem.field.as_deref(), Some("body"));
    }
}
