//! HTTP routing glue for the IAM REST API.

use actix_web::{web, HttpResponse};

use crate::error::IamError;
use crate::models::{
    AssumeRoleRequest, CreateAccountRequest, CreatePrincipalRequest, CreateRoleRequest,
    EvaluateRequest, RegisterResourceRequest,
};
use crate::service::IamService;

/// Register all IAM endpoints on the supplied Actix configuration.
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("")
            .route("/accounts", web::post().to(create_account))
            .route(
                "/accounts/{account_id}/principals",
                web::post().to(create_principal),
            )
            .route("/resources", web::post().to(register_resource))
            .route("/roles", web::post().to(create_role))
            .route("/sts/assume-role", web::post().to(assume_role))
            .route("/authz/evaluate", web::post().to(evaluate_request)),
    );
}

/// POST /accounts
async fn create_account(
    service: web::Data<IamService>,
    payload: web::Json<CreateAccountRequest>,
) -> Result<HttpResponse, IamError> {
    let response = service.create_account(payload.into_inner()).await?;
    Ok(HttpResponse::Created().json(response))
}

/// POST /accounts/{id}/principals
async fn create_principal(
    service: web::Data<IamService>,
    path: web::Path<String>,
    payload: web::Json<CreatePrincipalRequest>,
) -> Result<HttpResponse, IamError> {
    let response = service
        .create_principal(&path.into_inner(), payload.into_inner())
        .await?;
    Ok(HttpResponse::Created().json(response))
}

/// POST /resources
async fn register_resource(
    service: web::Data<IamService>,
    payload: web::Json<RegisterResourceRequest>,
) -> Result<HttpResponse, IamError> {
    let response = service.register_resource(payload.into_inner()).await?;
    Ok(HttpResponse::Created().json(response))
}

/// POST /roles
async fn create_role(
    service: web::Data<IamService>,
    payload: web::Json<CreateRoleRequest>,
) -> Result<HttpResponse, IamError> {
    let response = service.create_role(payload.into_inner()).await?;
    Ok(HttpResponse::Created().json(response))
}

/// POST /sts/assume-role
async fn assume_role(
    service: web::Data<IamService>,
    payload: web::Json<AssumeRoleRequest>,
) -> Result<HttpResponse, IamError> {
    let response = service.assume_role(payload.into_inner()).await?;
    Ok(HttpResponse::Ok().json(response))
}

/// POST /authz/evaluate
async fn evaluate_request(
    service: web::Data<IamService>,
    payload: web::Json<EvaluateRequest>,
) -> Result<HttpResponse, IamError> {
    let response = service.evaluate(payload.into_inner()).await?;
    Ok(HttpResponse::Ok().json(response))
}
