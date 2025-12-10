use actix_web::{http::StatusCode, HttpResponse, ResponseError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IamError {
    #[error("entity not found: {0}")]
    NotFound(String),
    #[error("entity already exists: {0}")]
    Conflict(String),
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl ResponseError for IamError {
    fn status_code(&self) -> StatusCode {
        match self {
            IamError::NotFound(_) => StatusCode::NOT_FOUND,
            IamError::Conflict(_) => StatusCode::CONFLICT,
            IamError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            IamError::InvalidRequest(_) => StatusCode::BAD_REQUEST,
            IamError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).json(serde_json::json!({
            "error": self.to_string()
        }))
    }
}
