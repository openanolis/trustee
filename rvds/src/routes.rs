use actix_web::{web, HttpResponse};
use log::info;

use crate::config::AppConfig;
use crate::error::ApiError;
use crate::models::{PublishEventRequest, PublishResponse, SubscribeRequest, SubscribeResponse};
use crate::state::AppState;

pub fn init_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/rvds")
            .route("/subscribe/trustee", web::post().to(subscribe_trustee))
            .route("/rv-publish-event", web::post().to(rv_publish_event)),
    );
}

async fn subscribe_trustee(
    _cfg: web::Data<AppConfig>,
    state: web::Data<AppState>,
    payload: web::Json<SubscribeRequest>,
) -> Result<HttpResponse, ApiError> {
    let added = state.add_trustees(&payload).await?;
    info!("Registered trustees: {:?}", added);
    Ok(HttpResponse::Ok().json(SubscribeResponse { registered: added }))
}

async fn rv_publish_event(
    _cfg: web::Data<AppConfig>,
    state: web::Data<AppState>,
    payload: web::Json<PublishEventRequest>,
) -> Result<HttpResponse, ApiError> {
    let results = state.forward_publish_event(payload.into_inner()).await?;
    Ok(HttpResponse::Ok().json(PublishResponse { forwarded: results }))
}
