use std::{net::SocketAddr, path::Path, sync::Arc, time::Duration};

use actix_cors::Cors;
use actix_web::{http::header, web, App, HttpServer};
use anyhow::Result;
use attestation_service::{config::Config, config::ConfigError, AttestationService, ServiceError};
use clap::{arg, command, Parser};
use log::info;
use openssl::{
    pkey::PKey,
    ssl::{SslAcceptor, SslMethod},
};
use strum::{AsRefStr, EnumString};
use thiserror::Error;
use tokio::sync::RwLock;

use crate::restful::{
    attestation, delete_policy, get_certificate, get_challenge, get_jwks, get_openid_configuration,
    get_policies, set_policy,
};

mod restful;

/// RESTful-AS command-line arguments.
#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Path to a CoCo-AS config file.
    #[arg(short, long)]
    pub config_file: Option<String>,

    /// Socket addresses (IP:port) to listen on, e.g. 127.0.0.1:8080.
    #[arg(short, long)]
    pub socket: SocketAddr,

    /// Path to the public key cert for HTTPS. Both public key cert and
    /// private key are provided then HTTPS will be enabled.
    #[arg(short = 't', long)]
    pub https_pubkey_cert: Option<String>,

    /// Path to the private key for HTTPS. Both public key cert and
    /// private key are provided then HTTPS will be enabled.
    #[arg(short = 'k', long)]
    pub https_prikey: Option<String>,

    /// Allowed origin for CORS access (e.g., "http://localhost:3000").
    /// Can be specified multiple times or comma-separated. When empty
    /// (the default), no CORS origins are allowed.
    #[arg(short = 'r', long = "allowed_origin", value_delimiter = ',', num_args = 1..)]
    pub allowed_origin: Vec<String>,

    /// HTTP/1.1 keep-alive timeout in seconds. Set to 0 to disable keep-alive.
    /// Keep this longer than the client's idle connection timeout to avoid
    /// clients reusing connections while the server is closing them.
    #[arg(long, default_value_t = 120)]
    pub http_keep_alive_secs: u64,
}

#[derive(EnumString, AsRefStr)]
#[strum(serialize_all = "lowercase")]
enum WebApi {
    #[strum(serialize = "/attestation")]
    Attestation,

    #[strum(serialize = "/policy")]
    Policy,

    #[strum(serialize = "/challenge")]
    Challenge,

    #[strum(serialize = "/certificate")]
    Certificate,

    #[strum(serialize = "/jwks")]
    Jwks,

    #[strum(serialize = "/.well-known/openid-configuration")]
    OpenIdConfiguration,
}

#[derive(Error, Debug)]
pub enum RestfulError {
    #[error("Creating service failed: {0}")]
    Service(#[from] ServiceError),
    #[error("Failed to read AS config file: {0}")]
    Config(#[from] ConfigError),
    #[error("Openssl errorstack: {0}")]
    Openssl(#[from] openssl::error::ErrorStack),
    #[error("failed to read HTTPS private key: {0}")]
    ReadHttpsKey(#[source] std::io::Error),
    #[error("failed to get HTTPS private key from pem: {0}")]
    ReadHttpsKeyFromPem(#[source] openssl::error::ErrorStack),
    #[error("set private key failed: {0}")]
    SetPrivateKey(#[source] openssl::error::ErrorStack),
    #[error("set HTTPS public key cert: {0}")]
    SetHttpsCert(#[source] openssl::error::ErrorStack),
    #[error("io error: {0}")]
    IO(#[from] std::io::Error),
    #[error("Failed to get certificate: {0}")]
    Certificate(#[from] anyhow::Error),
}

fn configure_cors(allowed_origin: &[String]) -> Cors {
    let mut cors = Cors::default()
        .allowed_methods(vec!["POST", "GET", "OPTIONS"])
        .allowed_headers(vec![header::CONTENT_TYPE, header::AUTHORIZATION])
        .max_age(86400);

    // Parse origin
    if !allowed_origin.is_empty() {
        let origins: Vec<String> = allowed_origin
            .iter()
            .flat_map(|s| s.split(','))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        for ori in &origins {
            if ori.starts_with("http://") || ori.starts_with("https://") {
                log::info!("Allowed CORS origin: {ori:?}");
                cors = cors.allowed_origin(ori.as_str());
            } else {
                log::error!(
                    "Invalid CORS origin format: '{ori}'. Must start with http:// or https://"
                );
            }
        }
    };

    cors
}

#[actix_web::main]
async fn main() -> Result<(), RestfulError> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let cli = Cli::parse();

    let http_keep_alive = Duration::from_secs(cli.http_keep_alive_secs);
    info!(
        "HTTP keep-alive timeout: {} seconds",
        cli.http_keep_alive_secs
    );

    let config = match cli.config_file {
        Some(path) => {
            info!("Using config file {path}");
            Config::try_from(Path::new(&path))?
        }
        None => {
            info!("No confile path provided, use default one.");
            Config::default()
        }
    };

    let attestation_service = AttestationService::new(config).await?;

    let allowed_origin = cli.allowed_origin.clone();

    let attestation_service = web::Data::new(Arc::new(RwLock::new(attestation_service)));
    let server = HttpServer::new(move || {
        App::new()
            .wrap(configure_cors(&allowed_origin))
            .service(web::resource(WebApi::Attestation.as_ref()).route(web::post().to(attestation)))
            .service(
                web::resource(WebApi::Policy.as_ref())
                    .route(web::post().to(set_policy))
                    .route(web::get().to(get_policies)),
            )
            .service(
                web::resource("/policy/{policy_id}")
                    .route(web::delete().to(delete_policy))
                    .route(web::get().to(get_policies)),
            )
            .service(web::resource(WebApi::Challenge.as_ref()).route(web::post().to(get_challenge)))
            .service(
                web::resource(WebApi::Certificate.as_ref()).route(web::get().to(get_certificate)),
            )
            .service(web::resource(WebApi::Jwks.as_ref()).route(web::get().to(get_jwks)))
            .service(
                web::resource(WebApi::OpenIdConfiguration.as_ref())
                    .route(web::get().to(get_openid_configuration)),
            )
            .app_data(web::Data::clone(&attestation_service))
    })
    .keep_alive(http_keep_alive);

    let server = match (cli.https_prikey, cli.https_pubkey_cert) {
        (Some(prikey), Some(pubkey_cert)) => {
            let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls())?;

            let prikey = tokio::fs::read(prikey)
                .await
                .map_err(RestfulError::ReadHttpsKey)?;
            let prikey =
                PKey::private_key_from_pem(&prikey).map_err(RestfulError::ReadHttpsKeyFromPem)?;

            builder
                .set_private_key(&prikey)
                .map_err(RestfulError::SetPrivateKey)?;
            builder
                .set_certificate_chain_file(pubkey_cert)
                .map_err(RestfulError::SetHttpsCert)?;
            log::info!("starting HTTPS server at https://{}", cli.socket);
            server.bind_openssl(cli.socket, builder)?.run()
        }
        _ => {
            log::info!("starting HTTP server at http://{}", cli.socket);
            server
                .bind((cli.socket.ip().to_string(), cli.socket.port()))?
                .run()
        }
    };

    server.await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_keep_alive_defaults_to_120_seconds() {
        let cli = Cli::try_parse_from(["restful-as", "--socket", "127.0.0.1:8080"])
            .expect("parse default CLI options");
        assert_eq!(cli.http_keep_alive_secs, 120);
    }

    #[test]
    fn http_keep_alive_can_be_configured_or_disabled() {
        let cli = Cli::try_parse_from([
            "restful-as",
            "--socket",
            "127.0.0.1:8080",
            "--http-keep-alive-secs",
            "30",
        ])
        .expect("parse configured keep-alive");
        assert_eq!(cli.http_keep_alive_secs, 30);

        let cli = Cli::try_parse_from([
            "restful-as",
            "--socket",
            "127.0.0.1:8080",
            "--http-keep-alive-secs",
            "0",
        ])
        .expect("parse disabled keep-alive");
        assert_eq!(cli.http_keep_alive_secs, 0);
    }
}
