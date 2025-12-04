mod api;
mod attestation;
mod config;
mod error;
mod models;
mod policy;
mod service;
mod storage;
mod token;

use std::path::PathBuf;

use actix_web::{web, App, HttpServer};
use clap::Parser;

use crate::config::IamConfig;
use crate::service::IamService;

/// Command-line switches for the IAM binary.
#[derive(Parser, Debug)]
#[command(author, version, about = "Trustee IAM Service")]
struct Cli {
    #[arg(short, long, default_value = "config/iam.toml")]
    config: PathBuf,
}

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    let cli = Cli::parse();
    let config =
        IamConfig::from_file(&cli.config).map_err(|err| anyhow::anyhow!(err.to_string()))?;
    let service = IamService::new(&config)
        .map_err(|err| anyhow::anyhow!(format!("failed to start IAM: {err}")))?;
    let bind_addr = config.server.bind_address.clone();
    let shared_service = web::Data::new(service);

    HttpServer::new(move || {
        App::new()
            .app_data(shared_service.clone())
            .configure(api::configure)
    })
    .bind(&bind_addr)?
    .run()
    .await?;

    Ok(())
}
