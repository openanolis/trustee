mod config;
mod error;
mod ledger;
mod models;
mod routes;
mod state;

use actix_web::{web, App, HttpServer};
use env_logger::Env;
use log::{error, info};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Run bootstrap logic in a dedicated function to make error handling explicit.
    if let Err(err) = run().await {
        error!("RVDS failed to start: {err:?}");
        std::process::exit(1);
    }
    Ok(())
}

async fn run() -> anyhow::Result<()> {
    // Initialize logger with a sensible default level.
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let cfg = config::AppConfig::from_env()?;
    let bind_addr = cfg.listen_addr.clone();
    let state = state::AppState::initialize(&cfg).await?;

    info!(
        "RVDS starting on {} with data dir {:?}",
        cfg.listen_addr, cfg.data_dir
    );

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(cfg.clone()))
            .app_data(web::Data::new(state.clone()))
            .configure(routes::init_routes)
    })
    .bind(bind_addr)?
    .run()
    .await?;

    Ok(())
}
