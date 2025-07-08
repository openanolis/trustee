//! This tool is to connect the RVPS

use anyhow::*;
use clap::{Args, Parser};
use log::info;
use shadow_rs::shadow;

use reference_value_provider_service::client;

shadow!(build);

/// Default address of RVPS
const DEFAULT_ADDR: &str = "http://127.0.0.1:50003";

async fn register(addr: &str, provenance_path: &str) -> Result<()> {
    let message = std::fs::read_to_string(provenance_path).context("read provenance")?;

    client::register(addr.to_string(), message).await?;
    info!("Register provenance succeeded.");

    Ok(())
}

async fn query(addr: &str) -> Result<()> {
    let rvs = client::query(addr.to_string()).await?;
    info!("Get reference values succeeded:\n {rvs}");
    Ok(())
}

async fn delete(addr: &str, name: &str) -> Result<()> {
    client::delete(addr.to_string(), name.to_string()).await?;
    info!("Delete reference value succeeded.");
    Ok(())
}

/// RVPS command-line arguments.
#[derive(Parser)]
#[command(name = "rvps-tool")]
#[command(bin_name = "rvps-tool")]
#[command(author, version, about, long_about = None)]
enum Cli {
    /// Register reference values
    Register(RegisterArgs),

    /// Query reference values
    Query(QueryArgs),

    /// Delete reference value
    Delete(DeleteArgs),
}

#[derive(Args)]
#[command(author, version, about, long_about = None)]
struct RegisterArgs {
    /// The address of target RVPS
    #[arg(short, long, default_value = DEFAULT_ADDR)]
    addr: String,

    /// The path to the provenance json file
    #[arg(short, long)]
    path: String,
}

#[derive(Args)]
#[command(author, version, about, long_about = None)]
struct QueryArgs {
    /// The address of target RVPS
    #[arg(short, long, default_value = DEFAULT_ADDR)]
    addr: String,
}

#[derive(Args)]
#[command(author, version, about, long_about = None)]
struct DeleteArgs {
    /// The address of target RVPS
    #[arg(short, long, default_value = DEFAULT_ADDR)]
    addr: String,

    /// The name of the reference value to delete
    #[arg(short, long)]
    name: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let version = format!(
        "\nv{}\ncommit: {}\nbuildtime: {}",
        build::PKG_VERSION,
        build::COMMIT_HASH,
        build::BUILD_TIME
    );

    info!("CoCo RVPS Client tool: {version}");

    let cli = Cli::parse();

    match cli {
        Cli::Register(para) => register(&para.addr, &para.path).await,
        Cli::Query(para) => query(&para.addr).await,
        Cli::Delete(para) => delete(&para.addr, &para.name).await,
    }
}
