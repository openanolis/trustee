mod cli;
mod commands;
mod config;
mod data;
mod rekor;
mod rvps_message;

use anyhow::Result;
use clap::Parser;
use cli::Commands;

#[tokio::main]
async fn main() -> Result<()> {
    config::init_logger();
    let cli = cli::Cli::parse();

    match cli.command {
        Commands::GetEvidence {
            aa_url,
            runtime_data,
            runtime_data_file,
            output,
        } => commands::get_evidence::run(&aa_url, runtime_data, runtime_data_file, output).await?,
        Commands::Verify {
            evidence,
            tee,
            runtime_raw,
            runtime_raw_file,
            runtime_json,
            runtime_json_file,
            runtime_hash_alg,
            init_data_digest,
            init_data_toml,
            policies,
            claims,
        } => {
            commands::verify::run(
                evidence,
                tee,
                runtime_raw,
                runtime_raw_file,
                runtime_json,
                runtime_json_file,
                runtime_hash_alg,
                init_data_digest,
                init_data_toml,
                policies,
                claims,
            )
            .await?
        }
        Commands::InjectResource {
            api_url,
            resource_path,
            resource_file,
            tee,
            nonce,
            init_data_digest,
            init_data_toml,
            policies,
        } => {
            commands::inject_resource::run(
                api_url,
                resource_path,
                resource_file,
                tee,
                nonce,
                init_data_digest,
                init_data_toml,
                policies,
            )
            .await?
        }
        Commands::SetReferenceValue(args) => {
            commands::set_reference_value::run(args).await?;
        }
    }

    Ok(())
}
