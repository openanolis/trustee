use anyhow::*;
use attester::detect_tee_type;
use attester::BoxedAttester;
use base64::Engine;
use clap::Parser;

#[derive(Parser)]
#[clap(name = "Evidence Collector for Trustee")]
#[clap(version, about = "A command line client tool to collect TEE Evidence.", long_about = None)]
struct Cli {
    /// Base64 encoded report data.
    #[clap(long, value_parser, default_value_t = String::from(""))]
    report_data: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let tee = detect_tee_type();
    let attester = BoxedAttester::try_from(tee)?;

    let cli = Cli::parse();

    let report_data = base64::engine::general_purpose::STANDARD
        .decode(cli.report_data)
        .map_err(|_| anyhow!("Invalid Report data"))?;

    let evidence = attester.get_evidence(report_data).await?;

    let b64_evidence = base64::engine::general_purpose::STANDARD.encode(evidence.as_bytes());

    std::fs::write("./evidence.txt", b64_evidence)?;

    Ok(())
}
