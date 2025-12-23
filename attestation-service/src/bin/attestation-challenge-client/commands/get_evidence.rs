use crate::data::load_runtime_data_for_fetch;
use anyhow::{bail, Context, Result};
use reqwest::Client;
use std::fs;
use std::path::PathBuf;

pub async fn run(
    aa_url: &str,
    runtime_data: Option<String>,
    runtime_data_file: Option<PathBuf>,
    output: Option<PathBuf>,
) -> Result<()> {
    let runtime_data = load_runtime_data_for_fetch(runtime_data, runtime_data_file)?;
    let base = aa_url.trim_end_matches('/');
    let url = format!("{}/aa/evidence", base);

    let client = Client::new();
    let resp = client
        .get(url)
        .query(&[("runtime_data", runtime_data)])
        .send()
        .await
        .context("send request to api-server-rest")?;

    if !resp.status().is_success() {
        bail!("request failed with status {}", resp.status());
    }

    let body = resp.text().await.context("read evidence body")?;

    if let Some(path) = output {
        fs::write(&path, &body).with_context(|| format!("write evidence to {}", path.display()))?;
        println!("evidence saved to {}", path.display());
    } else {
        println!("{body}");
    }

    Ok(())
}
