//! Local RIM verification using the official NVIDIA NVAT 2.x CLI.
//! A separate process isolates the SDK's initialization and OpenSSL/XML state
//! and avoids linking libnvat into CPU-only and wasm builds. The executable
//! and libraries are trusted verifier dependencies installed by the operator.

use super::{check_gpu_claims, check_nonce};
use crate::nvidia_config::NvidiaVerifierConfig;
use anyhow::{anyhow, ensure, Context, Result};
use serde_json::{json, Value};
use std::{io::Write, process::Stdio, time::Duration};
use tokio::{io::AsyncReadExt, process::Command, time::timeout};

pub(super) async fn verify(
    config: &NvidiaVerifierConfig,
    arch: &str,
    report: &str,
    certificate: &str,
    nonce: &[u8; 32],
) -> Result<Value> {
    let evidence = json!([{"arch": arch, "nonce": hex::encode(nonce),
        "evidence": report, "certificate": certificate}]);
    let mut input = tempfile::NamedTempFile::new().context("Create private NVAT evidence file")?;
    serde_json::to_writer(&mut input, &evidence)?;
    input.flush()?;
    let mut command = Command::new(&config.local_verifier_path);
    command
        .args([
            "attest",
            "--device",
            "gpu",
            "--verifier",
            "local",
            "--gpu-evidence-source",
            "file",
            "--gpu-evidence-file",
        ])
        .arg(input.path())
        .args([
            "--nonce",
            &hex::encode(nonce),
            "--rim-url",
            &config.rim_url,
            "--ocsp-url",
            &config.ocsp_url,
            "--format",
            "json",
            "--log-level",
            "off",
        ])
        // Prevent the SDK from reading inherited cloud service keys.
        .env_remove("NV_ATTESTATION_SERVICE_KEY")
        .env_remove("NVIDIA_ATTESTATION_SERVICE_KEY")
        .env_remove("NVIDIA_API_KEY")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    if let Some(path) = &config.tls_ca_cert {
        command.args(["--tls-ca-cert", path]);
    }
    let mut child = command.spawn().context(
        "Start NVIDIA local verifier; install NVAT 2.x or configure local_verifier_path",
    )?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("Missing NVAT output pipe"))?;
    let operation = async {
        let mut bytes = Vec::new();
        stdout
            .take((super::MAX_RESPONSE_SIZE + 1) as u64)
            .read_to_end(&mut bytes)
            .await?;
        if bytes.len() > super::MAX_RESPONSE_SIZE {
            child.kill().await?;
            anyhow::bail!("NVAT output too large");
        }
        let status = child.wait().await?;
        ensure!(
            status.success(),
            "NVIDIA local verification failed (exit {})",
            status.code().unwrap_or(-1)
        );
        parse_result(&bytes, nonce)
    };
    timeout(Duration::from_secs(120), operation)
        .await
        .context("NVIDIA local verification timed out")?
}

fn parse_result(bytes: &[u8], nonce: &[u8; 32]) -> Result<Value> {
    let result: Value = serde_json::from_slice(bytes).context("Invalid NVAT JSON output")?;
    ensure!(
        result["result_code"].as_u64() == Some(0),
        "NVAT returned a negative verification result"
    );
    let claims = result["claims"]
        .as_array()
        .ok_or_else(|| anyhow!("Missing NVAT claims"))?;
    ensure!(claims.len() == 1, "NVAT must return exactly one GPU result");
    let mut claims = claims[0].clone();
    ensure!(
        claims["x-nvidia-gpu-claims-version"] == "4.0",
        "Local NVIDIA verifier must emit claims version 4.0 (NVAT 2.x)"
    );
    check_nonce(&claims, nonce)?;
    check_gpu_claims(&claims)?;
    let claims_map = claims
        .as_object_mut()
        .ok_or_else(|| anyhow!("Invalid NVAT claims"))?;
    claims_map.insert("x-nvidia-overall-att-result".into(), json!(true));
    claims_map.insert("verifier".into(), json!("rim"));
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sdk_output_requires_success_complete_claims_and_expected_nonce() {
        let mut claims = crate::nvidia::tests::valid_claims();
        claims["x-nvidia-gpu-claims-version"] = json!("4.0");
        let good = json!({"result_code": 0, "claims": [claims]});
        let bytes = serde_json::to_vec(&good).unwrap();
        assert_eq!(parse_result(&bytes, &[7; 32]).unwrap()["verifier"], "rim");
        assert!(parse_result(&bytes, &[8; 32]).is_err());
        for bad in [
            json!({"result_code": 12, "claims": good["claims"]}),
            json!({"result_code": 0, "claims": []}),
            json!({"result_code": 0, "claims": [good["claims"][0], good["claims"][0]]}),
            json!({"claims": good["claims"]}),
        ] {
            assert!(parse_result(&serde_json::to_vec(&bad).unwrap(), &[7; 32]).is_err());
        }
        let mut missing = good;
        missing["claims"][0]
            .as_object_mut()
            .unwrap()
            .remove("x-nvidia-gpu-driver-rim-signature-verified");
        assert!(parse_result(&serde_json::to_vec(&missing).unwrap(), &[7; 32]).is_err());
    }

    #[tokio::test]
    async fn missing_sdk_fails_without_nras_fallback() {
        let config = NvidiaVerifierConfig {
            local_verifier_path: "/nonexistent/nvattest".into(),
            ..Default::default()
        };
        let error = verify(&config, "BLACKWELL", "cmVwb3J0", "Y2VydA==", &[7; 32])
            .await
            .unwrap_err();
        assert!(error.to_string().contains("Start NVIDIA local verifier"));
    }
}
