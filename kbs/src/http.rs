// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};

use crate::config::HttpServerConfig;

pub fn tls_config(config: &HttpServerConfig) -> Result<openssl::ssl::SslAcceptorBuilder> {
    use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};

    let cert_file = config
        .certificate
        .as_ref()
        .ok_or_else(|| anyhow!("Missing certificate"))?;

    let key_file = config
        .private_key
        .as_ref()
        .ok_or_else(|| anyhow!("Missing private key"))?;

    let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls())?;
    builder.set_private_key_file(key_file, SslFiletype::PEM)?;
    builder.set_certificate_chain_file(cert_file)?;

    Ok(builder)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn create_test_cert_and_key() -> (TempDir, PathBuf, PathBuf) {
        // Create temporary directory
        let temp_dir = TempDir::new().unwrap();

        // Create paths for certificate and key
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");

        // Sample self-signed certificate and private key for testing
        // Note: This is a test certificate only, do not use in production
        let test_cert = r#"-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUJAz9HHGK6QcfQKYUq1a4qPPppbUwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNDA1MjAwMDAwMDBaFw0yNTA1
MjAwMDAwMDBaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDNd0f8hdjrI89BxYP0yZVUkdcRtZLsvnM1wj6RZB9Q
fzoL6FBwc10L7cdXaEj2gsHMj9XHgZCOa84OdQWBioPYlgPUHKhexTBRs/FG4KQk
T+mONchwHZmjm3kTXJcecIly5BQspBdYpEwtlYthhWob0kshxgtkZENuDk35nmUD
xPCHcbGNnusfyKrMxvcV5h8hs08lDHAhzPjBaMm9kD0eHsjAmseZ2lUPmn2N9CdL
8dgekwzwUlsbMQaOBwkBjcUd/w/clBmDd9r8tF5pceWT7tBzziJmnDk5AQhdDICs
q9CAxf71YtSQgoZYTAdhD1I8AJFBlniqsxDtlQ1ZVeJBAgMBAAGjUzBRMB0GA1Ud
DgQWBBRZnUQgQDXHRTtBBJEbZXJhiWi+6jAfBgNVHSMEGDAWgBRZnUQgQDXHRTtB
BJEbZXJhiWi+6jAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQB8
XpkvcCOaIIEBZoD/IY9uSKGg3eQxJDLcwRYTGGa7HUUPZIuRA8xGLWoiKAGjGgH7
uP56scH2QHJ6un3BVxQGX1YwKEWNVbGCwGHj1lUNxpN+EjpZxQmGjBN6+3BheBQP
SgeUg9DPyOav3jWEeXZBzuUXXmKkv6cFl0Xto0wJhvxQqWQJNJNMCrFBSQXRJVR2
6GHWuE6YFP5D0KIwaGYZ+CbqKXkTm9tFj+MA9qjHJQYOHNhZcYcJYQrU2JMKJnIg
5/3QKQ6vbvJJZ0yXcKIUQIxUvRbVx9cKG+Rg3O/1PuZDHbULrNshYkDCXtJ9RnUJ
sTLRj+Xjy6rvKVyDJUXI
-----END CERTIFICATE-----"#;

        let test_key = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDNd0f8hdjrI89B
xYP0yZVUkdcRtZLsvnM1wj6RZB9QfzoL6FBwc10L7cdXaEj2gsHMj9XHgZCOa84O
dQWBioPYlgPUHKhexTBRs/FG4KQkT+mONchwHZmjm3kTXJcecIly5BQspBdYpEwt
lYthhWob0kshxgtkZENuDk35nmUDxPCHcbGNnusfyKrMxvcV5h8hs08lDHAhzPjB
aMm9kD0eHsjAmseZ2lUPmn2N9CdL8dgekwzwUlsbMQaOBwkBjcUd/w/clBmDd9r8
tF5pceWT7tBzziJmnDk5AQhdDICsq9CAxf71YtSQgoZYTAdhD1I8AJFBlniqsxDt
lQ1ZVeJBAgMBAAECggEBAJDDloMfOz0W342slsnRhK5eqclAacBXFCooBz73LVir
fHw6Lu9Yu5BEqYt1BYyqNNLAxcezsK5BH0Ype77Y3VcNXhPvNHCT8haNBVQxNZOl
Nb/GOWQlCH55WoTy9VjBVRLIXH4ROMRmP4FXn+NSWwZAE/MvFC87ZxcadkdiPv5m
2AnnEyQ70wVSNiETIFxcjRbkFjwOMP2r4Sn3AGHc2eP9DT7lPoECw4SOX4ZhfylJ
cRn2dc4E7U1BmUSAsG5DR5g/kz/yP1LZkZYiPltExoUHOA1QWsVA/V0Xk/0PCWbs
tbEA7AkrGBAmAZD0FdsR+e9WpkUl5s4oq/O4338k5gECgYEA5z8W8OQrUu8RYKNV
1clYycaIdBu0m9JVSCBj/UUZxbMkYxmpB4aRY7xSPEnAhc2L5a0K+DGdDnPGIrAy
oCyPk/cDfBVF8QqPGw2Vnu7YtAXMYZKXjsFCPZNmrXZyoMv1YkQQwku1B1eHE6bz
AcycvLkTCPlThbLQG/wbde1dhiECgYEA48VNA9bNeTAmD30aBR8DcOA6AUqum7c6
BxpElFiuq7kV0A1WM5AllN+6pA8aY8egsZZAUYVbnIkpg9kpPCoWk7ZWsxEOBmOA
LwOD35BBglcxvladrP8oWYafN8VaoTTFM64VAW9e/QoYPEiflNT6UVNONcYp0/fG
KVTt5RkoOGECgYEAuABw8olVilNAQn7IbMZRlXkPZPpYKCo1FoZ/7B1A5eZlkotB
Yp/FGc4jwouEIPXMETVg728Uc+H73m18LMkMV/rpBunckEZthAGdlhwEvkvh/r50
nXHnzAoxASQ29RM0REObn9W+PSRAAEYKM6Zzn7x9gRBDAtkodFcxPlclhyECgYA1
kUANh3dHlB9CZcZcoZEPPFBhIZace9F3yoLEs9EqYUqstC2kM5RJl1xbEYk6rtfl
MWHEjJFgnM152Xn44jAPc6RhbNxsqsNt3hNSUwqHiMWdWBJRDPmLKbdnkW17lZ9k
sZWmSbx1IA1ldctFMAkEoad8epcMI1b7D+5lFVgcIQKBgBclVf2Koe3QMVT4TQHg
m745Mkp+dQapeszSOUqxiLm36wFBefOAkg5CPSn6gFQoSHmrGplfBDcoe+dAUAWI
fMo2c7NQNjkjaO3Fjsrtk86X6Bd/yooxiwgouZSNgDGc3/0nQa9Rt8W70cfNkGPU
dUk4MOZyfBeYo5z0uDIbhZ/H
-----END PRIVATE KEY-----"#;

        // Write certificate and key to files
        let mut cert_file = File::create(&cert_path).unwrap();
        cert_file.write_all(test_cert.as_bytes()).unwrap();

        let mut key_file = File::create(&key_path).unwrap();
        key_file.write_all(test_key.as_bytes()).unwrap();

        (temp_dir, cert_path, key_path)
    }

    #[test]
    fn test_tls_config_success() {
        // Create test certificate and key
        let (_temp_dir, cert_path, key_path) = create_test_cert_and_key();

        // Create HttpServerConfig with the test files
        let config = HttpServerConfig {
            sockets: vec!["127.0.0.1:8080".parse().unwrap()],
            private_key: Some(key_path),
            certificate: Some(cert_path),
            insecure_http: false,
            payload_request_size: 2,
        };

        // Test TLS configuration
        let result = tls_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_tls_config_missing_certificate() {
        // Create HttpServerConfig with missing certificate
        let config = HttpServerConfig {
            sockets: vec!["127.0.0.1:8080".parse().unwrap()],
            private_key: Some(PathBuf::from("/path/to/key.pem")),
            certificate: None,
            insecure_http: false,
            payload_request_size: 2,
        };

        // Test TLS configuration
        let result = tls_config(&config);
        assert!(result.is_err());

        match result {
            Err(e) => assert!(e.to_string().contains("Missing certificate")),
            _ => panic!("Expected error for missing certificate"),
        }
    }

    #[test]
    fn test_tls_config_missing_private_key() {
        // Create HttpServerConfig with missing private key
        let config = HttpServerConfig {
            sockets: vec!["127.0.0.1:8080".parse().unwrap()],
            private_key: None,
            certificate: Some(PathBuf::from("/path/to/cert.pem")),
            insecure_http: false,
            payload_request_size: 2,
        };

        // Test TLS configuration
        let result = tls_config(&config);
        assert!(result.is_err());

        match result {
            Err(e) => assert!(e.to_string().contains("Missing private key")),
            _ => panic!("Expected error for missing private key"),
        }
    }

    #[test]
    fn test_tls_config_invalid_files() {
        // Create HttpServerConfig with invalid file paths
        let config = HttpServerConfig {
            sockets: vec!["127.0.0.1:8080".parse().unwrap()],
            private_key: Some(PathBuf::from("/nonexistent/key.pem")),
            certificate: Some(PathBuf::from("/nonexistent/cert.pem")),
            insecure_http: false,
            payload_request_size: 2,
        };

        // Test TLS configuration
        let result = tls_config(&config);
        assert!(result.is_err());

        // We don't need to access the specific error message here,
        // just verify it's an error
        let error_occurred = result.is_err();
        assert!(error_occurred);
    }
}
