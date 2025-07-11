use anyhow::{Context, Result};
use log::{debug, info};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

use crate::{Config, Rvps};

use crate::rvps_api::reference::reference_value_provider_service_server::{
    ReferenceValueProviderService, ReferenceValueProviderServiceServer,
};
use crate::rvps_api::reference::{
    ReferenceValueDeleteRequest, ReferenceValueDeleteResponse, ReferenceValueQueryRequest,
    ReferenceValueQueryResponse, ReferenceValueRegisterRequest, ReferenceValueRegisterResponse,
};

pub struct RvpsServer {
    rvps: Arc<RwLock<Rvps>>,
}

impl RvpsServer {
    pub fn new(rvps: Arc<RwLock<Rvps>>) -> Self {
        Self { rvps }
    }
}

#[tonic::async_trait]
impl ReferenceValueProviderService for RvpsServer {
    async fn query_reference_value(
        &self,
        _request: Request<ReferenceValueQueryRequest>,
    ) -> Result<Response<ReferenceValueQueryResponse>, Status> {
        let rvs = self
            .rvps
            .read()
            .await
            .get_digests()
            .await
            .map_err(|e| Status::aborted(format!("Query reference value: {e}")))?;

        let reference_value_results = serde_json::to_string(&rvs)
            .map_err(|e| Status::aborted(format!("Serde reference value: {e}")))?;
        info!("Reference values: {}", reference_value_results);

        let res = ReferenceValueQueryResponse {
            reference_value_results,
        };
        Ok(Response::new(res))
    }

    async fn register_reference_value(
        &self,
        request: Request<ReferenceValueRegisterRequest>,
    ) -> Result<Response<ReferenceValueRegisterResponse>, Status> {
        let request = request.into_inner();

        debug!("registry reference value: {}", request.message);

        self.rvps
            .write()
            .await
            .verify_and_extract(&request.message)
            .await
            .map_err(|e| Status::aborted(format!("Register reference value: {e}")))?;

        let res = ReferenceValueRegisterResponse {};
        Ok(Response::new(res))
    }

    async fn delete_reference_value(
        &self,
        request: Request<ReferenceValueDeleteRequest>,
    ) -> Result<Response<ReferenceValueDeleteResponse>, Status> {
        let request = request.into_inner();

        debug!("Delete reference value: {}", request.name);

        let deleted = self
            .rvps
            .write()
            .await
            .delete_reference_value(&request.name)
            .await
            .map_err(|e| Status::aborted(format!("Delete reference value: {e}")))?;

        if deleted {
            info!("Reference value '{}' deleted successfully", request.name);
        } else {
            info!("Reference value '{}' not found", request.name);
        }

        let res = ReferenceValueDeleteResponse {};
        Ok(Response::new(res))
    }
}

pub async fn start(socket: SocketAddr, config: Config) -> Result<()> {
    let service = Rvps::new(config)?;
    let inner = Arc::new(RwLock::new(service));
    let rvps_server = RvpsServer::new(inner.clone());

    Server::builder()
        .add_service(ReferenceValueProviderServiceServer::new(rvps_server))
        .serve(socket)
        .await
        .context("gRPC error")
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tempfile::tempdir;
    use tokio::sync::RwLock;
    use tonic::Request;

    use crate::storage::ReferenceValueStorageConfig;
    use crate::Rvps;

    // Helper function to create a test Rvps instance
    async fn create_test_rvps() -> Arc<RwLock<Rvps>> {
        // Create a temporary directory for storage
        let temp_dir = tempdir().expect("Failed to create temp dir");
        let dir_path = temp_dir.path().to_string_lossy().to_string();

        // Create storage config
        let storage_config = crate::storage::local_fs::Config {
            file_path: dir_path,
        };
        let config = crate::Config {
            storage: ReferenceValueStorageConfig::LocalFs(storage_config),
        };

        // Create Rvps instance
        let rvps = Rvps::new(config).expect("Failed to create Rvps instance");
        Arc::new(RwLock::new(rvps))
    }

    // Helper function to add a test reference value
    async fn add_test_reference_value(rvps: &Arc<RwLock<Rvps>>) {
        // Create a valid message with sample reference value
        let payload = r#"{
            "test_artifact": ["hash1", "hash2"]
        }"#;
        let payload_base64 = base64::engine::general_purpose::STANDARD.encode(payload);

        let message = format!(
            r#"{{
            "version": "0.1.0",
            "payload": "{}",
            "type": "sample"
        }}"#,
            payload_base64
        );

        // Add the reference value
        rvps.write()
            .await
            .verify_and_extract(&message)
            .await
            .expect("Failed to add reference value");
    }

    #[tokio::test]
    async fn test_query_reference_value_empty() {
        // Create a server with empty Rvps
        let rvps = create_test_rvps().await;
        let server = RvpsServer::new(rvps);

        // Create a query request
        let request = Request::new(ReferenceValueQueryRequest {});

        // Call query_reference_value
        let response = server
            .query_reference_value(request)
            .await
            .expect("Query failed");
        let response_inner = response.into_inner();

        // Parse the response
        let reference_values: HashMap<String, Vec<String>> =
            serde_json::from_str(&response_inner.reference_value_results)
                .expect("Failed to parse response");

        // Verify the response is empty
        assert!(reference_values.is_empty(), "Response should be empty");
    }

    #[tokio::test]
    async fn test_query_reference_value_with_data() {
        // Create a server with Rvps
        let rvps = create_test_rvps().await;

        // Add a test reference value
        add_test_reference_value(&rvps).await;

        let server = RvpsServer::new(rvps);

        // Create a query request
        let request = Request::new(ReferenceValueQueryRequest {});

        // Call query_reference_value
        let response = server
            .query_reference_value(request)
            .await
            .expect("Query failed");
        let response_inner = response.into_inner();

        // Parse the response
        let reference_values: HashMap<String, Vec<String>> =
            serde_json::from_str(&response_inner.reference_value_results)
                .expect("Failed to parse response");

        // Verify the response contains the test reference value
        assert!(!reference_values.is_empty(), "Response should not be empty");
        assert!(
            reference_values.contains_key("test_artifact"),
            "Response should contain test_artifact"
        );
        assert_eq!(
            reference_values["test_artifact"].len(),
            2,
            "test_artifact should have 2 hash values"
        );
        assert!(
            reference_values["test_artifact"].contains(&"hash1".to_string()),
            "test_artifact should contain hash1"
        );
        assert!(
            reference_values["test_artifact"].contains(&"hash2".to_string()),
            "test_artifact should contain hash2"
        );
    }

    #[tokio::test]
    async fn test_register_reference_value() {
        // Create a server with Rvps
        let rvps = create_test_rvps().await;
        let server = RvpsServer::new(rvps.clone());

        // Create a valid message with sample reference value
        let payload = r#"{
            "test_artifact": ["hash1", "hash2"]
        }"#;
        let payload_base64 = base64::engine::general_purpose::STANDARD.encode(payload);

        let message = format!(
            r#"{{
            "version": "0.1.0",
            "payload": "{}",
            "type": "sample"
        }}"#,
            payload_base64
        );

        // Create a register request
        let request = Request::new(ReferenceValueRegisterRequest { message });

        // Call register_reference_value
        let response = server
            .register_reference_value(request)
            .await
            .expect("Register failed");

        // Verify the response is empty (as expected)
        let _response_inner = response.into_inner();

        // Verify the reference value was added
        let digests = rvps
            .read()
            .await
            .get_digests()
            .await
            .expect("Failed to get digests");
        assert!(!digests.is_empty(), "Digests should not be empty");
        assert!(
            digests.contains_key("test_artifact"),
            "Digests should contain test_artifact"
        );
    }

    #[tokio::test]
    async fn test_register_reference_value_invalid() {
        // Create a server with Rvps
        let rvps = create_test_rvps().await;
        let server = RvpsServer::new(rvps);

        // Create an invalid message
        let message = r#"{
            "version": "999.999.999", 
            "payload": "invalid",
            "type": "sample"
        }"#
        .to_string();

        // Create a register request
        let request = Request::new(ReferenceValueRegisterRequest { message });

        // Call register_reference_value
        let result = server.register_reference_value(request).await;
        assert!(result.is_err(), "Register should fail with invalid message");
        assert!(
            result.unwrap_err().message().contains("Version unmatched"),
            "Error message should mention version mismatch"
        );
    }

    #[tokio::test]
    async fn test_delete_reference_value_existing() {
        // Create a server with Rvps
        let rvps = create_test_rvps().await;

        // Add a test reference value
        add_test_reference_value(&rvps).await;

        let server = RvpsServer::new(rvps.clone());

        // Verify the reference value exists
        let digests = rvps
            .read()
            .await
            .get_digests()
            .await
            .expect("Failed to get digests");
        assert!(
            digests.contains_key("test_artifact"),
            "test_artifact should exist before deletion"
        );

        // Create a delete request
        let request = Request::new(ReferenceValueDeleteRequest {
            name: "test_artifact".to_string(),
        });

        // Call delete_reference_value
        let response = server
            .delete_reference_value(request)
            .await
            .expect("Delete failed");

        // Verify the response is empty (as expected)
        let _response_inner = response.into_inner();

        // Verify the reference value was deleted
        let digests = rvps
            .read()
            .await
            .get_digests()
            .await
            .expect("Failed to get digests");
        assert!(
            !digests.contains_key("test_artifact"),
            "test_artifact should not exist after deletion"
        );
    }

    #[tokio::test]
    async fn test_delete_reference_value_nonexistent() {
        // Create a server with Rvps
        let rvps = create_test_rvps().await;
        let server = RvpsServer::new(rvps);

        // Create a delete request for a nonexistent reference value
        let request = Request::new(ReferenceValueDeleteRequest {
            name: "nonexistent".to_string(),
        });

        // Call delete_reference_value
        let response = server
            .delete_reference_value(request)
            .await
            .expect("Delete should succeed even for nonexistent values");

        // Verify the response is empty (as expected)
        let _response_inner = response.into_inner();
    }
}
