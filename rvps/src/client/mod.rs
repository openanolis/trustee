// Copyright (c) 2025 IBM
//
// SPDX-License-Identifier: Apache-2.0
//
// Helpers for building a client for the RVPS

use anyhow::Result;

use crate::rvps_api::reference::{
    reference_value_provider_service_client::ReferenceValueProviderServiceClient,
    ReferenceValueDeleteRequest, ReferenceValueQueryRequest, ReferenceValueRegisterRequest,
};

pub async fn register(address: String, message: String) -> Result<()> {
    let mut client = ReferenceValueProviderServiceClient::connect(address).await?;
    let req = tonic::Request::new(ReferenceValueRegisterRequest { message });

    client.register_reference_value(req).await?;

    Ok(())
}

pub async fn query(address: String) -> Result<String> {
    let mut client = ReferenceValueProviderServiceClient::connect(address).await?;
    let req = tonic::Request::new(ReferenceValueQueryRequest {});

    let rvs = client
        .query_reference_value(req)
        .await?
        .into_inner()
        .reference_value_results;

    Ok(rvs)
}

pub async fn delete(address: String, name: String) -> Result<()> {
    let mut client = ReferenceValueProviderServiceClient::connect(address).await?;
    let req = tonic::Request::new(ReferenceValueDeleteRequest { name });

    client.delete_reference_value(req).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;
    use tonic::transport::Server;
    use tonic::{Request, Response, Status};

    use crate::rvps_api::reference::{
        reference_value_provider_service_server::{
            ReferenceValueProviderService, ReferenceValueProviderServiceServer,
        },
        ReferenceValueDeleteRequest, ReferenceValueDeleteResponse, ReferenceValueQueryRequest,
        ReferenceValueQueryResponse, ReferenceValueRegisterRequest, ReferenceValueRegisterResponse,
    };

    // Mock implementation of the ReferenceValueProviderService
    struct MockRvpsServer {
        // Control behavior of the mock server
        should_fail_register: bool,
        should_fail_query: bool,
        should_fail_delete: bool,
        // Store the last received message for verification
        last_register_message: std::sync::Mutex<Option<String>>,
        // Response to return for query
        query_response: String,
        // Store the last deleted name for verification
        last_deleted_name: std::sync::Mutex<Option<String>>,
    }

    impl Default for MockRvpsServer {
        fn default() -> Self {
            Self {
                should_fail_register: false,
                should_fail_query: false,
                should_fail_delete: false,
                last_register_message: std::sync::Mutex::new(None),
                query_response: r#"{"test_artifact":["hash1","hash2"]}"#.to_string(),
                last_deleted_name: std::sync::Mutex::new(None),
            }
        }
    }

    #[tonic::async_trait]
    impl ReferenceValueProviderService for MockRvpsServer {
        async fn query_reference_value(
            &self,
            _request: Request<ReferenceValueQueryRequest>,
        ) -> std::result::Result<Response<ReferenceValueQueryResponse>, Status> {
            if self.should_fail_query {
                return Err(Status::internal("Mock query failure"));
            }

            let response = ReferenceValueQueryResponse {
                reference_value_results: self.query_response.clone(),
            };

            Ok(Response::new(response))
        }

        async fn register_reference_value(
            &self,
            request: Request<ReferenceValueRegisterRequest>,
        ) -> std::result::Result<Response<ReferenceValueRegisterResponse>, Status> {
            if self.should_fail_register {
                return Err(Status::internal("Mock register failure"));
            }

            let message = request.into_inner().message;
            if let Result::Ok(mut last_message) = self.last_register_message.lock() {
                *last_message = Some(message);
            }

            let response = ReferenceValueRegisterResponse {};
            Ok(Response::new(response))
        }

        async fn delete_reference_value(
            &self,
            request: Request<ReferenceValueDeleteRequest>,
        ) -> std::result::Result<Response<ReferenceValueDeleteResponse>, Status> {
            if self.should_fail_delete {
                return Err(Status::internal("Mock delete failure"));
            }

            let name = request.into_inner().name;
            if let Result::Ok(mut last_name) = self.last_deleted_name.lock() {
                *last_name = Some(name);
            }

            let response = ReferenceValueDeleteResponse {};
            Ok(Response::new(response))
        }
    }

    // Helper function to start a mock server
    async fn start_mock_server(mock_server: MockRvpsServer) -> (String, oneshot::Sender<()>) {
        // Use a random port instead of a fixed port
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind to random port");
        let addr = listener.local_addr().expect("Failed to get local address");

        // Create a shutdown channel
        let (tx, rx) = oneshot::channel();

        // Create the server
        let service = ReferenceValueProviderServiceServer::new(mock_server);

        // Spawn the server in a separate task
        tokio::spawn(async move {
            Server::builder()
                .add_service(service)
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    async {
                        rx.await.ok();
                    },
                )
                .await
                .expect("Server failed to start");
        });

        // Give the server time to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Return the address and shutdown sender
        (format!("http://{}", addr), tx)
    }

    #[tokio::test]
    async fn test_register_success() {
        // Start a mock server
        let mock_server = MockRvpsServer::default();
        let (address, _shutdown) = start_mock_server(mock_server).await;

        // Test message to register
        let test_message = "test message".to_string();

        // Call register
        let result = register(address, test_message.clone()).await;
        assert!(result.is_ok(), "Register should succeed");

        // Note: We can't verify the message was received without access to the server instance
        // This test just verifies that the register call succeeds
    }

    #[tokio::test]
    async fn test_register_failure() {
        // Start a mock server that will fail register requests
        let mock_server = MockRvpsServer {
            should_fail_register: true,
            ..Default::default()
        };
        let (address, _shutdown) = start_mock_server(mock_server).await;

        // Call register
        let result = register(address, "test message".to_string()).await;
        assert!(result.is_err(), "Register should fail");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Mock register failure"),
            "Error should contain the mock failure message"
        );
    }

    #[tokio::test]
    async fn test_query_success() {
        // Start a mock server with a specific query response
        let expected_response = r#"{"test_artifact":["hash1","hash2"]}"#.to_string();
        let mock_server = MockRvpsServer {
            query_response: expected_response.clone(),
            ..Default::default()
        };
        let (address, _shutdown) = start_mock_server(mock_server).await;

        // Call query
        let result = query(address).await;
        assert!(result.is_ok(), "Query should succeed");
        assert_eq!(
            result.unwrap(),
            expected_response,
            "Query should return the expected response"
        );
    }

    #[tokio::test]
    async fn test_query_failure() {
        // Start a mock server that will fail query requests
        let mock_server = MockRvpsServer {
            should_fail_query: true,
            ..Default::default()
        };
        let (address, _shutdown) = start_mock_server(mock_server).await;

        // Call query
        let result = query(address).await;
        assert!(result.is_err(), "Query should fail");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Mock query failure"),
            "Error should contain the mock failure message"
        );
    }

    #[tokio::test]
    async fn test_delete_success() {
        // Start a mock server
        let mock_server = MockRvpsServer::default();
        let (address, _shutdown) = start_mock_server(mock_server).await;

        // Test name to delete
        let test_name = "test_artifact".to_string();

        // Call delete
        let result = delete(address, test_name.clone()).await;
        assert!(result.is_ok(), "Delete should succeed");

        // Note: We can't verify the name was received without access to the server instance
        // This test just verifies that the delete call succeeds
    }

    #[tokio::test]
    async fn test_delete_failure() {
        // Start a mock server that will fail delete requests
        let mock_server = MockRvpsServer {
            should_fail_delete: true,
            ..Default::default()
        };
        let (address, _shutdown) = start_mock_server(mock_server).await;

        // Call delete
        let result = delete(address, "test_artifact".to_string()).await;
        assert!(result.is_err(), "Delete should fail");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Mock delete failure"),
            "Error should contain the mock failure message"
        );
    }
}
