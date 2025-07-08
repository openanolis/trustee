// Copyright (c) 2025 IBM
//
// SPDX-License-Identifier: Apache-2.0
//
// Helpers for building a client for the RVPS

use anyhow::*;

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
