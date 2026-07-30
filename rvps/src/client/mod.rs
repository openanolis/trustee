// Copyright (c) 2025 IBM
//
// SPDX-License-Identifier: Apache-2.0
//
// Helpers for building a client for the RVPS

use anyhow::*;

use crate::rvps_api::reference::{
    reference_value_provider_service_client::ReferenceValueProviderServiceClient,
    ReferenceValueDeleteRequest, ReferenceValueListRequest, ReferenceValueQueryRequest,
    ReferenceValueRegisterRequest,
};

pub async fn register(address: String, message: String) -> Result<()> {
    let mut client = ReferenceValueProviderServiceClient::connect(address).await?;
    let req = tonic::Request::new(ReferenceValueRegisterRequest { message });

    client.register_reference_value(req).await?;

    Ok(())
}

pub async fn query(address: String) -> Result<String> {
    Ok(query_by_id(address, String::new())
        .await?
        .unwrap_or_else(|| "{}".to_string()))
}

/// Query one reference value. A missing or expired value returns `None`.
pub async fn query_by_id(address: String, reference_value_id: String) -> Result<Option<String>> {
    let mut client = ReferenceValueProviderServiceClient::connect(address).await?;
    let req = tonic::Request::new(ReferenceValueQueryRequest { reference_value_id });

    let rvs = client
        .query_reference_value(req)
        .await?
        .into_inner()
        .reference_value_results;

    Ok((!rvs.is_empty()).then_some(rvs))
}

pub async fn delete(address: String, name: String) -> Result<()> {
    let mut client = ReferenceValueProviderServiceClient::connect(address).await?;
    let req = tonic::Request::new(ReferenceValueDeleteRequest { name });

    client.delete_reference_value(req).await?;

    Ok(())
}

pub async fn set_reference_value_list(address: String, payload: String) -> Result<()> {
    let mut client = ReferenceValueProviderServiceClient::connect(address).await?;
    let req = tonic::Request::new(ReferenceValueListRequest { payload });

    client.set_reference_value_list(req).await?;

    Ok(())
}
