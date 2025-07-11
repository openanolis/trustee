// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::*;
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use kbs_types::{Attestation, Challenge, Tee};
use log::info;
use mobc::{Manager, Pool};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use tokio::sync::Mutex;
use tonic::transport::Channel;

use crate::attestation::backend::{make_nonce, Attest};

use self::attestation::{
    attestation_request::RuntimeData, attestation_service_client::AttestationServiceClient,
    AttestationRequest, ChallengeRequest, DeletePolicyRequest, GetPolicyRequest,
    ListPoliciesRequest, SetPolicyRequest,
};

mod attestation {
    tonic::include_proto!("attestation");
}

pub const DEFAULT_AS_ADDR: &str = "http://127.0.0.1:50004";
pub const DEFAULT_POOL_SIZE: u64 = 100;

pub const COCO_AS_HASH_ALGORITHM: &str = "sha384";

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct GrpcConfig {
    #[serde(default = "default_as_addr")]
    pub(crate) as_addr: String,
    #[serde(default = "default_pool_size")]
    pub(crate) pool_size: u64,
}

fn default_as_addr() -> String {
    DEFAULT_AS_ADDR.to_string()
}

fn default_pool_size() -> u64 {
    DEFAULT_POOL_SIZE
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            as_addr: DEFAULT_AS_ADDR.to_string(),
            pool_size: DEFAULT_POOL_SIZE,
        }
    }
}

pub struct GrpcClientPool {
    pool: Mutex<Pool<GrpcManager>>,
}

impl GrpcClientPool {
    pub async fn new(config: GrpcConfig) -> Result<Self> {
        info!(
            "connect to remote AS [{}] with pool size {}",
            config.as_addr, config.pool_size
        );
        let manager = GrpcManager {
            as_addr: config.as_addr,
        };
        let pool = Mutex::new(Pool::builder().max_open(config.pool_size).build(manager));

        Ok(Self { pool })
    }
}

#[async_trait]
impl Attest for GrpcClientPool {
    async fn set_policy(&self, policy_id: &str, policy: &str) -> Result<()> {
        let req = tonic::Request::new(SetPolicyRequest {
            policy_id: policy_id.to_string(),
            policy: policy.to_string(),
        });

        let mut client = { self.pool.lock().await.get().await? };

        client
            .set_attestation_policy(req)
            .await
            .map_err(|e| anyhow!("Set Policy Failed: {:?}", e))?;

        Ok(())
    }

    async fn get_policy(&self, policy_id: &str) -> Result<String> {
        let req = tonic::Request::new(GetPolicyRequest {
            policy_id: policy_id.to_string(),
        });

        let mut client = { self.pool.lock().await.get().await? };

        let resp = client
            .get_attestation_policy(req)
            .await
            .map_err(|e| anyhow!("Get Policy Failed: {:?}", e))?;

        Ok(resp.into_inner().policy)
    }

    async fn list_policies(&self) -> Result<HashMap<String, String>> {
        let req = tonic::Request::new(ListPoliciesRequest {});

        let mut client = { self.pool.lock().await.get().await? };

        let resp = client
            .list_attestation_policies(req)
            .await
            .map_err(|e| anyhow!("List Policies Failed: {:?}", e))?;

        let mut policies_map = HashMap::new();
        for policy_info in resp.into_inner().policies {
            policies_map.insert(policy_info.policy_id, policy_info.policy_hash);
        }

        Ok(policies_map)
    }

    async fn delete_policy(&self, policy_id: &str) -> Result<()> {
        let req = tonic::Request::new(DeletePolicyRequest {
            policy_id: policy_id.to_string(),
        });

        let mut client = { self.pool.lock().await.get().await? };

        client
            .delete_attestation_policy(req)
            .await
            .map_err(|e| anyhow!("Delete Policy Failed: {:?}", e))?;

        Ok(())
    }

    async fn verify(&self, tee: Tee, nonce: &str, attestation: &str) -> Result<String> {
        let attestation: Attestation = serde_json::from_str(attestation)?;

        // TODO: align with the guest-components/kbs-protocol side.
        let runtime_data_plaintext = json!({"tee-pubkey": attestation.tee_pubkey, "nonce": nonce});
        let runtime_data_plaintext = serde_json::to_string(&runtime_data_plaintext)
            .context("CoCo AS client: serialize runtime data failed")?;

        let tee = serde_json::to_string(&tee)
            .context("CoCo AS client: serialize tee type failed.")?
            .trim_end_matches('"')
            .trim_start_matches('"')
            .to_string();
        let req = tonic::Request::new(AttestationRequest {
            tee,
            evidence: URL_SAFE_NO_PAD.encode(attestation.tee_evidence),
            runtime_data_hash_algorithm: COCO_AS_HASH_ALGORITHM.into(),
            init_data_hash_algorithm: COCO_AS_HASH_ALGORITHM.into(),
            runtime_data: Some(RuntimeData::StructuredRuntimeData(runtime_data_plaintext)),
            init_data: None,
            policy_ids: vec!["default".to_string()],
        });

        let mut client = { self.pool.lock().await.get().await? };

        let token = client
            .attestation_evaluate(req)
            .await?
            .into_inner()
            .attestation_token;

        Ok(token)
    }

    async fn generate_challenge(&self, tee: Tee, tee_parameters: String) -> Result<Challenge> {
        let nonce = match tee {
            Tee::Se => {
                let mut inner = HashMap::new();
                inner.insert(String::from("tee"), String::from("se"));
                inner.insert(String::from("tee_params"), tee_parameters);
                let req = tonic::Request::new(ChallengeRequest { inner });

                let mut client = { self.pool.lock().await.get().await? };

                client
                    .get_attestation_challenge(req)
                    .await?
                    .into_inner()
                    .attestation_challenge
            }
            _ => make_nonce().await?,
        };

        let challenge = Challenge {
            nonce,
            extra_params: String::new(),
        };

        Ok(challenge)
    }
}

pub struct GrpcManager {
    as_addr: String,
}

#[async_trait]
impl Manager for GrpcManager {
    type Connection = AttestationServiceClient<Channel>;
    type Error = tonic::transport::Error;

    async fn connect(&self) -> Result<Self::Connection, Self::Error> {
        let connection = AttestationServiceClient::connect(self.as_addr.clone()).await?;
        std::result::Result::Ok(connection)
    }

    async fn check(&self, conn: Self::Connection) -> Result<Self::Connection, Self::Error> {
        std::result::Result::Ok(conn)
    }
}
