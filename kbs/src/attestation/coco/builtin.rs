// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::*;
use async_trait::async_trait;
use attestation_service::{config::Config as AsConfig, AttestationService, Data, HashAlgorithm};
use kbs_types::{Attestation, Challenge, Tee};
use serde_json::json;
use std::collections::HashMap;
use tokio::sync::RwLock;

use crate::attestation::backend::{make_nonce, Attest};

pub struct BuiltInCoCoAs {
    inner: RwLock<AttestationService>,
}

#[async_trait]
impl Attest for BuiltInCoCoAs {
    async fn set_policy(&self, policy_id: &str, policy: &str) -> Result<()> {
        self.inner
            .write()
            .await
            .set_policy(policy_id.to_string(), policy.to_string())
            .await
    }

    async fn get_policy(&self, policy_id: &str) -> Result<String> {
        self.inner
            .read()
            .await
            .get_policy(policy_id.to_string())
            .await
    }

    async fn list_policies(&self) -> Result<HashMap<String, String>> {
        self.inner.read().await.list_policies().await
    }

    async fn delete_policy(&self, policy_id: &str) -> Result<()> {
        self.inner
            .write()
            .await
            .delete_policy(policy_id.to_string())
            .await
    }

    async fn verify(&self, tee: Tee, nonce: &str, attestation: &str) -> Result<String> {
        let attestation: Attestation = serde_json::from_str(attestation)?;

        // TODO: align with the guest-components/kbs-protocol side.
        let runtime_data_plaintext = json!({"tee-pubkey": attestation.tee_pubkey, "nonce": nonce});

        self.inner
            .read()
            .await
            .evaluate(
                attestation.tee_evidence.into_bytes(),
                tee,
                Some(Data::Structured(runtime_data_plaintext)),
                HashAlgorithm::Sha384,
                None,
                HashAlgorithm::Sha384,
                vec!["default".to_string()],
            )
            .await
    }

    async fn generate_challenge(&self, tee: Tee, tee_parameters: String) -> Result<Challenge> {
        let nonce = match tee {
            Tee::Se => {
                self.inner
                    .read()
                    .await
                    .generate_supplemental_challenge(tee, tee_parameters)
                    .await?
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

impl BuiltInCoCoAs {
    pub async fn new(config: AsConfig) -> Result<Self> {
        let inner = RwLock::new(AttestationService::new(config).await?);
        Ok(Self { inner })
    }
}
