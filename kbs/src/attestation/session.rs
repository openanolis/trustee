// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use actix_web::cookie::{
    time::{Duration, OffsetDateTime},
    Cookie,
};
use anyhow::{anyhow, bail, Context, Result};
use kbs_types::{Challenge, Request};
use key_value_storage::{PutCondition, PutOptions, PutOutcome, Storage};
use log::warn;
use serde::{Deserialize, Serialize};
use std::time::Duration as StdDuration;
use uuid::Uuid;

pub(crate) static KBS_SESSION_ID: &str = "kbs-session-id";

/// Finite State Machine model for RCAR handshake
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) enum SessionStatus {
    Authed {
        request: Request,
        challenge: Challenge,
        id: String,
        timeout: OffsetDateTime,
    },

    Attested {
        token: String,
        id: String,
        timeout: OffsetDateTime,
    },
}

macro_rules! impl_member {
    ($attr: ident, $typ: ident) => {
        pub fn $attr(&self) -> &$typ {
            match self {
                SessionStatus::Authed { $attr, .. } => $attr,
                SessionStatus::Attested { $attr, .. } => $attr,
            }
        }
    };
    ($attr: ident, $typ: ident, $branch: ident) => {
        pub fn $attr(&self) -> &$typ {
            match self {
                SessionStatus::$branch { $attr, .. } => $attr,
                _ => panic!("unexpected status"),
            }
        }
    };
}

impl SessionStatus {
    pub fn auth(request: Request, timeout: i64, challenge: Challenge) -> Self {
        let id = Uuid::new_v4().as_simple().to_string();

        let timeout = OffsetDateTime::now_utc() + Duration::minutes(timeout);

        Self::Authed {
            request,
            challenge,
            id,
            timeout,
        }
    }

    pub fn cookie<'a>(&self) -> Cookie<'a> {
        match self {
            SessionStatus::Authed { id, timeout, .. } => Cookie::build(KBS_SESSION_ID, id.clone())
                .expires(*timeout)
                .finish(),
            SessionStatus::Attested { id, timeout, .. } => {
                Cookie::build(KBS_SESSION_ID, id.clone())
                    .expires(*timeout)
                    .finish()
            }
        }
    }

    impl_member!(request, Request, Authed);
    impl_member!(challenge, Challenge, Authed);
    impl_member!(id, str);
    impl_member!(timeout, OffsetDateTime);

    pub fn is_expired(&self) -> bool {
        *self.timeout() < OffsetDateTime::now_utc()
    }

    fn remaining_ttl(&self) -> Result<StdDuration> {
        let seconds = (*self.timeout() - OffsetDateTime::now_utc()).whole_seconds();
        if seconds <= 0 {
            bail!("session expired")
        }
        Ok(StdDuration::from_secs(seconds as u64))
    }

    pub fn attest(&mut self, token: String) {
        match self {
            SessionStatus::Authed { id, timeout, .. } => {
                *self = SessionStatus::Attested {
                    token,
                    id: id.clone(),
                    timeout: *timeout,
                };
            }
            SessionStatus::Attested { .. } => {
                warn!("session already attested.");
            }
        }
    }
}

pub(crate) struct SessionRecord {
    pub status: SessionStatus,
    pub revision: u64,
}

pub(crate) struct SessionMap {
    storage: Storage,
}

impl SessionMap {
    pub fn new(storage: Storage) -> Self {
        Self { storage }
    }

    pub async fn insert(&self, session: SessionStatus) -> Result<()> {
        let value = serde_json::to_vec(&session).context("serialize KBS session")?;
        let outcome = self
            .storage
            .put(
                session.id(),
                &value,
                PutOptions {
                    condition: PutCondition::IfAbsent,
                    ttl: Some(session.remaining_ttl()?),
                },
            )
            .await
            .context("store KBS session")?;
        match outcome {
            PutOutcome::Created { .. } => Ok(()),
            PutOutcome::Updated { .. } | PutOutcome::Conflict { .. } => {
                Err(anyhow!("KBS session id already exists"))
            }
        }
    }

    pub async fn get(&self, id: &str) -> Result<Option<SessionRecord>> {
        let Some(entry) = self.storage.get(id).await.context("load KBS session")? else {
            return Ok(None);
        };
        let status = serde_json::from_slice(&entry.value).context("deserialize KBS session")?;
        Ok(Some(SessionRecord {
            status,
            revision: entry.revision,
        }))
    }

    /// Persist a state transition only if the caller observed the latest
    /// revision. A false result means another replica won the transition.
    pub async fn update(&self, session: &SessionStatus, expected_revision: u64) -> Result<bool> {
        let value = serde_json::to_vec(session).context("serialize KBS session")?;
        let outcome = self
            .storage
            .put(
                session.id(),
                &value,
                PutOptions {
                    condition: PutCondition::IfRevision(expected_revision),
                    ttl: Some(session.remaining_ttl()?),
                },
            )
            .await
            .context("update KBS session")?;
        Ok(matches!(outcome, PutOutcome::Updated { .. }))
    }

    pub async fn purge_expired(&self) -> Result<u64> {
        self.storage
            .purge_expired()
            .await
            .context("purge expired KBS sessions")
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use kbs_types::Tee;
    use key_value_storage::memory::MemoryStorage;
    use key_value_storage::mysql::{MysqlConfig, MysqlStorage};
    use serde_json::Value;

    use super::*;

    fn authed_session() -> SessionStatus {
        SessionStatus::auth(
            Request {
                version: "0.4.0".into(),
                tee: Tee::Sample,
                extra_params: Value::Null,
            },
            10,
            Challenge {
                nonce: "nonce".into(),
                extra_params: Value::Null,
            },
        )
    }

    #[tokio::test]
    async fn session_transition_is_visible_across_instances() {
        let storage: Storage = Arc::new(MemoryStorage::default());
        let first = SessionMap::new(storage.clone());
        let second = SessionMap::new(storage);
        let session = authed_session();
        let id = session.id().to_string();
        first.insert(session).await.unwrap();

        let record = second.get(&id).await.unwrap().unwrap();
        let mut attested = record.status;
        attested.attest("token".into());
        assert!(second.update(&attested, record.revision).await.unwrap());

        let record = first.get(&id).await.unwrap().unwrap();
        assert!(matches!(
            record.status,
            SessionStatus::Attested { token, .. } if token == "token"
        ));
    }

    #[tokio::test]
    async fn only_one_concurrent_session_transition_wins() {
        let storage: Storage = Arc::new(MemoryStorage::default());
        let sessions = Arc::new(SessionMap::new(storage));
        let session = authed_session();
        let id = session.id().to_string();
        sessions.insert(session).await.unwrap();
        let record = sessions.get(&id).await.unwrap().unwrap();

        let mut tasks = Vec::new();
        for index in 0..16 {
            let sessions = sessions.clone();
            let mut status = record.status.clone();
            let revision = record.revision;
            tasks.push(tokio::spawn(async move {
                status.attest(format!("token-{index}"));
                sessions.update(&status, revision).await.unwrap()
            }));
        }

        let mut winners = 0;
        for task in tasks {
            if task.await.unwrap() {
                winners += 1;
            }
        }
        assert_eq!(winners, 1);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn shared_storage_mysql_session_transition() {
        let Ok(url) = std::env::var("MYSQL_TEST_URL") else {
            return;
        };
        let config = MysqlConfig {
            url,
            url_env: None,
            ..Default::default()
        };
        let first: Storage = Arc::new(
            MysqlStorage::connect(config.clone(), "kbs_session_adapter_test")
                .await
                .unwrap(),
        );
        let second: Storage = Arc::new(
            MysqlStorage::connect(config, "kbs_session_adapter_test")
                .await
                .unwrap(),
        );
        let first = SessionMap::new(first);
        let second = SessionMap::new(second);
        let session = authed_session();
        let id = session.id().to_string();
        first.insert(session).await.unwrap();

        let record = second.get(&id).await.unwrap().unwrap();
        let mut status = record.status;
        status.attest("mysql-token".into());
        assert!(second.update(&status, record.revision).await.unwrap());
        assert!(matches!(
            first.get(&id).await.unwrap().unwrap().status,
            SessionStatus::Attested { token, .. } if token == "mysql-token"
        ));
    }
}
