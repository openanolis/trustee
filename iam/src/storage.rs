//! Extremely simple in-memory storage used by the IAM MVP.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::error::IamError;
use crate::models::{
    Account, AccountId, Principal, PrincipalId, Resource, ResourceArn, Role, RoleId,
};

/// Cloneable handle to the shared in-memory store.
#[derive(Clone, Default)]
pub struct Store {
    accounts: Arc<RwLock<HashMap<AccountId, Account>>>,
    principals: Arc<RwLock<HashMap<PrincipalId, Principal>>>,
    resources: Arc<RwLock<HashMap<ResourceArn, Resource>>>,
    roles: Arc<RwLock<HashMap<RoleId, Role>>>,
}

impl Store {
    /// Insert a new account if the identifier is unused.
    pub async fn insert_account(&self, account: Account) -> Result<Account, IamError> {
        let mut guard = self.accounts.write().await;
        if guard.contains_key(&account.id) {
            return Err(IamError::Conflict(format!(
                "account {} already exists",
                account.id
            )));
        }
        guard.insert(account.id.clone(), account.clone());
        Ok(account)
    }

    /// Fetch an account by id.
    pub async fn get_account(&self, account_id: &str) -> Result<Account, IamError> {
        let guard = self.accounts.read().await;
        guard
            .get(account_id)
            .cloned()
            .ok_or_else(|| IamError::NotFound(format!("account {}", account_id)))
    }

    /// Insert a new principal if not already present.
    pub async fn insert_principal(&self, principal: Principal) -> Result<Principal, IamError> {
        let mut guard = self.principals.write().await;
        if guard.contains_key(&principal.id) {
            return Err(IamError::Conflict(format!(
                "principal {} already exists",
                principal.id
            )));
        }
        guard.insert(principal.id.clone(), principal.clone());
        Ok(principal)
    }

    /// Fetch a principal by id.
    pub async fn get_principal(&self, principal_id: &str) -> Result<Principal, IamError> {
        let guard = self.principals.read().await;
        guard
            .get(principal_id)
            .cloned()
            .ok_or_else(|| IamError::NotFound(format!("principal {}", principal_id)))
    }

    /// Insert a new resource ARN entry.
    pub async fn insert_resource(&self, resource: Resource) -> Result<Resource, IamError> {
        let mut guard = self.resources.write().await;
        if guard.contains_key(&resource.arn) {
            return Err(IamError::Conflict(format!(
                "resource {} already exists",
                resource.arn
            )));
        }
        guard.insert(resource.arn.clone(), resource.clone());
        Ok(resource)
    }

    /// Fetch a resource by ARN.
    pub async fn get_resource(&self, arn: &str) -> Result<Resource, IamError> {
        let guard = self.resources.read().await;
        guard
            .get(arn)
            .cloned()
            .ok_or_else(|| IamError::NotFound(format!("resource {}", arn)))
    }

    /// Insert a new role definition.
    pub async fn insert_role(&self, role: Role) -> Result<Role, IamError> {
        let mut guard = self.roles.write().await;
        if guard.contains_key(&role.id) {
            return Err(IamError::Conflict(format!(
                "role {} already exists",
                role.id
            )));
        }
        guard.insert(role.id.clone(), role.clone());
        Ok(role)
    }

    /// Fetch a role by id.
    pub async fn get_role(&self, role_id: &str) -> Result<Role, IamError> {
        let guard = self.roles.read().await;
        guard
            .get(role_id)
            .cloned()
            .ok_or_else(|| IamError::NotFound(format!("role {}", role_id)))
    }
}
