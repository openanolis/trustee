//! Business logic façade consumed by HTTP handlers.

use chrono::Utc;
use serde_json::{json, Map, Value};

use crate::attestation::verify_attestation;
use crate::config::IamConfig;
use crate::error::IamError;
use crate::models::{
    generate_id, Account, AccountResponse, AssumeRoleRequest, AssumeRoleResponse,
    CreateAccountRequest, CreatePrincipalRequest, CreateRoleRequest, EvaluateRequest,
    EvaluateResponse, Principal, PrincipalResponse, RegisterResourceRequest, Resource,
    ResourceResponse, Role, RoleResponse,
};
use crate::policy::evaluate_policy;
use crate::storage::Store;
use crate::token::TokenSigner;

/// Public entry point that wires storage, policy evaluation and token signing.
pub struct IamService {
    store: Store,
    signer: TokenSigner,
}

impl IamService {
    /// Build a service instance using the provided configuration.
    pub fn new(config: &IamConfig) -> Result<Self, IamError> {
        let signer = TokenSigner::new(&config.crypto)?;
        Ok(Self {
            store: Store::default(),
            signer,
        })
    }

    /// Create a logical account boundary.
    pub async fn create_account(
        &self,
        request: CreateAccountRequest,
    ) -> Result<AccountResponse, IamError> {
        let account = Account {
            id: generate_id("acct"),
            name: request.name,
            labels: request.labels,
            created_at: Utc::now(),
        };
        let stored = self.store.insert_account(account).await?;
        Ok(AccountResponse { account: stored })
    }

    /// Create a principal under a specific account.
    pub async fn create_principal(
        &self,
        account_id: &str,
        request: CreatePrincipalRequest,
    ) -> Result<PrincipalResponse, IamError> {
        // Ensure the parent account exists
        let _ = self.store.get_account(account_id).await?;
        let principal = Principal {
            id: generate_id("prn"),
            account_id: account_id.to_string(),
            name: request.name,
            principal_type: request.principal_type,
            attributes: request.attributes,
            created_at: Utc::now(),
        };
        let stored = self.store.insert_principal(principal).await?;
        Ok(PrincipalResponse { principal: stored })
    }

    /// Register a resource and return its derived ARN.
    pub async fn register_resource(
        &self,
        request: RegisterResourceRequest,
    ) -> Result<ResourceResponse, IamError> {
        let owner = self.store.get_account(&request.owner_account_id).await?;
        let resource_id = generate_id("res");
        let arn = format!(
            "arn:trustee::{}:{}/{}",
            owner.id, request.resource_type, resource_id
        );
        let resource = Resource {
            arn,
            owner_account_id: owner.id,
            resource_type: request.resource_type,
            tags: request.tags,
            attributes: request.attributes,
            created_at: Utc::now(),
        };
        let stored = self.store.insert_resource(resource).await?;
        Ok(ResourceResponse { resource: stored })
    }

    /// Create a role definition with both trust and access policies.
    pub async fn create_role(&self, request: CreateRoleRequest) -> Result<RoleResponse, IamError> {
        let role = Role {
            id: generate_id("role"),
            name: request.name,
            description: request.description,
            trust_policy: request.trust_policy,
            access_policy: request.access_policy,
            labels: request.labels,
            created_at: Utc::now(),
        };
        let stored = self.store.insert_role(role).await?;
        Ok(RoleResponse { role: stored })
    }

    /// Evaluate trust policy + attestation and issue a session token.
    pub async fn assume_role(
        &self,
        request: AssumeRoleRequest,
    ) -> Result<AssumeRoleResponse, IamError> {
        let AssumeRoleRequest {
            principal_id,
            role_id,
            requested_duration_seconds,
            session_name,
            attestation_token,
            context: assume_context,
        } = request;
        let principal = self.store.get_principal(&principal_id).await?;
        let role = self.store.get_role(&role_id).await?;
        let attestation_ctx = verify_attestation(attestation_token.as_deref())?;
        let request_context = assume_context.unwrap_or_default();

        let mut context = Map::new();
        context.insert("principal".to_string(), principal_to_value(&principal));
        context.insert("env".to_string(), Value::Object(attestation_ctx.to_env()));
        context.insert(
            "request".to_string(),
            Value::Object(request_context.clone()),
        );

        let allowed = evaluate_policy(&role.trust_policy, "sts:AssumeRole", &role.id, &context);
        if !allowed {
            return Err(IamError::Unauthorized(format!(
                "principal {} is not allowed to assume role {}",
                principal.id, role.id
            )));
        }

        let signed = self.signer.issue(
            &principal,
            &role,
            attestation_ctx.to_env(),
            request_context,
            requested_duration_seconds,
            session_name,
        )?;
        Ok(AssumeRoleResponse {
            token: signed.token,
            expires_at: signed.claims.expires_at(),
        })
    }

    /// Evaluate access policy using a previously issued session token.
    pub async fn evaluate(&self, request: EvaluateRequest) -> Result<EvaluateResponse, IamError> {
        let EvaluateRequest {
            token,
            action,
            resource,
            context: eval_context,
        } = request;
        let claims = self.signer.verify(&token)?;
        let role = self.store.get_role(&claims.role).await?;
        let principal = self.store.get_principal(&claims.sub).await?;
        let mut policy_context = Map::new();
        policy_context.insert("principal".to_string(), principal_to_value(&principal));
        policy_context.insert("env".to_string(), Value::Object(claims.env));
        if let Ok(resource_meta) = self.store.get_resource(&resource).await {
            policy_context.insert("resource".to_string(), resource_to_value(&resource_meta));
        }
        let request_context = eval_context.unwrap_or_default();
        policy_context.insert(
            "request".to_string(),
            json!({
                "action": action,
                "resource": resource,
                "context": Value::Object(request_context.clone()),
            }),
        );

        let allowed = evaluate_policy(&role.access_policy, &action, &resource, &policy_context);
        Ok(EvaluateResponse { allowed })
    }
}

/// Convert a principal into a JSON object for policy contexts.
fn principal_to_value(principal: &Principal) -> Value {
    json!({
        "id": principal.id,
        "accountId": principal.account_id,
        "name": principal.name,
        "type": principal.principal_type,
        "attributes": Value::Object(principal.attributes.values.clone()),
    })
}

/// Convert a resource record into a JSON object for policy contexts.
fn resource_to_value(resource: &Resource) -> Value {
    json!({
        "arn": resource.arn,
        "ownerAccountId": resource.owner_account_id,
        "resourceType": resource.resource_type,
        "tags": resource.tags,
        "attributes": Value::Object(resource.attributes.values.clone()),
    })
}
