//! rmcp handler for Security Director Cloud tools.

use mecmcp_audit::{Attribution, AuditScope};
use mecmcp_auth::{CallerCtx, NoGrant};
use mecmcp_server::{
    ResultFormat, ResultLimits, audit_scope, authorize_call, caller_from_extensions,
    filter_tools_for_scope, tool_error, tool_result,
};
use rmcp::{
    RoleServer, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        CallToolResult, Extensions, Implementation, ListToolsResult, PaginatedRequestParams,
        ServerCapabilities, ServerInfo,
    },
    service::RequestContext,
    tool, tool_handler, tool_router,
};
use rustsdcmcp_core::{
    ChangeManager, ListRequest, PolicyOperation, ResourceKind, SdcClient, SdcError,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

const RESULT_LIMITS: ResultLimits = ResultLimits {
    max_text_bytes: 8 * 1024 * 1024,
    max_json_bytes: 8 * 1024 * 1024,
};

/// Exact MCP tool registry used for token validation and drift tests.
pub const KNOWN_TOOLS: &[&str] = &[
    "get_sdc_tenant_scope",
    "list_sdc_devices",
    "get_sdc_device",
    "list_sdc_firewall_policies",
    "get_sdc_firewall_policy",
    "list_sdc_nat_policies",
    "get_sdc_nat_policy",
    "list_sdc_resources",
    "get_sdc_resource",
    "get_sdc_preview_status",
    "get_sdc_deploy_status",
    "get_sdc_preview_device_result",
    "get_sdc_deploy_device_result",
    "prepare_sdc_policy_deploy",
    "approve_sdc_change_set",
    "apply_sdc_change_set",
    "get_sdc_change_set",
];

/// Tools that can cause an SDC deployment lifecycle mutation.
pub const WRITE_TOOLS: &[&str] = &[
    "prepare_sdc_policy_deploy",
    "approve_sdc_change_set",
    "apply_sdc_change_set",
];

/// Security Director Cloud MCP handler.
#[derive(Clone)]
pub struct SdcHandler {
    tenant: Arc<str>,
    client: SdcClient,
    changes: Arc<ChangeManager>,
    tool_router: ToolRouter<Self>,
}

impl SdcHandler {
    /// Construct a handler for one configured tenant.
    #[must_use]
    pub fn new(
        tenant: impl Into<Arc<str>>,
        client: SdcClient,
        changes: Arc<ChangeManager>,
    ) -> Self {
        Self {
            tenant: tenant.into(),
            client,
            changes,
            tool_router: Self::sdc_tool_router(),
        }
    }

    fn authorize(
        &self,
        caller: Option<&CallerCtx<NoGrant>>,
        tool: &'static str,
        tenant: &str,
    ) -> Result<(), HandlerAuthorizationError> {
        authorize_request(caller, tool, tenant, &self.tenant)
    }
}

fn authorize_request(
    caller: Option<&CallerCtx<NoGrant>>,
    tool: &'static str,
    tenant: &str,
    configured_tenant: &str,
) -> Result<(), HandlerAuthorizationError> {
    if caller.is_none() && WRITE_TOOLS.contains(&tool) {
        return Err(HandlerAuthorizationError(
            "SDC write tools require an authenticated bearer token".to_owned(),
        ));
    }
    authorize_call(caller, tool, Some(tenant), WRITE_TOOLS)
        .map_err(|error| HandlerAuthorizationError(error.to_string()))?;
    if tenant != configured_tenant {
        return Err(HandlerAuthorizationError(
            "requested tenant is not configured or authorized".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct HandlerAuthorizationError(String);

fn owner(caller: Option<&CallerCtx<NoGrant>>) -> String {
    caller
        .map(|caller| caller.token_name.clone())
        .unwrap_or_else(|| "stdio".to_owned())
}

fn attribution(caller: Option<&CallerCtx<NoGrant>>, change_ref: Option<String>) -> Attribution {
    let mut attribution = caller
        .map(Attribution::from_caller)
        .unwrap_or_else(Attribution::stdio);
    attribution.change_ref = change_ref;
    attribution
}

fn finish<T: Serialize>(mut audit: AuditScope, result: Result<T, SdcError>) -> CallToolResult {
    match &result {
        Ok(_) => audit.succeed(),
        Err(error) => audit.fail(error),
    }
    tool_result(result, ResultFormat::PrettyJson, RESULT_LIMITS)
}

/// Arguments shared by tenant-level tools.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TenantArgs {
    /// Configured tenant alias.
    pub tenant: String,
}

/// Arguments for bounded list tools.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Zero-based offset.
    #[serde(default)]
    pub from: u64,
    /// Explicit positive page size.
    pub size: u32,
}

/// Arguments for one device.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Device UUID.
    pub device_uuid: String,
}

/// Arguments for one policy.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Policy UUID.
    pub policy_id: String,
}

/// Arguments for a generic allowlisted collection.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResourceListArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Allowlisted resource family.
    pub resource: ResourceKind,
    /// Zero-based offset.
    #[serde(default)]
    pub from: u64,
    /// Explicit positive page size.
    pub size: u32,
}

/// Arguments for one generic allowlisted resource.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResourceArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Allowlisted resource family.
    pub resource: ResourceKind,
    /// Resource UUID.
    pub uuid: String,
}

/// Arguments for one asynchronous job.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JobArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Preview or deploy identifier.
    pub job_id: String,
}

/// Arguments for one device result within an asynchronous job.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JobDeviceArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Preview or deploy identifier.
    pub job_id: String,
    /// Device UUID.
    pub device_id: String,
}

/// Arguments for previewing and planning a deployment.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrepareArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Exact policy target operations to preview.
    pub policies: Vec<PolicyOperation>,
}

/// Arguments for independent change-set approval.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApproveArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Change-set identifier.
    pub change_set_id: String,
    /// Exact plan digest returned by prepare.
    pub expected_digest: String,
}

/// Arguments for applying an approved change set.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApplyArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Change-set identifier.
    pub change_set_id: String,
    /// Exact approved plan digest.
    pub expected_digest: String,
    /// Exact preview digest returned by prepare.
    pub expected_preview_digest: String,
    /// Optional external ticket or change reference.
    #[serde(default)]
    pub change_ref: Option<String>,
}

/// Arguments for current change-set status.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChangeSetArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Change-set identifier.
    pub change_set_id: String,
}

#[tool_router(router = sdc_tool_router, vis = "pub(crate)")]
impl SdcHandler {
    #[tool(
        name = "get_sdc_tenant_scope",
        description = "Return the SDC tenant ID bound to the configured credential."
    )]
    async fn get_sdc_tenant_scope(
        &self,
        Parameters(args): Parameters<TenantArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "get_sdc_tenant_scope",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "get_sdc_tenant_scope", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish(
            audit,
            self.client.tenant_scope(&CancellationToken::new()).await,
        ))
    }

    #[tool(
        name = "list_sdc_devices",
        description = "List managed SDC devices with bounded pagination."
    )]
    async fn list_sdc_devices(
        &self,
        Parameters(args): Parameters<ListArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "list_sdc_devices",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "list_sdc_devices", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        let result = ListRequest::new(args.from, args.size, self.client.max_page_size())
            .map_err(SdcError::from);
        let result = match result {
            Ok(page) => {
                self.client
                    .list_devices(page, &CancellationToken::new())
                    .await
            }
            Err(error) => Err(error),
        };
        Ok(finish(audit, result))
    }

    #[tool(
        name = "get_sdc_device",
        description = "Get one managed SDC device by UUID."
    )]
    async fn get_sdc_device(
        &self,
        Parameters(args): Parameters<DeviceArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(caller, "get_sdc_device", "read", vec![args.tenant.clone()]);
        if let Err(error) = self.authorize(caller, "get_sdc_device", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish(
            audit,
            self.client
                .get_device(&args.device_uuid, &CancellationToken::new())
                .await,
        ))
    }

    #[tool(
        name = "list_sdc_firewall_policies",
        description = "List SDC firewall policies with bounded pagination."
    )]
    async fn list_sdc_firewall_policies(
        &self,
        Parameters(args): Parameters<ListArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "list_sdc_firewall_policies",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "list_sdc_firewall_policies", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        let result = ListRequest::new(args.from, args.size, self.client.max_page_size())
            .map_err(SdcError::from);
        let result = match result {
            Ok(page) => {
                self.client
                    .list_firewall_policies(page, &CancellationToken::new())
                    .await
            }
            Err(error) => Err(error),
        };
        Ok(finish(audit, result))
    }

    #[tool(
        name = "get_sdc_firewall_policy",
        description = "Get one SDC firewall policy by UUID."
    )]
    async fn get_sdc_firewall_policy(
        &self,
        Parameters(args): Parameters<PolicyArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "get_sdc_firewall_policy",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "get_sdc_firewall_policy", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish(
            audit,
            self.client
                .get_firewall_policy(&args.policy_id, &CancellationToken::new())
                .await,
        ))
    }

    #[tool(
        name = "list_sdc_nat_policies",
        description = "List SDC NAT policies with bounded pagination."
    )]
    async fn list_sdc_nat_policies(
        &self,
        Parameters(args): Parameters<ListArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "list_sdc_nat_policies",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "list_sdc_nat_policies", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        let result = ListRequest::new(args.from, args.size, self.client.max_page_size())
            .map_err(SdcError::from);
        let result = match result {
            Ok(page) => {
                self.client
                    .list_nat_policies(page, &CancellationToken::new())
                    .await
            }
            Err(error) => Err(error),
        };
        Ok(finish(audit, result))
    }

    #[tool(
        name = "get_sdc_nat_policy",
        description = "Get one SDC NAT policy by ID."
    )]
    async fn get_sdc_nat_policy(
        &self,
        Parameters(args): Parameters<PolicyArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "get_sdc_nat_policy",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "get_sdc_nat_policy", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish(
            audit,
            self.client
                .get_nat_policy(&args.policy_id, &CancellationToken::new())
                .await,
        ))
    }

    #[tool(
        name = "list_sdc_resources",
        description = "List an allowlisted SDC address, application, service, or scheduler collection."
    )]
    async fn list_sdc_resources(
        &self,
        Parameters(args): Parameters<ResourceListArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "list_sdc_resources",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "list_sdc_resources", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        let result = ListRequest::new(args.from, args.size, self.client.max_page_size())
            .map_err(SdcError::from);
        let result = match result {
            Ok(page) => {
                self.client
                    .list_resource(args.resource, page, &CancellationToken::new())
                    .await
            }
            Err(error) => Err(error),
        };
        Ok(finish(audit, result))
    }

    #[tool(
        name = "get_sdc_resource",
        description = "Get one allowlisted SDC address, application, service, or scheduler object."
    )]
    async fn get_sdc_resource(
        &self,
        Parameters(args): Parameters<ResourceArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "get_sdc_resource",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "get_sdc_resource", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish(
            audit,
            self.client
                .get_resource(args.resource, &args.uuid, &CancellationToken::new())
                .await,
        ))
    }

    #[tool(
        name = "get_sdc_preview_status",
        description = "Read one SDC policy preview job status."
    )]
    async fn get_sdc_preview_status(
        &self,
        Parameters(args): Parameters<JobArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "get_sdc_preview_status",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "get_sdc_preview_status", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish(
            audit,
            self.client
                .preview_status(&args.job_id, &CancellationToken::new())
                .await,
        ))
    }

    #[tool(
        name = "get_sdc_deploy_status",
        description = "Read one SDC policy deploy job status."
    )]
    async fn get_sdc_deploy_status(
        &self,
        Parameters(args): Parameters<JobArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "get_sdc_deploy_status",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "get_sdc_deploy_status", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish(
            audit,
            self.client
                .deploy_status(&args.job_id, &CancellationToken::new())
                .await,
        ))
    }

    #[tool(
        name = "get_sdc_preview_device_result",
        description = "Read one per-device SDC preview result in CLI format."
    )]
    async fn get_sdc_preview_device_result(
        &self,
        Parameters(args): Parameters<JobDeviceArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "get_sdc_preview_device_result",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "get_sdc_preview_device_result", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish(
            audit,
            self.client
                .preview_device_result(&args.job_id, &args.device_id, &CancellationToken::new())
                .await,
        ))
    }

    #[tool(
        name = "get_sdc_deploy_device_result",
        description = "Read one per-device SDC deploy result in CLI format."
    )]
    async fn get_sdc_deploy_device_result(
        &self,
        Parameters(args): Parameters<JobDeviceArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "get_sdc_deploy_device_result",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "get_sdc_deploy_device_result", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish(
            audit,
            self.client
                .deploy_device_result(&args.job_id, &args.device_id, &CancellationToken::new())
                .await,
        ))
    }

    #[tool(
        name = "prepare_sdc_policy_deploy",
        description = "Preview SDC policy target changes and create a digest-bound change set. This does not deploy."
    )]
    async fn prepare_sdc_policy_deploy(
        &self,
        Parameters(args): Parameters<PrepareArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "prepare_sdc_policy_deploy",
            "prepare",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "prepare_sdc_policy_deploy", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish(
            audit,
            self.changes
                .prepare(owner(caller), args.policies, &CancellationToken::new())
                .await,
        ))
    }

    #[tool(
        name = "approve_sdc_change_set",
        description = "Approve an exact SDC change-set digest as a principal distinct from its owner."
    )]
    async fn approve_sdc_change_set(
        &self,
        Parameters(args): Parameters<ApproveArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "approve_sdc_change_set",
            "approve",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "approve_sdc_change_set", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish(
            audit,
            self.changes
                .approve(args.change_set_id, owner(caller), args.expected_digest)
                .await,
        ))
    }

    #[tool(
        name = "apply_sdc_change_set",
        description = "Apply only an independently approved, preview-bound SDC policy deployment and wait for a terminal outcome."
    )]
    async fn apply_sdc_change_set(
        &self,
        Parameters(args): Parameters<ApplyArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "apply_sdc_change_set",
            "apply",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "apply_sdc_change_set", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        let attribution = attribution(caller, args.change_ref);
        Ok(finish(
            audit,
            self.changes
                .apply(
                    args.change_set_id,
                    owner(caller),
                    args.expected_digest,
                    args.expected_preview_digest,
                    &attribution,
                    &CancellationToken::new(),
                )
                .await,
        ))
    }

    #[tool(
        name = "get_sdc_change_set",
        description = "Return the current shared lifecycle state for one SDC change set."
    )]
    async fn get_sdc_change_set(
        &self,
        Parameters(args): Parameters<ChangeSetArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "get_sdc_change_set",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "get_sdc_change_set", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish(audit, self.changes.status(args.change_set_id).await))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for SdcHandler {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("rustsdcmcp", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "Security Director Cloud MCP server. Start with get_sdc_tenant_scope, \
                 use bounded read tools for discovery, and use prepare/approve/apply \
                 for policy deployment. There is no direct deploy tool.",
            )
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, rmcp::ErrorData> {
        Ok(ListToolsResult::with_all_items(filter_tools_for_scope(
            self.tool_router.list_all(),
            caller_from_extensions::<NoGrant>(&context.extensions),
            WRITE_TOOLS,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mecmcp_auth::{ActorType, ScopeSet};

    fn caller(targets: ScopeSet, tools: ScopeSet) -> CallerCtx<NoGrant> {
        CallerCtx {
            token_name: "alice".to_owned(),
            devices: targets,
            tools,
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: ActorType::Human,
        }
    }

    #[test]
    fn unauthenticated_paths_are_read_only() {
        assert!(authorize_request(None, "get_sdc_tenant_scope", "tenant-a", "tenant-a").is_ok());
        assert!(
            authorize_request(None, "prepare_sdc_policy_deploy", "tenant-a", "tenant-a").is_err()
        );
        assert!(authorize_request(None, "approve_sdc_change_set", "tenant-a", "tenant-a").is_err());
    }

    #[test]
    fn authenticated_calls_require_exact_tool_and_tenant_scopes() {
        let scoped = caller(
            ScopeSet::Allowlist(vec!["tenant-a".to_owned()]),
            ScopeSet::Allowlist(vec!["prepare_sdc_policy_deploy".to_owned()]),
        );
        assert!(
            authorize_request(
                Some(&scoped),
                "prepare_sdc_policy_deploy",
                "tenant-a",
                "tenant-a"
            )
            .is_ok()
        );
        assert!(
            authorize_request(
                Some(&scoped),
                "prepare_sdc_policy_deploy",
                "tenant-b",
                "tenant-a"
            )
            .is_err()
        );
        assert!(
            authorize_request(
                Some(&scoped),
                "apply_sdc_change_set",
                "tenant-a",
                "tenant-a"
            )
            .is_err()
        );
    }
}
