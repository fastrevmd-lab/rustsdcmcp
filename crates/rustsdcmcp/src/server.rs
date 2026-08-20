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
    ChangeManager, ListRequest, NatWriteOperation, ObjectWriteAction, PolicyOperation,
    ResourceKind, SdcClient, SdcError, WritableResource, project_ca_certificates, project_license,
    project_licenses, project_local_certificates,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
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
    "list_sdc_config_versions",
    "list_sdc_firewall_policies",
    "get_sdc_firewall_policy",
    "list_sdc_firewall_rules",
    "get_sdc_firewall_rule",
    "list_sdc_firewall_rule_groups",
    "get_sdc_firewall_hierarchy",
    "list_sdc_nat_policies",
    "get_sdc_nat_policy",
    "list_sdc_nat_rules",
    "get_sdc_nat_rule",
    "list_sdc_nat_rule_groups",
    "get_sdc_nat_hierarchy",
    "list_sdc_nat_pools",
    "get_sdc_nat_pool",
    "list_sdc_device_groups",
    "get_sdc_device_group",
    "list_sdc_resources",
    "get_sdc_resource",
    "list_sdc_ipsec_profiles",
    "get_sdc_ipsec_profile",
    "list_sdc_tunnels",
    "get_sdc_tunnel",
    "get_sdc_tunnel_count",
    "list_sdc_ca_certificates",
    "list_sdc_local_certificates",
    "list_sdc_device_ca_certificates",
    "list_sdc_device_local_certificates",
    "list_sdc_licenses",
    "get_sdc_license",
    "get_sdc_preview_status",
    "get_sdc_deploy_status",
    "get_sdc_preview_device_result",
    "get_sdc_deploy_device_result",
    "prepare_sdc_policy_deploy",
    "approve_sdc_change_set",
    "apply_sdc_change_set",
    "get_sdc_change_set",
    "get_sdc_change_set_details",
    "discard_sdc_operation",
    "prepare_sdc_object_write",
    "apply_sdc_object_write",
    "prepare_sdc_nat_write",
    "apply_sdc_nat_write",
    "prepare_sdc_firewall_write",
    "apply_sdc_firewall_write",
    "prepare_sdc_license_write",
    "apply_sdc_license_write",
    "prepare_sdc_device_inventory_sync",
    "apply_sdc_device_inventory_sync",
    "get_sdc_firewall_policy_state",
];

/// Tools that can cause an SDC deployment or object lifecycle mutation.
pub const WRITE_TOOLS: &[&str] = &[
    "prepare_sdc_policy_deploy",
    "approve_sdc_change_set",
    "apply_sdc_change_set",
    "prepare_sdc_object_write",
    "apply_sdc_object_write",
    "prepare_sdc_nat_write",
    "apply_sdc_nat_write",
    "prepare_sdc_firewall_write",
    "apply_sdc_firewall_write",
    "prepare_sdc_license_write",
    "apply_sdc_license_write",
    "prepare_sdc_device_inventory_sync",
    "apply_sdc_device_inventory_sync",
    "discard_sdc_operation",
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

/// Arguments for one NAT pool.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NatPoolArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// NAT pool ID.
    pub pool_id: String,
}

/// Arguments for one device group.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceGroupArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Device group UUID.
    pub group_uuid: String,
}

/// Arguments for a device group list, with an optional server-side projection.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceGroupListArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Zero-based start index.
    ///
    /// Defaulted like `ListArgs::from`; omitting it must stay valid.
    #[serde(default)]
    pub from: u64,
    /// Explicit positive page size.
    pub size: u32,
    /// Optional `fields` projection applied by the API, one entry per field.
    ///
    /// `size` bounds the number of groups, not the size of each one, and a
    /// group embeds its membership. Projecting keeps an estate-scale list
    /// readable.
    #[serde(default)]
    pub fields: Vec<String>,
}

/// Arguments for planning one firewall policy write.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrepareFirewallArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Which mutation to plan.
    pub action: rustsdcmcp_core::FirewallWriteOperation,
    /// Target policy UUID. Required for update and delete, absent for create.
    #[serde(default)]
    pub uuid: Option<String>,
    /// Policy definition. Required for create and update, absent for delete.
    #[serde(default)]
    pub body: Option<Value>,
}

/// Arguments for applying one approved firewall policy write.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApplyFirewallArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Change-set identifier.
    pub change_set_id: String,
    /// Exact approved plan digest.
    pub expected_digest: String,
    /// Exact plan digest returned by prepare.
    pub expected_plan_digest: String,
    /// Optional external ticket or change reference.
    #[serde(default)]
    pub change_ref: Option<String>,
}

/// Arguments for firewall policy state read.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FirewallPolicyStateArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Firewall policy UUID.
    pub policy_uuid: String,
    /// Include per-device deployment states in the response.
    #[serde(default)]
    pub include_assigned_devices: bool,
}

/// Arguments for planning one license/certificate write.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrepareLicenseArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Which mutation to plan.
    pub action: rustsdcmcp_core::LicenseWriteOperation,
    /// Target device UUID.
    pub device_uuid: String,
    /// Request body (license key, certificate data, etc).
    pub body: Value,
}

/// Arguments for planning a device configuration sync.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrepareDeviceInventorySyncArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Devices whose inventory SDC should re-read.
    pub device_uuids: Vec<String>,
}

/// Arguments for running one approved device sync.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApplyDeviceInventorySyncArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Approved change-set identifier.
    pub change_set_id: String,
    /// Exact approved digest.
    pub expected_digest: String,
    /// Exact plan digest returned by prepare.
    pub expected_plan_digest: String,
    /// Optional external change reference for the audit record.
    #[serde(default)]
    pub change_ref: Option<String>,
}

/// Arguments for applying one approved license/certificate write.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApplyLicenseArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Change-set identifier.
    pub change_set_id: String,
    /// Exact approved plan digest.
    pub expected_digest: String,
    /// Exact plan digest returned by prepare.
    pub expected_plan_digest: String,
    /// Optional external ticket or change reference.
    #[serde(default)]
    pub change_ref: Option<String>,
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

/// Arguments for device certificate list.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceCertificateListArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Device UUID.
    pub device_uuid: String,
    /// Zero-based offset.
    #[serde(default)]
    pub from: u64,
    /// Explicit positive page size.
    pub size: u32,
}

/// Arguments for device license list.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceLicenseListArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Device UUID.
    pub device_uuid: String,
    /// Zero-based offset.
    #[serde(default)]
    pub from: u64,
    /// Explicit positive page size.
    pub size: u32,
}

/// Arguments for one license.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LicenseArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Device UUID.
    pub device_uuid: String,
    /// License UUID.
    pub license_uuid: String,
}

/// Arguments for tenant-wide certificate list.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CertificateListArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Zero-based offset.
    #[serde(default)]
    pub from: u64,
    /// Explicit positive page size.
    pub size: u32,
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
    /// Optional `fields` projection applied by the API, one entry per field.
    ///
    /// `size` bounds the number of objects, not the size of each one, and
    /// profile families embed rule and pattern lists. Projecting keeps an
    /// estate-scale list readable.
    #[serde(default)]
    pub fields: Vec<String>,
}

/// Arguments for firewall policy rules list.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FirewallRulesListArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Policy UUID.
    pub policy_uuid: String,
    /// Scope: 'global' or 'zone'.
    pub scope: String,
    /// Zero-based offset.
    #[serde(default)]
    pub from: u64,
    /// Explicit positive page size.
    pub size: u32,
}

/// Arguments for one firewall policy rule.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FirewallRuleArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Policy UUID.
    pub policy_uuid: String,
    /// Scope: 'global' or 'zone'.
    pub scope: String,
    /// Rule UUID.
    pub rule_uuid: String,
}

/// Arguments for firewall policy rule groups list.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FirewallRuleGroupsListArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Policy UUID.
    pub policy_uuid: String,
    /// Scope: 'global' or 'zone'.
    pub scope: String,
    /// Zero-based offset.
    #[serde(default)]
    pub from: u64,
    /// Explicit positive page size.
    pub size: u32,
}

/// Arguments for firewall policy hierarchy.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FirewallHierarchyArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Policy UUID.
    pub policy_uuid: String,
    /// Scope: 'global' or 'zone'.
    pub scope: String,
}

/// Arguments for NAT policy rules list.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NatRulesListArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Policy ID.
    pub policy_id: String,
    /// Zero-based offset.
    #[serde(default)]
    pub from: u64,
    /// Explicit positive page size.
    pub size: u32,
}

/// Arguments for one NAT policy rule.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NatRuleArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Policy ID.
    pub policy_id: String,
    /// Rule ID.
    pub rule_id: String,
}

/// Arguments for NAT policy rule groups list.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NatRuleGroupsListArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Policy ID.
    pub policy_id: String,
    /// Zero-based offset.
    #[serde(default)]
    pub from: u64,
    /// Explicit positive page size.
    pub size: u32,
}

/// Arguments for NAT policy hierarchy.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NatHierarchyArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Policy ID.
    pub policy_id: String,
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

/// Arguments for listing IPsec profiles.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IpsecProfileListArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Zero-based offset.
    #[serde(default)]
    pub from: u64,
    /// Explicit positive page size.
    pub size: u32,
}

/// Arguments for one IPsec profile.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IpsecProfileArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// IPsec profile name.
    pub profile_name: String,
}

/// Arguments for listing tunnels.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TunnelListArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Zero-based offset.
    #[serde(default)]
    pub from: u64,
    /// Explicit positive page size.
    pub size: u32,
}

/// Arguments for one tunnel.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TunnelArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Tunnel ID.
    pub tunnel_id: String,
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
    /// Exact approved preview digest returned by prepare.
    pub expected_preview_digest: String,
    /// Optional external ticket or change reference.
    #[serde(default)]
    pub change_ref: Option<String>,
}

/// Arguments for discarding one terminal-but-unreconciled operation.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiscardOperationArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Operation identifier reported by the change-set state.
    pub operation_id: String,
    /// The operation's expected fingerprint, so a stale caller cannot clear an
    /// operation it has not read.
    pub expected_fingerprint: String,
}

/// Arguments for planning one object write.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrepareObjectArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Which mutation to plan.
    pub action: ObjectWriteAction,
    /// Allowlisted **writable** resource family.
    ///
    /// Narrower than the read catalog: most readable families have no
    /// validated write path.
    pub resource: WritableResource,
    /// Target object UUID. Required for update and delete, absent for create.
    #[serde(default)]
    pub uuid: Option<String>,
    /// Object definition. Required for create and update, absent for delete.
    #[serde(default)]
    pub body: Option<Value>,
}

/// Arguments for applying one approved object write.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApplyObjectArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Change-set identifier.
    pub change_set_id: String,
    /// Exact approved plan digest.
    pub expected_digest: String,
    /// Exact plan digest returned by prepare.
    pub expected_plan_digest: String,
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

/// Arguments for planning one NAT write.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrepareNatArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Which NAT mutation to plan.
    pub action: NatWriteOperation,
    /// Target policy ID. Required for all operations except CreatePolicy.
    #[serde(default)]
    pub policy_id: Option<String>,
    /// Target rule ID. Required for UpdateRule and DeleteRule.
    #[serde(default)]
    pub rule_id: Option<String>,
    /// Target rule group ID. Required for UpdateRuleGroup.
    #[serde(default)]
    pub group_id: Option<String>,
    /// Object definition. Required for create and update, absent for delete.
    #[serde(default)]
    pub body: Option<Value>,
}

/// Arguments for applying one approved NAT write.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApplyNatArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Change-set identifier.
    pub change_set_id: String,
    /// Exact approved plan digest.
    pub expected_digest: String,
    /// Exact plan digest returned by prepare.
    pub expected_plan_digest: String,
    /// Optional external ticket or change reference.
    #[serde(default)]
    pub change_ref: Option<String>,
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
        cancellation: CancellationToken,
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
        Ok(finish(audit, self.client.tenant_scope(&cancellation).await))
    }

    #[tool(
        name = "list_sdc_devices",
        description = "List managed SDC devices with bounded pagination."
    )]
    async fn list_sdc_devices(
        &self,
        Parameters(args): Parameters<ListArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
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
            Ok(page) => self.client.list_devices(page, &cancellation).await,
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
        cancellation: CancellationToken,
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
                .get_device(&args.device_uuid, &cancellation)
                .await,
        ))
    }

    #[tool(
        name = "list_sdc_config_versions",
        description = "List archived configuration versions for one device. Returns unbounded results; a device with a long archive may exceed max_response_bytes and fail."
    )]
    async fn list_sdc_config_versions(
        &self,
        Parameters(args): Parameters<DeviceArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "list_sdc_config_versions",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "list_sdc_config_versions", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish(
            audit,
            self.client
                .list_config_versions(&args.device_uuid, &cancellation)
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
        cancellation: CancellationToken,
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
                    .list_firewall_policies(page, &cancellation)
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
        cancellation: CancellationToken,
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
                .get_firewall_policy(&args.policy_id, &cancellation)
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
        cancellation: CancellationToken,
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
            Ok(page) => self.client.list_nat_policies(page, &cancellation).await,
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
        cancellation: CancellationToken,
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
                .get_nat_policy(&args.policy_id, &cancellation)
                .await,
        ))
    }

    #[tool(
        name = "list_sdc_firewall_rules",
        description = "List firewall policy rules with bounded pagination. Scope must be 'global' or 'zone'."
    )]
    async fn list_sdc_firewall_rules(
        &self,
        Parameters(args): Parameters<FirewallRulesListArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "list_sdc_firewall_rules",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "list_sdc_firewall_rules", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        let result = ListRequest::new(args.from, args.size, self.client.max_page_size())
            .map_err(SdcError::from);
        let result = match result {
            Ok(page) => {
                self.client
                    .list_firewall_rules(&args.policy_uuid, &args.scope, page, &cancellation)
                    .await
            }
            Err(error) => Err(error),
        };
        Ok(finish(audit, result))
    }

    #[tool(
        name = "get_sdc_firewall_rule",
        description = "Get one firewall policy rule by UUID. Scope must be 'global' or 'zone'."
    )]
    async fn get_sdc_firewall_rule(
        &self,
        Parameters(args): Parameters<FirewallRuleArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "get_sdc_firewall_rule",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "get_sdc_firewall_rule", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish(
            audit,
            self.client
                .get_firewall_rule(
                    &args.policy_uuid,
                    &args.scope,
                    &args.rule_uuid,
                    &cancellation,
                )
                .await,
        ))
    }

    #[tool(
        name = "list_sdc_firewall_rule_groups",
        description = "List firewall policy rule groups with bounded pagination. Scope must be 'global' or 'zone'."
    )]
    async fn list_sdc_firewall_rule_groups(
        &self,
        Parameters(args): Parameters<FirewallRuleGroupsListArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "list_sdc_firewall_rule_groups",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "list_sdc_firewall_rule_groups", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        let result = ListRequest::new(args.from, args.size, self.client.max_page_size())
            .map_err(SdcError::from);
        let result = match result {
            Ok(page) => {
                self.client
                    .list_firewall_rule_groups(&args.policy_uuid, &args.scope, page, &cancellation)
                    .await
            }
            Err(error) => Err(error),
        };
        Ok(finish(audit, result))
    }

    #[tool(
        name = "get_sdc_firewall_hierarchy",
        description = "Get firewall policy rule hierarchy showing rule groups and ordering. Scope must be 'global' or 'zone'."
    )]
    async fn get_sdc_firewall_hierarchy(
        &self,
        Parameters(args): Parameters<FirewallHierarchyArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "get_sdc_firewall_hierarchy",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "get_sdc_firewall_hierarchy", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish(
            audit,
            self.client
                .get_firewall_hierarchy(&args.policy_uuid, &args.scope, &cancellation)
                .await,
        ))
    }

    #[tool(
        name = "list_sdc_nat_rules",
        description = "List NAT policy rules with bounded pagination."
    )]
    async fn list_sdc_nat_rules(
        &self,
        Parameters(args): Parameters<NatRulesListArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "list_sdc_nat_rules",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "list_sdc_nat_rules", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        let result = ListRequest::new(args.from, args.size, self.client.max_page_size())
            .map_err(SdcError::from);
        let result = match result {
            Ok(page) => {
                self.client
                    .list_nat_rules(&args.policy_id, page, &cancellation)
                    .await
            }
            Err(error) => Err(error),
        };
        Ok(finish(audit, result))
    }

    #[tool(
        name = "get_sdc_nat_rule",
        description = "Get one NAT policy rule by ID."
    )]
    async fn get_sdc_nat_rule(
        &self,
        Parameters(args): Parameters<NatRuleArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "get_sdc_nat_rule",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "get_sdc_nat_rule", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish(
            audit,
            self.client
                .get_nat_rule(&args.policy_id, &args.rule_id, &cancellation)
                .await,
        ))
    }

    #[tool(
        name = "list_sdc_nat_rule_groups",
        description = "List NAT policy rule groups with bounded pagination."
    )]
    async fn list_sdc_nat_rule_groups(
        &self,
        Parameters(args): Parameters<NatRuleGroupsListArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "list_sdc_nat_rule_groups",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "list_sdc_nat_rule_groups", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        let result = ListRequest::new(args.from, args.size, self.client.max_page_size())
            .map_err(SdcError::from);
        let result = match result {
            Ok(page) => {
                self.client
                    .list_nat_rule_groups(&args.policy_id, page, &cancellation)
                    .await
            }
            Err(error) => Err(error),
        };
        Ok(finish(audit, result))
    }

    #[tool(
        name = "get_sdc_nat_hierarchy",
        description = "Get NAT policy rule hierarchy showing rule groups and ordering."
    )]
    async fn get_sdc_nat_hierarchy(
        &self,
        Parameters(args): Parameters<NatHierarchyArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "get_sdc_nat_hierarchy",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "get_sdc_nat_hierarchy", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish(
            audit,
            self.client
                .get_nat_hierarchy(&args.policy_id, &cancellation)
                .await,
        ))
    }

    #[tool(
        name = "list_sdc_nat_pools",
        description = "List SDC NAT pools with bounded pagination."
    )]
    async fn list_sdc_nat_pools(
        &self,
        Parameters(args): Parameters<ListArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "list_sdc_nat_pools",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "list_sdc_nat_pools", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        let result = ListRequest::new(args.from, args.size, self.client.max_page_size())
            .map_err(SdcError::from);
        let result = match result {
            Ok(page) => self.client.list_nat_pools(page, &cancellation).await,
            Err(error) => Err(error),
        };
        Ok(finish(audit, result))
    }

    #[tool(
        name = "list_sdc_device_groups",
        description = "List SDC device groups with bounded pagination. Optional `fields` applies the API's server-side projection; a group embeds its membership, so an unprojected list of large groups can exceed the response limit."
    )]
    async fn list_sdc_device_groups(
        &self,
        Parameters(args): Parameters<DeviceGroupListArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "list_sdc_device_groups",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "list_sdc_device_groups", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        let result = ListRequest::new(args.from, args.size, self.client.max_page_size())
            .map_err(SdcError::from);
        let result = match result {
            Ok(page) => {
                self.client
                    .list_device_groups(page, &args.fields, &cancellation)
                    .await
            }
            Err(error) => Err(error),
        };
        Ok(finish(audit, result))
    }

    #[tool(
        name = "get_sdc_device_group",
        description = "Get one SDC device group by UUID, including its member devices. Note that SDC does not currently support deploying policy to a device group: the pinned API marks the DEVICE_GROUP target type as not supported, future support."
    )]
    async fn get_sdc_device_group(
        &self,
        Parameters(args): Parameters<DeviceGroupArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "get_sdc_device_group",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "get_sdc_device_group", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish(
            audit,
            self.client
                .get_device_group(&args.group_uuid, &cancellation)
                .await,
        ))
    }

    #[tool(name = "get_sdc_nat_pool", description = "Get one SDC NAT pool by ID.")]
    async fn get_sdc_nat_pool(
        &self,
        Parameters(args): Parameters<NatPoolArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "get_sdc_nat_pool",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "get_sdc_nat_pool", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish(
            audit,
            self.client.get_nat_pool(&args.pool_id, &cancellation).await,
        ))
    }

    #[tool(
        name = "list_sdc_ca_certificates",
        description = "List CA certificates across all devices with bounded pagination."
    )]
    async fn list_sdc_ca_certificates(
        &self,
        Parameters(args): Parameters<CertificateListArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "list_sdc_ca_certificates",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "list_sdc_ca_certificates", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        let result = ListRequest::new(args.from, args.size, self.client.max_page_size())
            .map_err(SdcError::from);
        let result = match result {
            Ok(page) => self
                .client
                .list_ca_certificates(page, &cancellation)
                .await
                .and_then(project_ca_certificates),
            Err(error) => Err(error),
        };
        Ok(finish(audit, result))
    }

    #[tool(
        name = "list_sdc_local_certificates",
        description = "List local certificates across all devices with bounded pagination."
    )]
    async fn list_sdc_local_certificates(
        &self,
        Parameters(args): Parameters<CertificateListArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "list_sdc_local_certificates",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "list_sdc_local_certificates", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        let result = ListRequest::new(args.from, args.size, self.client.max_page_size())
            .map_err(SdcError::from);
        let result = match result {
            Ok(page) => self
                .client
                .list_local_certificates(page, &cancellation)
                .await
                .and_then(project_local_certificates),
            Err(error) => Err(error),
        };
        Ok(finish(audit, result))
    }

    #[tool(
        name = "list_sdc_device_ca_certificates",
        description = "List CA certificates for one device with bounded pagination."
    )]
    async fn list_sdc_device_ca_certificates(
        &self,
        Parameters(args): Parameters<DeviceCertificateListArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "list_sdc_device_ca_certificates",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "list_sdc_device_ca_certificates", &args.tenant)
        {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        let result = ListRequest::new(args.from, args.size, self.client.max_page_size())
            .map_err(SdcError::from);
        let result = match result {
            Ok(page) => self
                .client
                .list_device_ca_certificates(&args.device_uuid, page, &cancellation)
                .await
                .and_then(project_ca_certificates),
            Err(error) => Err(error),
        };
        Ok(finish(audit, result))
    }

    #[tool(
        name = "list_sdc_device_local_certificates",
        description = "List local certificates for one device with bounded pagination."
    )]
    async fn list_sdc_device_local_certificates(
        &self,
        Parameters(args): Parameters<DeviceCertificateListArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "list_sdc_device_local_certificates",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) =
            self.authorize(caller, "list_sdc_device_local_certificates", &args.tenant)
        {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        let result = ListRequest::new(args.from, args.size, self.client.max_page_size())
            .map_err(SdcError::from);
        let result = match result {
            Ok(page) => self
                .client
                .list_device_local_certificates(&args.device_uuid, page, &cancellation)
                .await
                .and_then(project_local_certificates),
            Err(error) => Err(error),
        };
        Ok(finish(audit, result))
    }

    #[tool(
        name = "list_sdc_licenses",
        description = "List licenses for one device with bounded pagination."
    )]
    async fn list_sdc_licenses(
        &self,
        Parameters(args): Parameters<DeviceLicenseListArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "list_sdc_licenses",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "list_sdc_licenses", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        let result = ListRequest::new(args.from, args.size, self.client.max_page_size())
            .map_err(SdcError::from);
        let result = match result {
            Ok(page) => self
                .client
                .list_licenses(&args.device_uuid, page, &cancellation)
                .await
                .and_then(project_licenses),
            Err(error) => Err(error),
        };
        Ok(finish(audit, result))
    }

    #[tool(
        name = "get_sdc_license",
        description = "Get one license by device UUID and license UUID."
    )]
    async fn get_sdc_license(
        &self,
        Parameters(args): Parameters<LicenseArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(caller, "get_sdc_license", "read", vec![args.tenant.clone()]);
        if let Err(error) = self.authorize(caller, "get_sdc_license", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish(
            audit,
            self.client
                .get_license(&args.device_uuid, &args.license_uuid, &cancellation)
                .await
                .and_then(project_license),
        ))
    }

    #[tool(
        name = "prepare_sdc_firewall_write",
        description = "Plan one firewall policy create, update, or delete and create a digest-bound change set. This does not write."
    )]
    async fn prepare_sdc_firewall_write(
        &self,
        Parameters(args): Parameters<PrepareFirewallArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "prepare_sdc_firewall_write",
            "prepare",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "prepare_sdc_firewall_write", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish(
            audit,
            self.changes
                .prepare_firewall_write(
                    owner(caller),
                    args.action,
                    args.uuid,
                    args.body.unwrap_or(Value::Null),
                    &cancellation,
                )
                .await,
        ))
    }

    #[tool(
        name = "apply_sdc_firewall_write",
        description = "Apply only an independently approved SDC firewall policy write, refusing it if the target changed since it was planned."
    )]
    async fn apply_sdc_firewall_write(
        &self,
        Parameters(args): Parameters<ApplyFirewallArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "apply_sdc_firewall_write",
            "apply",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "apply_sdc_firewall_write", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        let attribution = attribution(caller, args.change_ref);
        Ok(finish(
            audit,
            self.changes
                .apply_firewall_write(
                    args.change_set_id,
                    owner(caller),
                    args.expected_digest,
                    args.expected_plan_digest,
                    &attribution,
                    &cancellation,
                )
                .await,
        ))
    }

    #[tool(
        name = "prepare_sdc_license_write",
        description = "Plan one license or certificate install/delete and create a digest-bound change set. This does not write."
    )]
    async fn prepare_sdc_license_write(
        &self,
        Parameters(args): Parameters<PrepareLicenseArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "prepare_sdc_license_write",
            "prepare",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "prepare_sdc_license_write", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        // The projected view, not the raw result: `before` is captured from the
        // same endpoints the read tools serve, and returning it verbatim would
        // disclose through the write tools what the read tools drop (#55).
        Ok(finish(
            audit,
            self.changes
                .prepare_license_write(
                    owner(caller),
                    args.action,
                    args.device_uuid,
                    args.body,
                    &cancellation,
                )
                .await
                .and_then(|result| result.caller_view()),
        ))
    }

    #[tool(
        name = "apply_sdc_license_write",
        description = "Apply only an independently approved SDC license/certificate write."
    )]
    async fn apply_sdc_license_write(
        &self,
        Parameters(args): Parameters<ApplyLicenseArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "apply_sdc_license_write",
            "apply",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "apply_sdc_license_write", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        let attribution = attribution(caller, args.change_ref);
        Ok(finish(
            audit,
            self.changes
                .apply_license_write(
                    args.change_set_id,
                    owner(caller),
                    args.expected_digest,
                    args.expected_plan_digest,
                    &attribution,
                    &cancellation,
                )
                .await
                // Same reason as prepare: the plan carries the captured
                // before-state, and the caller sees it projected (#55).
                .and_then(|result| result.caller_view()),
        ))
    }

    #[tool(
        name = "prepare_sdc_device_inventory_sync",
        description = "Plan a device INVENTORY sync and create a digest-bound change set. SDC re-reads each device's inventory and updates its own model; no device is written. This does NOT reconcile configuration drift: device_config_state (OUT_OF_BAND_CHANGED) is left untouched. This does not run the sync."
    )]
    async fn prepare_sdc_device_inventory_sync(
        &self,
        Parameters(args): Parameters<PrepareDeviceInventorySyncArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "prepare_sdc_device_inventory_sync",
            "prepare",
            vec![args.tenant.clone()],
        );
        if let Err(error) =
            self.authorize(caller, "prepare_sdc_device_inventory_sync", &args.tenant)
        {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish(
            audit,
            self.changes
                .prepare_device_sync(owner(caller), args.device_uuids, &cancellation)
                .await,
        ))
    }

    #[tool(
        name = "apply_sdc_device_inventory_sync",
        description = "Run only an independently approved SDC device inventory sync. Reconciles inventory state, not configuration."
    )]
    async fn apply_sdc_device_inventory_sync(
        &self,
        Parameters(args): Parameters<ApplyDeviceInventorySyncArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "apply_sdc_device_inventory_sync",
            "apply",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "apply_sdc_device_inventory_sync", &args.tenant)
        {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        let attribution = attribution(caller, args.change_ref);
        Ok(finish(
            audit,
            self.changes
                .apply_device_sync(
                    args.change_set_id,
                    owner(caller),
                    args.expected_digest,
                    args.expected_plan_digest,
                    &attribution,
                    &cancellation,
                )
                .await,
        ))
    }

    #[tool(
        name = "get_sdc_firewall_policy_state",
        description = "Retrieve the operational state of a firewall policy by its UUID. Returns deployment state and optionally per-device states."
    )]
    async fn get_sdc_firewall_policy_state(
        &self,
        Parameters(args): Parameters<FirewallPolicyStateArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "get_sdc_firewall_policy_state",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "get_sdc_firewall_policy_state", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish(
            audit,
            self.client
                .get_firewall_policy_state(
                    &args.policy_uuid,
                    args.include_assigned_devices,
                    &cancellation,
                )
                .await,
        ))
    }

    #[tool(
        name = "list_sdc_resources",
        description = "List one allowlisted SDC resource collection. The `resource` enum in this schema is the catalog of available families."
    )]
    async fn list_sdc_resources(
        &self,
        Parameters(args): Parameters<ResourceListArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
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
                    .list_resource(args.resource, page, &args.fields, &cancellation)
                    .await
            }
            Err(error) => Err(error),
        };
        Ok(finish(audit, result))
    }

    #[tool(
        name = "get_sdc_resource",
        description = "Get one object from an allowlisted SDC resource collection by UUID. The `resource` enum in this schema is the catalog of available families."
    )]
    async fn get_sdc_resource(
        &self,
        Parameters(args): Parameters<ResourceArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
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
                .get_resource(args.resource, &args.uuid, &cancellation)
                .await,
        ))
    }

    #[tool(
        name = "list_sdc_ipsec_profiles",
        description = "List IPsec profiles with bounded pagination. This is a /api/v2/ endpoint."
    )]
    async fn list_sdc_ipsec_profiles(
        &self,
        Parameters(args): Parameters<IpsecProfileListArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "list_sdc_ipsec_profiles",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "list_sdc_ipsec_profiles", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        let result = ListRequest::new(args.from, args.size, self.client.max_page_size())
            .map_err(SdcError::from);
        let result = match result {
            Ok(page) => self.client.list_ipsec_profiles(page, &cancellation).await,
            Err(error) => Err(error),
        };
        Ok(finish(audit, result))
    }

    #[tool(
        name = "get_sdc_ipsec_profile",
        description = "Get one IPsec profile by name. Profiles are addressed by profile_name, not UUID."
    )]
    async fn get_sdc_ipsec_profile(
        &self,
        Parameters(args): Parameters<IpsecProfileArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "get_sdc_ipsec_profile",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "get_sdc_ipsec_profile", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish(
            audit,
            self.client
                .get_ipsec_profile(&args.profile_name, &cancellation)
                .await,
        ))
    }

    #[tool(
        name = "list_sdc_tunnels",
        description = "List tunnels with bounded pagination. Tunnels are read-only derived state."
    )]
    async fn list_sdc_tunnels(
        &self,
        Parameters(args): Parameters<TunnelListArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "list_sdc_tunnels",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "list_sdc_tunnels", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        let result = ListRequest::new(args.from, args.size, self.client.max_page_size())
            .map_err(SdcError::from);
        let result = match result {
            Ok(page) => self.client.list_tunnels(page, &cancellation).await,
            Err(error) => Err(error),
        };
        Ok(finish(audit, result))
    }

    #[tool(
        name = "get_sdc_tunnel",
        description = "Get one tunnel by ID. Tunnels are read-only derived state."
    )]
    async fn get_sdc_tunnel(
        &self,
        Parameters(args): Parameters<TunnelArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(caller, "get_sdc_tunnel", "read", vec![args.tenant.clone()]);
        if let Err(error) = self.authorize(caller, "get_sdc_tunnel", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish(
            audit,
            self.client.get_tunnel(&args.tunnel_id, &cancellation).await,
        ))
    }

    #[tool(
        name = "get_sdc_tunnel_count",
        description = "Get tunnel status count. Returns counts by status."
    )]
    async fn get_sdc_tunnel_count(
        &self,
        Parameters(args): Parameters<TenantArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "get_sdc_tunnel_count",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "get_sdc_tunnel_count", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish(audit, self.client.tunnel_count(&cancellation).await))
    }

    #[tool(
        name = "get_sdc_preview_status",
        description = "Read one SDC policy preview job status."
    )]
    async fn get_sdc_preview_status(
        &self,
        Parameters(args): Parameters<JobArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
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
                .preview_status(&args.job_id, &cancellation)
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
        cancellation: CancellationToken,
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
            self.client.deploy_status(&args.job_id, &cancellation).await,
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
        cancellation: CancellationToken,
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
                .preview_device_result(&args.job_id, &args.device_id, &cancellation)
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
        cancellation: CancellationToken,
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
                .deploy_device_result(&args.job_id, &args.device_id, &cancellation)
                .await,
        ))
    }

    #[tool(
        name = "prepare_sdc_policy_deploy",
        description = "Preview SDC policy target changes and create a digest-bound change set. This does not deploy. A deploy has been observed committing a deletion its preview did not disclose (#66), so treat the preview as a lower bound on what will change, not a complete statement of it."
    )]
    async fn prepare_sdc_policy_deploy(
        &self,
        Parameters(args): Parameters<PrepareArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
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
                .prepare(owner(caller), args.policies, &cancellation)
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
        cancellation: CancellationToken,
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
                    &cancellation,
                )
                .await,
        ))
    }

    #[tool(
        name = "prepare_sdc_object_write",
        description = "Plan one address, application, service, or scheduler write and create a digest-bound change set. This does not write."
    )]
    async fn prepare_sdc_object_write(
        &self,
        Parameters(args): Parameters<PrepareObjectArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "prepare_sdc_object_write",
            "prepare",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "prepare_sdc_object_write", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish(
            audit,
            self.changes
                .prepare_object_write(
                    owner(caller),
                    args.action,
                    args.resource,
                    args.uuid,
                    args.body.unwrap_or(Value::Null),
                    &cancellation,
                )
                .await,
        ))
    }

    #[tool(
        name = "apply_sdc_object_write",
        description = "Apply only an independently approved SDC object write, refusing it if the target changed since it was planned."
    )]
    async fn apply_sdc_object_write(
        &self,
        Parameters(args): Parameters<ApplyObjectArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "apply_sdc_object_write",
            "apply",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "apply_sdc_object_write", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        let attribution = attribution(caller, args.change_ref);
        Ok(finish(
            audit,
            self.changes
                .apply_object_write(
                    args.change_set_id,
                    owner(caller),
                    args.expected_digest,
                    args.expected_plan_digest,
                    &attribution,
                    &cancellation,
                )
                .await,
        ))
    }

    #[tool(
        name = "prepare_sdc_nat_write",
        description = "Plan one NAT policy, rule, or rule-group write and create a digest-bound change set. This does not write."
    )]
    async fn prepare_sdc_nat_write(
        &self,
        Parameters(args): Parameters<PrepareNatArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "prepare_sdc_nat_write",
            "prepare",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "prepare_sdc_nat_write", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish(
            audit,
            self.changes
                .prepare_nat_write(
                    owner(caller),
                    args.action,
                    args.policy_id,
                    args.rule_id,
                    args.group_id,
                    args.body.unwrap_or(Value::Null),
                    &cancellation,
                )
                .await,
        ))
    }

    #[tool(
        name = "apply_sdc_nat_write",
        description = "Apply only an independently approved SDC NAT write, refusing it if the target changed since it was planned."
    )]
    async fn apply_sdc_nat_write(
        &self,
        Parameters(args): Parameters<ApplyNatArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "apply_sdc_nat_write",
            "apply",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "apply_sdc_nat_write", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        let attribution = attribution(caller, args.change_ref);
        Ok(finish(
            audit,
            self.changes
                .apply_nat_write(
                    args.change_set_id,
                    owner(caller),
                    args.expected_digest,
                    args.expected_plan_digest,
                    &attribution,
                    &cancellation,
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

    #[tool(
        name = "discard_sdc_operation",
        description = "Discard one terminal-but-unreconciled SDC operation so applies are unblocked. A failed deploy otherwise refuses every later apply on the tenant. Requires the operation's expected fingerprint, and only its owner may discard it. The operation remains visible in change-set state."
    )]
    async fn discard_sdc_operation(
        &self,
        Parameters(args): Parameters<DiscardOperationArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "discard_sdc_operation",
            "discard",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "discard_sdc_operation", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish(
            audit,
            self.changes
                .discard(
                    args.operation_id,
                    owner(caller),
                    args.expected_fingerprint,
                    &cancellation,
                )
                .await,
        ))
    }

    #[tool(
        name = "get_sdc_change_set_details",
        description = "Retrieve the prepared change from a change set, including preview_digest. \
                       Use this to recover the preview digest when the original PrepareResult was \
                       not persisted after prepare_sdc_policy_deploy."
    )]
    async fn get_sdc_change_set_details(
        &self,
        Parameters(args): Parameters<ChangeSetArgs>,
        extensions: Extensions,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "get_sdc_change_set_details",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "get_sdc_change_set_details", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish(
            audit,
            self.changes.prepared_change(args.change_set_id).await,
        ))
    }
}

/// Wrap a filtered tool list in the result shape a 2026-07-28 client accepts.
///
/// `ListToolsResult::with_all_items` leaves `ttl_ms` and `cache_scope` unset and
/// both are omitted on the wire; a client on that protocol validates the result
/// and rejects it, which surfaces as "tools fetch failed" against a server that
/// is healthy and answering in milliseconds. Servers that do not override
/// `list_tools` get these from rmcp's generated handler — this one filters by
/// scope, so it supplies them itself.
///
/// Gated on the negotiated version exactly as rmcp does: the fields belong to
/// 2026-07-28 and later, and a strict legacy client rejects what it did not
/// negotiate.
///
/// `private` where rmcp's unfiltered list says `public`, because this list is
/// per token: a cache keyed only on the URL must not serve one caller's
/// permitted surface to another.
fn listed_tools(tools: Vec<rmcp::model::Tool>, cache_hints: bool) -> ListToolsResult {
    let listed = ListToolsResult::with_all_items(tools);
    if cache_hints {
        listed
            .with_ttl_ms(0)
            .with_cache_scope(rmcp::model::CacheScope::Private)
    } else {
        listed
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
        // `with_all_items` leaves `ttl_ms` and `cache_scope` unset, and both
        // are omitted on the wire. A 2026-07-28 client validates the tools/list
        // result and rejects one without them — reported as "tools fetch
        // failed" against a server that is otherwise healthy and fast. Servers
        // that do not override `list_tools` get these from rmcp's generated
        // handler; this one filters by scope, so it supplies them itself.
        //
        // `private`: the list is per token, so a cache keyed only on the URL
        // must not serve one caller's surface to another.
        let cache_hints = context
            .protocol_version()
            .is_some_and(|version| version >= rmcp::model::ProtocolVersion::V_2026_07_28);
        Ok(listed_tools(
            filter_tools_for_scope(
                self.tool_router.list_all(),
                caller_from_extensions::<NoGrant>(&context.extensions),
                WRITE_TOOLS,
            ),
            cache_hints,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mecmcp_auth::{ActorType, ScopeSet};
    use std::collections::BTreeSet;

    #[test]
    fn known_tools_matches_the_registered_router_exactly() {
        // `KNOWN_TOOLS` is what `token_cmd` validates minted token scopes against.
        // If it drifts from the router, a real tool becomes unmintable and a
        // deleted one stays mintable, both without any other test failing.
        let registered = SdcHandler::sdc_tool_router()
            .list_all()
            .iter()
            .map(|tool| tool.name.to_string())
            .collect::<BTreeSet<_>>();
        let known = KNOWN_TOOLS
            .iter()
            .map(|tool| (*tool).to_owned())
            .collect::<BTreeSet<_>>();
        assert_eq!(registered, known);
    }

    #[test]
    fn every_write_tool_is_a_registered_tool() {
        let known = KNOWN_TOOLS.iter().copied().collect::<BTreeSet<_>>();
        for tool in WRITE_TOOLS {
            assert!(known.contains(tool), "{tool} is not a registered tool");
        }
    }

    fn caller(targets: ScopeSet, tools: ScopeSet) -> CallerCtx<NoGrant> {
        CallerCtx {
            token_name: "alice".to_owned(),
            client_name: None,
            model_id: None,
            session_id: None,
            devices: targets,
            tools,
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: ActorType::Human,
            request_id: uuid::Uuid::new_v4(),
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

    #[test]
    fn firewall_write_authorization_sabotage() {
        // Prove that firewall write tools enforce scope checks.
        // Without these checks, a token scoped for one tenant could
        // write to another tenant's policies.

        // Token scoped for firewall writes on tenant-a
        let scoped_firewall = caller(
            ScopeSet::Allowlist(vec!["tenant-a".to_owned()]),
            ScopeSet::Allowlist(vec![
                "prepare_sdc_firewall_write".to_owned(),
                "apply_sdc_firewall_write".to_owned(),
            ]),
        );

        // Allowed: tenant-a with firewall write tools
        assert!(
            authorize_request(
                Some(&scoped_firewall),
                "prepare_sdc_firewall_write",
                "tenant-a",
                "tenant-a"
            )
            .is_ok()
        );
        assert!(
            authorize_request(
                Some(&scoped_firewall),
                "apply_sdc_firewall_write",
                "tenant-a",
                "tenant-a"
            )
            .is_ok()
        );

        // Blocked: wrong tenant
        assert!(
            authorize_request(
                Some(&scoped_firewall),
                "prepare_sdc_firewall_write",
                "tenant-b",
                "tenant-a"
            )
            .is_err()
        );
        assert!(
            authorize_request(
                Some(&scoped_firewall),
                "apply_sdc_firewall_write",
                "tenant-b",
                "tenant-a"
            )
            .is_err()
        );

        // Token scoped for object writes only
        let scoped_object = caller(
            ScopeSet::Allowlist(vec!["tenant-a".to_owned()]),
            ScopeSet::Allowlist(vec![
                "prepare_sdc_object_write".to_owned(),
                "apply_sdc_object_write".to_owned(),
            ]),
        );

        // Blocked: wrong tool
        assert!(
            authorize_request(
                Some(&scoped_object),
                "prepare_sdc_firewall_write",
                "tenant-a",
                "tenant-a"
            )
            .is_err()
        );
        assert!(
            authorize_request(
                Some(&scoped_object),
                "apply_sdc_firewall_write",
                "tenant-a",
                "tenant-a"
            )
            .is_err()
        );

        // Unauthenticated: blocked for write tools
        assert!(
            authorize_request(None, "prepare_sdc_firewall_write", "tenant-a", "tenant-a").is_err()
        );
        assert!(
            authorize_request(None, "apply_sdc_firewall_write", "tenant-a", "tenant-a").is_err()
        );

        // Read tool accessible without auth
        assert!(
            authorize_request(
                None,
                "get_sdc_firewall_policy_state",
                "tenant-a",
                "tenant-a"
            )
            .is_ok()
        );
    }

    #[test]
    fn nat_write_tools_require_authentication() {
        // Unauthenticated calls must be rejected
        assert!(
            authorize_request(None, "prepare_sdc_nat_write", "tenant-a", "tenant-a").is_err(),
            "prepare_sdc_nat_write must require authentication"
        );
        assert!(
            authorize_request(None, "apply_sdc_nat_write", "tenant-a", "tenant-a").is_err(),
            "apply_sdc_nat_write must require authentication"
        );
    }

    #[test]
    fn nat_write_tools_enforce_scope_boundaries() {
        // Token scoped to prepare_sdc_nat_write only
        let prepare_only = caller(
            ScopeSet::Allowlist(vec!["tenant-a".to_owned()]),
            ScopeSet::Allowlist(vec!["prepare_sdc_nat_write".to_owned()]),
        );

        // Can prepare but not apply
        assert!(
            authorize_request(
                Some(&prepare_only),
                "prepare_sdc_nat_write",
                "tenant-a",
                "tenant-a"
            )
            .is_ok(),
            "prepare_sdc_nat_write with correct scope must succeed"
        );
        assert!(
            authorize_request(
                Some(&prepare_only),
                "apply_sdc_nat_write",
                "tenant-a",
                "tenant-a"
            )
            .is_err(),
            "apply_sdc_nat_write without correct scope must fail"
        );

        // Token scoped to apply_sdc_nat_write only
        let apply_only = caller(
            ScopeSet::Allowlist(vec!["tenant-a".to_owned()]),
            ScopeSet::Allowlist(vec!["apply_sdc_nat_write".to_owned()]),
        );

        // Can apply but not prepare
        assert!(
            authorize_request(
                Some(&apply_only),
                "apply_sdc_nat_write",
                "tenant-a",
                "tenant-a"
            )
            .is_ok(),
            "apply_sdc_nat_write with correct scope must succeed"
        );
        assert!(
            authorize_request(
                Some(&apply_only),
                "prepare_sdc_nat_write",
                "tenant-a",
                "tenant-a"
            )
            .is_err(),
            "prepare_sdc_nat_write without correct scope must fail"
        );

        // Wrong tenant must fail
        assert!(
            authorize_request(
                Some(&prepare_only),
                "prepare_sdc_nat_write",
                "tenant-b",
                "tenant-a"
            )
            .is_err(),
            "NAT write with wrong tenant must fail"
        );
    }
}

#[cfg(test)]
mod tools_list_cache_tests {
    use super::listed_tools;

    /// mecmcp: a 2026-07-28 client rejects a tools/list without these, and the
    /// failure reads as an unreachable server rather than a malformed reply.
    #[test]
    fn a_modern_client_gets_a_private_cache_descriptor() {
        let listed = listed_tools(Vec::new(), true);
        assert_eq!(
            listed.ttl_ms,
            Some(0),
            "a 2026-07-28 client rejects a tools/list without ttlMs"
        );
        assert_eq!(
            listed.cache_scope,
            Some(rmcp::model::CacheScope::Private),
            "the list is filtered per token, so it must not be shared"
        );
    }

    /// The fields are not part of the older result shape, and a strict legacy
    /// client rejects what it did not negotiate.
    #[test]
    fn a_legacy_client_gets_no_cache_descriptor() {
        let listed = listed_tools(Vec::new(), false);
        assert_eq!(listed.ttl_ms, None);
        assert_eq!(listed.cache_scope, None);
    }
}
