//! Typed SDC request and asynchronous-job models.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Bounded SDC list request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListRequest {
    /// Zero-based result offset.
    pub from: u64,
    /// Explicit positive result count.
    pub size: u32,
}

impl ListRequest {
    /// Construct a page under the configured maximum.
    ///
    /// # Errors
    ///
    /// Refuses `size=0`, which SDC interprets as an unbounded response.
    pub fn new(from: u64, size: u32, max_size: u32) -> Result<Self, ListRequestError> {
        if max_size == 0 || size == 0 || size > max_size {
            return Err(ListRequestError { max_size });
        }
        Ok(Self { from, size })
    }

    /// Exact SDC `from` and `size` query pairs.
    #[must_use]
    pub fn query_pairs(self) -> Vec<(String, String)> {
        vec![
            ("from".to_owned(), self.from.to_string()),
            ("size".to_owned(), self.size.to_string()),
        ]
    }
}

/// Invalid bounded SDC page request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("page size must be between 1 and {max_size}")]
pub struct ListRequestError {
    /// Configured maximum page size.
    pub max_size: u32,
}

/// Policy family accepted by batch preview and deploy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyType {
    /// Firewall security policy.
    Firewall,
    /// NAT policy.
    Nat,
}

/// SDC deployment target type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TargetType {
    /// One device UUID.
    Device,
    /// One device-group UUID.
    DeviceGroup,
}

/// One SDC policy operation target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Target {
    /// Device or device-group identifier.
    pub target_id: String,
    /// Target family.
    pub target_type: TargetType,
}

impl Target {
    /// Construct a device target.
    #[must_use]
    pub fn device(identifier: impl Into<String>) -> Self {
        Self {
            target_id: identifier.into(),
            target_type: TargetType::Device,
        }
    }
}

/// Exact `PolicyOperationEntry` from the pinned OpenAPI document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyOperation {
    /// Policy UUID.
    pub policy_id: String,
    /// Policy family.
    pub policy_type: PolicyType,
    /// Targets to deploy.
    #[serde(default)]
    pub deploy_targets: Vec<Target>,
    /// Targets to undeploy.
    #[serde(default)]
    pub undeploy_targets: Vec<Target>,
}

/// Exact batch preview request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewRequest {
    /// Policies and target operations to preview.
    pub policies: Vec<PolicyOperation>,
}

/// Policy reference accepted by batch deploy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyEntry {
    /// Policy UUID.
    pub policy_id: String,
    /// Policy family.
    pub policy_type: PolicyType,
}

/// Exact batch deploy request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeployRequest {
    /// Policies whose current assignments SDC should deploy.
    pub policies: Vec<PolicyEntry>,
}

impl From<&PreviewRequest> for DeployRequest {
    fn from(preview: &PreviewRequest) -> Self {
        Self {
            policies: preview
                .policies
                .iter()
                .map(|policy| PolicyEntry {
                    policy_id: policy.policy_id.clone(),
                    policy_type: policy.policy_type,
                })
                .collect(),
        }
    }
}

/// Tenant identity returned by `/api/v2/tenant/tenant-id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantScope {
    /// Tenant UUID bound to the credential.
    pub tenant_id: String,
}

/// Overall preview/deploy state documented by SDC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeploymentStatus {
    /// SDC could not classify the operation.
    #[serde(rename = "DEPLOY_STATUS_UNKNOWN")]
    Unknown,
    /// Queued but not started.
    #[serde(rename = "PENDING")]
    Pending,
    /// Work is in progress.
    #[serde(rename = "IN_PROGRESS")]
    InProgress,
    /// All targets completed.
    #[serde(rename = "COMPLETED")]
    Completed,
    /// Some targets failed.
    #[serde(rename = "PARTIAL_SUCCESS")]
    PartialSuccess,
    /// All targets failed.
    #[serde(rename = "FAILED")]
    Failed,
}

impl DeploymentStatus {
    /// Whether SDC declares this state terminal.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::PartialSuccess | Self::Failed)
    }

    /// Whether every target completed successfully.
    #[must_use]
    pub const fn succeeded(self) -> bool {
        matches!(self, Self::Completed)
    }
}

/// Per-device deployment state documented by SDC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceDeploymentStatus {
    /// Unknown state.
    #[serde(rename = "DEVICE_STATUS_UNKNOWN")]
    Unknown,
    /// Work is in progress.
    #[serde(rename = "DEVICE_STATUS_IN_PROGRESS")]
    InProgress,
    /// Work completed.
    #[serde(rename = "DEVICE_STATUS_COMPLETED")]
    Completed,
    /// Work failed.
    #[serde(rename = "DEVICE_STATUS_FAILED")]
    Failed,
    /// Work is pending.
    #[serde(rename = "DEVICE_STATUS_PENDING")]
    Pending,
    /// Target was skipped.
    #[serde(rename = "DEVICE_STATUS_SKIPPED")]
    Skipped,
    /// Target failure was explicitly ignored by SDC.
    #[serde(rename = "DEVICE_STATUS_IGNORED_FAILURE")]
    IgnoredFailure,
}

/// Per-device entry in a preview/deploy status response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceStatusEntry {
    /// Device UUID.
    pub device_id: String,
    /// Device display name.
    #[serde(default)]
    pub device_name: String,
    /// Device-level status.
    pub status: DeviceDeploymentStatus,
    /// SDC status detail.
    #[serde(default)]
    pub message: String,
}

/// Shared shape of preview and deploy status responses.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JobStatus {
    /// Overall status.
    pub status: DeploymentStatus,
    /// Per-device statuses.
    #[serde(default)]
    pub device_deployment_status: Vec<DeviceStatusEntry>,
    /// SDC status detail.
    #[serde(default)]
    pub message: String,
    /// Preview identifier, when this is a preview.
    #[serde(default)]
    pub preview_id: Option<String>,
    /// Deploy identifier, when this is a deploy.
    #[serde(default)]
    pub deploy_id: Option<String>,
}

/// Preview submission response.
#[derive(Debug, Deserialize)]
pub(crate) struct PreviewResponse {
    pub(crate) preview_id: String,
}

/// Deploy submission response.
#[derive(Debug, Deserialize)]
pub(crate) struct DeployResponse {
    pub(crate) deploy_id: String,
}
