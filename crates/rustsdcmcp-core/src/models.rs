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
///
/// SDC is a management plane whose API adds states over time. An unrecognized
/// value is preserved verbatim rather than rejected, so a vendor-side addition
/// degrades one classification instead of failing every read tool that returns
/// a job status. It is never treated as terminal or successful.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeploymentStatus {
    /// SDC could not classify the operation.
    Unknown,
    /// Queued but not started.
    Pending,
    /// Work is in progress.
    InProgress,
    /// All targets completed.
    Completed,
    /// Some targets failed.
    PartialSuccess,
    /// All targets failed.
    Failed,
    /// A state absent from the pinned OpenAPI document, kept verbatim.
    Unrecognized(String),
}

impl DeploymentStatus {
    /// Exact wire value from the pinned OpenAPI document.
    #[must_use]
    pub fn as_wire(&self) -> &str {
        match self {
            Self::Unknown => "DEPLOY_STATUS_UNKNOWN",
            Self::Pending => "PENDING",
            Self::InProgress => "IN_PROGRESS",
            Self::Completed => "COMPLETED",
            Self::PartialSuccess => "PARTIAL_SUCCESS",
            Self::Failed => "FAILED",
            Self::Unrecognized(value) => value,
        }
    }

    fn from_wire(value: &str) -> Self {
        match value {
            "DEPLOY_STATUS_UNKNOWN" => Self::Unknown,
            "PENDING" => Self::Pending,
            "IN_PROGRESS" => Self::InProgress,
            "COMPLETED" => Self::Completed,
            "PARTIAL_SUCCESS" => Self::PartialSuccess,
            "FAILED" => Self::Failed,
            other => Self::Unrecognized(other.to_owned()),
        }
    }

    /// Whether SDC declares this state terminal.
    ///
    /// An unrecognized state is not terminal: polling continues to its
    /// deadline and reports an indeterminate outcome rather than inventing a
    /// verdict for a state this build cannot classify.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::PartialSuccess | Self::Failed)
    }

    /// Whether every target completed successfully.
    #[must_use]
    pub fn succeeded(&self) -> bool {
        matches!(self, Self::Completed)
    }
}

impl Serialize for DeploymentStatus {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_wire())
    }
}

impl<'de> Deserialize<'de> for DeploymentStatus {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::from_wire(&String::deserialize(deserializer)?))
    }
}

/// Per-device deployment state documented by SDC.
///
/// Preserves unrecognized values for the same reason as [`DeploymentStatus`]:
/// one device reporting a state this build predates must not fail the whole
/// job-status read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceDeploymentStatus {
    /// Unknown state.
    Unknown,
    /// Work is in progress.
    InProgress,
    /// Work completed.
    Completed,
    /// Work failed.
    Failed,
    /// Work is pending.
    Pending,
    /// Target was skipped.
    Skipped,
    /// Target failure was explicitly ignored by SDC.
    IgnoredFailure,
    /// A state absent from the pinned OpenAPI document, kept verbatim.
    Unrecognized(String),
}

impl DeviceDeploymentStatus {
    /// Exact wire value from the pinned OpenAPI document.
    #[must_use]
    pub fn as_wire(&self) -> &str {
        match self {
            Self::Unknown => "DEVICE_STATUS_UNKNOWN",
            Self::InProgress => "DEVICE_STATUS_IN_PROGRESS",
            Self::Completed => "DEVICE_STATUS_COMPLETED",
            Self::Failed => "DEVICE_STATUS_FAILED",
            Self::Pending => "DEVICE_STATUS_PENDING",
            Self::Skipped => "DEVICE_STATUS_SKIPPED",
            Self::IgnoredFailure => "DEVICE_STATUS_IGNORED_FAILURE",
            Self::Unrecognized(value) => value,
        }
    }

    fn from_wire(value: &str) -> Self {
        match value {
            "DEVICE_STATUS_UNKNOWN" => Self::Unknown,
            "DEVICE_STATUS_IN_PROGRESS" => Self::InProgress,
            "DEVICE_STATUS_COMPLETED" => Self::Completed,
            "DEVICE_STATUS_FAILED" => Self::Failed,
            "DEVICE_STATUS_PENDING" => Self::Pending,
            "DEVICE_STATUS_SKIPPED" => Self::Skipped,
            "DEVICE_STATUS_IGNORED_FAILURE" => Self::IgnoredFailure,
            other => Self::Unrecognized(other.to_owned()),
        }
    }
}

impl Serialize for DeviceDeploymentStatus {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_wire())
    }
}

impl<'de> Deserialize<'de> for DeviceDeploymentStatus {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::from_wire(&String::deserialize(deserializer)?))
    }
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

/// NAT write operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NatWriteOperation {
    /// Create NAT policy.
    CreatePolicy,
    /// Update NAT policy.
    UpdatePolicy,
    /// Delete NAT policy.
    DeletePolicy,
    /// Create NAT rule.
    CreateRule,
    /// Update NAT rule.
    UpdateRule,
    /// Delete NAT rule.
    DeleteRule,
    /// Create NAT rule group.
    CreateRuleGroup,
    /// Update NAT rule group.
    UpdateRuleGroup,
}
