//! Security Director Cloud domain client and change-control adapter.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod catalog;
mod change;
mod client;
mod compat;
mod config;
mod models;
mod prepared;

pub use catalog::ResourceKind;
pub use change::{ApplyResult, ChangeManager, PrepareResult, SdcTransaction, ValidationReport};
pub use client::{SdcClient, SdcError};
pub use config::{AuthScheme, SdcConfig};
pub use models::{
    DeployRequest, DeploymentStatus, DeviceDeploymentStatus, DeviceStatusEntry, JobStatus,
    ListRequest, ListRequestError, PolicyEntry, PolicyOperation, PolicyType, PreviewRequest,
    Target, TargetType, TenantScope,
};
pub use prepared::{SdcPreparedChange, SdcPreparedTarget};
