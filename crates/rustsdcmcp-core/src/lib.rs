//! Security Director Cloud domain client and change-control adapter.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod catalog;
mod change;
mod client;
mod config;
mod models;
mod object_write;
mod prepared;

pub use catalog::ResourceKind;
pub use change::{
    ApplyResult, ChangeManager, ObjectApplyResult, ObjectPrepareResult, PrepareResult,
    SdcTransaction, ValidationReport,
};
pub use client::{SdcClient, SdcError};
pub use config::{AuthScheme, SdcConfig};
pub use models::{
    DeployRequest, DeploymentStatus, DeviceDeploymentStatus, DeviceStatusEntry, JobStatus,
    ListRequest, ListRequestError, PolicyEntry, PolicyOperation, PolicyType, PreviewRequest,
    Target, TargetType, TenantScope,
};
pub use object_write::{
    ObjectValidationReport, ObjectWriteAction, SdcObjectTransaction, SdcPreparedObjectWrite,
};
pub use prepared::{SdcPreparedChange, SdcPreparedTarget};
