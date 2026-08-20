//! Security Director Cloud domain client and change-control adapter.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod catalog;
mod change;
mod client;
mod config;
mod device_sync;
mod firewall_write;
mod license_write;
mod models;
mod nat_write;
mod object_write;
mod prepared;
mod projection;

pub use catalog::{ResourceKind, WritableResource};
pub use change::{
    ApplyResult, ChangeManager, NatApplyResult, NatPrepareResult, ObjectApplyResult,
    ObjectPrepareResult, PrepareResult, SdcTransaction, ValidationReport,
};
pub use client::{SdcClient, SdcError};
pub use config::{AuthScheme, SdcConfig};
pub use device_sync::SdcPreparedDeviceSync;
pub use firewall_write::{
    FirewallApplyResult, FirewallPrepareResult, FirewallValidationReport, FirewallWriteOperation,
    SdcFirewallTransaction, SdcPreparedFirewallWrite,
};
pub use license_write::{
    LicenseApplyResult, LicensePrepareResult, LicenseValidationReport, LicenseWriteOperation,
    SdcLicenseTransaction, SdcPreparedLicenseWrite,
};
pub use models::{
    DeployRequest, DeploymentStatus, DeviceDeploymentStatus, DeviceStatusEntry, JobStatus,
    ListRequest, ListRequestError, NatWriteOperation, PolicyEntry, PolicyOperation, PolicyType,
    PreviewRequest, Target, TargetType, TenantScope, validate_deploy_targets,
};
pub use nat_write::{NatValidationReport, SdcNatTransaction, SdcPreparedNatWrite};
pub use object_write::{
    ObjectValidationReport, ObjectWriteAction, SdcObjectTransaction, SdcPreparedObjectWrite,
};
pub use prepared::{SdcPreparedChange, SdcPreparedTarget};
pub use projection::{
    project_ca_certificates, project_license, project_licenses, project_local_certificates,
};
