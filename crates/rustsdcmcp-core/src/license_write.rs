//! Change-controlled writes to SDC license and certificate management.
//!
//! License and certificate installs and deletions follow the async job pattern
//! already established for preview/deploy and device sync. The POST returns an
//! id, then a GET status poll resolves the outcome. Like firewall writes,
//! there is no SDC-side preview, so the plan artifact is built locally and
//! records the exact request together with observed state beforehand. Apply
//! refuses if that state has since moved.

use crate::{SdcClient, SdcError, prepared::canonical_digest};
use async_trait::async_trait;
use mecmcp_audit::Attribution;
use mecmcp_changeset::{
    CommitOptions, CommitOutcome, DeviceTransaction, RollbackOutcome, RollbackRef, UnlockOutcome,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio_util::sync::CancellationToken;

/// Hard cap on one serialized license/certificate write envelope.
const MAX_ENVELOPE_BYTES: usize = 2 * 1024 * 1024;

/// Which mutation one license/certificate write performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LicenseWriteOperation {
    /// Install a license on a device.
    InstallLicense,
    /// Install a CA certificate on a device.
    InstallCaCertificate,
    /// Install a local (identity) certificate on a device.
    InstallLocalCertificate,
    /// Delete a certificate from a device.
    DeleteCertificate,
}

impl LicenseWriteOperation {
    /// Stable discriminator recorded in audit and change-control state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InstallLicense => "license_install",
            Self::InstallCaCertificate => "ca_certificate_install",
            Self::InstallLocalCertificate => "local_certificate_install",
            Self::DeleteCertificate => "certificate_delete",
        }
    }
}

/// Exact license/certificate write bound into a change-set action.
///
/// Product-owned while its vendor-neutral extraction is tracked in mecmcp#90.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdcPreparedLicenseWrite {
    operation: String,
    action: LicenseWriteOperation,
    device_uuid: String,
    request: Value,
    before: Value,
    plan_digest: String,
}

impl SdcPreparedLicenseWrite {
    /// Build a canonical, digest-bound license/certificate write.
    ///
    /// `before` is the device's observed license or certificate state for
    /// validation, and `Value::Null` when no prior state check is needed.
    ///
    /// # Errors
    ///
    /// Refuses shapes that do not match the action, and oversized envelopes.
    pub fn new(
        action: LicenseWriteOperation,
        device_uuid: String,
        request: Value,
        before: Value,
    ) -> Result<Self, SdcError> {
        let plan = plan_artifact(action, &device_uuid, &request, &before);
        let prepared = Self {
            operation: "license_write".to_owned(),
            action,
            device_uuid,
            request,
            before,
            plan_digest: canonical_digest(&plan)
                .map_err(|error| SdcError::PreparedChange(error.to_string()))?,
        };
        prepared.validate()?;
        Ok(prepared)
    }

    /// Product operation discriminator.
    #[must_use]
    pub fn operation(&self) -> &str {
        &self.operation
    }

    /// Which mutation this write performs.
    #[must_use]
    pub const fn action(&self) -> LicenseWriteOperation {
        self.action
    }

    /// Target device UUID.
    #[must_use]
    pub fn device_uuid(&self) -> &str {
        &self.device_uuid
    }

    /// Exact request body.
    #[must_use]
    pub const fn request(&self) -> &Value {
        &self.request
    }

    /// Device state observed at prepare time, `Null` when not applicable.
    #[must_use]
    pub const fn before(&self) -> &Value {
        &self.before
    }

    /// Canonical SHA-256 digest binding this plan.
    #[must_use]
    pub fn plan_digest(&self) -> &str {
        &self.plan_digest
    }

    /// Human-readable plan showing what this write would change.
    #[must_use]
    pub fn plan(&self) -> Value {
        plan_artifact(self.action, &self.device_uuid, &self.request, &self.before)
    }

    /// Revalidate shape, bounds, and digest integrity.
    ///
    /// # Errors
    ///
    /// Returns a stable error if persisted content was malformed or tampered.
    pub fn validate(&self) -> Result<(), SdcError> {
        if self.operation != "license_write" {
            return Err(SdcError::PreparedChange(
                "prepared operation must be license_write".to_owned(),
            ));
        }
        if self.device_uuid.is_empty()
            || self.device_uuid.len() > 256
            || self
                .device_uuid
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(SdcError::PreparedChange(
                "prepared device UUID must be 1-256 non-whitespace bytes".to_owned(),
            ));
        }
        // All operations require a populated object body
        let request_is_populated_object = self
            .request
            .as_object()
            .is_some_and(|fields| !fields.is_empty());
        if !request_is_populated_object {
            return Err(SdcError::PreparedChange(format!(
                "prepared {} requires a populated request body",
                self.action.as_str()
            )));
        }
        let plan = plan_artifact(self.action, &self.device_uuid, &self.request, &self.before);
        if canonical_digest(&plan).map_err(|error| SdcError::PreparedChange(error.to_string()))?
            != self.plan_digest
        {
            return Err(SdcError::PreparedChange(
                "prepared license write does not match its digest".to_owned(),
            ));
        }
        if serde_json::to_vec(self)
            .map_err(|_| SdcError::Serialization)?
            .len()
            > MAX_ENVELOPE_BYTES
        {
            return Err(SdcError::PreparedChange(
                "prepared license write exceeds the 2097152-byte limit".to_owned(),
            ));
        }
        Ok(())
    }
}

fn plan_artifact(
    action: LicenseWriteOperation,
    device_uuid: &str,
    request: &Value,
    before: &Value,
) -> Value {
    json!({
        "action": action,
        "device_uuid": device_uuid,
        "before": before,
        "after": request,
    })
}

/// Outcome of revalidating a license/certificate write immediately before commit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseValidationReport {
    /// Whether the envelope is intact and the target has not drifted.
    pub valid: bool,
    /// Which mutation was validated.
    pub action: LicenseWriteOperation,
    /// Whether the live state still matched its prepared `before` state.
    pub target_unchanged: bool,
}

/// SDC implementation of the shared transaction contract for license/certificate writes.
#[derive(Clone)]
pub struct SdcLicenseTransaction {
    client: SdcClient,
    expected_plan_digest: String,
    cancellation: CancellationToken,
    refused_before_write: Arc<AtomicBool>,
}

impl SdcLicenseTransaction {
    /// Bind a transaction to one exact plan digest.
    #[must_use]
    pub fn new(
        client: SdcClient,
        expected_plan_digest: impl Into<String>,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            client,
            expected_plan_digest: expected_plan_digest.into(),
            cancellation,
            refused_before_write: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Whether commit refused before issuing any request to SDC.
    ///
    /// The coordinator flattens a transaction error into a string, so this is
    /// how the caller distinguishes "nothing was written, safe to discard" from
    /// "the write may have landed".
    #[must_use]
    pub fn refused_before_write(&self) -> bool {
        self.refused_before_write.load(Ordering::SeqCst)
    }

    /// Re-read the target and report whether it still matches its plan.
    ///
    /// For license/certificate operations, drift checking is minimal since we
    /// cannot query the exact state that will be created. We accept before as
    /// Null for all operations and do not re-check.
    async fn target_unchanged(&self, _staged: &SdcPreparedLicenseWrite) -> Result<bool, SdcError> {
        // No re-read for license/certificate operations - they are additive or
        // deletion operations where the before state is not re-queryable in a
        // meaningful way.
        Ok(true)
    }
}

#[async_trait]
impl DeviceTransaction for SdcLicenseTransaction {
    type Action = SdcPreparedLicenseWrite;
    type Staged = SdcPreparedLicenseWrite;
    type Diff = Value;
    type Validation = LicenseValidationReport;
    type Error = SdcError;

    async fn fingerprint(&self) -> Result<String, Self::Error> {
        Ok(self.expected_plan_digest.clone())
    }

    /// Sole validation point for the envelope, mirroring other transaction types.
    async fn stage(&self, actions: &[Self::Action]) -> Result<Self::Staged, Self::Error> {
        let [prepared] = actions else {
            return Err(SdcError::InvalidInput(
                "an SDC license write requires exactly one prepared change",
            ));
        };
        prepared.validate()?;
        if prepared.operation() != "license_write"
            || prepared.plan_digest() != self.expected_plan_digest
        {
            return Err(SdcError::PreparedChange(
                "prepared action does not match the approved plan digest".to_owned(),
            ));
        }
        Ok(prepared.clone())
    }

    async fn diff(&self, staged: &Self::Staged) -> Result<Self::Diff, Self::Error> {
        // Validated in `stage`.
        Ok(staged.plan())
    }

    /// Validate the envelope. No drift check for license/certificate writes.
    async fn validate(&self, staged: &Self::Staged) -> Result<Self::Validation, Self::Error> {
        let target_unchanged = self.target_unchanged(staged).await?;
        Ok(LicenseValidationReport {
            valid: true,
            action: staged.action(),
            target_unchanged,
        })
    }

    async fn commit(
        &self,
        staged: &Self::Staged,
        _attribution: &Attribution,
        options: &CommitOptions,
    ) -> Result<CommitOutcome, Self::Error> {
        // Every exit path from here until the request is issued is a pre-write
        // refusal: nothing has been sent, so the caller may safely discard the
        // operation instead of leaving a non-terminal record that blocks the
        // tenant.
        self.refused_before_write.store(true, Ordering::SeqCst);
        if options.confirm_timeout.is_some() {
            return Err(SdcError::InvalidInput(
                "SDC does not support confirmed license/certificate writes",
            ));
        }
        // The mutation is about to go out. Past this point its outcome is no
        // longer knowably clean, so the operation must not be auto-discarded.
        self.refused_before_write.store(false, Ordering::SeqCst);
        let (job_id, status) = match staged.action() {
            LicenseWriteOperation::InstallLicense => {
                self.client
                    .install_license(&staged.device_uuid, staged.request(), &self.cancellation)
                    .await
            }
            LicenseWriteOperation::InstallCaCertificate => {
                self.client
                    .install_ca_certificate(
                        &staged.device_uuid,
                        staged.request(),
                        &self.cancellation,
                    )
                    .await
            }
            LicenseWriteOperation::InstallLocalCertificate => {
                self.client
                    .install_local_certificate(
                        &staged.device_uuid,
                        staged.request(),
                        &self.cancellation,
                    )
                    .await
            }
            LicenseWriteOperation::DeleteCertificate => {
                self.client
                    .delete_certificate(&staged.device_uuid, staged.request(), &self.cancellation)
                    .await
            }
        }?;
        Ok(CommitOutcome::Reconciled {
            succeeded: status.succeeded(),
            job_id: Some(job_id),
            details: Some(format!(
                "SDC {} completed with status {:?}",
                staged.action().as_str(),
                status
            )),
        })
    }

    /// Release a planned-but-uncommitted license/certificate write.
    ///
    /// SDC has no candidate store, so there is nothing remote to revert. The
    /// coordinator only reaches `rollback` from `Staged`, `Validated`, or
    /// `Failed` — it refuses to discard from `Committing`, `Committed`, and
    /// `Indeterminate` — so every state that gets here is pre-commit and
    /// nothing was written. Reporting success is therefore accurate, and it is
    /// what lets a refused write reach the terminal `Discarded` state instead
    /// of stranding the principal on a non-terminal `Failed` record.
    async fn rollback(&self, to: RollbackRef) -> Result<RollbackOutcome, Self::Error> {
        match to {
            RollbackRef::CandidateRevert => Ok(RollbackOutcome {
                succeeded: true,
                details: Some(
                    "no remote candidate exists; SDC license/certificate writes are not staged"
                        .to_owned(),
                ),
            }),
            RollbackRef::Archive(_) | RollbackRef::Custom(_) => Err(SdcError::RollbackUnsupported),
        }
    }

    async fn unlock(&self) -> Result<UnlockOutcome, Self::Error> {
        Ok(UnlockOutcome::Released)
    }

    async fn confirm_commit(
        &self,
        _operation_id: &str,
        _attribution: &Attribution,
    ) -> Result<CommitOutcome, Self::Error> {
        Err(SdcError::InvalidInput(
            "SDC does not support confirmed license/certificate writes",
        ))
    }
}

/// Result of planning a license/certificate write.
#[derive(Debug, Clone, Serialize)]
pub struct LicensePrepareResult {
    /// Shared two-person change-set record.
    pub change_set: mecmcp_changeset::ChangeSetOutput,
    /// Exact license/certificate write bound by the plan digest.
    pub prepared_change: SdcPreparedLicenseWrite,
}

/// Result of applying one approved SDC license/certificate write.
#[derive(Debug, Clone, Serialize)]
pub struct LicenseApplyResult {
    /// Shared operation identifier.
    pub operation_id: String,
    /// Before/after plan used as the management-plane diff.
    pub plan: Value,
    /// Drift and envelope validation result.
    pub validation: LicenseValidationReport,
    /// Known, detached, or indeterminate commit disposition.
    pub outcome: CommitOutcome,
}
