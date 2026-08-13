//! SDC adapter for the shared preview-bound, two-person change lifecycle.

use crate::{
    DeployRequest, JobStatus, NatValidationReport, NatWriteOperation, ObjectValidationReport,
    ObjectWriteAction, PolicyOperation, ResourceKind, SdcClient, SdcError, SdcNatTransaction,
    SdcObjectTransaction, SdcPreparedChange, SdcPreparedNatWrite, SdcPreparedObjectWrite,
};
use async_trait::async_trait;
use mecmcp_audit::Attribution;
use mecmcp_changeset::{
    ChangeSetOutput, ChangesetCoordinator, CommitOptions, CommitOutcome, DeviceTransaction,
    OperationLimits, RollbackOutcome, RollbackRef, StagedRecovery, UnlockOutcome,
    mutation_policy_signature,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{path::Path, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

/// Output of the SDC prepare/plan phase.
#[derive(Debug, Clone, Serialize)]
pub struct PrepareResult {
    /// Shared two-person change-set record.
    pub change_set: ChangeSetOutput,
    /// Exact request and complete preview bound by the plan digest.
    pub prepared_change: SdcPreparedChange,
}

/// Result of applying, validating, and resolving an approved SDC deployment.
#[derive(Debug, Clone, Serialize)]
pub struct ApplyResult {
    /// Shared operation identifier.
    pub operation_id: String,
    /// Preview artifact used as the management-plane diff.
    pub preview: Value,
    /// Prepared-change validation result.
    pub validation: ValidationReport,
    /// Known, detached, or indeterminate commit disposition.
    pub outcome: CommitOutcome,
}

/// Validation result for a prepared SDC change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationReport {
    /// Whether the preview completed successfully and the envelope is intact.
    pub valid: bool,
    /// Preview job identifier.
    pub preview_job_id: Option<String>,
    /// Exact terminal preview status.
    pub status: crate::DeploymentStatus,
}

/// SDC implementation of the shared transaction contract.
#[derive(Clone)]
pub struct SdcTransaction {
    client: SdcClient,
    expected_preview_digest: String,
    cancellation: CancellationToken,
}

impl SdcTransaction {
    /// Bind a transaction to one exact preview digest.
    #[must_use]
    pub fn new(
        client: SdcClient,
        expected_preview_digest: impl Into<String>,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            client,
            expected_preview_digest: expected_preview_digest.into(),
            cancellation,
        }
    }
}

#[async_trait]
impl DeviceTransaction for SdcTransaction {
    type Action = SdcPreparedChange;
    type Staged = SdcPreparedChange;
    type Diff = Value;
    type Validation = ValidationReport;
    type Error = SdcError;

    async fn fingerprint(&self) -> Result<String, Self::Error> {
        Ok(self.expected_preview_digest.clone())
    }

    /// Sole validation point for the envelope.
    ///
    /// `stage` is the trust boundary: it is where a persisted or caller-supplied
    /// action enters, and the coordinator always runs it before `diff`,
    /// `validate`, or `commit` receive the staged value. Revalidating in each of
    /// those recomputes a SHA-256 over the canonicalized preview and reserializes
    /// the whole envelope -- up to `MAX_ARTIFACT_BYTES` (8 MiB) -- four times per
    /// apply, which scales with estate size for no additional guarantee.
    async fn stage(&self, actions: &[Self::Action]) -> Result<Self::Staged, Self::Error> {
        let [prepared] = actions else {
            return Err(SdcError::InvalidInput(
                "an SDC transaction requires exactly one prepared change",
            ));
        };
        prepared
            .validate()
            .map_err(|error| SdcError::PreparedChange(error.to_string()))?;
        if prepared.operation() != "policy_deploy"
            || prepared.preview_digest() != self.expected_preview_digest
        {
            return Err(SdcError::PreparedChange(
                "expected_preview_digest does not match the prepared change".to_owned(),
            ));
        }
        Ok(prepared.clone())
    }

    async fn diff(&self, staged: &Self::Staged) -> Result<Self::Diff, Self::Error> {
        // Validated in `stage`; see the note there.
        Ok(staged.preview().clone())
    }

    async fn validate(&self, staged: &Self::Staged) -> Result<Self::Validation, Self::Error> {
        // Validated in `stage`; see the note there.
        let status: JobStatus =
            serde_json::from_value(staged.preview().get("status").cloned().ok_or(
                SdcError::PreparedChange("preview artifact is missing terminal status".to_owned()),
            )?)
            .map_err(|_| {
                SdcError::PreparedChange("preview artifact has invalid terminal status".to_owned())
            })?;
        if !status.status.succeeded() {
            return Err(SdcError::JobFailed {
                status: status.status,
            });
        }
        Ok(ValidationReport {
            valid: true,
            preview_job_id: Some(staged.preview_job_id().to_owned()),
            status: status.status,
        })
    }

    async fn commit(
        &self,
        staged: &Self::Staged,
        _attribution: &Attribution,
        options: &CommitOptions,
    ) -> Result<CommitOutcome, Self::Error> {
        if options.confirm_timeout.is_some() {
            return Err(SdcError::InvalidInput(
                "SDC does not support confirmed deployment",
            ));
        }
        // Validated in `stage`; see the note there. The deploy request itself is
        // bound by the change-set digest that approval checked, not by the
        // preview digest, so revalidating here would not cover it either.
        let request: DeployRequest = serde_json::from_value(staged.request().clone())
            .map_err(|_| SdcError::PreparedChange("deploy request is invalid".to_owned()))?;
        match self
            .client
            .deploy_prepared(&request, &self.cancellation)
            .await
        {
            Ok((job_id, status)) => Ok(CommitOutcome::Reconciled {
                succeeded: status.status.succeeded(),
                job_id: Some(job_id),
                details: Some(format!("SDC deployment ended with {:?}", status.status)),
            }),
            Err(SdcError::JobDeadline | SdcError::Cancelled) => Ok(CommitOutcome::Indeterminate {
                reason: "SDC deployment was submitted but its terminal outcome was not observed"
                    .to_owned(),
            }),
            Err(error) => Err(error),
        }
    }

    /// Report that there is nothing left to revert.
    ///
    /// `mecmcp-changeset::discard_operation` is the only caller. It refuses to
    /// discard an operation in `Validating`, `Committing`, `Committed`,
    /// `Discarded`, or `Indeterminate`, so anything reaching here either never
    /// reached the device or is `Failed` — and SDC reverts the device itself on
    /// a failed deploy, observed as `sduser` issuing `commit confirmed` and then
    /// `discard-changes` with a rollback.
    ///
    /// Returning `Err` here is worse than useless: `discard_operation` turns it
    /// into a `Failed` or `Indeterminate` record, and `Indeterminate` cannot be
    /// discarded again, so the operation would be permanently unrecoverable —
    /// the opposite of what a discard is for.
    ///
    /// This is not a claim that SDC supports arbitrary rollback. It does not,
    /// and no other caller asks it to.
    async fn rollback(&self, _to: RollbackRef) -> Result<RollbackOutcome, Self::Error> {
        Ok(RollbackOutcome {
            succeeded: true,
            details: Some(
                "SDC reverts the device itself when a deploy fails, so a discarded \
                 operation has nothing left to revert locally"
                    .to_owned(),
            ),
        })
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
            "SDC does not support confirmed deployment",
        ))
    }
}

/// Output of the SDC object-write plan phase.
#[derive(Debug, Clone, Serialize)]
pub struct ObjectPrepareResult {
    /// Shared two-person change-set record.
    pub change_set: ChangeSetOutput,
    /// Exact object write bound by the plan digest.
    pub prepared_change: SdcPreparedObjectWrite,
}

/// Result of applying one approved SDC object write.
#[derive(Debug, Clone, Serialize)]
pub struct ObjectApplyResult {
    /// Shared operation identifier.
    pub operation_id: String,
    /// Before/after plan used as the management-plane diff.
    pub plan: Value,
    /// Drift and envelope validation result.
    pub validation: ObjectValidationReport,
    /// Known, detached, or indeterminate commit disposition.
    pub outcome: CommitOutcome,
}

/// Output of the SDC NAT-write plan phase.
#[derive(Debug, Clone, Serialize)]
pub struct NatPrepareResult {
    /// Shared two-person change-set record.
    pub change_set: ChangeSetOutput,
    /// Exact NAT write bound by the plan digest.
    pub prepared_change: SdcPreparedNatWrite,
}

/// Result of applying one approved SDC NAT write.
#[derive(Debug, Clone, Serialize)]
pub struct NatApplyResult {
    /// Shared operation identifier.
    pub operation_id: String,
    /// Before/after plan used as the management-plane diff.
    pub plan: Value,
    /// Drift and envelope validation result.
    pub validation: NatValidationReport,
    /// Known, detached, or indeterminate commit disposition.
    pub outcome: CommitOutcome,
}

/// Product adapter around the shared change-set coordinator.
pub struct ChangeManager {
    coordinator: Arc<ChangesetCoordinator>,
    client: SdcClient,
    tenant: String,
    endpoint: String,
    policy_signature: String,
    object_signature: String,
    nat_signature: String,
    license_signature: String,
}

impl ChangeManager {
    /// Load durable change-control state for one configured tenant.
    ///
    /// # Errors
    ///
    /// Returns an error when an absolute state path cannot be loaded safely.
    /// `lab_mode` waives the second principal for single-operator use. It is
    /// off in every deployment that does not ask for it, and the waiver is
    /// recorded rather than faked: `mecmcp-changeset` stores `approver: null`
    /// with `approval_waiver: "lab-mode"` and a waiver digest binding
    /// `(change_set_id, plan_digest, owner, approved_at)`, so a waived change
    /// set can never be mistaken for a genuine two-person approval.
    pub fn load(
        client: SdcClient,
        tenant: impl Into<String>,
        endpoint: impl Into<String>,
        state_path: Option<&Path>,
        approval_ttl: Duration,
        lab_mode: bool,
    ) -> Result<Self, SdcError> {
        let tenant = tenant.into();
        let endpoint = endpoint.into();
        let policy_signature =
            mutation_policy_signature(format!("sdc-policy-deploy-v1:{tenant}:{endpoint}"));
        let object_signature =
            mutation_policy_signature(format!("sdc-object-write-v1:{tenant}:{endpoint}"));
        let nat_signature =
            mutation_policy_signature(format!("sdc-nat-write-v1:{tenant}:{endpoint}"));
        let license_signature =
            mutation_policy_signature(format!("sdc-license-write-v1:{tenant}:{endpoint}"));
        let coordinator = ChangesetCoordinator::load_with_recovery(
            state_path,
            OperationLimits::default(),
            approval_ttl,
            lab_mode,
            StagedRecovery::Discard,
        )
        .map_err(|error| SdcError::ChangeControl(error.to_string()))?;
        Ok(Self {
            coordinator: Arc::new(coordinator),
            client,
            tenant,
            endpoint,
            policy_signature,
            object_signature,
            nat_signature,
            license_signature,
        })
    }

    /// Resolve an object's current state and create its digest-bound plan.
    ///
    /// Create carries no prior state; update and delete read the live object
    /// so the plan records exactly what the write would replace or remove.
    ///
    /// # Errors
    ///
    /// Returns an error when the target cannot be read, the envelope is
    /// invalid, or change-control state cannot be written.
    pub async fn prepare_object_write(
        &self,
        owner: String,
        action: ObjectWriteAction,
        resource: ResourceKind,
        uuid: Option<String>,
        request: Value,
        cancellation: &CancellationToken,
    ) -> Result<ObjectPrepareResult, SdcError> {
        let before = match (action, uuid.as_deref()) {
            (ObjectWriteAction::Create, _) => Value::Null,
            (_, Some(identifier)) => {
                self.client
                    .get_resource(resource, identifier, cancellation)
                    .await?
            }
            (ObjectWriteAction::Update | ObjectWriteAction::Delete, None) => {
                return Err(SdcError::InvalidInput(
                    "update and delete require the target object UUID",
                ));
            }
        };
        let prepared = SdcPreparedObjectWrite::new(action, resource, uuid, request, before)?;
        let change_set = self
            .coordinator
            .create_change_set(
                self.tenant.clone(),
                vec![prepared.clone()],
                owner.clone(),
                prepared.plan_digest().to_owned(),
                self.object_signature.clone(),
            )
            .await
            .map_err(|error| SdcError::ChangeControl(error.to_string()))?;
        let change_set = self.waive_if_lab_mode(change_set, &owner).await?;
        Ok(ObjectPrepareResult {
            change_set,
            prepared_change: prepared,
        })
    }

    /// Discard an object write that failed before anything was sent to SDC.
    ///
    /// Returns a caller-facing description rather than an error: the original
    /// failure is what the operator needs, and this only says whether the
    /// blocked record was cleared.
    async fn release_unwritten(
        &self,
        operation_id: &str,
        owner: &str,
        expected_plan_digest: &str,
        transaction: &SdcObjectTransaction,
        cancellation: &CancellationToken,
    ) -> String {
        match self
            .coordinator
            .discard_operation(
                operation_id,
                &self.tenant,
                owner,
                expected_plan_digest,
                transaction,
                cancellation,
            )
            .await
        {
            Ok(_) => "the planned write was discarded".to_owned(),
            Err(discard_error) => format!(
                "the planned write also could not be discarded and needs manual resolution: {discard_error}"
            ),
        }
    }

    /// Apply, diff, drift-check, and commit one exact approved object write.
    ///
    /// # Errors
    ///
    /// Returns an error when approval does not match, the object drifted since
    /// prepare, or the SDC write fails.
    pub async fn apply_object_write(
        &self,
        change_set_id: String,
        owner: String,
        expected_digest: String,
        expected_plan_digest: String,
        attribution: &Attribution,
        cancellation: &CancellationToken,
    ) -> Result<ObjectApplyResult, SdcError> {
        let transaction = SdcObjectTransaction::new(
            self.client.clone(),
            expected_plan_digest.clone(),
            cancellation.clone(),
        );
        let applied = self
            .coordinator
            .apply_change_set(
                change_set_id,
                self.tenant.clone(),
                self.endpoint.clone(),
                owner.clone(),
                expected_digest,
                expected_plan_digest.clone(),
                &transaction,
                "object_write",
                None,
                attribution,
                cancellation,
            )
            .await
            .map_err(|error| SdcError::ChangeControl(error.to_string()))?;
        let operation_id = applied.operation_id;
        let staged = applied.staged;
        let plan = self
            .coordinator
            .diff_operation(
                &operation_id,
                &self.tenant,
                &owner,
                &expected_plan_digest,
                &transaction,
                &staged,
                cancellation,
            )
            .await
            .map_err(|error| SdcError::ChangeControl(error.to_string()))?;
        let validation = match self
            .coordinator
            .validate_operation(
                &operation_id,
                &self.tenant,
                &owner,
                &expected_plan_digest,
                &transaction,
                &staged,
                cancellation,
            )
            .await
        {
            Ok(report) => report,
            Err(error) => {
                // A refused validation records the operation `Failed`, which is
                // not terminal: it keeps blocking this principal with no
                // operator route out. Staging and validation only read, so
                // nothing was written and discarding is truthful.
                let detail = self
                    .release_unwritten(
                        &operation_id,
                        &owner,
                        &expected_plan_digest,
                        &transaction,
                        cancellation,
                    )
                    .await;
                return Err(SdcError::ChangeControl(format!("{error}; {detail}")));
            }
        };
        let outcome = match self
            .coordinator
            .commit_operation(
                &operation_id,
                &self.tenant,
                &owner,
                &expected_plan_digest,
                &self.object_signature,
                &transaction,
                &staged,
                attribution,
                &CommitOptions::default(),
                cancellation,
            )
            .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                // Only a refusal that happened before anything was sent is safe
                // to discard. If the write may have landed, leaving the record
                // for reconciliation is the honest outcome even though it
                // blocks this principal.
                if !transaction.refused_before_write() {
                    return Err(SdcError::ChangeControl(error.to_string()));
                }
                let detail = self
                    .release_unwritten(
                        &operation_id,
                        &owner,
                        &expected_plan_digest,
                        &transaction,
                        cancellation,
                    )
                    .await;
                return Err(SdcError::ChangeControl(format!("{error}; {detail}")));
            }
        };
        Ok(ObjectApplyResult {
            operation_id,
            plan,
            validation,
            outcome,
        })
    }

    /// Resolve a firewall policy's current state and create its digest-bound plan.
    ///
    /// Create carries no prior state; update and delete read the live policy
    /// so the plan records exactly what the write would replace or remove.
    ///
    /// # Errors
    ///
    /// Returns an error when the target cannot be read, the envelope is
    /// invalid, or change-control state cannot be written.
    pub async fn prepare_firewall_write(
        &self,
        owner: String,
        action: crate::FirewallWriteOperation,
        uuid: Option<String>,
        request: Value,
        cancellation: &CancellationToken,
    ) -> Result<crate::FirewallPrepareResult, SdcError> {
        let before = match (action, uuid.as_deref()) {
            (crate::FirewallWriteOperation::CreatePolicy, _) => Value::Null,
            (_, Some(identifier)) => {
                self.client
                    .get_firewall_policy(identifier, cancellation)
                    .await?
            }
            (
                crate::FirewallWriteOperation::UpdatePolicy
                | crate::FirewallWriteOperation::DeletePolicy,
                None,
            ) => {
                return Err(SdcError::InvalidInput(
                    "update and delete require the target policy UUID",
                ));
            }
        };
        let prepared = crate::SdcPreparedFirewallWrite::new(action, uuid, request, before)?;
        let change_set = self
            .coordinator
            .create_change_set(
                self.tenant.clone(),
                vec![prepared.clone()],
                owner.clone(),
                prepared.plan_digest().to_owned(),
                "firewall-policy-write-v1".to_owned(),
            )
            .await
            .map_err(|error| SdcError::ChangeControl(error.to_string()))?;
        let change_set = self.waive_if_lab_mode(change_set, &owner).await?;
        Ok(crate::FirewallPrepareResult {
            change_set,
            prepared_change: prepared,
        })
    }

    /// Apply, diff, drift-check, and commit one exact approved firewall policy write.
    ///
    /// # Errors
    ///
    /// Returns an error when approval does not match, the policy drifted since
    /// prepare, or the SDC write fails.
    pub async fn apply_firewall_write(
        &self,
        change_set_id: String,
        owner: String,
        expected_digest: String,
        expected_plan_digest: String,
        attribution: &Attribution,
        cancellation: &CancellationToken,
    ) -> Result<crate::FirewallApplyResult, SdcError> {
        let transaction = crate::SdcFirewallTransaction::new(
            self.client.clone(),
            expected_plan_digest.clone(),
            cancellation.clone(),
        );
        let applied = self
            .coordinator
            .apply_change_set(
                change_set_id,
                self.tenant.clone(),
                self.endpoint.clone(),
                owner.clone(),
                expected_digest,
                expected_plan_digest.clone(),
                &transaction,
                "firewall_write",
                None,
                attribution,
                cancellation,
            )
            .await
            .map_err(|error| SdcError::ChangeControl(error.to_string()))?;
        let operation_id = applied.operation_id;
        let staged = applied.staged;
        let plan = self
            .coordinator
            .diff_operation(
                &operation_id,
                &self.tenant,
                &owner,
                &expected_plan_digest,
                &transaction,
                &staged,
                cancellation,
            )
            .await
            .map_err(|error| SdcError::ChangeControl(error.to_string()))?;
        let validation = match self
            .coordinator
            .validate_operation(
                &operation_id,
                &self.tenant,
                &owner,
                &expected_plan_digest,
                &transaction,
                &staged,
                cancellation,
            )
            .await
        {
            Ok(report) => report,
            Err(error) => {
                // A refused validation records the operation `Failed`, which is
                // not terminal: it keeps blocking this principal with no
                // operator route out. Staging and validation only read, so
                // nothing was written and discarding is truthful.
                let detail = self
                    .release_unwritten_firewall(
                        &operation_id,
                        &owner,
                        &expected_plan_digest,
                        &transaction,
                        cancellation,
                    )
                    .await;
                return Err(SdcError::ChangeControl(format!("{error}; {detail}")));
            }
        };
        let outcome = match self
            .coordinator
            .commit_operation(
                &operation_id,
                &self.tenant,
                &owner,
                &expected_plan_digest,
                "firewall-policy-write-v1",
                &transaction,
                &staged,
                attribution,
                &CommitOptions::default(),
                cancellation,
            )
            .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                // Only a refusal that happened before anything was sent is safe
                // to discard. If the write may have landed, leaving the record
                // for reconciliation is the honest outcome even though it
                // blocks this principal.
                if !transaction.refused_before_write() {
                    return Err(SdcError::ChangeControl(error.to_string()));
                }
                let detail = self
                    .release_unwritten_firewall(
                        &operation_id,
                        &owner,
                        &expected_plan_digest,
                        &transaction,
                        cancellation,
                    )
                    .await;
                return Err(SdcError::ChangeControl(format!("{error}; {detail}")));
            }
        };
        Ok(crate::FirewallApplyResult {
            operation_id,
            plan,
            validation,
            outcome,
        })
    }

    /// Discard a firewall write that failed before anything was sent to SDC.
    ///
    /// Returns a caller-facing description rather than an error: the original
    /// failure is what the operator needs, and this only says whether the
    /// blocked record was cleared.
    async fn release_unwritten_firewall(
        &self,
        operation_id: &str,
        owner: &str,
        expected_plan_digest: &str,
        transaction: &crate::SdcFirewallTransaction,
        cancellation: &CancellationToken,
    ) -> String {
        match self
            .coordinator
            .discard_operation(
                operation_id,
                &self.tenant,
                owner,
                expected_plan_digest,
                transaction,
                cancellation,
            )
            .await
        {
            Ok(_) => "the planned firewall write was discarded".to_owned(),
            Err(discard_error) => format!(
                "the planned firewall write also could not be discarded and needs manual resolution: {discard_error}"
            ),
        }
    }

    /// Prepare a license or certificate write.
    ///
    /// Reads the current state of licenses or certificates on the device so
    /// the plan records exactly what the write would change. Apply refuses if
    /// that state has since moved.
    ///
    /// # Errors
    ///
    /// Returns an error when the target cannot be read, the envelope is
    /// invalid, or change-control state cannot be written.
    pub async fn prepare_license_write(
        &self,
        owner: String,
        action: crate::LicenseWriteOperation,
        device_uuid: String,
        request: Value,
        cancellation: &CancellationToken,
    ) -> Result<crate::LicensePrepareResult, SdcError> {
        use crate::LicenseWriteOperation::*;
        // Read the device's current license or certificate state so the digest
        // binds to observed reality and apply can detect drift.
        let before = match action {
            InstallLicense => {
                // Fetch all licenses on this device to capture the state before adding another
                self.client
                    .list_licenses(
                        &device_uuid,
                        crate::ListRequest::new(0, 100, 100)?,
                        cancellation,
                    )
                    .await?
            }
            InstallCaCertificate => {
                // Fetch all CA certificates on this device
                self.client
                    .list_device_ca_certificates(
                        &device_uuid,
                        crate::ListRequest::new(0, 100, 100)?,
                        cancellation,
                    )
                    .await?
            }
            InstallLocalCertificate => {
                // Fetch all local certificates on this device
                self.client
                    .list_device_local_certificates(
                        &device_uuid,
                        crate::ListRequest::new(0, 100, 100)?,
                        cancellation,
                    )
                    .await?
            }
            DeleteCertificate => {
                // Fetch both certificate types since delete can target either
                let ca_certs = self
                    .client
                    .list_device_ca_certificates(
                        &device_uuid,
                        crate::ListRequest::new(0, 100, 100)?,
                        cancellation,
                    )
                    .await?;
                let local_certs = self
                    .client
                    .list_device_local_certificates(
                        &device_uuid,
                        crate::ListRequest::new(0, 100, 100)?,
                        cancellation,
                    )
                    .await?;
                serde_json::json!({
                    "ca_certificates": ca_certs,
                    "local_certificates": local_certs,
                })
            }
        };
        let prepared = crate::SdcPreparedLicenseWrite::new(action, device_uuid, request, before)?;
        let change_set = self
            .coordinator
            .create_change_set(
                self.tenant.clone(),
                vec![prepared.clone()],
                owner.clone(),
                prepared.plan_digest().to_owned(),
                self.license_signature.clone(),
            )
            .await
            .map_err(|error| SdcError::ChangeControl(error.to_string()))?;
        let change_set = self.waive_if_lab_mode(change_set, &owner).await?;
        Ok(crate::LicensePrepareResult {
            change_set,
            prepared_change: prepared,
        })
    }

    /// Apply, diff, and commit one exact approved license/certificate write.
    ///
    /// # Errors
    ///
    /// Returns an error when approval does not match or the SDC write fails.
    pub async fn apply_license_write(
        &self,
        change_set_id: String,
        owner: String,
        expected_digest: String,
        expected_plan_digest: String,
        attribution: &Attribution,
        cancellation: &CancellationToken,
    ) -> Result<crate::LicenseApplyResult, SdcError> {
        let transaction = crate::SdcLicenseTransaction::new(
            self.client.clone(),
            expected_plan_digest.clone(),
            cancellation.clone(),
        );
        let applied = self
            .coordinator
            .apply_change_set(
                change_set_id,
                self.tenant.clone(),
                self.endpoint.clone(),
                owner.clone(),
                expected_digest,
                expected_plan_digest.clone(),
                &transaction,
                "license_write",
                None,
                attribution,
                cancellation,
            )
            .await
            .map_err(|error| SdcError::ChangeControl(error.to_string()))?;
        let operation_id = applied.operation_id;
        let staged = applied.staged;
        let plan = self
            .coordinator
            .diff_operation(
                &operation_id,
                &self.tenant,
                &owner,
                &expected_plan_digest,
                &transaction,
                &staged,
                cancellation,
            )
            .await
            .map_err(|error| SdcError::ChangeControl(error.to_string()))?;
        let validation = match self
            .coordinator
            .validate_operation(
                &operation_id,
                &self.tenant,
                &owner,
                &expected_plan_digest,
                &transaction,
                &staged,
                cancellation,
            )
            .await
        {
            Ok(report) => report,
            Err(error) => {
                let detail = self
                    .release_unwritten_license(
                        &operation_id,
                        &owner,
                        &expected_plan_digest,
                        &transaction,
                        cancellation,
                    )
                    .await;
                return Err(SdcError::ChangeControl(format!("{error}; {detail}")));
            }
        };
        let outcome = match self
            .coordinator
            .commit_operation(
                &operation_id,
                &self.tenant,
                &owner,
                &expected_plan_digest,
                &self.license_signature,
                &transaction,
                &staged,
                attribution,
                &CommitOptions::default(),
                cancellation,
            )
            .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                if !transaction.refused_before_write() {
                    return Err(SdcError::ChangeControl(error.to_string()));
                }
                let detail = self
                    .release_unwritten_license(
                        &operation_id,
                        &owner,
                        &expected_plan_digest,
                        &transaction,
                        cancellation,
                    )
                    .await;
                return Err(SdcError::ChangeControl(format!("{error}; {detail}")));
            }
        };
        Ok(crate::LicenseApplyResult {
            operation_id,
            plan,
            validation,
            outcome,
        })
    }

    /// Discard a license write that failed before anything was sent to SDC.
    ///
    /// Returns a caller-facing description rather than an error: the original
    /// failure is what the operator needs, and this only says whether the
    /// blocked record was cleared.
    async fn release_unwritten_license(
        &self,
        operation_id: &str,
        owner: &str,
        expected_plan_digest: &str,
        transaction: &crate::SdcLicenseTransaction,
        cancellation: &CancellationToken,
    ) -> String {
        match self
            .coordinator
            .discard_operation(
                operation_id,
                &self.tenant,
                owner,
                expected_plan_digest,
                transaction,
                cancellation,
            )
            .await
        {
            Ok(_) => "the planned license write was discarded".to_owned(),
            Err(discard_error) => format!(
                "the planned license write also could not be discarded and needs manual resolution: {discard_error}"
            ),
        }
    }

    /// Resolve a NAT object's current state and create its digest-bound plan.
    ///
    /// Create carries no prior state; update and delete read the live object
    /// so the plan records exactly what the write would replace or remove.
    ///
    /// # Errors
    ///
    /// Returns an error when the target cannot be read, the envelope is
    /// invalid, or change-control state cannot be written.
    #[allow(clippy::too_many_arguments)]
    pub async fn prepare_nat_write(
        &self,
        owner: String,
        action: NatWriteOperation,
        policy_id: Option<String>,
        rule_id: Option<String>,
        group_id: Option<String>,
        request: Value,
        cancellation: &CancellationToken,
    ) -> Result<NatPrepareResult, SdcError> {
        use NatWriteOperation::*;

        let before = match action {
            CreatePolicy | CreateRule | CreateRuleGroup => Value::Null,
            UpdatePolicy | DeletePolicy => {
                let Some(ref pid) = policy_id else {
                    return Err(SdcError::InvalidInput(
                        "policy_id required for policy operations",
                    ));
                };
                self.client.get_nat_policy(pid, cancellation).await?
            }
            UpdateRule | DeleteRule => {
                let Some(ref pid) = policy_id else {
                    return Err(SdcError::InvalidInput(
                        "policy_id required for rule operations",
                    ));
                };
                let Some(ref rid) = rule_id else {
                    return Err(SdcError::InvalidInput(
                        "rule_id required for rule operations",
                    ));
                };
                self.client.get_nat_rule(pid, rid, cancellation).await?
            }
            UpdateRuleGroup => {
                // Rule group get is not yet implemented in client, use Null for now
                // TODO: Add get_nat_rule_group to client and use it here
                Value::Null
            }
        };

        let prepared =
            SdcPreparedNatWrite::new(action, policy_id, rule_id, group_id, request, before)?;
        let change_set = self
            .coordinator
            .create_change_set(
                self.tenant.clone(),
                vec![prepared.clone()],
                owner.clone(),
                prepared.plan_digest().to_owned(),
                self.nat_signature.clone(),
            )
            .await
            .map_err(|error| SdcError::ChangeControl(error.to_string()))?;
        let change_set = self.waive_if_lab_mode(change_set, &owner).await?;
        Ok(NatPrepareResult {
            change_set,
            prepared_change: prepared,
        })
    }

    /// Discard a NAT write that failed before anything was sent to SDC.
    ///
    /// Returns a caller-facing description rather than an error: the original
    /// failure is what the operator needs, and this only says whether the
    /// blocked record was cleared.
    async fn release_unwritten_nat(
        &self,
        operation_id: &str,
        owner: &str,
        expected_plan_digest: &str,
        transaction: &SdcNatTransaction,
        cancellation: &CancellationToken,
    ) -> String {
        match self
            .coordinator
            .discard_operation(
                operation_id,
                &self.tenant,
                owner,
                expected_plan_digest,
                transaction,
                cancellation,
            )
            .await
        {
            Ok(_) => "the planned NAT write was discarded".to_owned(),
            Err(discard_error) => format!(
                "the planned NAT write also could not be discarded and needs manual resolution: {discard_error}"
            ),
        }
    }

    /// Apply, diff, drift-check, and commit one exact approved NAT write.
    ///
    /// # Errors
    ///
    /// Returns an error when approval does not match, the object drifted since
    /// prepare, or the SDC write fails.
    pub async fn apply_nat_write(
        &self,
        change_set_id: String,
        owner: String,
        expected_digest: String,
        expected_plan_digest: String,
        attribution: &Attribution,
        cancellation: &CancellationToken,
    ) -> Result<NatApplyResult, SdcError> {
        let transaction = SdcNatTransaction::new(
            self.client.clone(),
            expected_plan_digest.clone(),
            cancellation.clone(),
        );
        let applied = self
            .coordinator
            .apply_change_set(
                change_set_id,
                self.tenant.clone(),
                self.endpoint.clone(),
                owner.clone(),
                expected_digest,
                expected_plan_digest.clone(),
                &transaction,
                "nat_write",
                None,
                attribution,
                cancellation,
            )
            .await
            .map_err(|error| SdcError::ChangeControl(error.to_string()))?;
        let operation_id = applied.operation_id;
        let staged = applied.staged;
        let plan = self
            .coordinator
            .diff_operation(
                &operation_id,
                &self.tenant,
                &owner,
                &expected_plan_digest,
                &transaction,
                &staged,
                cancellation,
            )
            .await
            .map_err(|error| SdcError::ChangeControl(error.to_string()))?;
        let validation = match self
            .coordinator
            .validate_operation(
                &operation_id,
                &self.tenant,
                &owner,
                &expected_plan_digest,
                &transaction,
                &staged,
                cancellation,
            )
            .await
        {
            Ok(report) => report,
            Err(error) => {
                // A refused validation records the operation `Failed`, which is
                // not terminal: it keeps blocking this principal with no
                // operator route out. Staging and validation only read, so
                // nothing was written and discarding is truthful.
                let detail = self
                    .release_unwritten_nat(
                        &operation_id,
                        &owner,
                        &expected_plan_digest,
                        &transaction,
                        cancellation,
                    )
                    .await;
                return Err(SdcError::ChangeControl(format!("{error}; {detail}")));
            }
        };
        let outcome = match self
            .coordinator
            .commit_operation(
                &operation_id,
                &self.tenant,
                &owner,
                &expected_plan_digest,
                &self.nat_signature,
                &transaction,
                &staged,
                attribution,
                &CommitOptions::default(),
                cancellation,
            )
            .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                // Only a refusal that happened before anything was sent is safe
                // to discard. If the write may have landed, leaving the record
                // for reconciliation is the honest outcome even though it
                // blocks this principal.
                if !transaction.refused_before_write() {
                    return Err(SdcError::ChangeControl(error.to_string()));
                }
                let detail = self
                    .release_unwritten_nat(
                        &operation_id,
                        &owner,
                        &expected_plan_digest,
                        &transaction,
                        cancellation,
                    )
                    .await;
                return Err(SdcError::ChangeControl(format!("{error}; {detail}")));
            }
        };
        Ok(NatApplyResult {
            operation_id,
            plan,
            validation,
            outcome,
        })
    }

    /// Resolve a preview and create its digest-bound two-person plan.
    pub async fn prepare(
        &self,
        owner: String,
        policies: Vec<PolicyOperation>,
        cancellation: &CancellationToken,
    ) -> Result<PrepareResult, SdcError> {
        for operation in &policies {
            crate::models::validate_deploy_targets(&operation.deploy_targets)?;
            crate::models::validate_deploy_targets(&operation.undeploy_targets)?;
        }
        let prepared = self
            .client
            .prepare_policy_deploy(policies, cancellation)
            .await?;
        let change_set = self
            .coordinator
            .create_change_set(
                self.tenant.clone(),
                vec![prepared.clone()],
                owner.clone(),
                prepared.preview_digest().to_owned(),
                self.policy_signature.clone(),
            )
            .await
            .map_err(|error| SdcError::ChangeControl(error.to_string()))?;
        let change_set = self.waive_if_lab_mode(change_set, &owner).await?;
        Ok(PrepareResult {
            change_set,
            prepared_change: prepared,
        })
    }

    /// Waive approval at creation when the server runs in lab mode.
    ///
    /// `mecmcp/docs/PACKAGING.md` requires the waiver be applied automatically
    /// at creation rather than through a separate tool: starting the service
    /// with `--lab-mode` is already the deliberate decision to run without a
    /// second reviewer, and the operator's flow stays plan-then-apply exactly
    /// as in production.
    ///
    /// Setting the coordinator's `lab_mode` flag alone is **not** enough —
    /// nothing waives, and a single operator still cannot move a plan past
    /// `Planned`. mecmcp#94 recorded exactly that defect on a sibling server,
    /// where the flag was wired but no caller invoked the waiver. A test pins
    /// this so the flag cannot become inert again.
    ///
    /// Upstream refuses the waiver unless lab mode is on and the caller owns
    /// the change set, and records it as `approver: null` with
    /// `approval_waiver: "lab-mode"` plus its own digest.
    async fn waive_if_lab_mode(
        &self,
        change_set: ChangeSetOutput,
        owner: &str,
    ) -> Result<ChangeSetOutput, SdcError> {
        if !self.coordinator.lab_mode() {
            return Ok(change_set);
        }
        self.coordinator
            .waive_approval(
                change_set.change_set_id.clone(),
                self.tenant.clone(),
                owner.to_owned(),
                change_set.digest.clone(),
            )
            .await
            .map_err(|error| SdcError::ChangeControl(error.to_string()))
    }

    /// Record an independent principal's approval of one exact plan digest.
    pub async fn approve(
        &self,
        change_set_id: String,
        approver: String,
        expected_digest: String,
    ) -> Result<ChangeSetOutput, SdcError> {
        self.coordinator
            .approve_change_set(
                change_set_id,
                self.tenant.clone(),
                approver,
                expected_digest,
            )
            .await
            .map_err(|error| SdcError::ChangeControl(error.to_string()))
    }

    /// Return current shared change-set state.
    pub async fn status(&self, change_set_id: String) -> Result<ChangeSetOutput, SdcError> {
        self.coordinator
            .change_set_status(change_set_id, self.tenant.clone())
            .await
            .map_err(|error| SdcError::ChangeControl(error.to_string()))
    }

    /// Retrieve the prepared change from a change set, including preview_digest.
    ///
    /// This method accesses the stored change-set actions and deserializes the first
    /// action as `SdcPreparedChange`, returning it if valid. Use this to recover the
    /// preview digest after `prepare_sdc_policy_deploy` when the original `PrepareResult`
    /// was not persisted by the caller.
    ///
    /// # Errors
    ///
    /// Returns an error if the change set does not exist, the actions cannot be
    /// deserialized as `SdcPreparedChange`, or the change set has no actions.
    pub async fn prepared_change(
        &self,
        change_set_id: String,
    ) -> Result<SdcPreparedChange, SdcError> {
        let record = self
            .coordinator
            .change_set(&change_set_id, &self.endpoint)
            .await
            .map_err(|error| SdcError::ChangeControl(error.to_string()))?;

        let action = record
            .actions
            .first()
            .ok_or_else(|| SdcError::ChangeControl("change set has no actions".to_owned()))?;

        serde_json::from_value::<SdcPreparedChange>(action.clone()).map_err(|error| {
            SdcError::ChangeControl(format!("failed to deserialize prepared change: {error}"))
        })
    }

    /// Apply, diff, validate, and deploy one exact approved plan.
    #[allow(clippy::too_many_arguments)]
    pub async fn apply(
        &self,
        change_set_id: String,
        owner: String,
        expected_digest: String,
        expected_preview_digest: String,
        attribution: &Attribution,
        cancellation: &CancellationToken,
    ) -> Result<ApplyResult, SdcError> {
        let transaction = SdcTransaction::new(
            self.client.clone(),
            expected_preview_digest.clone(),
            cancellation.clone(),
        );
        let applied = self
            .coordinator
            .apply_change_set(
                change_set_id,
                self.tenant.clone(),
                self.endpoint.clone(),
                owner.clone(),
                expected_digest,
                expected_preview_digest.clone(),
                &transaction,
                "policy_deploy",
                None,
                attribution,
                cancellation,
            )
            .await
            .map_err(|error| SdcError::ChangeControl(error.to_string()))?;
        let operation_id = applied.operation_id;
        let staged = applied.staged;
        let preview = self
            .coordinator
            .diff_operation(
                &operation_id,
                &self.tenant,
                &owner,
                &expected_preview_digest,
                &transaction,
                &staged,
                cancellation,
            )
            .await
            .map_err(|error| SdcError::ChangeControl(error.to_string()))?;
        let validation = self
            .coordinator
            .validate_operation(
                &operation_id,
                &self.tenant,
                &owner,
                &expected_preview_digest,
                &transaction,
                &staged,
                cancellation,
            )
            .await
            .map_err(|error| SdcError::ChangeControl(error.to_string()))?;
        let outcome = self
            .coordinator
            .commit_operation(
                &operation_id,
                &self.tenant,
                &owner,
                &expected_preview_digest,
                &self.policy_signature,
                &transaction,
                &staged,
                attribution,
                &CommitOptions::default(),
                cancellation,
            )
            .await
            .map_err(|error| SdcError::ChangeControl(error.to_string()))?;
        Ok(ApplyResult {
            operation_id,
            preview,
            validation,
            outcome,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PolicyType, Target, TargetType};
    use axum::{
        Json, Router,
        extract::State,
        routing::{get, post},
    };
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use url::Url;

    #[derive(Default)]
    struct Calls {
        previews: AtomicUsize,
        deploys: AtomicUsize,
    }

    async fn preview(State(calls): State<Arc<Calls>>, Json(body): Json<Value>) -> Json<Value> {
        calls.previews.fetch_add(1, Ordering::SeqCst);
        assert_eq!(body["policies"][0]["policy_id"], "policy-1");
        assert_eq!(
            body["policies"][0]["deploy_targets"][0]["target_id"],
            "device-1"
        );
        Json(json!({"preview_id": "preview-1"}))
    }

    async fn deploy(State(calls): State<Arc<Calls>>, Json(body): Json<Value>) -> Json<Value> {
        calls.deploys.fetch_add(1, Ordering::SeqCst);
        assert_eq!(
            body,
            json!({"policies": [{"policy_id": "policy-1", "policy_type": "FIREWALL"}]})
        );
        Json(json!({"deploy_id": "deploy-1"}))
    }

    async fn serve(app: Router) -> (Url, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let address = listener.local_addr().expect("test listener address");
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve test application");
        });
        (
            Url::parse(&format!("http://{address}/")).expect("test URL"),
            task,
        )
    }

    fn prepared_fixture() -> SdcPreparedChange {
        SdcPreparedChange::new(
            vec![crate::SdcPreparedTarget::new("device", "device-1").expect("target")],
            json!({"policies": [{"policy_id": "policy-1", "policy_type": "FIREWALL"}]}),
            json!({"status": {"status": "COMPLETED", "device_deployment_status": [], "message": ""}}),
            "preview-1".to_owned(),
        )
        .expect("prepared change")
    }

    #[tokio::test]
    async fn stage_still_rejects_a_tampered_envelope() {
        // `diff`, `validate`, and `commit` no longer revalidate, so `stage` is
        // the only place a persisted envelope is checked against its digest.
        // If that check ever weakens, a mutated preview reaches deployment.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = SdcClient::from_test_parts(
            Url::parse("https://example.invalid/").expect("url"),
            "test-secret".to_owned(),
            64 * 1024,
            100,
        );
        let prepared = prepared_fixture();
        let transaction = SdcTransaction::new(
            client,
            prepared.preview_digest().to_owned(),
            CancellationToken::new(),
        );

        // The untouched envelope stages, so the rejection below is not vacuous.
        transaction
            .stage(std::slice::from_ref(&prepared))
            .await
            .expect("an intact envelope stages");

        let mut raw = serde_json::to_value(&prepared).expect("serializes");
        raw["preview"]["status"]["message"] = json!("tampered after approval");
        let tampered: SdcPreparedChange =
            serde_json::from_value(raw).expect("tampered envelope still deserializes");

        let error = transaction
            .stage(&[tampered])
            .await
            .expect_err("a preview that no longer matches its digest must be refused");
        assert!(matches!(error, SdcError::PreparedChange(_)), "{error:?}");
    }

    #[tokio::test]
    async fn wrong_expected_preview_digest_names_the_right_field() {
        // Issue #52: when expected_preview_digest is wrong, the error must name
        // that field, not expected_digest.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = SdcClient::from_test_parts(
            Url::parse("https://example.invalid/").expect("url"),
            "test-secret".to_owned(),
            64 * 1024,
            100,
        );
        let prepared = prepared_fixture();
        let wrong_digest =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        let transaction =
            SdcTransaction::new(client, wrong_digest.to_owned(), CancellationToken::new());

        let error = transaction
            .stage(std::slice::from_ref(&prepared))
            .await
            .expect_err("wrong expected_preview_digest must be refused");
        match error {
            SdcError::PreparedChange(msg) => {
                assert!(
                    msg.contains("expected_preview_digest"),
                    "error message must name expected_preview_digest, not expected_digest; got: {msg}"
                );
            }
            _ => panic!("expected PreparedChange error, got {error:?}"),
        }
    }

    /// Lab mode is the single-operator path, and it must stay auditable.
    ///
    /// `mecmcp/docs/PACKAGING.md`: the waiver is applied automatically at
    /// creation rather than through a separate tool, so the operator's flow
    /// stays plan-then-apply exactly as in production.
    #[tokio::test]
    async fn lab_mode_lets_one_operator_apply_and_records_the_waiver() {
        let calls = Arc::new(Calls::default());
        let app = Router::new()
            .route("/api/v1/policies/preview", post(preview))
            .route(
                "/api/v1/policies/preview/{id}",
                get(|| async {
                    Json(json!({
                        "preview_id": "preview-1",
                        "status": "COMPLETED",
                        "device_deployment_status": [],
                        "message": ""
                    }))
                }),
            )
            .route("/api/v1/policies/deploy", post(deploy))
            .route(
                "/api/v1/policies/deploy/{id}",
                get(|| async {
                    Json(json!({
                        "deploy_id": "deploy-1",
                        "status": "COMPLETED",
                        "device_deployment_status": [],
                        "message": ""
                    }))
                }),
            )
            .with_state(calls.clone());
        let (base_url, server) = serve(app).await;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client =
            SdcClient::from_test_parts(base_url.clone(), "test-secret".to_owned(), 64 * 1024, 100);
        let manager = ChangeManager::load(
            client,
            "tenant-a",
            base_url.to_string(),
            None,
            Duration::from_secs(60),
            true,
        )
        .expect("change manager");
        let cancellation = CancellationToken::new();

        let prepared = manager
            .prepare(
                "alice".to_owned(),
                vec![PolicyOperation {
                    policy_id: "policy-1".to_owned(),
                    policy_type: PolicyType::Firewall,
                    deploy_targets: vec![Target::device("device-1")],
                    undeploy_targets: Vec::new(),
                }],
                &cancellation,
            )
            .await
            .expect("prepare");

        // No approver is ever fabricated: the waiver leaves the field null
        // rather than writing the owner into it (mecmcp#54).
        let planned = serde_json::to_value(&prepared.change_set)
            .expect("serialize change set")
            .to_string();
        assert!(
            !planned.contains("\"approver\":\"alice\""),
            "lab mode must not fabricate an approver; got {planned}"
        );
        assert!(
            planned.contains("lab-mode"),
            "the waiver must be recorded at creation so a waived change set is \
             never mistaken for a genuine two-person approval; got {planned}"
        );

        let change_set_id = prepared.change_set.change_set_id.clone();

        // No second principal, and no separate waive call: the operator's flow
        // stays plan-then-apply, exactly as in production.
        let result = manager
            .apply(
                change_set_id.clone(),
                "alice".to_owned(),
                prepared.change_set.digest,
                prepared.prepared_change.preview_digest().to_owned(),
                &Attribution::stdio(),
                &cancellation,
            )
            .await
            .expect("a single operator applies in lab mode");
        assert!(matches!(result.outcome, CommitOutcome::Reconciled { .. }));
        assert_eq!(calls.deploys.load(Ordering::SeqCst), 1);

        let applied = serde_json::to_value(
            manager
                .status(change_set_id)
                .await
                .expect("status after apply"),
        )
        .expect("serialize status")
        .to_string();
        assert!(
            !applied.contains("\"approver\":\"alice\""),
            "an applied waived change set must still show no approver; got {applied}"
        );
        assert!(
            applied.contains("lab-mode"),
            "the waiver must survive into the applied record; got {applied}"
        );

        server.abort();
    }

    #[tokio::test]
    async fn deployment_requires_preview_and_independent_approval() {
        let calls = Arc::new(Calls::default());
        let app = Router::new()
            .route("/api/v1/policies/preview", post(preview))
            .route(
                "/api/v1/policies/preview/{id}",
                get(|| async {
                    Json(json!({
                        "preview_id": "preview-1",
                        "status": "COMPLETED",
                        "device_deployment_status": [],
                        "message": ""
                    }))
                }),
            )
            .route("/api/v1/policies/deploy", post(deploy))
            .route(
                "/api/v1/policies/deploy/{id}",
                get(|| async {
                    Json(json!({
                        "deploy_id": "deploy-1",
                        "status": "COMPLETED",
                        "device_deployment_status": [],
                        "message": ""
                    }))
                }),
            )
            .with_state(calls.clone());
        let (base_url, server) = serve(app).await;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client =
            SdcClient::from_test_parts(base_url.clone(), "test-secret".to_owned(), 64 * 1024, 100);
        let manager = ChangeManager::load(
            client,
            "tenant-a",
            base_url.to_string(),
            None,
            Duration::from_secs(60),
            false,
        )
        .expect("change manager");
        let cancellation = CancellationToken::new();
        let prepared = manager
            .prepare(
                "alice".to_owned(),
                vec![PolicyOperation {
                    policy_id: "policy-1".to_owned(),
                    policy_type: PolicyType::Firewall,
                    deploy_targets: vec![Target::device("device-1")],
                    undeploy_targets: Vec::new(),
                }],
                &cancellation,
            )
            .await
            .expect("prepare");
        assert_eq!(calls.previews.load(Ordering::SeqCst), 1);
        assert_eq!(calls.deploys.load(Ordering::SeqCst), 0);

        let self_approval = manager
            .approve(
                prepared.change_set.change_set_id.clone(),
                "alice".to_owned(),
                prepared.change_set.digest.clone(),
            )
            .await;
        assert!(self_approval.is_err());
        manager
            .approve(
                prepared.change_set.change_set_id.clone(),
                "bob".to_owned(),
                prepared.change_set.digest.clone(),
            )
            .await
            .expect("independent approval");

        let result = manager
            .apply(
                prepared.change_set.change_set_id,
                "alice".to_owned(),
                prepared.change_set.digest,
                prepared.prepared_change.preview_digest().to_owned(),
                &Attribution::stdio(),
                &cancellation,
            )
            .await
            .expect("apply approved plan");
        assert!(matches!(
            result.outcome,
            CommitOutcome::Reconciled {
                succeeded: true,
                ..
            }
        ));
        assert_eq!(calls.deploys.load(Ordering::SeqCst), 1);
        server.abort();
    }

    fn object_fixture(before: Value) -> SdcPreparedObjectWrite {
        SdcPreparedObjectWrite::new(
            ObjectWriteAction::Update,
            ResourceKind::Addresses,
            Some("addr-1".to_owned()),
            json!({"name": "lab-net", "address_type": "IPV4"}),
            before,
        )
        .expect("prepared object write")
    }

    #[test]
    fn a_prepared_object_write_must_match_the_shape_of_its_action() {
        // Create carries no UUID and no prior state; update and delete require
        // both. A mismatch means the envelope was built or persisted wrong.
        assert!(
            SdcPreparedObjectWrite::new(
                ObjectWriteAction::Create,
                ResourceKind::Addresses,
                Some("addr-1".to_owned()),
                json!({"name": "x"}),
                Value::Null,
            )
            .is_err(),
            "create must not carry a target UUID"
        );
        assert!(
            SdcPreparedObjectWrite::new(
                ObjectWriteAction::Delete,
                ResourceKind::Addresses,
                Some("addr-1".to_owned()),
                json!({"name": "x"}),
                json!({"uuid": "addr-1"}),
            )
            .is_err(),
            "delete must not carry a request body"
        );
        assert!(
            SdcPreparedObjectWrite::new(
                ObjectWriteAction::Update,
                ResourceKind::Addresses,
                None,
                json!({"name": "x"}),
                json!({"uuid": "addr-1"}),
            )
            .is_err(),
            "update must carry a target UUID"
        );
    }

    #[test]
    fn a_prepared_object_write_rejects_a_body_the_client_would_refuse() {
        // An empty object is refused by create_resource/update_resource. If the
        // envelope accepted it, a plan could be independently approved and only
        // then fail, burning the change set for no reason.
        for action in [ObjectWriteAction::Create, ObjectWriteAction::Update] {
            let uuid = matches!(action, ObjectWriteAction::Update).then(|| "addr-1".to_owned());
            let before = if uuid.is_some() {
                json!({"uuid": "addr-1"})
            } else {
                Value::Null
            };
            assert!(
                SdcPreparedObjectWrite::new(
                    action,
                    ResourceKind::Addresses,
                    uuid,
                    json!({}),
                    before,
                )
                .is_err(),
                "{action:?} must refuse an empty body at prepare time"
            );
        }
    }

    #[tokio::test]
    async fn a_planned_object_write_can_be_released_because_nothing_was_written() {
        // `Failed` is not terminal in the coordinator, so a refused write must
        // be able to reach `Discarded`. Discard runs rollback first, and it is
        // only reachable pre-commit, so reporting success is accurate.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = SdcClient::from_test_parts(
            Url::parse("https://example.invalid/").expect("url"),
            "test-secret".to_owned(),
            64 * 1024,
            100,
        );
        let transaction =
            SdcObjectTransaction::new(client, "sha256:unused".to_owned(), CancellationToken::new());

        let outcome = transaction
            .rollback(mecmcp_changeset::RollbackRef::CandidateRevert)
            .await
            .expect("releasing an uncommitted object write must succeed");
        assert!(outcome.succeeded);

        transaction
            .rollback(mecmcp_changeset::RollbackRef::Archive(1))
            .await
            .expect_err("SDC has no rollback archive to load");
    }

    #[tokio::test]
    async fn object_write_stage_rejects_a_tampered_envelope() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = SdcClient::from_test_parts(
            Url::parse("https://example.invalid/").expect("url"),
            "test-secret".to_owned(),
            64 * 1024,
            100,
        );
        let prepared = object_fixture(json!({"uuid": "addr-1", "name": "as-prepared"}));
        let transaction = SdcObjectTransaction::new(
            client,
            prepared.plan_digest().to_owned(),
            CancellationToken::new(),
        );

        transaction
            .stage(std::slice::from_ref(&prepared))
            .await
            .expect("an intact envelope stages");

        let mut raw = serde_json::to_value(&prepared).expect("serializes");
        raw["request"]["name"] = json!("swapped after approval");
        let tampered: SdcPreparedObjectWrite =
            serde_json::from_value(raw).expect("tampered envelope still deserializes");

        transaction
            .stage(std::slice::from_ref(&tampered))
            .await
            .expect_err("a mutated request must not reach commit");
    }

    #[tokio::test]
    async fn object_write_refuses_a_target_that_drifted_since_prepare() {
        // An object write has no SDC preview to bind, so this drift check is
        // what makes the approved digest meaningful at apply time.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let app = Router::new().route(
            "/api/v1/addresses/addr-1",
            get(|| async { Json(json!({"uuid": "addr-1", "name": "changed-by-someone-else"})) }),
        );
        let (base_url, server) = serve(app).await;
        let client = SdcClient::from_test_parts(base_url, "test-secret".to_owned(), 64 * 1024, 100);
        let prepared = object_fixture(json!({"uuid": "addr-1", "name": "as-prepared"}));
        let transaction = SdcObjectTransaction::new(
            client,
            prepared.plan_digest().to_owned(),
            CancellationToken::new(),
        );
        let staged = transaction
            .stage(std::slice::from_ref(&prepared))
            .await
            .expect("stages");
        let error = transaction
            .validate(&staged)
            .await
            .expect_err("a drifted target must refuse");
        assert!(
            matches!(&error, SdcError::TargetDrifted),
            "unexpected error: {error:?}"
        );
        assert!(
            !transaction.refused_before_write(),
            "a validation refusal is not a commit-boundary refusal"
        );

        // The same drift must also stop the write itself, since the coordinator
        // drops and reacquires its guard between validate and commit.
        let error = transaction
            .commit(
                &staged,
                &Attribution::stdio(),
                &mecmcp_changeset::CommitOptions::default(),
            )
            .await
            .expect_err("a drifted target must not be written");
        assert!(
            matches!(&error, SdcError::TargetDrifted),
            "unexpected error: {error:?}"
        );
        assert!(
            transaction.refused_before_write(),
            "a commit-boundary refusal must be discardable"
        );
        server.abort();
    }

    #[tokio::test]
    async fn a_failed_pre_write_recheck_is_still_discardable() {
        // The recheck read itself can fail -- another actor deletes the target,
        // or the read errors transiently. Nothing was sent, so that must remain
        // discardable rather than stranding the tenant on a Failed record.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let app = Router::new().route(
            "/api/v1/addresses/addr-1",
            get(|| async { (axum::http::StatusCode::NOT_FOUND, Json(json!({}))) }),
        );
        let (base_url, server) = serve(app).await;
        let client = SdcClient::from_test_parts(base_url, "test-secret".to_owned(), 64 * 1024, 100);
        let prepared = object_fixture(json!({"uuid": "addr-1", "name": "as-prepared"}));
        let transaction = SdcObjectTransaction::new(
            client,
            prepared.plan_digest().to_owned(),
            CancellationToken::new(),
        );
        transaction
            .commit(
                &prepared,
                &Attribution::stdio(),
                &mecmcp_changeset::CommitOptions::default(),
            )
            .await
            .expect_err("a target that vanished must not be written");
        assert!(
            transaction.refused_before_write(),
            "a failed pre-write read must still be discardable"
        );
        server.abort();
    }

    #[tokio::test]
    async fn object_write_validates_when_the_target_is_unchanged() {
        // Guards against the drift check above passing vacuously.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let app = Router::new().route(
            "/api/v1/addresses/addr-1",
            get(|| async { Json(json!({"uuid": "addr-1", "name": "as-prepared"})) }),
        );
        let (base_url, server) = serve(app).await;
        let client = SdcClient::from_test_parts(base_url, "test-secret".to_owned(), 64 * 1024, 100);
        let prepared = object_fixture(json!({"uuid": "addr-1", "name": "as-prepared"}));
        let transaction = SdcObjectTransaction::new(
            client,
            prepared.plan_digest().to_owned(),
            CancellationToken::new(),
        );
        let staged = transaction
            .stage(std::slice::from_ref(&prepared))
            .await
            .expect("stages");
        let report = transaction
            .validate(&staged)
            .await
            .expect("an unchanged target validates");
        assert!(report.valid && report.target_unchanged);
        server.abort();
    }

    #[tokio::test]
    async fn license_write_refuses_drift_through_full_prepare_path() {
        // This tests the PREPARE layer: that prepare_license_write reads the
        // current state and binds it into the digest, so apply can detect drift.
        // The license_write.rs tests verify the transaction machinery given a
        // populated before; this tests that prepare actually populates it.
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Stub the license listing endpoint to return initial state at prepare time
        let initial_state = Arc::new(std::sync::Mutex::new(json!({
            "items": [{"uuid": "lic-1", "name": "initial"}],
            "count": 1
        })));
        let state_for_route = initial_state.clone();

        let app = Router::new().route(
            "/api/v1/devices/device-123/licenses",
            get(move || {
                let state = state_for_route.lock().expect("test mutex").clone();
                async move { Json(state) }
            }),
        );
        let (base_url, server) = serve(app).await;
        let client =
            SdcClient::from_test_parts(base_url.clone(), "test-secret".to_owned(), 64 * 1024, 100);
        let manager = ChangeManager::load(
            client.clone(),
            "tenant-a",
            base_url.to_string(),
            None,
            Duration::from_secs(60),
            false,
        )
        .expect("change manager");
        let cancellation = CancellationToken::new();

        // Call the real prepare_license_write - this must read and bind the initial state
        let prepared = manager
            .prepare_license_write(
                "alice".to_owned(),
                crate::LicenseWriteOperation::InstallLicense,
                "device-123".to_owned(),
                json!({"license_key": "NEW-KEY"}),
                &cancellation,
            )
            .await
            .expect("prepare");

        // The prepared change MUST have captured the observed license state,
        // not Value::Null. This is what binds into the plan digest.
        assert!(
            !prepared.prepared_change.before().is_null(),
            "prepare must read and bind the actual license state, not Null"
        );
        assert_eq!(
            prepared.prepared_change.before()["items"][0]["uuid"],
            "lic-1",
            "prepare must capture the exact observed state"
        );

        // Now drift the state - someone else added a license
        *initial_state.lock().expect("test mutex") = json!({
            "items": [
                {"uuid": "lic-1", "name": "initial"},
                {"uuid": "lic-2", "name": "added-by-someone-else"}
            ],
            "count": 2
        });

        // Try to validate - must refuse because the state drifted
        let transaction = crate::SdcLicenseTransaction::new(
            client,
            prepared.prepared_change.plan_digest().to_owned(),
            cancellation.clone(),
        );
        let staged = transaction
            .stage(std::slice::from_ref(&prepared.prepared_change))
            .await
            .expect("stages");

        let error = transaction
            .validate(&staged)
            .await
            .expect_err("a drifted license state must refuse");
        assert!(
            matches!(&error, SdcError::TargetDrifted),
            "unexpected error: {error:?}"
        );

        server.abort();
    }

    #[tokio::test]
    async fn certificate_delete_refuses_drift_through_full_prepare_path() {
        // DeleteCertificate is the sharp case: drift means deleting the wrong cert.
        // This must go through the real prepare path to prove it reads both lists.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let ca_state = Arc::new(std::sync::Mutex::new(json!({
            "items": [{"uuid": "ca-1", "name": "original-ca"}],
            "count": 1
        })));
        let local_state = Arc::new(std::sync::Mutex::new(json!({
            "items": [{"uuid": "local-1", "name": "original-local"}],
            "count": 1
        })));

        let ca_for_route = ca_state.clone();
        let local_for_route = local_state.clone();

        let app = Router::new()
            .route(
                "/api/v1/devices/device-456/ca_certificates",
                get(move || {
                    let state = ca_for_route.lock().expect("test mutex").clone();
                    async move { Json(state) }
                }),
            )
            .route(
                "/api/v1/devices/device-456/local_certificates",
                get(move || {
                    let state = local_for_route.lock().expect("test mutex").clone();
                    async move { Json(state) }
                }),
            );

        let (base_url, server) = serve(app).await;
        let client =
            SdcClient::from_test_parts(base_url.clone(), "test-secret".to_owned(), 64 * 1024, 100);
        let manager = ChangeManager::load(
            client.clone(),
            "tenant-a",
            base_url.to_string(),
            None,
            Duration::from_secs(60),
            false,
        )
        .expect("change manager");
        let cancellation = CancellationToken::new();

        // Prepare a certificate deletion - reads both CA and local cert lists
        let prepared = manager
            .prepare_license_write(
                "alice".to_owned(),
                crate::LicenseWriteOperation::DeleteCertificate,
                "device-456".to_owned(),
                json!({"certificate_id": "ca-1"}),
                &cancellation,
            )
            .await
            .expect("prepare");

        // The prepared change MUST have captured both certificate lists.
        // DeleteCertificate reads both CA and local certs since either could be deleted.
        assert!(
            !prepared.prepared_change.before().is_null(),
            "prepare must read certificate state, not Null"
        );
        assert!(
            prepared.prepared_change.before()["ca_certificates"].is_object(),
            "prepare must read CA certificates"
        );
        assert!(
            prepared.prepared_change.before()["local_certificates"].is_object(),
            "prepare must read local certificates"
        );

        // Drift: the CA cert was replaced between prepare and apply
        *ca_state.lock().expect("test mutex") = json!({
            "items": [{"uuid": "ca-2", "name": "replaced-by-someone-else"}],
            "count": 1
        });

        // Try to validate - must refuse to prevent deleting the replacement
        let transaction = crate::SdcLicenseTransaction::new(
            client,
            prepared.prepared_change.plan_digest().to_owned(),
            cancellation,
        );
        let staged = transaction
            .stage(std::slice::from_ref(&prepared.prepared_change))
            .await
            .expect("stages");

        let error = transaction
            .validate(&staged)
            .await
            .expect_err("drifted certificate state must refuse deletion");
        assert!(
            matches!(&error, SdcError::TargetDrifted),
            "unexpected error: {error:?}"
        );

        server.abort();
    }

    #[tokio::test]
    async fn a_device_group_target_is_refused_before_any_sdc_request() {
        let calls = Arc::new(Calls::default());
        let app = Router::new()
            .route("/api/v1/policies/preview", post(preview))
            .with_state(calls.clone());
        let (base_url, server) = serve(app).await;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client =
            SdcClient::from_test_parts(base_url.clone(), "test-secret".to_owned(), 64 * 1024, 100);
        let manager = ChangeManager::load(
            client,
            "tenant-a",
            base_url.to_string(),
            None,
            Duration::from_secs(60),
            false,
        )
        .expect("change manager");

        let error = manager
            .prepare(
                "alice".to_owned(),
                vec![PolicyOperation {
                    policy_id: "policy-1".to_owned(),
                    policy_type: PolicyType::Firewall,
                    deploy_targets: vec![Target {
                        target_id: "group-1".to_owned(),
                        target_type: TargetType::DeviceGroup,
                    }],
                    undeploy_targets: Vec::new(),
                }],
                &CancellationToken::new(),
            )
            .await
            .expect_err("a device-group target must be refused");

        assert!(error.to_string().contains("DEVICE_GROUP"));
        assert_eq!(
            calls.previews.load(Ordering::SeqCst),
            0,
            "refusal must happen before a preview job is spent on the management plane"
        );
        server.abort();
    }

    #[tokio::test]
    async fn rollback_reports_that_sdc_already_reverted_rather_than_erroring() {
        // discard_operation is rollback's only caller, and it turns an Err into a
        // Failed or Indeterminate record. Indeterminate cannot be discarded again,
        // so erroring here makes a wedged operation permanently unrecoverable.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = SdcClient::from_test_parts(
            "https://sdc.invalid/".parse().expect("test url"),
            "test-secret".to_owned(),
            64 * 1024,
            100,
        );
        let transaction = SdcTransaction::new(client, "sha256:whatever", CancellationToken::new());

        let outcome = transaction
            .rollback(RollbackRef::CandidateRevert)
            .await
            .expect("rollback must not error: SDC has already reverted the device");

        assert!(outcome.succeeded);
        let details = outcome.details.expect("the reason must be recorded");
        assert!(
            details.contains("SDC"),
            "details must say who reverted the device; got: {details}"
        );
    }
}
