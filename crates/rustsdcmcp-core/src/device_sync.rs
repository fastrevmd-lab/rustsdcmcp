//! Device configuration sync: re-read a device into SDC's model.
//!
//! # Direction
//!
//! `BulkSyncDevices` **imports**. It reads the device's running configuration
//! and updates SDC's model to match; it does not push SDC's view down onto the
//! device. The OpenAPI spec states no direction at all — description, request
//! body (`{"uuids": […]}`) and response (`{"sync_id": …}`) are all silent — so
//! this was settled by experiment against `vsrx-ci` on the live tenant,
//! snapshot-gated and scoped to one device: the device's commit log was
//! unchanged across the sync. Recorded in `docs/sdc-api/README.md` §5.
//!
//! That is the property this whole module depends on. If a future SDC release
//! changes it, everything here becomes a device write and the reasoning below
//! about blast radius stops holding.
//!
//! # Why it is still gated
//!
//! An import changes no device, so the usual argument — "a mutation can break a
//! network" — does not apply. It is gated anyway, for a different reason: it
//! changes what SDC believes is current, and every later preview and deploy is
//! computed against that belief. A sync that silently absorbs an out-of-band
//! change decides what a subsequent deploy will *not* flag as a difference.
//! That is a management-plane state change worth two people, and it is the
//! argument this module relies on rather than the device-safety one.

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

/// Cap on the encoded prepared change, matching the other write paths.
const MAX_ENVELOPE_BYTES: usize = 2 * 1024 * 1024;

/// Cap on devices in one sync.
///
/// A sync is bounded by how many devices an approver can reasonably review in
/// the plan, not by what the API accepts. The API takes an unbounded array.
const MAX_DEVICES_PER_SYNC: usize = 64;

/// Exact device sync bound into a change-set action.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdcPreparedDeviceSync {
    operation: String,
    device_uuids: Vec<String>,
    /// Each device's observed state at plan time, keyed by UUID.
    before: Value,
    plan_digest: String,
}

impl SdcPreparedDeviceSync {
    /// Build a canonical, digest-bound device sync.
    ///
    /// `before` is what each named device looked like when the plan was made —
    /// its `device_config_state` in particular, which is the field that says
    /// whether SDC thinks it has drifted. Binding it means an approver is
    /// approving a sync of devices in the state they were shown, and an apply
    /// can tell if that changed.
    ///
    /// # Errors
    ///
    /// Refuses an empty or oversized device list, a malformed UUID, duplicates,
    /// or an oversized envelope.
    pub fn new(mut device_uuids: Vec<String>, before: Value) -> Result<Self, SdcError> {
        if device_uuids.is_empty() {
            return Err(SdcError::PreparedChange(
                "device sync requires at least one device".to_owned(),
            ));
        }
        if device_uuids.len() > MAX_DEVICES_PER_SYNC {
            return Err(SdcError::PreparedChange(format!(
                "device sync covers {} devices, more than the {MAX_DEVICES_PER_SYNC} an approver \
                 can be expected to review",
                device_uuids.len()
            )));
        }
        for uuid in &device_uuids {
            if uuid.is_empty()
                || uuid.len() > 256
                || uuid
                    .bytes()
                    .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
            {
                return Err(SdcError::PreparedChange(
                    "device UUIDs must be 1-256 non-whitespace bytes".to_owned(),
                ));
            }
        }
        // Sorted so the digest does not depend on the order the caller happened
        // to list devices in; deduplicated because syncing a device twice in one
        // plan is a mistake, not an instruction.
        device_uuids.sort();
        let before_dedup = device_uuids.len();
        device_uuids.dedup();
        if device_uuids.len() != before_dedup {
            return Err(SdcError::PreparedChange(
                "device sync names the same device more than once".to_owned(),
            ));
        }

        let plan = plan_artifact(&device_uuids, &before);
        let prepared = Self {
            operation: "device_sync".to_owned(),
            device_uuids,
            before,
            plan_digest: canonical_digest(&plan)
                .map_err(|error| SdcError::PreparedChange(error.to_string()))?,
        };
        prepared.validate()?;
        Ok(prepared)
    }

    /// Devices this sync covers.
    #[must_use]
    pub fn device_uuids(&self) -> &[String] {
        &self.device_uuids
    }

    /// Observed state at plan time.
    #[must_use]
    pub const fn before(&self) -> &Value {
        &self.before
    }

    /// Canonical SHA-256 digest binding this plan.
    #[must_use]
    pub fn plan_digest(&self) -> &str {
        &self.plan_digest
    }

    /// Human-readable plan showing what this sync would read.
    #[must_use]
    pub fn plan(&self) -> Value {
        plan_artifact(&self.device_uuids, &self.before)
    }

    /// Revalidate shape, bounds, and digest integrity.
    ///
    /// # Errors
    ///
    /// Returns a stable error if persisted content was malformed or tampered.
    pub fn validate(&self) -> Result<(), SdcError> {
        if self.operation != "device_sync" {
            return Err(SdcError::PreparedChange(
                "prepared operation must be device_sync".to_owned(),
            ));
        }
        if self.device_uuids.is_empty() {
            return Err(SdcError::PreparedChange(
                "prepared device sync names no devices".to_owned(),
            ));
        }
        let plan = plan_artifact(&self.device_uuids, &self.before);
        if canonical_digest(&plan).map_err(|error| SdcError::PreparedChange(error.to_string()))?
            != self.plan_digest
        {
            return Err(SdcError::PreparedChange(
                "prepared device sync does not match its digest".to_owned(),
            ));
        }
        if serde_json::to_vec(self)
            .map_err(|_| SdcError::Serialization)?
            .len()
            > MAX_ENVELOPE_BYTES
        {
            return Err(SdcError::PreparedChange(format!(
                "prepared device sync exceeds the {MAX_ENVELOPE_BYTES}-byte limit"
            )));
        }
        Ok(())
    }
}

/// The plan an approver sees.
///
/// `direction` is stated explicitly rather than left implicit: an approver
/// reading "sync these devices" cannot otherwise tell whether they are about to
/// absorb a device's config or overwrite it.
fn plan_artifact(device_uuids: &[String], before: &Value) -> Value {
    json!({
        "action": "device_sync",
        "direction": "import: reads each device and updates SDC's model; no device is written",
        "device_uuids": device_uuids,
        "before": before,
    })
}

/// Outcome of revalidating a device sync immediately before it runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSyncValidationReport {
    /// Whether the envelope is intact and no device drifted.
    pub valid: bool,
    /// How many devices the sync covers.
    pub device_count: usize,
    /// Whether every device still matched the state observed at plan time.
    pub targets_unchanged: bool,
}

/// SDC implementation of the shared transaction contract for device sync.
#[derive(Clone)]
pub struct SdcDeviceSyncTransaction {
    client: SdcClient,
    expected_plan_digest: String,
    cancellation: CancellationToken,
    refused_before_write: Arc<AtomicBool>,
}

impl SdcDeviceSyncTransaction {
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
    #[must_use]
    pub fn refused_before_write(&self) -> bool {
        self.refused_before_write.load(Ordering::SeqCst)
    }

    /// Re-read every named device and report whether the plan still holds.
    ///
    /// The state that matters is `device_config_state`: it is what says whether
    /// SDC believes the device has drifted, and therefore what the sync is for.
    /// If a device that was `OUT_OF_BAND_CHANGED` at plan time now reads
    /// `IN_SYNC`, someone has already reconciled it and this plan describes work
    /// that no longer exists — approving one thing and doing another.
    async fn targets_unchanged(&self, staged: &SdcPreparedDeviceSync) -> Result<bool, SdcError> {
        for uuid in staged.device_uuids() {
            let current = self.client.get_device(uuid, &self.cancellation).await?;
            let now = current.get("device_config_state");
            let then = staged
                .before()
                .get(uuid)
                .and_then(|entry| entry.get("device_config_state"));
            if now != then {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

#[async_trait]
impl DeviceTransaction for SdcDeviceSyncTransaction {
    type Action = SdcPreparedDeviceSync;
    type Staged = SdcPreparedDeviceSync;
    type Diff = Value;
    type Validation = DeviceSyncValidationReport;
    type Error = SdcError;

    async fn fingerprint(&self) -> Result<String, Self::Error> {
        Ok(self.expected_plan_digest.clone())
    }

    async fn stage(&self, actions: &[Self::Action]) -> Result<Self::Staged, Self::Error> {
        let [prepared] = actions else {
            return Err(SdcError::InvalidInput(
                "an SDC device sync requires exactly one prepared change",
            ));
        };
        prepared.validate()?;
        if prepared.plan_digest() != self.expected_plan_digest {
            return Err(SdcError::PreparedChange(
                "prepared action does not match the approved plan digest".to_owned(),
            ));
        }
        Ok(prepared.clone())
    }

    async fn diff(&self, staged: &Self::Staged) -> Result<Self::Diff, Self::Error> {
        Ok(staged.plan())
    }

    async fn validate(&self, staged: &Self::Staged) -> Result<Self::Validation, Self::Error> {
        let targets_unchanged = self.targets_unchanged(staged).await?;
        if !targets_unchanged {
            return Err(SdcError::TargetDrifted);
        }
        Ok(DeviceSyncValidationReport {
            valid: true,
            device_count: staged.device_uuids().len(),
            targets_unchanged,
        })
    }

    async fn commit(
        &self,
        staged: &Self::Staged,
        _attribution: &Attribution,
        options: &CommitOptions,
    ) -> Result<CommitOutcome, Self::Error> {
        // Every exit from here until the request goes out is a pre-write
        // refusal: nothing was sent, so the caller may discard the operation
        // rather than strand a non-terminal record on the tenant.
        self.refused_before_write.store(true, Ordering::SeqCst);
        if options.confirm_timeout.is_some() {
            return Err(SdcError::InvalidInput(
                "SDC does not support confirmed device syncs",
            ));
        }
        // Re-check drift immediately before running. `validate` already did, but
        // the coordinator releases its guard in between, and that guard cannot
        // exclude someone working directly against SDC. This narrows the window
        // rather than closing it — SDC offers no conditional write.
        if !self.targets_unchanged(staged).await? {
            return Err(SdcError::TargetDrifted);
        }
        self.refused_before_write.store(false, Ordering::SeqCst);
        let (sync_id, status) = self
            .client
            .sync_devices(staged.device_uuids(), &self.cancellation)
            .await?;
        Ok(CommitOutcome::Reconciled {
            succeeded: status.succeeded(),
            job_id: Some(sync_id),
            details: Some(format!(
                "SDC imported {} device(s) with status {status:?}",
                staged.device_uuids().len()
            )),
        })
    }

    /// Release a planned-but-unrun sync.
    ///
    /// Nothing is staged remotely — SDC has no candidate store — and the
    /// coordinator only reaches `rollback` from pre-commit states, so reporting
    /// success is accurate and lets a refused sync reach `Discarded` instead of
    /// stranding a non-terminal record.
    async fn rollback(&self, to: RollbackRef) -> Result<RollbackOutcome, Self::Error> {
        match to {
            RollbackRef::CandidateRevert => Ok(RollbackOutcome {
                succeeded: true,
                details: Some(
                    "no remote candidate exists; SDC device syncs are not staged".to_owned(),
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
            "SDC does not support confirmed device syncs",
        ))
    }
}

/// Result of planning a device sync.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceSyncPrepareResult {
    /// Shared two-person change-set record.
    pub change_set: mecmcp_changeset::ChangeSetOutput,
    /// Exact sync bound by the plan digest.
    pub prepared_change: SdcPreparedDeviceSync,
}

/// Result of running one approved device sync.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceSyncApplyResult {
    /// Shared operation identifier.
    pub operation_id: String,
    /// The plan, including the direction the sync runs in.
    pub plan: Value,
    /// Drift and envelope validation result.
    pub validation: DeviceSyncValidationReport,
    /// Known, detached, or indeterminate disposition.
    pub outcome: CommitOutcome,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn before_state() -> Value {
        json!({
            "dev-a": {"device_config_state": "OUT_OF_BAND_CHANGED"},
            "dev-b": {"device_config_state": "IN_SYNC"},
        })
    }

    /// The digest must not depend on the order a caller happened to list
    /// devices in, or two identical plans would fail to compare equal and an
    /// approval could not be matched to an apply.
    #[test]
    fn device_order_does_not_change_the_digest() {
        let one = SdcPreparedDeviceSync::new(
            vec!["dev-a".to_owned(), "dev-b".to_owned()],
            before_state(),
        )
        .expect("prepare");
        let other = SdcPreparedDeviceSync::new(
            vec!["dev-b".to_owned(), "dev-a".to_owned()],
            before_state(),
        )
        .expect("prepare");

        assert_eq!(one.plan_digest(), other.plan_digest());
        assert_eq!(one.device_uuids(), other.device_uuids());
    }

    /// Naming a device twice is a mistake, not an instruction to sync it twice.
    #[test]
    fn a_repeated_device_is_refused() {
        let result = SdcPreparedDeviceSync::new(
            vec!["dev-a".to_owned(), "dev-a".to_owned()],
            before_state(),
        );

        assert!(result.is_err(), "a duplicate device must be refused");
    }

    /// The bound is what an approver can review, not what the API accepts.
    #[test]
    fn a_sync_larger_than_an_approver_can_review_is_refused() {
        let many: Vec<String> = (0..=MAX_DEVICES_PER_SYNC)
            .map(|n| format!("dev-{n}"))
            .collect();

        let result = SdcPreparedDeviceSync::new(many, before_state());

        assert!(result.is_err(), "an unreviewable sync must be refused");
    }

    /// The observed state is what the approval is bound to: if the devices'
    /// state differed at plan time, that is a different plan.
    #[test]
    fn a_different_observed_state_is_a_different_plan() {
        let planned =
            SdcPreparedDeviceSync::new(vec!["dev-a".to_owned()], before_state()).expect("prepare");
        let drifted = SdcPreparedDeviceSync::new(
            vec!["dev-a".to_owned()],
            json!({"dev-a": {"device_config_state": "IN_SYNC"}}),
        )
        .expect("prepare");

        assert_ne!(
            planned.plan_digest(),
            drifted.plan_digest(),
            "the digest must bind the state the approver was shown"
        );
    }

    /// An approver reading a plan cannot otherwise tell whether they are about
    /// to absorb a device's configuration or overwrite it. The direction is the
    /// single most important thing on this plan.
    #[test]
    fn the_plan_states_its_direction() {
        let prepared =
            SdcPreparedDeviceSync::new(vec!["dev-a".to_owned()], before_state()).expect("prepare");

        let plan = prepared.plan();
        let direction = plan["direction"].as_str().unwrap_or_default();
        assert!(
            direction.contains("import") && direction.contains("no device is written"),
            "the plan must say which way the sync runs: {direction}"
        );
    }

    /// Tampering with a persisted envelope must be caught on reload.
    #[test]
    fn a_tampered_envelope_fails_validation() {
        let prepared =
            SdcPreparedDeviceSync::new(vec!["dev-a".to_owned()], before_state()).expect("prepare");
        let mut raw = serde_json::to_value(&prepared).expect("serialize");
        raw["device_uuids"] = json!(["dev-a", "dev-smuggled"]);

        let tampered: SdcPreparedDeviceSync =
            serde_json::from_value(raw).expect("deserialize tampered");

        assert!(
            tampered.validate().is_err(),
            "a device added after approval must not validate"
        );
    }
}
