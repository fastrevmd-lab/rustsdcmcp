//! Device **inventory** sync: re-read a device's inventory into SDC's model.
//!
//! # What this is, and what it is not
//!
//! `BulkSyncDevices` **imports**, and it reconciles **inventory only**. Verified
//! against `vsrx-ci` on the live tenant (`docs/sdc-api/README.md` §5): the
//! device's commit log was unchanged across the sync, and the state it moved was
//! the inventory pair alone —
//!
//! | field | before | after |
//! |---|---|---|
//! | `device_sync_status` | `OUT_OF_SYNC` | `IN_SYNC` |
//! | `inventory_sync_info.overall_sync_status` | `OUT_OF_SYNC` | `IN_SYNC` |
//! | `device_config_state` | `OUT_OF_BAND_CHANGED` | **unchanged** |
//!
//! So this is **not** the remedy for a device that drifted through out-of-band
//! CLI edits, which was the motivating problem in rustsdcmcp#21. Whatever clears
//! `OUT_OF_BAND_CHANGED` is a different operation and is still unidentified.
//! Every name and description here says "inventory" for that reason: calling it
//! a configuration sync would tell an operator reconciliation happened when it
//! did not.
//!
//! # Why it is gated
//!
//! It writes no device, so "a mutation can break a network" does not apply. It
//! is gated because it changes what SDC believes about a device, and later
//! previews and deploys are computed against SDC's beliefs.
//!
//! # The job shape differs from every other SDC job
//!
//! `GetSyncStatus` answers `SUCCESS`/`FAILURE`, not the deploy path's
//! `PENDING`/`IN_PROGRESS`/`COMPLETED`/`PARTIAL_SUCCESS`/`FAILED`, so
//! [`DeviceSyncStatus`] exists rather than reusing `DeploymentStatus`. Polling
//! through the deploy vocabulary would never observe a terminal state: every
//! apply would burn its deadline and report a timeout on a sync that had already
//! succeeded.

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
    pub fn new(device_uuids: Vec<String>, before: Value) -> Result<Self, SdcError> {
        let device_uuids = Self::canonical_device_list(device_uuids)?;
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

    /// Check and canonicalise a device list without reading anything.
    ///
    /// Separated so a caller can refuse a malformed or oversized request
    /// *before* spending a read per device against the tenant — the bound is on
    /// outbound work, not only on what ends up in the plan.
    ///
    /// # Errors
    ///
    /// Refuses an empty or oversized list, a malformed UUID, or duplicates.
    pub fn canonical_device_list(mut device_uuids: Vec<String>) -> Result<Vec<String>, SdcError> {
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

        Ok(device_uuids)
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
        "direction": "import: reads each device's inventory and updates SDC's model; \
                      no device is written",
        "does_not": "reconcile configuration drift — device_config_state is left untouched",
        "device_uuids": device_uuids,
        "before": before,
    })
}

/// The inventory state `BulkSyncDevices` moves, as a comparable pair.
///
/// Anything else on the device record changes for reasons unrelated to this
/// operation, and comparing it would refuse plans over irrelevant drift.
fn inventory_state(device: &Value) -> (Option<String>, Option<String>) {
    let sync_status = device
        .get("device_sync_status")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let overall = device
        .get("inventory_sync_info")
        .and_then(|info| info.get("overall_sync_status"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    (sync_status, overall)
}

/// Terminal state of a device inventory sync.
///
/// `GetSyncStatus` answers `SUCCESS`/`FAILURE` and does not share the deploy
/// path's vocabulary. An unrecognised value is kept verbatim and treated as
/// non-terminal, so a vocabulary SDC adds later surfaces as a timeout rather
/// than as a silent success.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub enum DeviceSyncStatus {
    /// Every named device synced.
    Success,
    /// At least one device failed.
    Failure,
    /// A value absent from the observed vocabulary, kept verbatim.
    Unrecognized(String),
}

impl DeviceSyncStatus {
    /// Whether polling may stop.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Success | Self::Failure)
    }

    /// Whether the sync succeeded for every device.
    #[must_use]
    pub fn succeeded(&self) -> bool {
        matches!(self, Self::Success)
    }
}

impl From<String> for DeviceSyncStatus {
    fn from(value: String) -> Self {
        match value.as_str() {
            "SUCCESS" => Self::Success,
            "FAILURE" => Self::Failure,
            _ => Self::Unrecognized(value),
        }
    }
}

impl From<DeviceSyncStatus> for String {
    fn from(value: DeviceSyncStatus) -> Self {
        match value {
            DeviceSyncStatus::Success => "SUCCESS".to_owned(),
            DeviceSyncStatus::Failure => "FAILURE".to_owned(),
            DeviceSyncStatus::Unrecognized(other) => other,
        }
    }
}

/// One device's result within a sync job.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeviceSyncEntry {
    /// SDC device UUID.
    #[serde(default)]
    pub uuid: String,
    /// Device hostname as SDC reports it here — note this is the *hostname*,
    /// not the SDC device name, which differ on the live tenant.
    #[serde(default)]
    pub name: String,
    /// This device's outcome.
    pub status: DeviceSyncStatus,
    /// SDC's per-device message.
    #[serde(default)]
    pub message: String,
}

/// One `GetSyncStatus` response.
///
/// The per-device array is kept. A bulk sync where one device fails answers
/// overall `FAILURE` with a per-device entry for each; collapsing that to one
/// flag would tell an operator "it failed" while withholding which device and
/// why — the two things needed to act on it.
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceSyncJob {
    /// Overall job state.
    pub status: DeviceSyncStatus,
    /// Per-device results, when SDC supplies them.
    #[serde(default)]
    pub device_sync_status: Vec<DeviceSyncEntry>,
}

impl DeviceSyncJob {
    /// Devices that did not sync, as `uuid: message` pairs.
    #[must_use]
    pub fn failures(&self) -> Vec<String> {
        self.device_sync_status
            .iter()
            .filter(|entry| !entry.status.succeeded())
            .map(|entry| {
                let who = if entry.uuid.is_empty() {
                    entry.name.as_str()
                } else {
                    entry.uuid.as_str()
                };
                format!("{who}: {}", entry.message)
            })
            .collect()
    }
}

/// A sync that failed, and whether it had already been accepted.
///
/// The distinction is the whole point: before submission nothing happened and
/// the operation may be discarded; after submission SDC may be syncing right
/// now, and the `sync_id` is the only handle an operator has to find out.
#[derive(Debug)]
pub enum DeviceSyncFailure {
    /// Refused before anything was sent.
    BeforeSubmit(SdcError),
    /// Accepted, outcome unknown.
    AfterSubmit {
        /// Job identifier, for `GET /api/v1/devices/sync/{sync_id}`.
        sync_id: String,
        /// What went wrong while learning the outcome.
        source: SdcError,
    },
}

impl std::fmt::Display for DeviceSyncFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BeforeSubmit(error) => write!(formatter, "{error}"),
            Self::AfterSubmit { sync_id, source } => write!(
                formatter,
                "{source}; the sync was accepted as {sync_id} and may still be running \
                 — query GET /api/v1/devices/sync/{sync_id}"
            ),
        }
    }
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
    /// The fields compared are the ones this endpoint actually moves —
    /// `device_sync_status` and `inventory_sync_info.overall_sync_status`.
    /// Comparing `device_config_state` would look more meaningful and detect
    /// nothing: the live record shows this sync leaves it untouched, so a
    /// competing sync between prepare and apply would pass a check built on it
    /// while having already done the work being approved.
    async fn targets_unchanged(&self, staged: &SdcPreparedDeviceSync) -> Result<bool, SdcError> {
        for uuid in staged.device_uuids() {
            let current = self.client.get_device(uuid, &self.cancellation).await?;
            let then = staged
                .before()
                .get(uuid)
                .map(inventory_state)
                .unwrap_or_default();
            if inventory_state(&current) != then {
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
        match self
            .client
            .sync_devices(staged.device_uuids(), &self.cancellation)
            .await
        {
            Ok((sync_id, job)) => {
                let failures = job.failures();
                let detail = if failures.is_empty() {
                    format!(
                        "SDC synced inventory for {} device(s) with status {:?}",
                        staged.device_uuids().len(),
                        job.status
                    )
                } else {
                    // A bulk sync reports one overall status and a result per
                    // device. Reporting only the overall one tells an operator
                    // "it failed" and withholds which device and why.
                    format!(
                        "SDC inventory sync finished {:?}; {} device(s) failed: {}",
                        job.status,
                        failures.len(),
                        failures.join("; ")
                    )
                };
                Ok(CommitOutcome::Reconciled {
                    succeeded: job.status.succeeded() && failures.is_empty(),
                    job_id: Some(sync_id),
                    details: Some(detail),
                })
            }
            // Refused before anything was sent: nothing happened, and the
            // coordinator may discard the operation rather than strand it.
            Err(DeviceSyncFailure::BeforeSubmit(error)) => Err(error),
            // Accepted, outcome unlearned. `Failed` would be a claim that
            // nothing happened; SDC may be syncing right now. The `sync_id`
            // travels with the record because it is the only handle an operator
            // has for `GET /api/v1/devices/sync/{sync_id}`.
            Err(failure @ DeviceSyncFailure::AfterSubmit { .. }) => {
                Ok(CommitOutcome::Indeterminate {
                    reason: format!("device inventory sync outcome is unknown: {failure}"),
                })
            }
        }
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
            "dev-a": {
                "device_sync_status": "OUT_OF_SYNC",
                "inventory_sync_info": {"overall_sync_status": "OUT_OF_SYNC"},
                "device_config_state": "OUT_OF_BAND_CHANGED",
            },
            "dev-b": {
                "device_sync_status": "IN_SYNC",
                "inventory_sync_info": {"overall_sync_status": "IN_SYNC"},
            },
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
            json!({"dev-a": {
                "device_sync_status": "IN_SYNC",
                "inventory_sync_info": {"overall_sync_status": "IN_SYNC"},
            }}),
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
    fn the_plan_states_its_direction_and_its_limits() {
        let prepared =
            SdcPreparedDeviceSync::new(vec!["dev-a".to_owned()], before_state()).expect("prepare");

        let plan = prepared.plan();
        let direction = plan["direction"].as_str().unwrap_or_default();
        assert!(
            direction.contains("import") && direction.contains("no device is written"),
            "the plan must say which way the sync runs: {direction}"
        );
        assert!(direction.contains("inventory"), "{direction}");
        let limits = plan["does_not"].as_str().unwrap_or_default();
        assert!(
            limits.contains("device_config_state"),
            "the plan must say that configuration drift is NOT reconciled, or an \
             operator approving it will believe it was: {limits}"
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

    /// The status vocabulary is this endpoint's own. Reusing the deploy path's
    /// meant no value was ever terminal, so every apply burned its deadline and
    /// reported a timeout on a sync that had already succeeded.
    #[test]
    fn the_sync_vocabulary_is_terminal_where_the_deploy_one_is_not() {
        assert!(DeviceSyncStatus::from("SUCCESS".to_owned()).is_terminal());
        assert!(DeviceSyncStatus::from("SUCCESS".to_owned()).succeeded());
        assert!(DeviceSyncStatus::from("FAILURE".to_owned()).is_terminal());
        assert!(!DeviceSyncStatus::from("FAILURE".to_owned()).succeeded());
    }

    /// An unfamiliar value must keep polling rather than be read as success —
    /// a vocabulary SDC adds later should surface as a timeout, not as a silent
    /// completion.
    #[test]
    fn an_unrecognised_status_is_not_terminal() {
        let status = DeviceSyncStatus::from("PARTIAL".to_owned());

        assert!(
            !status.is_terminal(),
            "unknown states must not stop polling"
        );
        assert!(!status.succeeded());
        assert_eq!(
            String::from(status),
            "PARTIAL",
            "the wire value is kept verbatim"
        );
    }

    /// Drift must be judged on the fields this endpoint moves. Watching
    /// `device_config_state` would look meaningful and detect nothing, because
    /// the sync leaves it untouched.
    #[test]
    fn drift_is_detected_on_the_inventory_pair_this_sync_moves() {
        let planned =
            SdcPreparedDeviceSync::new(vec!["dev-a".to_owned()], before_state()).expect("prepare");

        // Someone else synced it: the inventory pair moved, config state did not.
        let after_someone_else_synced = json!({
            "device_sync_status": "IN_SYNC",
            "inventory_sync_info": {"overall_sync_status": "IN_SYNC"},
            "device_config_state": "OUT_OF_BAND_CHANGED",
        });
        let then = planned.before().get("dev-a").expect("planned device");

        assert_ne!(
            inventory_state(&after_someone_else_synced),
            inventory_state(then),
            "a competing sync must be visible in the fields this operation moves"
        );
    }

    /// The bound has to hold before any device is read, or it bounds nothing
    /// outbound: one bad identifier in last place would still cost a GET per
    /// preceding entry against the tenant's rate limit.
    #[test]
    fn the_device_list_is_checked_without_reading_anything() {
        let too_many: Vec<String> = (0..=MAX_DEVICES_PER_SYNC)
            .map(|n| format!("dev-{n}"))
            .collect();
        assert!(SdcPreparedDeviceSync::canonical_device_list(too_many).is_err());

        let malformed = vec!["dev-a".to_owned(), "bad uuid".to_owned()];
        assert!(SdcPreparedDeviceSync::canonical_device_list(malformed).is_err());

        let good = SdcPreparedDeviceSync::canonical_device_list(vec![
            "dev-b".to_owned(),
            "dev-a".to_owned(),
        ])
        .expect("a valid list canonicalises");
        assert_eq!(good, vec!["dev-a".to_owned(), "dev-b".to_owned()], "sorted");
    }

    /// A bulk sync answers one overall status and a result per device. Reporting
    /// only the overall one tells an operator "it failed" and withholds the two
    /// things they need: which device, and why.
    #[test]
    fn a_partial_failure_names_the_devices_that_failed() {
        let job = DeviceSyncJob {
            status: DeviceSyncStatus::Failure,
            device_sync_status: vec![
                DeviceSyncEntry {
                    uuid: "dev-a".to_owned(),
                    name: "host-a".to_owned(),
                    status: DeviceSyncStatus::Success,
                    message: "Successful sync inventory".to_owned(),
                },
                DeviceSyncEntry {
                    uuid: "dev-b".to_owned(),
                    name: "host-b".to_owned(),
                    status: DeviceSyncStatus::Failure,
                    message: "device unreachable".to_owned(),
                },
            ],
        };

        let failures = job.failures();

        assert_eq!(failures.len(), 1, "only the failed device is reported");
        assert!(failures[0].contains("dev-b"), "{failures:?}");
        assert!(failures[0].contains("device unreachable"), "{failures:?}");
    }

    /// After acceptance, every failure must carry the job id. An operator told
    /// "outcome unknown" with no handle cannot find out; the id is the only
    /// route to `GET /api/v1/devices/sync/{sync_id}`.
    #[test]
    fn a_post_submission_failure_carries_the_sync_id() {
        let failure = DeviceSyncFailure::AfterSubmit {
            sync_id: "3d5e881b".to_owned(),
            source: SdcError::JobDeadline,
        };

        let rendered = failure.to_string();

        assert!(rendered.contains("3d5e881b"), "{rendered}");
        assert!(
            rendered.contains("may still be running"),
            "the message must not read as a failure: {rendered}"
        );
    }

    /// Before submission nothing happened, and the message must not imply a job
    /// exists to go looking for.
    #[test]
    fn a_pre_submission_failure_mentions_no_job() {
        let failure = DeviceSyncFailure::BeforeSubmit(SdcError::InvalidInput("bad list"));

        let rendered = failure.to_string();

        assert!(!rendered.contains("sync_id"), "{rendered}");
        assert!(!rendered.contains("still be running"), "{rendered}");
    }
}
