//! SDC adapter for the shared preview-bound, two-person change lifecycle.

use crate::{DeployRequest, JobStatus, PolicyOperation, SdcClient, SdcError, SdcPreparedChange};
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
                "prepared action does not match the approved preview digest".to_owned(),
            ));
        }
        Ok(prepared.clone())
    }

    async fn diff(&self, staged: &Self::Staged) -> Result<Self::Diff, Self::Error> {
        staged
            .validate()
            .map_err(|error| SdcError::PreparedChange(error.to_string()))?;
        Ok(staged.preview().clone())
    }

    async fn validate(&self, staged: &Self::Staged) -> Result<Self::Validation, Self::Error> {
        staged
            .validate()
            .map_err(|error| SdcError::PreparedChange(error.to_string()))?;
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
        staged
            .validate()
            .map_err(|error| SdcError::PreparedChange(error.to_string()))?;
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

    async fn rollback(&self, _to: RollbackRef) -> Result<RollbackOutcome, Self::Error> {
        Err(SdcError::RollbackUnsupported)
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

/// Product adapter around the shared change-set coordinator.
pub struct ChangeManager {
    coordinator: Arc<ChangesetCoordinator>,
    client: SdcClient,
    tenant: String,
    endpoint: String,
    policy_signature: String,
}

impl ChangeManager {
    /// Load durable change-control state for one configured tenant.
    ///
    /// # Errors
    ///
    /// Returns an error when an absolute state path cannot be loaded safely.
    pub fn load(
        client: SdcClient,
        tenant: impl Into<String>,
        endpoint: impl Into<String>,
        state_path: Option<&Path>,
        approval_ttl: Duration,
    ) -> Result<Self, SdcError> {
        let tenant = tenant.into();
        let endpoint = endpoint.into();
        let policy_signature =
            mutation_policy_signature(format!("sdc-policy-deploy-v1:{tenant}:{endpoint}"));
        let coordinator = ChangesetCoordinator::load_with_recovery(
            state_path,
            OperationLimits::default(),
            approval_ttl,
            false,
            StagedRecovery::Discard,
        )
        .map_err(|error| SdcError::ChangeControl(error.to_string()))?;
        Ok(Self {
            coordinator: Arc::new(coordinator),
            client,
            tenant,
            endpoint,
            policy_signature,
        })
    }

    /// Resolve a preview and create its digest-bound two-person plan.
    pub async fn prepare(
        &self,
        owner: String,
        policies: Vec<PolicyOperation>,
        cancellation: &CancellationToken,
    ) -> Result<PrepareResult, SdcError> {
        let prepared = self
            .client
            .prepare_policy_deploy(policies, cancellation)
            .await?;
        let change_set = self
            .coordinator
            .create_change_set(
                self.tenant.clone(),
                vec![prepared.clone()],
                owner,
                prepared.preview_digest().to_owned(),
                self.policy_signature.clone(),
            )
            .await
            .map_err(|error| SdcError::ChangeControl(error.to_string()))?;
        Ok(PrepareResult {
            change_set,
            prepared_change: prepared,
        })
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
    use crate::{PolicyType, Target};
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
}
