//! Regression contract for mecmcp 0.3.6 persisted changeset state and output.

use mecmcp_changeset::{
    ChangeSetState, ChangesetCoordinator, OperationLimits, StagedRecovery,
    mutation_policy_signature,
};
use serde_json::Value;
use std::{fs, time::Duration};

const FIXTURE: &[u8] = include_bytes!("fixtures/mecmcp-0.3.6-state.json");

#[cfg(unix)]
fn secure(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("secure copied fixture");
}

#[cfg(not(unix))]
fn secure(_path: &std::path::Path) {}

#[tokio::test]
async fn released_coordinator_reads_036_state_without_rewriting_or_waiver_output() {
    let document: Value = serde_json::from_slice(FIXTURE).expect("valid fixture JSON");
    assert_eq!(document["version"], 2);
    assert_eq!(document["state"]["operations"], serde_json::json!({}));
    let change_sets = document["state"]["change_sets"]
        .as_object()
        .expect("change-set map");
    assert_eq!(change_sets.len(), 1);
    let (change_set_id, record) = change_sets.iter().next().expect("fixture change set");
    assert_eq!(record["owner"], "fixture-owner");
    assert_eq!(record["device"], "fixture-tenant");
    assert_eq!(record["state"], "planned");
    assert_eq!(
        record["expected_candidate_fingerprint"],
        format!("sha256:{}", "a".repeat(64))
    );
    assert_eq!(
        record["actions"],
        serde_json::json!([{
            "operation": "policy_deploy",
            "policy_ids": ["fixture-policy"],
            "preview_digest": format!("sha256:{}", "b".repeat(64))
        }])
    );
    let policy_signature =
        mutation_policy_signature("sdc-policy-deploy-v1:fixture-tenant:https://fixture.invalid");
    assert_eq!(
        policy_signature,
        "sha256:60de6b705166a8c38449ce419e1ff954f8651f9dbb7bc64fbcaf0944d9e1ded5"
    );
    assert_eq!(record["policy_signature"], policy_signature);

    let directory = tempfile::tempdir().expect("temporary fixture directory");
    let state_path = directory.path().join("changeset-state.json");
    fs::write(&state_path, FIXTURE).expect("copy fixture");
    secure(&state_path);
    let before = fs::read(&state_path).expect("read fixture before load");

    let coordinator = ChangesetCoordinator::load_with_recovery(
        Some(&state_path),
        OperationLimits::default(),
        Duration::from_secs(60),
        false,
        StagedRecovery::Discard,
    )
    .expect("load 0.3.6 state");
    let output = coordinator
        .change_set_status(change_set_id.clone(), "fixture-tenant".to_owned())
        .await
        .expect("read fixture change set");

    assert_eq!(output.change_set_id.as_str(), change_set_id);
    assert_eq!(output.owner, record["owner"].as_str().expect("owner"));
    assert_eq!(output.device, record["device"].as_str().expect("device"));
    assert_eq!(output.digest, record["digest"].as_str().expect("digest"));
    assert_eq!(output.state, ChangeSetState::Planned);
    assert_eq!(
        output.expires_at_unix,
        record["expires_at_unix"].as_u64().expect("expiry")
    );
    assert_eq!(output.action_count, 1);
    assert!(output.approver.is_none());
    let serialized = serde_json::to_value(output).expect("serialize change-set output");
    assert!(
        serialized.get("approval_waiver").is_none(),
        "ordinary two-person output must omit approval_waiver"
    );

    let after = fs::read(&state_path).expect("read fixture after status");
    assert_eq!(
        after, before,
        "loading and reading must not rewrite 0.3.6 state"
    );
}
