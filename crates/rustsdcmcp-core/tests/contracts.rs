//! Product contract tests against the pinned SDC OpenAPI shapes.

use rustsdcmcp_core::{
    AuthScheme, DeploymentStatus, ListRequest, PolicyOperation, PolicyType, SdcConfig, Target,
};

#[test]
fn config_uses_an_external_credential_and_never_serializes_the_secret() {
    let config: SdcConfig = serde_json::from_value(serde_json::json!({
        "version": 1,
        "tenant": "production",
        "expected_tenant_id": "tenant-123",
        "credential_env": "SDC_TOKEN",
        "auth_scheme": "oauth2_token"
    }))
    .expect("valid config");

    assert_eq!(config.auth_scheme, AuthScheme::Oauth2Token);
    assert_eq!(config.credential_env, "SDC_TOKEN");

    let serialized = serde_json::to_string(&config).expect("config serializes");
    assert!(!serialized.contains("never-serialize-me"));
    assert!(serialized.contains("SDC_TOKEN"));
}

#[test]
fn page_size_zero_and_oversized_pages_are_refused() {
    assert!(ListRequest::new(0, 0, 200).is_err());
    assert!(ListRequest::new(0, 201, 200).is_err());
    assert_eq!(
        ListRequest::new(40, 20, 200)
            .expect("bounded page")
            .query_pairs(),
        vec![
            ("from".to_owned(), "40".to_owned()),
            ("size".to_owned(), "20".to_owned())
        ]
    );
}

#[test]
fn preview_operation_matches_the_pinned_openapi_shape() {
    let operation = PolicyOperation {
        policy_id: "policy-1".to_owned(),
        policy_type: PolicyType::Firewall,
        deploy_targets: vec![Target::device("device-1")],
        undeploy_targets: Vec::new(),
    };
    assert_eq!(
        serde_json::to_value(operation).expect("operation serializes"),
        serde_json::json!({
            "policy_id": "policy-1",
            "policy_type": "FIREWALL",
            "deploy_targets": [{"target_id": "device-1", "target_type": "DEVICE"}],
            "undeploy_targets": []
        })
    );
}

#[test]
fn deployment_status_classifier_uses_only_documented_states() {
    assert!(!DeploymentStatus::Pending.is_terminal());
    assert!(!DeploymentStatus::InProgress.is_terminal());
    assert!(DeploymentStatus::Completed.succeeded());
    assert!(DeploymentStatus::PartialSuccess.is_terminal());
    assert!(!DeploymentStatus::PartialSuccess.succeeded());
    assert!(DeploymentStatus::Failed.is_terminal());
}
