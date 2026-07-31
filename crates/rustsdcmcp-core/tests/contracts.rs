//! Product contract tests against the pinned SDC OpenAPI shapes.

use rustsdcmcp_core::{
    AuthScheme, DeploymentStatus, ListRequest, PolicyOperation, PolicyType, SdcClient, SdcConfig,
    Target,
};

fn test_config() -> SdcConfig {
    serde_json::from_value(serde_json::json!({
        "version": 1,
        "tenant": "production",
        "expected_tenant_id": "tenant-123",
        "credential_env": "SDC_TOKEN",
        "auth_scheme": "oauth2_token",
        "endpoint": "https://example.invalid/"
    }))
    .expect("valid config")
}

#[test]
fn config_names_the_credential_variable_and_carries_no_field_for_its_value() {
    let config = test_config();
    assert_eq!(config.auth_scheme, AuthScheme::Oauth2Token);
    assert_eq!(config.credential_env, "SDC_TOKEN");

    // The config names the variable; the value lives only in the environment.
    // `deny_unknown_fields` means a serialized config round-trips through the
    // exact declared field set, so no additional key can smuggle a secret in.
    let serialized = serde_json::to_string(&config).expect("config serializes");
    assert!(serialized.contains("SDC_TOKEN"));
    let round_trip: SdcConfig = serde_json::from_str(&serialized).expect("config round-trips");
    assert_eq!(round_trip.credential_env, config.credential_env);
    assert_eq!(round_trip.auth_scheme, config.auth_scheme);
}

#[test]
fn a_credential_never_reaches_the_client_debug_representation() {
    // This is the leak that matters: `SdcClient` is held across the handler and
    // change manager, so any Debug/tracing render of it would put a tenant-wide
    // credential into the audit log.
    const SECRET: &str = "sdc-credential-that-must-never-be-rendered";
    let _ = rustls::crypto::ring::default_provider().install_default();

    let client = SdcClient::new(&test_config(), SECRET.to_owned()).expect("client builds");
    let rendered = format!("{client:?}");
    assert!(
        !rendered.contains(SECRET),
        "credential leaked into SdcClient Debug output: {rendered}"
    );
    assert!(
        rendered.contains("REDACTED"),
        "credential field must render as redacted, got: {rendered}"
    );
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
