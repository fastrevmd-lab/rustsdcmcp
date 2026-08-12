//! HTTP transport boundary tests.
//!
//! These tests were originally in src/compat/http.rs and cover behaviour
//! rustsdcmcp still cares about even after migrating to mecmcp 0.7.0's
//! upstream transport assembly.

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use mecmcp_auth::{
    ActorType, BearerSyntax, CallerCtx, KnownNames, NoGrant, ScopeSet, TokenStoreFile,
};
use mecmcp_transport::{
    BearerAuthenticator, BearerBoundary, BearerResponseProfile, HostOriginPolicy,
    HttpTransportConfig, LimitsConfig, TransportIdentity, build_streamable_http_router,
};
use rmcp::{
    ServerHandler,
    model::{Implementation, ServerCapabilities, ServerInfo},
};
use rustsdcmcp::{KNOWN_TOOLS, SdcHandler, build_http_router};
use rustsdcmcp_core::{ChangeManager, SdcClient, SdcConfig};
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt as _;

#[derive(Debug, Clone, Default)]
struct EmptyServer;

impl ServerHandler for EmptyServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("empty", "1"))
    }
}

fn caller() -> CallerCtx<NoGrant> {
    CallerCtx {
        token_name: "test".to_owned(),
        devices: ScopeSet::Wildcard,
        tools: ScopeSet::Wildcard,
        grant: None,
        provider: None,
        provider_tier: None,
        on_behalf_of: None,
        actor_type: ActorType::Human,
    }
}

fn router_with_limit(max_request_body_bytes: usize) -> Router {
    let authenticator = BearerAuthenticator::new(BearerSyntax::Strict, |candidate| {
        (candidate == "secret").then(caller)
    });
    let limits = LimitsConfig {
        max_request_body_bytes,
        ..LimitsConfig::default()
    };
    let config = HttpTransportConfig::new(
        TransportIdentity::new("testmcp", "test", "test", ["tenant"]),
        limits,
        HostOriginPolicy::enforced(Vec::<String>::new(), Vec::<String>::new()),
        CancellationToken::new(),
    )
    .with_bearer(BearerBoundary::new(
        authenticator,
        BearerResponseProfile::detailed("test"),
    ));
    let (router, _shutdown) =
        build_streamable_http_router(|| Ok::<_, std::io::Error>(EmptyServer), config)
            .expect("router");
    router
}

/// Build a router through rustsdcmcp's own `build_http_router`, so a regression
/// in *this crate's* wiring — not just in mecmcp — fails the build.
///
/// The handler is never dispatched to: every assertion below is answered by the
/// host/origin guard, which sits in front of it.
fn sdc_router(allowed_hosts: Vec<String>, allowed_origins: Vec<String>) -> Router {
    sdc_router_inner(allowed_hosts, allowed_origins, None)
}

/// Same handler, but with a bearer token store installed so the scope preflight
/// has a caller to check against.
fn sdc_router_with_auth(store: Option<Arc<TokenStoreFile<NoGrant>>>) -> Router {
    sdc_router_inner(Vec::new(), Vec::new(), store)
}

fn sdc_router_inner(
    allowed_hosts: Vec<String>,
    allowed_origins: Vec<String>,
    token_store: Option<Arc<TokenStoreFile<NoGrant>>>,
) -> Router {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config: SdcConfig = serde_json::from_value(serde_json::json!({
        "version": 1,
        "tenant": "test",
        "expected_tenant_id": "test",
        "credential_env": "SDC_TEST_CREDENTIAL",
        "auth_scheme": "api_key",
    }))
    .expect("config");
    let client = SdcClient::new(&config, "test-credential".to_owned()).expect("client");
    let changes = Arc::new(
        ChangeManager::load(
            client.clone(),
            "test",
            config.endpoint.clone(),
            None,
            Duration::from_secs(60),
            false,
        )
        .expect("changes"),
    );
    let handler = SdcHandler::new(Arc::<str>::from("test"), client, changes);
    let (router, _shutdown) = build_http_router(
        handler,
        token_store,
        allowed_hosts,
        allowed_origins,
        LimitsConfig::default(),
        false,
        CancellationToken::new(),
    )
    .expect("router");
    router
}

/// A request that clears the host/origin guard reaches rmcp, which answers 406
/// because this bare probe carries no `Accept: text/event-stream`.
///
/// Asserting that exact code — rather than merely "not 421" — is what stops these
/// tests passing for the wrong reason: a probe rejected earlier in the stack would
/// not return 406 either.
const PASSED_THE_GUARD: StatusCode = StatusCode::NOT_ACCEPTABLE;

/// Send one probe with exactly one `Host` header and at most one `Origin`.
///
/// `Request::builder().header()` appends rather than replaces, so setting a
/// default `Host` here and overriding it later would leave two — and the guard
/// reads the first, silently passing every test.
async fn probe(router: Router, host: &str, origin: Option<&str>) -> StatusCode {
    let mut request = Request::builder().method("POST").uri("/mcp");
    request = request.header(header::HOST, host);
    if let Some(origin) = origin {
        request = request.header(header::ORIGIN, origin);
    }
    router
        .oneshot(request.body(Body::from("{}")).expect("request"))
        .await
        .expect("response")
        .status()
}

/// The 609 production shape: `--allowed-host 192.168.1.194` while bound to `:30031`.
///
/// A portless Host allowlist entry must match ANY port. Matching the port exactly
/// here would return 421 on every request the live server receives.
#[tokio::test]
async fn portless_allowed_host_matches_any_port() {
    let router = sdc_router(vec!["192.168.1.194".to_owned()], Vec::new());
    assert_eq!(
        probe(router, "192.168.1.194:30031", None).await,
        PASSED_THE_GUARD,
        "a portless --allowed-host entry must match the port the server is bound to"
    );
}

/// The allowlist extends rmcp's loopback default rather than replacing it.
#[tokio::test]
async fn loopback_stays_allowed_when_a_host_is_added() {
    let router = sdc_router(vec!["192.168.1.194".to_owned()], Vec::new());
    assert_eq!(probe(router, "localhost", None).await, PASSED_THE_GUARD);
}

/// The DNS-rebinding guard (RUSTSEC-2026-0189). There is no way to turn it off.
#[tokio::test]
async fn unlisted_host_is_rejected() {
    let router = sdc_router(vec!["192.168.1.194".to_owned()], Vec::new());
    assert_eq!(
        probe(router, "attacker.example.com", None).await,
        StatusCode::MISDIRECTED_REQUEST,
    );
}

/// Origin is deliberately stricter than Host: a portless entry matches only a
/// portless browser Origin, because wildcarding a port here would widen the policy.
#[tokio::test]
async fn origin_allowlist_is_passed_through() {
    let allowed = sdc_router(Vec::new(), vec!["https://sdc.example.com".to_owned()]);
    assert_eq!(
        probe(allowed, "localhost", Some("https://sdc.example.com")).await,
        PASSED_THE_GUARD,
    );
    let rejected = sdc_router(Vec::new(), vec!["https://sdc.example.com".to_owned()]);
    assert_eq!(
        probe(rejected, "localhost", Some("https://attacker.example.com")).await,
        StatusCode::FORBIDDEN,
    );
}

#[tokio::test]
async fn router_requires_bearer() {
    let response = router_with_limit(1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::HOST, "localhost")
                .body(Body::from("{}"))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn router_rejects_body_over_limit_before_rmcp_dispatch() {
    let response = router_with_limit(64)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::HOST, "localhost")
                .header(header::AUTHORIZATION, "Bearer secret")
                .body(Body::from(vec![b'x'; 65]))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

/// A token scoped to one tenant must be refused when it names another.
///
/// This is the scope preflight doing its job, and until now nothing in this
/// repo asserted it. `compat/preflight.rs` carried its own tests, and deleting
/// that module in favour of `mecmcp_transport::ToolScopePreflight` took them
/// with it — leaving the wiring untested. Verified by removing
/// `.with_preflight(preflight)` from `build_http_router`: the whole suite stayed
/// green, which is exactly the gap this closes.
///
/// mecmcp's own tests prove the generic preflight refuses out-of-scope targets.
/// What only this repo can prove is that it is wired here with SDC's target
/// field — `tenant` — so a mis-wired field name is caught rather than silently
/// admitting everything.
#[tokio::test]
async fn out_of_scope_tenant_is_refused() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().expect("tempdir");
    let token_path = dir.path().join("tokens.json");

    let known_tenants = ["permitted".to_owned()];
    let known = KnownNames {
        devices: Some(&known_tenants),
        tools: KNOWN_TOOLS,
    };
    let secret = TokenStoreFile::<NoGrant>::add(
        &token_path,
        "scoped",
        ScopeSet::Allowlist(vec!["permitted".to_owned()]),
        ScopeSet::Wildcard,
        &known,
    )
    .expect("token add")
    .expose_secret()
    .to_owned();
    let store = Arc::new(TokenStoreFile::<NoGrant>::load(&token_path).expect("load token store"));

    let router = sdc_router_with_auth(Some(store));

    let call = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "list_sdc_devices", "arguments": {"tenant": "forbidden", "size": 10}}
    });
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::HOST, "localhost")
                .header(header::AUTHORIZATION, format!("Bearer {secret}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&call).expect("body")))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a token scoped to 'permitted' must not reach a tool call naming 'forbidden'"
    );
}
