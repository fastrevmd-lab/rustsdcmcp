use crate::compat::bearer::{BearerBoundary, apply_bearer_boundary};
use axum::{Router, middleware};
use mecmcp_transport::{
    ConcurrencyState, LimitedSessionManager, LimitsConfig, LimitsConfigError, PrometheusRuntime,
    TransportIdentity, apply_body_limit, apply_rate_limit, concurrency_middleware,
};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use std::{net::SocketAddr, sync::Arc};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone)]
/// mecmcp-compat: type mecmcp_transport::HostOriginPolicy https://github.com/fastrevmd-lab/mecmcp/issues/114
pub(crate) enum HostOriginPolicy {
    Enforced {
        allowed_hosts: Vec<String>,
        allowed_origins: Vec<String>,
    },
}

impl HostOriginPolicy {
    /// mecmcp-compat: method HostOriginPolicy::enforced https://github.com/fastrevmd-lab/mecmcp/issues/148
    pub(crate) fn enforced(
        allowed_hosts: impl IntoIterator<Item = impl Into<String>>,
        allowed_origins: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self::Enforced {
            allowed_hosts: allowed_hosts.into_iter().map(Into::into).collect(),
            allowed_origins: allowed_origins.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Clone)]
/// mecmcp-compat: type mecmcp_transport::HttpTransportConfig https://github.com/fastrevmd-lab/mecmcp/issues/115
pub(crate) struct HttpTransportConfig {
    identity: TransportIdentity,
    limits: LimitsConfig,
    host_origin: HostOriginPolicy,
    bearer: Option<BearerBoundary>,
    enable_metrics: bool,
    shutdown: CancellationToken,
}

impl HttpTransportConfig {
    /// mecmcp-compat: method HttpTransportConfig::new https://github.com/fastrevmd-lab/mecmcp/issues/150
    /// `shutdown` is a constructor argument rather than a builder step because
    /// rmcp terminates every active session on that token: a listener built
    /// without one leaks SSE streams past process shutdown, so it must not be
    /// possible to forget it.
    pub(crate) fn new(
        identity: TransportIdentity,
        limits: LimitsConfig,
        host_origin: HostOriginPolicy,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            identity,
            limits,
            host_origin,
            bearer: None,
            enable_metrics: false,
            shutdown,
        }
    }

    /// mecmcp-compat: method HttpTransportConfig::with_bearer https://github.com/fastrevmd-lab/mecmcp/issues/151
    pub(crate) fn with_bearer(mut self, bearer: BearerBoundary) -> Self {
        self.bearer = Some(bearer);
        self
    }

    /// mecmcp-compat: method HttpTransportConfig::with_metrics https://github.com/fastrevmd-lab/mecmcp/issues/152
    pub(crate) fn with_metrics(mut self, enable_metrics: bool) -> Self {
        self.enable_metrics = enable_metrics;
        self
    }
}

#[derive(Debug, thiserror::Error)]
/// mecmcp-compat: type mecmcp_transport::HttpTransportBuildError https://github.com/fastrevmd-lab/mecmcp/issues/116
pub(crate) enum HttpTransportBuildError {
    #[error("invalid HTTP transport limits: {0}")]
    Limits(#[from] LimitsConfigError),
    #[error("installing HTTP transport metrics: {0}")]
    Metrics(String),
}

#[derive(Debug, thiserror::Error)]
/// mecmcp-compat: type mecmcp_transport::HttpServeError https://github.com/fastrevmd-lab/mecmcp/issues/117
pub(crate) enum HttpServeError {
    #[error("binding HTTP listener at {address}: {error}")]
    Bind {
        address: SocketAddr,
        #[source]
        error: std::io::Error,
    },
    #[error("serving HTTP transport: {0}")]
    Serve(#[source] std::io::Error),
}

/// mecmcp-compat: function mecmcp_transport::streamable_http_server_config https://github.com/fastrevmd-lab/mecmcp/issues/149
pub(crate) fn streamable_http_server_config(
    policy: &HostOriginPolicy,
    shutdown: CancellationToken,
    limits: &mecmcp_transport::LimitsConfig,
) -> StreamableHttpServerConfig {
    let HostOriginPolicy::Enforced {
        allowed_hosts,
        allowed_origins,
    } = policy;
    // Not `StreamableHttpServerConfig::default()`. rmcp 3 added its own
    // `max_request_body_bytes`, defaulting to 4 MiB and enforced *inside* rmcp
    // after `apply_body_limit` has already accepted the request, so `default()`
    // silently overrides whatever limit the operator configured.
    let mut config = mecmcp_transport::streamable_http_server_config(limits);
    config.allowed_hosts.extend(allowed_hosts.iter().cloned());
    if !allowed_origins.is_empty() {
        config.allowed_origins = allowed_origins.clone();
    }
    config.cancellation_token = shutdown;
    config
}

/// mecmcp-compat: function mecmcp_transport::build_streamable_http_router https://github.com/fastrevmd-lab/mecmcp/issues/153
pub(crate) fn build_streamable_http_router<S>(
    service_factory: impl Fn() -> Result<S, std::io::Error> + Send + Sync + 'static,
    config: HttpTransportConfig,
) -> Result<Router, HttpTransportBuildError>
where
    S: rmcp::ServerHandler + Send + 'static,
{
    config.limits.validate()?;
    let sessions = LimitedSessionManager::new(LocalSessionManager::default(), &config.limits);
    let concurrency = ConcurrencyState::new(
        &config.limits,
        config.identity.target_keys.clone(),
        Some(sessions.tracker()),
    );
    let service = StreamableHttpService::new(
        service_factory,
        sessions,
        streamable_http_server_config(&config.host_origin, config.shutdown.clone(), &config.limits),
    );
    let mut router =
        Router::new()
            .nest_service("/mcp", service)
            .layer(middleware::from_fn_with_state(
                concurrency,
                concurrency_middleware,
            ));
    router = apply_rate_limit(router, &config.limits);
    if let Some(boundary) = config.bearer {
        router = apply_bearer_boundary(router, boundary);
    }
    router = apply_body_limit(router, &config.limits);
    if config.enable_metrics {
        let runtime = Arc::new(
            PrometheusRuntime::install(
                &config.identity.metric_prefix,
                &config.identity.server_label,
            )
            .map_err(|error| HttpTransportBuildError::Metrics(error.to_string()))?,
        );
        router = router.merge(runtime.router().layer(axum::Extension(runtime)));
    }
    Ok(router)
}

/// mecmcp-compat: function mecmcp_transport::serve_router https://github.com/fastrevmd-lab/mecmcp/issues/154
pub(crate) async fn serve_router(
    router: Router,
    address: SocketAddr,
    tls: Option<Arc<rustls::ServerConfig>>,
    shutdown: CancellationToken,
) -> Result<(), HttpServeError> {
    // Both listeners run on axum_server so they share one forced deadline.
    // `axum::serve`'s `with_graceful_shutdown` takes a signal but no deadline:
    // it waits on every in-flight connection task forever, and an MCP SSE
    // stream never ends on its own, so the plaintext listener -- the packaged
    // default -- would hang until systemd's TimeoutStopSec SIGKILL.
    let listener = std::net::TcpListener::bind(address)
        .map_err(|error| HttpServeError::Bind { address, error })?;
    listener
        .set_nonblocking(true)
        .map_err(|error| HttpServeError::Bind { address, error })?;

    // Backstop only. rmcp ends the sessions on the same token and the SDC
    // client aborts its own work, so the drain is normally immediate; this
    // bounds a stuck connection well under the unit's TimeoutStopSec=30s.
    let shutdown_grace = std::time::Duration::from_secs(10);
    let handle = axum_server::Handle::new();
    tokio::spawn({
        let handle = handle.clone();
        async move {
            shutdown.cancelled().await;
            handle.graceful_shutdown(Some(shutdown_grace));
        }
    });
    let service = router.into_make_service_with_connect_info::<SocketAddr>();

    match tls {
        Some(tls) => {
            let config = axum_server::tls_rustls::RustlsConfig::from_config(tls);
            axum_server::tls_rustls::from_tcp_rustls(listener, config)
                .map_err(|error| HttpServeError::Bind { address, error })?
                .handle(handle)
                .serve(service)
                .await
        }
        None => {
            axum_server::from_tcp(listener)
                .map_err(|error| HttpServeError::Bind { address, error })?
                .handle(handle)
                .serve(service)
                .await
        }
    }
    .map_err(HttpServeError::Serve)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compat::bearer::{
        BearerAuthenticator, BearerBoundary, BearerResponseProfile, BearerSyntax,
    };
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode, header},
    };
    use mecmcp_auth::{ActorType, CallerCtx, NoGrant, ScopeSet};
    use mecmcp_transport::{LimitsConfig, TransportIdentity};
    use rmcp::{
        ServerHandler,
        model::{Implementation, ServerCapabilities, ServerInfo},
    };
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
            max_request_body_bytes,
        ));
        build_streamable_http_router(|| Ok::<_, std::io::Error>(EmptyServer), config)
            .expect("router")
    }

    #[test]
    fn host_origin_policy_preserves_loopback_defaults() {
        let policy =
            HostOriginPolicy::enforced(["mcp.example.test"], ["https://client.example.test"]);
        let shutdown = CancellationToken::new();
        let config = streamable_http_server_config(
            &policy,
            shutdown.clone(),
            &mecmcp_transport::LimitsConfig::default(),
        );
        // rmcp terminates every active session on this token, so an open SSE
        // stream must not outlive process shutdown.
        assert!(!config.cancellation_token.is_cancelled());
        shutdown.cancel();
        assert!(config.cancellation_token.is_cancelled());
        assert!(config.allowed_hosts.contains(&"localhost".to_owned()));
        assert!(
            config
                .allowed_hosts
                .contains(&"mcp.example.test".to_owned())
        );
        assert_eq!(
            config.allowed_origins,
            vec!["https://client.example.test".to_owned()],
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
}
