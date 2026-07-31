//! SDC parameters for the shared MCP Streamable HTTP transport.

use crate::{
    SdcHandler, WRITE_TOOLS,
    compat::{
        bearer::{BearerAuthenticator, BearerBoundary, BearerResponseProfile, BearerSyntax},
        http::{HostOriginPolicy, HttpTransportConfig, build_streamable_http_router, serve_router},
        preflight::{MalformedArgumentsPolicy, TargetField, ToolScopePreflight},
    },
};
use anyhow::{Context, Result};
use axum::Router;
use mecmcp_auth::{CallerCtx, NoGrant, TokenStoreFile};
use mecmcp_transport::{LimitsConfig, TransportIdentity};
use std::{net::SocketAddr, sync::Arc};
use tokio_util::sync::CancellationToken;

/// Build the complete shared HTTP router with SDC-owned identity and scope fields.
pub fn build_http_router(
    handler: SdcHandler,
    token_store: Option<Arc<TokenStoreFile<NoGrant>>>,
    allowed_hosts: Vec<String>,
    allowed_origins: Vec<String>,
    limits: LimitsConfig,
    enable_metrics: bool,
    shutdown: CancellationToken,
) -> Result<Router> {
    let body_limit = limits.max_request_body_bytes;
    let identity = TransportIdentity::new("sdcmcp", "sdc", "rustsdcmcp", ["tenant"]);
    let mut config = HttpTransportConfig::new(
        identity,
        limits,
        HostOriginPolicy::enforced(allowed_hosts, allowed_origins),
        shutdown,
    )
    .with_metrics(enable_metrics);

    if let Some(store_file) = token_store {
        let auth_store = store_file.clone();
        let authenticator = BearerAuthenticator::new(BearerSyntax::Strict, move |candidate| {
            let snapshot = auth_store.store();
            snapshot.authenticate(candidate).map(CallerCtx::from)
        });
        let preflight = ToolScopePreflight::new(
            WRITE_TOOLS,
            [TargetField::scalar("tenant")],
            MalformedArgumentsPolicy::Deny,
        );
        let boundary = BearerBoundary::new(
            authenticator,
            BearerResponseProfile::detailed("sdcmcp"),
            body_limit,
        )
        .with_preflight(preflight);
        config = config.with_bearer(boundary);
    }

    build_streamable_http_router(move || Ok::<_, std::io::Error>(handler.clone()), config)
        .context("building shared SDC Streamable HTTP router")
}

/// Serve the shared HTTP router over plain HTTP or supplied TLS.
#[allow(clippy::too_many_arguments)]
pub async fn serve_http(
    handler: SdcHandler,
    address: SocketAddr,
    token_store: Option<Arc<TokenStoreFile<NoGrant>>>,
    allowed_hosts: Vec<String>,
    allowed_origins: Vec<String>,
    limits: LimitsConfig,
    enable_metrics: bool,
    tls: Option<Arc<rustls::ServerConfig>>,
    shutdown: CancellationToken,
) -> Result<()> {
    let router = build_http_router(
        handler,
        token_store,
        allowed_hosts,
        allowed_origins,
        limits,
        enable_metrics,
        shutdown.clone(),
    )?;
    serve_router(router, address, tls, shutdown)
        .await
        .context("serving SDC Streamable HTTP")
}
