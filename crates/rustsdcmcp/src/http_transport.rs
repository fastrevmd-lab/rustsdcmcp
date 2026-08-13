//! SDC parameters for the shared MCP Streamable HTTP transport.

use crate::{SdcHandler, WRITE_TOOLS};
use anyhow::{Context, Result};
use mecmcp_auth::{BearerSyntax, CallerCtx, NoGrant, TokenStoreFile};
use mecmcp_transport::{
    BearerAuthenticator, BearerBoundary, BearerResponseProfile, HostOriginPolicy,
    HttpTransportConfig, LimitsConfig, MalformedArgumentsPolicy, NoAuthAcknowledgement,
    TargetField, ToolScopePreflight, TransportIdentity, build_streamable_http_router, serve_router,
};
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
) -> Result<mecmcp_transport::ServePlan> {
    let identity = TransportIdentity::new("sdcmcp", "sdc", "rustsdcmcp", ["tenant"]);
    let host_origin = HostOriginPolicy::enforced(allowed_hosts, allowed_origins);

    let config = if let Some(store_file) = token_store {
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
        let boundary =
            BearerBoundary::new(authenticator, BearerResponseProfile::detailed("sdcmcp"))
                .with_preflight(preflight);
        HttpTransportConfig::authenticated(
            identity.clone(),
            limits.clone(),
            host_origin,
            shutdown,
            boundary,
        )
        .with_metrics(enable_metrics)
    } else {
        HttpTransportConfig::unauthenticated(
            identity.clone(),
            limits.clone(),
            host_origin,
            shutdown,
            NoAuthAcknowledgement::operator_allowed_no_auth(),
        )
        .with_metrics(enable_metrics)
    };

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
    shutdown_timeout: std::time::Duration,
) -> Result<()> {
    let plan = build_http_router(
        handler,
        token_store,
        allowed_hosts,
        allowed_origins,
        limits,
        enable_metrics,
        shutdown,
    )?;
    serve_router(plan, address, tls, shutdown_timeout)
        .await
        .context("serving SDC Streamable HTTP")
}
