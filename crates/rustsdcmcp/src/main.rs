//! Security Director Cloud MCP server executable.

use anyhow::{Context, Result};
use clap::Parser as _;
use mecmcp_auth::{NoGrant, TokenStoreFile};
use mecmcp_runtime::cli::{Cli, Command, Transport};
use rmcp::ServiceExt as _;
use rustsdcmcp::{KNOWN_TOOLS, SdcHandler, serve_http};
use rustsdcmcp_core::{ChangeManager, SdcClient, SdcConfig};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio_util::sync::CancellationToken;

/// Bearer-token boundary selected for the Streamable HTTP listener.
#[derive(Debug, PartialEq, Eq)]
enum AuthMode {
    /// Load and enforce this bearer-token store.
    Tokens(PathBuf),
    /// Serve unauthenticated. `mecmcp_runtime::cli_validate` confines this to loopback.
    NoAuth,
}

/// Decide the listener's authentication boundary, refusing every combination
/// that would otherwise resolve to a silently unauthenticated listener.
///
/// `mecmcp_runtime::cli_validate` already refuses a listener with neither flag
/// and confines `--allow-no-auth` to loopback, but it accepts both flags
/// together. Selecting a mode here rather than falling through to `None` keeps
/// that combination from dropping the token store without a diagnostic.
fn resolve_auth_mode(
    tokens_file: Option<&Path>,
    allow_no_auth: bool,
) -> Result<AuthMode, &'static str> {
    match (tokens_file, allow_no_auth) {
        (Some(path), false) => Ok(AuthMode::Tokens(path.to_owned())),
        (None, true) => Ok(AuthMode::NoAuth),
        (Some(_), true) => Err(
            "--tokens-file and --allow-no-auth are mutually exclusive: pass --tokens-file for an authenticated listener, or --allow-no-auth alone for an unauthenticated loopback one",
        ),
        (None, false) => Err(
            "--transport streamable-http requires --tokens-file (or --allow-no-auth on loopback)",
        ),
    }
}

/// Cancel `shutdown` on the first SIGTERM or SIGINT.
///
/// `mecmcp_runtime::shutdown::GracefulShutdown` supplies the Ctrl-C half; the
/// SIGTERM watcher beside it covers how systemd actually stops this unit.
fn install_shutdown_signals(shutdown: CancellationToken) -> Result<()> {
    let coordinator = mecmcp_runtime::shutdown::GracefulShutdown::new();
    let interrupt = coordinator.subscribe();
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("installing SIGTERM handler")?;
    tokio::spawn(async move {
        // Hold the coordinator so its Ctrl-C sender stays alive.
        let _coordinator = coordinator;
        tokio::select! {
            () = interrupt => tracing::info!("received SIGINT, shutting down"),
            _ = terminate.recv() => tracing::info!("received SIGTERM, shutting down"),
        }
        shutdown.cancel();
    });
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();
    mecmcp_runtime::cli_validate::validate(&args).map_err(|error| anyhow::anyhow!("{error}"))?;

    // Decide the listener's authentication boundary alongside the rest of the
    // CLI refusals, before anything reads a credential or contacts SDC. Only
    // loading the selected store is deferred, so an unusable flag combination
    // is reported as itself rather than as a downstream credential error.
    let auth_mode = match args.transport {
        // Stdio has no HTTP boundary, so a token store would never be consulted.
        Transport::Stdio => None,
        Transport::StreamableHttp => Some(
            resolve_auth_mode(args.tokens_file.as_deref(), args.allow_no_auth)
                .map_err(|error| anyhow::anyhow!("{error}"))?,
        ),
    };

    let redaction = if args.audit_redact.trim().is_empty() {
        None
    } else {
        Some(
            mecmcp_audit::AuditRedaction::parse(
                &args.audit_redact,
                args.audit_hmac_key_file.as_deref(),
            )
            .map_err(|error| anyhow::anyhow!("invalid --audit-redact: {error}"))?,
        )
    };
    mecmcp_audit::init_tracing(&mecmcp_audit::AuditConfig {
        format: mecmcp_audit::AuditFormat::parse(&args.audit_format),
        audit_log_file: args.audit_log_file.clone(),
        redaction,
        journald: args.audit_journald,
    })
    .context("initializing audit tracing")?;
    mecmcp_audit::install_duration_metric_name("sdcmcp_tool_duration_seconds");

    // The shared CLI retains its historic `device_mapping` field. For this
    // management-plane consumer, `-f/--device-mapping` selects sdc.json until
    // the target-neutral CLI work tracked in mecmcp#91 lands.
    let config = SdcConfig::from_path(&args.device_mapping)
        .with_context(|| format!("loading {}", args.device_mapping.display()))?;

    if let Some(Command::Token { action }) = args.command {
        return mecmcp_runtime::token_cmd::run(action, &[config.tenant], KNOWN_TOOLS)
            .map_err(anyhow::Error::from);
    }

    let provider = rustls::crypto::ring::default_provider();
    provider
        .clone()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install the rustls ring crypto provider"))?;

    let credential = std::env::var(&config.credential_env).map_err(|_| {
        anyhow::anyhow!(
            "credential environment variable '{}' is not set or is not valid Unicode",
            config.credential_env
        )
    })?;
    // `GracefulShutdown` installs a Ctrl-C handler only. systemd stops this
    // unit with SIGTERM (`KillSignal=SIGTERM`), which that coordinator does not
    // observe, so feed SIGTERM into the same trigger rather than standing up a
    // second coordinator beside it. The upstream gap is mecmcp's to close.
    let shutdown = CancellationToken::new();
    install_shutdown_signals(shutdown.clone())?;

    let client = SdcClient::new(&config, credential)
        .context("building SDC client")?
        .with_shutdown(shutdown.clone());
    client
        .verify_tenant(&config.expected_tenant_id, &shutdown)
        .await
        .context("verifying SDC credential tenant scope")?;

    let changes = Arc::new(ChangeManager::load(
        client.clone(),
        config.tenant.clone(),
        config.endpoint.clone(),
        config.changeset_state_file.as_deref(),
        Duration::from_secs(config.approval_ttl_secs),
    )?);
    let handler = SdcHandler::new(Arc::<str>::from(config.tenant.as_str()), client, changes);

    let token_store = match auth_mode {
        None => None,
        Some(AuthMode::Tokens(path)) => {
            let store = Arc::new(
                TokenStoreFile::<NoGrant>::load(&path)
                    .with_context(|| format!("loading {}", path.display()))?,
            );
            tracing::info!(tokens = store.store().len(), "token store loaded");
            Some(store)
        }
        Some(AuthMode::NoAuth) => {
            tracing::warn!(
                "--allow-no-auth: Streamable HTTP accepts unauthenticated requests on loopback"
            );
            None
        }
    };

    if let Some(store) = token_store.clone() {
        mecmcp_runtime::signals::install_hup_handler(move || match store.reload() {
            Ok(()) => tracing::info!(tokens = store.store().len(), "token store reloaded"),
            Err(error) => {
                tracing::error!(%error, "token reload failed; retaining previous snapshot");
            }
        })
        .context("installing token reload handler")?;
    }

    match args.transport {
        Transport::Stdio => {
            // serve_with_ct rather than serve: `serve` does not return until
            // the client sends `initialize`, so a token installed afterwards
            // would miss a signal arriving during the handshake and leave the
            // process blocked on an open stdin. The token owns the service
            // here, and cancelling it cascades to every in-flight request
            // context, so a signal abandons running SDC work rather than
            // waiting out the job-poll deadline.
            let service = handler
                .serve_with_ct((tokio::io::stdin(), tokio::io::stdout()), shutdown)
                .await
                .context("starting MCP stdio service")?;
            service
                .waiting()
                .await
                .context("MCP stdio service exited with error")?;
        }
        Transport::StreamableHttp => {
            let address = format!("{}:{}", args.host, args.port)
                .parse()
                .with_context(|| format!("parsing {}:{}", args.host, args.port))?;
            let tls = match (&args.tls_cert, &args.tls_key) {
                (Some(cert), Some(key)) => Some(
                    mecmcp_transport::load_tls(cert, key, Arc::new(provider))
                        .context("loading listener TLS")?,
                ),
                _ => None,
            };
            serve_http(
                handler,
                address,
                token_store,
                args.allowed_host,
                args.allowed_origin,
                mecmcp_transport::LimitsConfig::default(),
                false,
                tls,
                shutdown,
            )
            .await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{AuthMode, resolve_auth_mode};
    use std::path::{Path, PathBuf};

    #[test]
    fn a_tokens_file_alone_selects_an_authenticated_listener() {
        assert_eq!(
            resolve_auth_mode(Some(Path::new("/etc/rustsdcmcp/tokens.json")), false),
            Ok(AuthMode::Tokens(PathBuf::from(
                "/etc/rustsdcmcp/tokens.json"
            ))),
        );
    }

    #[test]
    fn allow_no_auth_alone_selects_the_unauthenticated_listener() {
        assert_eq!(resolve_auth_mode(None, true), Ok(AuthMode::NoAuth));
    }

    #[test]
    fn a_tokens_file_is_never_silently_dropped_by_allow_no_auth() {
        let refusal = resolve_auth_mode(Some(Path::new("/etc/rustsdcmcp/tokens.json")), true)
            .expect_err("supplying a token store and --allow-no-auth must be refused");
        assert!(refusal.contains("mutually exclusive"));
    }

    #[test]
    fn a_listener_with_no_authentication_decision_is_refused() {
        assert!(resolve_auth_mode(None, false).is_err());
    }
}
