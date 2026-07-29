//! Security Director Cloud MCP server executable.

use anyhow::{Context, Result};
use clap::Parser as _;
use mecmcp_auth::{NoGrant, TokenStoreFile};
use mecmcp_runtime::cli::{Cli, Command, Transport};
use rmcp::ServiceExt as _;
use rustsdcmcp::{KNOWN_TOOLS, SdcHandler, serve_http};
use rustsdcmcp_core::{ChangeManager, SdcClient, SdcConfig};
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();
    mecmcp_runtime::cli_validate::validate(&args).map_err(|error| anyhow::anyhow!("{error}"))?;

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
    let client = SdcClient::new(&config, credential).context("building SDC client")?;
    client
        .verify_tenant(&config.expected_tenant_id, &CancellationToken::new())
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

    let token_store = match (&args.tokens_file, args.allow_no_auth) {
        (Some(path), false) => {
            let store = Arc::new(
                TokenStoreFile::<NoGrant>::load(path)
                    .with_context(|| format!("loading {}", path.display()))?,
            );
            tracing::info!(tokens = store.store().len(), "token store loaded");
            Some(store)
        }
        (None, true) => {
            tracing::warn!(
                "--allow-no-auth: Streamable HTTP accepts unauthenticated requests on loopback"
            );
            None
        }
        _ => None,
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
            let service = handler
                .serve((tokio::io::stdin(), tokio::io::stdout()))
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
            )
            .await?;
        }
    }
    Ok(())
}
