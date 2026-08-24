//! Security Director Cloud MCP server executable.

use anyhow::{Context, Result};
use mecmcp_auth::{NoGrant, TokenStoreFile};
use mecmcp_runtime::cli::{Cli, Command, ParsedCli, Transport};
use rmcp::ServiceExt as _;
use rustsdcmcp::{KNOWN_TOOLS, SdcHandler, serve_http};
use rustsdcmcp_core::{ChangeManager, SdcClient, SdcConfig};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio_util::sync::CancellationToken;

/// Security Director Cloud MCP server.
//
// This is the shared `mecmcp` CLI plus the three standardized change-set
// flags. `mecmcp/docs/PACKAGING.md` standardizes `--lab-mode`, `--state-file`,
// and `--approval-timeout-secs` across every server in the family, and
// specifies that each server declares them on *its own* CLI type rather than in
// the shared `Cli` — `parse_with_provenance` parses this struct, not that one.
// Flattening keeps every shared flag while adding the three here.
//
// Doc comments on this struct become `--help` text, so the rationale stays in
// ordinary comments and only the description above is a doc comment.
#[derive(Debug, clap::Parser)]
struct ServerCli {
    /// Arguments shared by every mecmcp server.
    #[command(flatten)]
    shared: Cli,

    /// Run without two-person control; change sets are approved on creation.
    ///
    /// Off by default. The waiver is recorded, never fabricated: a waived
    /// change set carries `approver: null` alongside
    /// `approval_waiver: "lab-mode"`, and its own digest, so it stays
    /// distinguishable from a genuine two-person approval.
    #[arg(long)]
    lab_mode: bool,

    /// Absolute path to the change-set and operation state file.
    ///
    /// Falls back to `changeset_state_file` in the product configuration.
    #[arg(long)]
    state_file: Option<PathBuf>,

    /// How long an approval stays valid, in seconds. Must be greater than zero.
    ///
    /// Falls back to `approval_ttl_secs` in the product configuration.
    ///
    /// `SdcConfig` refuses a zero TTL, but an explicit flag bypasses that
    /// validation, and zero expires every change set at the instant it is
    /// created — approval fails, and lab mode's waiver reports the window
    /// already closed. Constrained here so the whole write surface cannot be
    /// disabled by one plausible-looking argument.
    #[arg(
        long,
        default_value_t = DEFAULT_APPROVAL_TIMEOUT_SECS,
        value_parser = clap::value_parser!(u64).range(1..),
    )]
    approval_timeout_secs: u64,
}

/// Parser default for `--approval-timeout-secs`.
///
/// Only reached when neither the flag nor product configuration supplies a
/// value, because `SdcConfig` carries its own serde default.
const DEFAULT_APPROVAL_TIMEOUT_SECS: u64 = 900;

/// Resolve one standard flag against product configuration.
///
/// The rule is `mecmcp/docs/PACKAGING.md`'s: an explicitly supplied CLI value
/// wins, otherwise product configuration, otherwise the built-in default.
///
/// The trap is deciding "explicitly supplied". A defaulted flag is
/// indistinguishable from a typed one by value alone, so comparing against the
/// default gets it wrong in both directions — it ignores a flag the operator
/// did type, and it overrides a configured value with a default nobody chose.
/// `was_supplied` answers from clap's own provenance instead.
fn resolve<T>(supplied_on_cli: bool, from_cli: T, from_config: T) -> T {
    if supplied_on_cli {
        from_cli
    } else {
        from_config
    }
}

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
/// `mecmcp_runtime::shutdown::GracefulShutdown` now handles both SIGINT and
/// SIGTERM, so we just subscribe to its unified signal.
fn install_shutdown_signals(shutdown: CancellationToken) -> Result<()> {
    let coordinator = mecmcp_runtime::shutdown::GracefulShutdown::new()
        .context("installing shutdown signal handlers")?;
    let interrupt = coordinator.subscribe();
    tokio::spawn(async move {
        // Hold the coordinator so its signal handlers stay alive.
        let _coordinator = coordinator;
        interrupt.await;
        shutdown.cancel();
    });
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // `parse_for`/`parse_with_provenance` name the binary and its version, so
    // `--version` answers instead of failing as an unknown argument. Parsing
    // the shared `Cli` directly leaves it with no version of its own
    // (mecmcp#159), which breaks the package-identity check a deployment runs.
    let parsed: ParsedCli<ServerCli> = mecmcp_runtime::cli::parse_with_provenance::<ServerCli>(
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
    );
    // Read provenance before consuming `parsed.cli`; `Command` is not `Clone`,
    // so the shared arguments have to be moved out rather than borrowed.
    let state_file_supplied = parsed.was_supplied("state_file");
    let approval_timeout_supplied = parsed.was_supplied("approval_timeout_secs");
    let ServerCli {
        shared: args,
        lab_mode,
        state_file: cli_state_file,
        approval_timeout_secs: cli_approval_timeout_secs,
    } = parsed.cli;
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

    // Explicit CLI beats product configuration, but only when actually typed.
    let state_file = resolve(
        state_file_supplied,
        cli_state_file,
        config.changeset_state_file.clone(),
    );
    let approval_ttl_secs = resolve(
        approval_timeout_supplied,
        cli_approval_timeout_secs,
        config.approval_ttl_secs,
    );

    if lab_mode {
        // A relaxed security control should be visible where someone will see
        // it, not inferred from flags typed weeks ago.
        tracing::warn!(
            "--lab-mode: two-person control is DISABLED. Change sets are approved on \
             creation with approver=null and approval_waiver=\"lab-mode\". Every \
             mutation still goes through prepare and apply, and waived approvals stay \
             distinguishable from genuine ones in the audit trail."
        );
    }
    tracing::info!(
        lab_mode,
        approval_ttl_secs,
        state_file = state_file
            .as_deref()
            .and_then(Path::to_str)
            .unwrap_or("<in-memory>"),
        "change-control configuration resolved"
    );

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

    // Built before the change manager because its coordinator takes the
    // recorder, and started eagerly so a misconfiguration stops the server here
    // rather than at the first change.
    let evidence = match args.evidence.into_config() {
        Ok(Some(config)) => {
            tracing::info!(
                server_id = %config.server_id,
                run_id = %config.run_id,
                "SSDF evidence pipeline enabled"
            );
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let transport = Arc::new(
                mecmcp_transport::evidence_transport::EvidenceHttpTransport::new(
                    args.evidence.ca_file(),
                    provider,
                )
                .context("building the SSDF evidence transport")?,
            );
            Some(
                mecmcp_audit::EvidenceService::start_with_transport(config, transport)
                    .context("starting the SSDF evidence pipeline")?,
            )
        }
        Ok(None) => None,
        Err(error) => anyhow::bail!("SSDF evidence configuration: {error}"),
    };

    let changes = Arc::new(ChangeManager::load(
        client.clone(),
        config.tenant.clone(),
        config.endpoint.clone(),
        state_file.as_deref(),
        Duration::from_secs(approval_ttl_secs),
        lab_mode,
        evidence
            .as_ref()
            .map(mecmcp_audit::EvidenceService::recorder),
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

    // Bound rather than propagated with `?`, so the flush below runs whichever
    // way serving ended. `EvidenceService::Drop` deliberately does not spool --
    // a Drop performing network I/O turns teardown into an unpredictable stall
    // -- so returning the error directly would lose every record the recorder
    // still held, on exactly the failure the trail exists to describe.
    let served: anyhow::Result<()> = async {
        match args.transport {
            Transport::Stdio => {
                // serve_with_ct rather than serve: `serve` does not return until
                // the client sends `initialize`, so a token installed afterwards
                // would miss a signal arriving during the handshake and leave the
                // process blocked on an open stdin. The token owns the service
                // here, and cancelling it cascades to every in-flight request
                // context, so a signal abandons running SDC work rather than
                // waiting out the job-poll deadline.
                let service = match handler
                    .serve_with_ct((tokio::io::stdin(), tokio::io::stdout()), shutdown)
                    .await
                {
                    Ok(service) => service,
                    // A signal arriving before the client sends `initialize` is the
                    // exact case this cancellation path exists for. rmcp reports it
                    // as ServerInitializeError::Cancelled; propagating that would
                    // exit non-zero and record a clean stop as a startup failure.
                    Err(rmcp::service::ServerInitializeError::Cancelled) => {
                        tracing::info!("shutdown signalled before initialization; exiting cleanly");
                        return Ok(());
                    }
                    Err(error) => {
                        return Err(anyhow::Error::new(error))
                            .context("starting MCP stdio service");
                    }
                };
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
                    args.allow_insecure_bind,
                    tls,
                    shutdown,
                    Duration::from_secs(10),
                )
                .await?;
            }
        }
        Ok(())
    }
    .await;

    // Deliver what is still spooled. The drain ships on an interval, so without
    // this every record since the last tick waits for the next start, and a
    // segment still open has never been spooled at all.
    if let Some(service) = evidence
        && let Err(error) = service.shutdown()
    {
        tracing::error!(%error, "the SSDF evidence pipeline did not flush cleanly");
    }

    served
}

#[cfg(test)]
mod tests {
    use super::{
        AuthMode, DEFAULT_APPROVAL_TIMEOUT_SECS, ParsedCli, ServerCli, resolve, resolve_auth_mode,
    };
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

    /// Parse an argument list through the same path `main` uses.
    fn parse(args: &[&str]) -> ParsedCli<ServerCli> {
        mecmcp_runtime::cli::try_parse_from::<ServerCli, _, _>("rustsdcmcp", "0.0.0-test", args)
            .expect("parses")
    }

    #[test]
    fn version_answers_instead_of_erroring() {
        // Parsing the shared `Cli` directly made `--version` an unknown
        // argument, which broke the package-identity check a deployment runs
        // (mecmcp#159). The error carries the rendered version, not a failure.
        let error = mecmcp_runtime::cli::try_parse_from::<ServerCli, _, _>(
            "rustsdcmcp",
            "9.9.9-test",
            ["rustsdcmcp", "--version"],
        )
        .expect_err("--version exits through clap");
        assert_eq!(error.kind(), clap::error::ErrorKind::DisplayVersion);
        assert!(
            error.to_string().contains("9.9.9-test"),
            "--version must name this binary's version, got: {error}"
        );
    }

    #[test]
    fn omitted_flags_fall_back_to_product_configuration() {
        let parsed = parse(&["rustsdcmcp", "--transport", "stdio"]);
        assert!(!parsed.was_supplied("approval_timeout_secs"));
        assert!(!parsed.was_supplied("state_file"));

        // The parser default must not win over a configured value.
        assert_eq!(
            resolve(
                parsed.was_supplied("approval_timeout_secs"),
                parsed.cli.approval_timeout_secs,
                3600
            ),
            3600
        );
    }

    #[test]
    fn an_explicit_flag_beats_product_configuration() {
        let parsed = parse(&["rustsdcmcp", "--approval-timeout-secs", "120"]);
        assert!(parsed.was_supplied("approval_timeout_secs"));
        assert_eq!(
            resolve(
                parsed.was_supplied("approval_timeout_secs"),
                parsed.cli.approval_timeout_secs,
                3600
            ),
            120
        );
    }

    #[test]
    fn a_flag_typed_with_the_default_value_still_wins() {
        // The trap PACKAGING.md names: comparing against the default cannot
        // tell a typed value from a defaulted one, so it would silently hand
        // this operator the configured 3600 they were overriding.
        let typed = format!("{DEFAULT_APPROVAL_TIMEOUT_SECS}");
        let parsed = parse(&["rustsdcmcp", "--approval-timeout-secs", &typed]);
        assert!(parsed.was_supplied("approval_timeout_secs"));
        assert_eq!(
            resolve(
                parsed.was_supplied("approval_timeout_secs"),
                parsed.cli.approval_timeout_secs,
                3600
            ),
            DEFAULT_APPROVAL_TIMEOUT_SECS
        );
    }

    #[test]
    fn state_file_resolves_without_moving_an_existing_deployment() {
        // Adoption must not silently relocate durable state. With the flag
        // absent, the configured path must survive untouched.
        let configured = Some(PathBuf::from("/var/lib/rustsdcmcp/changeset-state.json"));
        let parsed = parse(&["rustsdcmcp"]);
        assert_eq!(
            resolve(
                parsed.was_supplied("state_file"),
                parsed.cli.state_file.clone(),
                configured.clone()
            ),
            configured
        );

        let parsed = parse(&["rustsdcmcp", "--state-file", "/tmp/other.json"]);
        assert_eq!(
            resolve(
                parsed.was_supplied("state_file"),
                parsed.cli.state_file.clone(),
                configured
            ),
            Some(PathBuf::from("/tmp/other.json"))
        );
    }

    #[test]
    fn a_zero_approval_timeout_is_refused() {
        // Zero expires every change set at creation, so approval fails and
        // lab mode's waiver reports the window already closed. SdcConfig
        // rejects it, but an explicit flag bypasses that validation.
        let error = mecmcp_runtime::cli::try_parse_from::<ServerCli, _, _>(
            "rustsdcmcp",
            "0.0.0-test",
            ["rustsdcmcp", "--approval-timeout-secs", "0"],
        )
        .expect_err("a zero approval timeout must be refused");
        assert_eq!(error.kind(), clap::error::ErrorKind::ValueValidation);

        // One second is unhelpful but coherent, so it is the operator's call.
        assert_eq!(
            parse(&["rustsdcmcp", "--approval-timeout-secs", "1"])
                .cli
                .approval_timeout_secs,
            1
        );
    }

    #[test]
    fn lab_mode_is_off_unless_asked_for() {
        assert!(!parse(&["rustsdcmcp"]).cli.lab_mode);
        assert!(parse(&["rustsdcmcp", "--lab-mode"]).cli.lab_mode);
    }

    #[test]
    fn the_shared_flags_survive_flattening() {
        // Declaring the standard flags locally must not drop any shared one.
        let parsed = parse(&[
            "rustsdcmcp",
            "--transport",
            "streamable-http",
            "--host",
            "0.0.0.0",
            "--port",
            "30032",
            "--allowed-host",
            "rustsdcmcp-612.mechub.org:30032",
            "--lab-mode",
        ]);
        assert_eq!(parsed.cli.shared.host, "0.0.0.0");
        assert_eq!(parsed.cli.shared.port, 30032);
        assert_eq!(
            parsed.cli.shared.allowed_host,
            vec!["rustsdcmcp-612.mechub.org:30032".to_owned()]
        );
        assert!(parsed.cli.lab_mode);
    }
}
