//! SIGHUP hot-reload wiring: reopen the audit log, then reload the token store.

use mecmcp_audit::AuditFileSink;
use mecmcp_auth::{NoGrant, TokenStoreFile};
use std::sync::Arc;

/// Install the SIGHUP handler that reopens `audit_sink` (when configured) and
/// then reloads `token_store` (when configured), in that order.
///
/// The reopen runs first and unconditionally: it is the lossless half of log
/// rotation (the rotator renames the file, then signals the process), and a
/// failure there must not block the token reload that follows.
///
/// Installs nothing, returning `Ok(())` immediately, when neither is
/// configured — there is nothing to hot-reload, so SIGHUP keeps its default
/// disposition rather than gaining a handler that only exists to no-op.
/// Installing whenever *either* is configured (not just the token store)
/// matters on its own: a deployment with only `--audit-log-file` set still
/// needs a handler, or SIGHUP's default disposition (terminate) kills the
/// process on the very signal logrotate sends it.
///
/// # Errors
///
/// Returns the underlying I/O error if the signal handler cannot be
/// registered with the runtime.
pub fn install_sighup_handler(
    audit_sink: Option<AuditFileSink>,
    token_store: Option<Arc<TokenStoreFile<NoGrant>>>,
) -> std::io::Result<()> {
    if audit_sink.is_none() && token_store.is_none() {
        return Ok(());
    }
    mecmcp_runtime::signals::install_hup_handler(move || {
        if let Some(sink) = &audit_sink {
            match sink.reopen() {
                Ok(()) => {
                    tracing::info!(path = %sink.path().display(), "audit log reopened");
                }
                Err(error) => {
                    tracing::warn!(
                        %error,
                        path = %sink.path().display(),
                        "audit log reopen failed; keeping previous sink"
                    );
                }
            }
        }
        if let Some(store) = &token_store {
            match store.reload() {
                Ok(()) => tracing::info!(tokens = store.store().len(), "token store reloaded"),
                Err(error) => {
                    tracing::error!(%error, "token reload failed; retaining previous snapshot");
                }
            }
        }
    })
}
