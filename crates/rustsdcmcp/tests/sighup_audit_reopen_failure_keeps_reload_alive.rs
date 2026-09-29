//! A failed audit-log reopen must not take the SIGHUP handler down. Unix-only.
//!
//! `rustsdcmcp::install_sighup_handler` wraps the audit reopen and the token
//! reload in a single callback so the reopen always runs first, but a
//! `reopen()` failure must be a `warn`-log, not a panic — a panic inside that
//! callback would unwind the background task `mecmcp_runtime::signals`
//! spawned, silently ending SIGHUP handling for the rest of the process
//! (fail-closed on the device, not on the operator's ability to rotate logs
//! or push a new token). This proves the token reload half of the same
//! SIGHUP still runs when the audit half fails.
#![cfg(unix)]
#![allow(clippy::unwrap_used)]

use mecmcp_audit::AuditConfig;
use mecmcp_auth::{KnownNames, NoGrant, ScopeSet, TokenStoreFile};
use std::time::{Duration, Instant};

fn sighup_self() {
    let pid = rustix::process::getpid();
    rustix::process::kill_process(pid, rustix::process::Signal::HUP).expect("kill(SIGHUP)");
}

#[tokio::test(flavor = "multi_thread")]
async fn sighup_audit_reopen_failure_keeps_token_reload_alive() {
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let token_path = dir.path().join("tokens.json");

    let sink = mecmcp_audit::init_tracing(&AuditConfig {
        format: mecmcp_audit::AuditFormat::Json,
        audit_log_file: Some(audit_path.clone()),
        redaction: None,
        journald: false,
    })
    .expect("initializing audit tracing")
    .expect("a file sink was configured, so init_tracing must return one");

    let known_devices = ["tenant".to_owned()];
    let known = KnownNames {
        devices: Some(&known_devices),
        tools: &["get_sdc_tenant_scope"],
    };
    TokenStoreFile::<NoGrant>::add(
        &token_path,
        "first",
        ScopeSet::Wildcard,
        ScopeSet::Wildcard,
        &known,
    )
    .expect("seed token");
    let store =
        std::sync::Arc::new(TokenStoreFile::<NoGrant>::load(&token_path).expect("load store"));
    assert_eq!(store.store().len(), 1, "seeded with exactly one token");

    rustsdcmcp::install_sighup_handler(Some(sink), Some(store.clone()))
        .expect("installing SIGHUP handler");

    // Make the reopen fail: replace the audit path with a directory, so
    // `OpenOptions::create().append()` on it returns EISDIR. The server's
    // existing (now-unlinked) descriptor keeps working regardless.
    std::fs::remove_file(&audit_path).unwrap();
    std::fs::create_dir(&audit_path).unwrap();

    // Add a second token to the file on disk without touching `store` — this
    // is what SIGHUP's reload half must pick up.
    TokenStoreFile::<NoGrant>::add(
        &token_path,
        "second",
        ScopeSet::Wildcard,
        ScopeSet::Wildcard,
        &known,
    )
    .expect("add second token");

    sighup_self();

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if store.store().len() == 2 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "token store was never reloaded after a SIGHUP whose audit reopen failed \
             (stuck at {} entries) -- the failed reopen must not have taken the \
             handler down",
            store.store().len()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    std::fs::remove_dir(&audit_path).unwrap();
}
