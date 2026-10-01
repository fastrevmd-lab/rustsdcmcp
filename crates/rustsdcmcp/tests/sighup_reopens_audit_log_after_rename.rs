//! SIGHUP audit log reopen. Unix-only.
//!
//! Verifies that sending SIGHUP to a process with `rustsdcmcp::install_sighup_handler`
//! wired to a real [`mecmcp_audit::AuditFileSink`] reopens the sink in place: a
//! rename-then-signal rotation (the shape `packaging/logrotate/rustsdcmcp-audit`
//! performs) loses nothing written before the rename and routes everything
//! written after it to the fresh inode at the same path.
//!
//! `mecmcp_audit::init_tracing` installs a process-global subscriber and is
//! idempotent — a second call in the same binary returns `None` rather than a
//! working sink (see its doc comment). Every `tests/*.rs` file is its own
//! binary, so this test gets the global subscriber to itself; do not add a
//! second `#[test]` here that also calls `init_tracing`.
#![cfg(unix)]
#![allow(clippy::unwrap_used)]

use mecmcp_audit::{Attribution, AuditConfig, AuditFormat, AuditScope};
use std::time::{Duration, Instant};

fn sighup_self() {
    let pid = rustix::process::getpid();
    rustix::process::kill_process(pid, rustix::process::Signal::HUP).expect("kill(SIGHUP)");
}

async fn wait_for_nonempty(path: &std::path::Path, deadline: Instant) -> String {
    loop {
        if let Ok(contents) = std::fs::read_to_string(path)
            && !contents.is_empty()
        {
            return contents;
        }
        assert!(
            Instant::now() < deadline,
            "{} never became non-empty",
            path.display()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn emit_audit_record(tool: &'static str) {
    let mut scope = AuditScope::new(Attribution::stdio(), tool, "read", Vec::new());
    scope.succeed();
}

#[tokio::test(flavor = "multi_thread")]
async fn sighup_reopens_audit_log_after_rename() {
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");

    let sink = mecmcp_audit::init_tracing(&AuditConfig {
        format: AuditFormat::Json,
        audit_log_file: Some(audit_path.clone()),
        redaction: None,
        journald: false,
        otel: None,
    })
    .expect("initializing audit tracing")
    .expect("a file sink was configured, so init_tracing must return one");

    rustsdcmcp::install_sighup_handler(Some(sink), None).expect("installing SIGHUP handler");

    // First record lands in the original inode.
    emit_audit_record("sighup_test_marker_before");
    let deadline = Instant::now() + Duration::from_secs(5);
    let before = wait_for_nonempty(&audit_path, deadline).await;
    assert!(
        before.contains("sighup_test_marker_before"),
        "audit file missing first record: {before}"
    );

    // Rotate the way logrotate's rename-mode fragment does: move the file
    // aside, then signal the process.
    let rotated = dir.path().join("audit.jsonl.1");
    std::fs::rename(&audit_path, &rotated).unwrap();
    sighup_self();

    // Second record must land at the same path, in a fresh inode, once the
    // reopen has completed. Poll rather than sleep a fixed amount: the
    // reopen races the SIGHUP delivery and this keeps the happy path fast.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        emit_audit_record("sighup_test_marker_after");
        if let Ok(contents) = std::fs::read_to_string(&audit_path)
            && contents.contains("sighup_test_marker_after")
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "second record never appeared at {} within 5s after SIGHUP",
            audit_path.display()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    // The reopen and this loop's writes race the same way real traffic races
    // logrotate's rename + `postrotate` signal: a write submitted after the
    // rename but before the reopen completes still lands in the rotated
    // file, which is correct (nothing is lost) even though it makes the
    // rotated file a superset rather than an exact match of `before`. What
    // must never happen is `before` being truncated or reordered away.
    let rotated_contents = std::fs::read_to_string(&rotated).unwrap();
    assert!(
        rotated_contents.starts_with(&before),
        "the rotated-away file must keep everything written before the rename, losing nothing:\n{rotated_contents}"
    );
}
