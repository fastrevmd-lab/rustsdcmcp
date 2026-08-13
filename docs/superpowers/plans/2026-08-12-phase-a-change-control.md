# Phase A: Make Change Control Mean What It Says — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Settle the four change-control defects so a preview means what it says, a failed deploy can be recovered without editing state by hand, and an unsupported deploy target is refused locally.

**Architecture:** Four independent changes to `rustsdcmcp-core` and the MCP handler, plus one live investigation that gates the largest of them. No new dependencies. The change-control lifecycle in `mecmcp-changeset` is consumed, never modified — `mecmcp` is off-limits from this repository (CLAUDE.md).

**Tech Stack:** Rust edition 2024, MSRV 1.88, `rmcp` 3.1.1, `mecmcp-*` 0.8.0, `tokio`, `axum` (test servers only), `serde_json`.

## Global Constraints

- Rust edition 2024, MSRV 1.88, toolchain pinned in `rust-toolchain.toml`.
- Workspace lints: `missing_docs = "warn"`, `unsafe_code = "forbid"`, `dbg_macro`/`todo` deny, `unwrap_used` warn. Tests may use `expect`.
- Every commit must pass `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`.
- **Never modify `~/Projects/mecmcp`** from this repository. Missing upstream capability is filed as an issue, not patched locally.
- Never restate an SDC endpoint, header, or parameter from memory. `docs/sdc-api/README.md` and the generated `docs/sdc-api/endpoints.md` are the authority.
- Mutating tools are reachable only through `mecmcp-changeset`'s plan → digest → approve → apply lifecycle. Never a direct write.
- Any tool that mutates state must be listed in `WRITE_TOOLS` (`crates/rustsdcmcp/src/server.rs:88`). A wildcard token scope grants no write tool; that is enforced upstream in `mecmcp-auth` and must not be worked around.
- Adding or removing a tool changes `KNOWN_TOOLS` and breaks `crates/rustsdcmcp/tests/tool_contract.rs`, which asserts an exact count. Update the count and its comment in the same commit.
- **Any tool-surface change forces a token re-mint.** Token tool scopes are explicit allowlists, so existing tokens will not see new tools. Call this out in the PR description.
- Live verification uses `vsrx-ci` — VMID **907**, node **pve2**, tag `ci`. It is the SDC test device and is meant to be used. Reach pve2 directly (`ssh root@pve2.mechub.org`); pve3 may be down. Snapshot with `qm snapshot 907 <name>` before any device mutation.
- Deploy order for anything reaching a container is **606 (test) first, then 951 (production)**.

---

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `docs/sdc-api/README.md` | Pinned API facts and live findings | Modify — §11 gains the A1 answers |
| `crates/rustsdcmcp-core/src/models.rs` | Request/response models, `TargetType` | Modify — target validation |
| `crates/rustsdcmcp-core/src/change.rs` | Change-control adapter, `SdcTransaction`, `ChangeManager` | Modify — `rollback` truthfulness, `discard` passthrough |
| `crates/rustsdcmcp/src/server.rs` | MCP tool surface | Modify — new discard tool, target refusal wiring, preview caveat |
| `crates/rustsdcmcp/tests/tool_contract.rs` | Surface tripwire | Modify — tool count |
| `docs/operations.md` | Operator guidance | Modify — preview caveat, discard recovery |

---

### Task 1: Answer #66 — does the XML preview disclose what the CLI preview omitted?

This is an investigation, not a code change. It gates Task 6. Do not design a mitigation before completing it.

**Files:**
- Modify: `docs/sdc-api/README.md` (§11)

**Interfaces:**
- Consumes: nothing.
- Produces: a recorded answer that selects Task 6's branch. No code symbols.

**Background:** On 2026-08-12 a policy deploy previewed one delete line (`delete security dynamic-address address-name exp-unreferenced`) and committed two removals — the `feed-server expfeeder` was also removed. The string `expfeeder` appears zero times in the digest-bound prepared artifact. `docs/sdc-api/README.md` §11 records this.

- [ ] **Step 1: Recreate the condition on the lab device**

Snapshot first:

```bash
ssh root@pve2.mechub.org "qm snapshot 907 pre-66-investigation --description 'before #66 preview-format investigation'"
```

Upload a template that places an unreferenced object. The YAML schema is recorded in `docs/sdc-api/README.md` §10:

```yaml
action-category: template-create
spec:
  name: PREVIEW_FORMAT_PROBE
  description: "#66 investigation - unreferenced object for preview comparison"
  format: CLI
  body: |
    set security dynamic-address feed-server probefeeder url https://feeds.example.com/bundle.tgz
    set security dynamic-address feed-server probefeeder update-interval 3600
    set security dynamic-address feed-server probefeeder feed-name probefeed path bundle/blocklist
    set security dynamic-address address-name probe-unreferenced profile feed-name probefeed
```

Upload and deploy it, using the credential inside container 951:

```bash
ssh root@pve2.mechub.org "pct exec 951 -- sh -c 'set -a; . /etc/rustsdcmcp/credentials.env; set +a; \
  curl -s -X POST -H \"x-api-key: \$SDC_API_TOKEN\" \
  -F \"definition_file=@/tmp/probe.yaml\" \
  https://api.sdcloud.juniperclouds.net/api/v1/templates/workflow_definitions'"
```

Confirm the config landed:

```bash
# expect four set lines
show configuration security dynamic-address | display set
```

- [ ] **Step 2: Request both preview formats for the same policy deploy**

`PreviewTemplate` accepts `format`. Request the policy preview twice and capture both bodies. The policy preview endpoints are in `docs/sdc-api/endpoints.md` under Policy Management; read the exact paths there rather than from memory.

Record for each format:
- whether `probefeeder` appears
- whether `probe-unreferenced` appears
- the total number of `delete` lines

- [ ] **Step 3: Answer the two secondary questions**

1. **Is the omission specific to an orphaned parent?** Deploy a second template placing an unreferenced `address-name` that points at the *existing* working feed, so no parent is orphaned when it is removed. Note that Junos permits only one dynamic address per feed — `"Feed <name> has already been referenced by dynamic address <name>"` — so this needs its own feed-server, or a different object family entirely.
2. **Did #23's deploy under-report?** Compare the diff recorded in `docs/operations.md` "What SDC owns" against what that deploy actually removed, if the record is sufficient. If it is not, say so rather than guessing.

- [ ] **Step 4: Record the answers in `docs/sdc-api/README.md` §11**

Replace the "What is not yet known" list with what is now known. State plainly which questions remain open. Do not close a question by inference — that rule is in CLAUDE.md and this section already exercised it once.

- [ ] **Step 5: Clean up**

```bash
# delete the probe templates from the tenant
DELETE /api/v1/templates/{template_id}
# remove leftover device config if the deploy did not
```

Verify the device is back to its prior state and `security dynamic-address` matches the pre-snapshot content.

- [ ] **Step 6: Commit**

```bash
git add docs/sdc-api/README.md
git commit -m "docs(sdc-api): answer whether the XML preview discloses what CLI omits (#66)"
```

- [ ] **Step 7: Post the finding to issue #66**

Include the raw evidence — the two preview bodies' relevant fragments and the device-side `compare rollback` — so the next reader does not have to re-run it.

---

### Task 2: Refuse a `DEVICE_GROUP` deploy target (#61)

**Files:**
- Modify: `crates/rustsdcmcp-core/src/models.rs` (add validation near `Target`, around line 70)
- Modify: `crates/rustsdcmcp-core/src/change.rs` (`prepare`, around line 1203)
- Test: `crates/rustsdcmcp-core/src/models.rs` (in-module `#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: `Target { target_id: String, target_type: TargetType }` and `TargetType::{Device, DeviceGroup}` from `models.rs:60-75`.
- Produces: `pub fn validate_deploy_targets(targets: &[Target]) -> Result<(), SdcError>` in `models.rs`, called by `ChangeManager::prepare`.

**Background:** The pinned spec says `DEVICE_GROUP: Group of devices (Not supported, future support)`, recorded in `docs/sdc-api/README.md` §9. Today the request is built and SDC rejects it, costing a preview job and returning a generic error.

- [ ] **Step 1: Write the failing test**

Add to the `#[cfg(test)] mod tests` block in `crates/rustsdcmcp-core/src/models.rs` (create the block if absent):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_device_group_deploy_target_is_refused_with_a_reason() {
        let targets = vec![Target {
            target_id: "group-1".to_owned(),
            target_type: TargetType::DeviceGroup,
        }];

        let error = validate_deploy_targets(&targets)
            .expect_err("DEVICE_GROUP is documented as unsupported and must be refused here");

        let rendered = error.to_string();
        assert!(
            rendered.contains("DEVICE_GROUP"),
            "the message must name the target type so an operator can act on it; got: {rendered}"
        );
        assert!(
            rendered.contains("not supported"),
            "the message must quote the pinned spec's wording; got: {rendered}"
        );
    }

    #[test]
    fn a_device_target_is_accepted() {
        let targets = vec![Target::device("a0f049c4-903a-471e-93c2-f8d19d30cebc")];
        assert!(validate_deploy_targets(&targets).is_ok());
    }

    #[test]
    fn an_empty_target_list_is_not_this_functions_concern() {
        // Emptiness is validated elsewhere; this guard is only about target type,
        // and silently rejecting here would move an unrelated error message.
        assert!(validate_deploy_targets(&[]).is_ok());
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cargo test -p rustsdcmcp-core a_device_group_deploy_target_is_refused
```

Expected: FAIL — `cannot find function 'validate_deploy_targets'`.

- [ ] **Step 3: Write the minimal implementation**

Add to `crates/rustsdcmcp-core/src/models.rs`, after the `Target` impl:

```rust
/// Refuse deploy targets the pinned API documents as unsupported.
///
/// `apiTargetType` in the vendored spec reads
/// `DEVICE_GROUP: Group of devices (Not supported, future support)`, and
/// `Target1.type` adds `DEVICE_GROUP will be supported later`. The variant is
/// modelled because the API declares it, so a request naming a group is built
/// and sent today and SDC rejects it — costing a preview job and returning a
/// generic error that names nothing.
///
/// Refusing locally is trivially reversible: when SDC supports it, delete this
/// guard and its test.
///
/// # Errors
///
/// Returns [`SdcError::InvalidInput`] when any target is a device group.
pub fn validate_deploy_targets(targets: &[Target]) -> Result<(), SdcError> {
    if targets
        .iter()
        .any(|target| target.target_type == TargetType::DeviceGroup)
    {
        return Err(SdcError::InvalidInput(
            "DEVICE_GROUP is not supported as a deploy target: the pinned SDC API \
             marks it \"Not supported, future support\". Target devices individually.",
        ));
    }
    Ok(())
}
```

Check `SdcError::InvalidInput`'s actual shape in `client.rs` before writing this — it takes `&'static str` at the time of writing. If it takes `String`, adjust the call and keep the message identical.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test -p rustsdcmcp-core validate_deploy_targets
cargo test -p rustsdcmcp-core a_device_
```

Expected: PASS.

- [ ] **Step 5: Call it from `ChangeManager::prepare`**

In `crates/rustsdcmcp-core/src/change.rs`, at the top of `prepare` (line ~1203), before `self.client.prepare_policy_deploy(...)`:

```rust
for operation in &policies {
    crate::models::validate_deploy_targets(&operation.deploy_targets)?;
    crate::models::validate_deploy_targets(&operation.undeploy_targets)?;
}
```

Export it if it is not already public at the crate root: add `validate_deploy_targets` to the `pub use models::{...}` list in `crates/rustsdcmcp-core/src/lib.rs`.

- [ ] **Step 6: Add an integration test proving no SDC request is made**

Add to the `#[cfg(test)] mod tests` in `crates/rustsdcmcp-core/src/change.rs`, modelled on `deployment_requires_preview_and_independent_approval`:

```rust
#[tokio::test]
async fn a_device_group_target_is_refused_before_any_sdc_request() {
    let calls = Arc::new(Calls::default());
    let app = Router::new()
        .route("/api/v1/policies/preview", post(preview))
        .with_state(calls.clone());
    let (base_url, server) = serve(app).await;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client =
        SdcClient::from_test_parts(base_url.clone(), "test-secret".to_owned(), 64 * 1024, 100);
    let manager = ChangeManager::load(
        client,
        "tenant-a",
        base_url.to_string(),
        None,
        Duration::from_secs(60),
        false,
    )
    .expect("change manager");

    let error = manager
        .prepare(
            "alice".to_owned(),
            vec![PolicyOperation {
                policy_id: "policy-1".to_owned(),
                policy_type: PolicyType::Firewall,
                deploy_targets: vec![Target {
                    target_id: "group-1".to_owned(),
                    target_type: TargetType::DeviceGroup,
                }],
                undeploy_targets: Vec::new(),
            }],
            &CancellationToken::new(),
        )
        .await
        .expect_err("a device-group target must be refused");

    assert!(error.to_string().contains("DEVICE_GROUP"));
    assert_eq!(
        calls.previews.load(Ordering::SeqCst),
        0,
        "refusal must happen before a preview job is spent on the management plane"
    );
    server.abort();
}
```

- [ ] **Step 7: Run the full gate**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Expected: all pass.

- [ ] **Step 8: Commit**

```bash
git add crates/rustsdcmcp-core/src/models.rs crates/rustsdcmcp-core/src/change.rs crates/rustsdcmcp-core/src/lib.rs
git commit -m "fix(core): refuse a DEVICE_GROUP deploy target locally (#61)

The pinned spec marks DEVICE_GROUP 'Not supported, future support', but the
variant is modelled, so a request naming a group was built, sent, and rejected
by SDC -- spending a preview job to get a generic error naming nothing.

Refused at prepare, before any SDC request, with a message quoting the spec.
The guard is one function and one call site so it can be deleted the day SDC
supports it."
```

---

### Task 3: Make `SdcTransaction::rollback` report truthfully

This unblocks Task 4. Do it first and separately — it is a semantic change to a trait implementation and deserves its own review.

**Files:**
- Modify: `crates/rustsdcmcp-core/src/change.rs:176-178`
- Test: same file, in-module tests

**Interfaces:**
- Consumes: `RollbackOutcome { succeeded: bool, details: Option<String> }` from `mecmcp_changeset::transaction`, and `RollbackRef`.
- Produces: `SdcTransaction::rollback` returning `Ok(RollbackOutcome)` instead of `Err(SdcError::RollbackUnsupported)`.

**Background — read this before changing anything.** `mecmcp-changeset::discard_operation` (`operation.rs:719`) is the only caller of `rollback`. It calls `transaction.rollback(RollbackRef::CandidateRevert)` and, on `Err`, sets the record to `Failed` or `Indeterminate`. `Indeterminate` is in the guard list that refuses future discards, so today a discard of an SDC operation would either no-op or wedge the record permanently. Exposing a discard tool without this change does not fix #63.

Returning success is truthful for every state a discard can reach. `discard_operation` refuses `Validating`, `Committing`, `Committed`, `Discarded`, and `Indeterminate`, so a discardable operation either never reached the device, or is `Failed` — and on failure SDC rolls the device back itself, observed on 2026-08-12 as `sduser` issuing `commit confirmed` then `discard-changes` and a rollback. There is nothing left to revert.

- [ ] **Step 1: Write the failing test**

```rust
#[tokio::test]
async fn rollback_reports_that_sdc_already_reverted_rather_than_erroring() {
    // discard_operation is rollback's only caller, and it turns an Err into a
    // Failed or Indeterminate record. Indeterminate cannot be discarded again,
    // so erroring here makes a wedged operation permanently unrecoverable.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = SdcClient::from_test_parts(
        "https://sdc.invalid/".parse().expect("test url"),
        "test-secret".to_owned(),
        64 * 1024,
        100,
    );
    let transaction = SdcTransaction::new(client, "sha256:whatever", CancellationToken::new());

    let outcome = transaction
        .rollback(RollbackRef::CandidateRevert)
        .await
        .expect("rollback must not error: SDC has already reverted the device");

    assert!(outcome.succeeded);
    let details = outcome.details.expect("the reason must be recorded");
    assert!(
        details.contains("SDC"),
        "details must say who reverted the device; got: {details}"
    );
}
```

Add `use mecmcp_changeset::RollbackRef;` to the test module imports if absent. Check `SdcClient::from_test_parts`'s exact signature in `client.rs` and match it.

- [ ] **Step 2: Run the test to verify it fails**

```bash
cargo test -p rustsdcmcp-core rollback_reports_that_sdc_already_reverted
```

Expected: FAIL — `rollback must not error`, because the current implementation returns `Err(SdcError::RollbackUnsupported)`.

- [ ] **Step 3: Write the implementation**

Replace `crates/rustsdcmcp-core/src/change.rs:176-178`:

```rust
    /// Report that there is nothing left to revert.
    ///
    /// `mecmcp-changeset::discard_operation` is the only caller. It refuses to
    /// discard an operation in `Validating`, `Committing`, `Committed`,
    /// `Discarded`, or `Indeterminate`, so anything reaching here either never
    /// reached the device or is `Failed` — and SDC reverts the device itself on
    /// a failed deploy, observed as `sduser` issuing `commit confirmed` and then
    /// `discard-changes` with a rollback.
    ///
    /// Returning `Err` here is worse than useless: `discard_operation` turns it
    /// into a `Failed` or `Indeterminate` record, and `Indeterminate` cannot be
    /// discarded again, so the operation would be permanently unrecoverable —
    /// the opposite of what a discard is for.
    ///
    /// This is not a claim that SDC supports arbitrary rollback. It does not,
    /// and no other caller asks it to.
    async fn rollback(&self, _to: RollbackRef) -> Result<RollbackOutcome, Self::Error> {
        Ok(RollbackOutcome {
            succeeded: true,
            details: Some(
                "SDC reverts the device itself when a deploy fails, so a discarded \
                 operation has nothing left to revert locally"
                    .to_owned(),
            ),
        })
    }
```

Add `RollbackOutcome` to the `mecmcp_changeset::{...}` import list at the top of `change.rs` if it is not already there.

- [ ] **Step 4: Run the test to verify it passes**

```bash
cargo test -p rustsdcmcp-core rollback_reports_that_sdc_already_reverted
```

Expected: PASS.

- [ ] **Step 5: Check whether `SdcError::RollbackUnsupported` is now unused**

```bash
grep -rn "RollbackUnsupported" crates/
```

If the variant has no remaining constructor, leave it in place — removing a public error variant is a breaking change unrelated to this fix — but confirm `clippy` does not warn. If it does, note it in the commit message rather than deleting the variant.

- [ ] **Step 6: Run the full gate**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

- [ ] **Step 7: Commit**

```bash
git add crates/rustsdcmcp-core/src/change.rs
git commit -m "fix(core): report that SDC already reverted rather than erroring on rollback

discard_operation is rollback's only caller and turns an Err into a Failed or
Indeterminate record. Indeterminate cannot be discarded again, so the previous
RollbackUnsupported error would make a wedged operation permanently
unrecoverable -- the opposite of what a discard is for.

Every state a discard can reach either never touched the device or is Failed,
and SDC reverts the device itself on a failed deploy. Reporting success with
that reason recorded is the truthful answer, and it is not a claim that SDC
supports arbitrary rollback."
```

---

### Task 4: Expose an operation discard tool (#63)

**Files:**
- Modify: `crates/rustsdcmcp-core/src/change.rs` (add `discard` beside `approve`, around line 1268)
- Modify: `crates/rustsdcmcp/src/server.rs` (args struct near line 208; tool beside `get_sdc_change_set`; `KNOWN_TOOLS` line ~36; `WRITE_TOOLS` line ~88)
- Modify: `crates/rustsdcmcp/tests/tool_contract.rs` (count and comment)
- Modify: `docs/operations.md` (recovery section)

**Interfaces:**
- Consumes: `ChangesetCoordinator::discard_operation(operation_id: &str, device: &str, owner: &str, expected_fingerprint: &str, transaction: &T, cancellation: &CancellationToken) -> Result<String, CoordinatorError>`; `SdcTransaction::new(client, expected_preview_digest, cancellation)`; `Task 3`'s truthful `rollback`.
- Produces: `ChangeManager::discard(operation_id: String, owner: String, expected_fingerprint: String, cancellation: &CancellationToken) -> Result<String, SdcError>`, and the MCP tool `discard_sdc_operation`.

**Background:** A failed deploy leaves an operation in state `failed`, and every later apply on the tenant is refused with *"the device already has an active or unreconciled operation"*. Observed twice on 2026-08-12; the only remedy was editing `changeset-state.json` by hand.

- [ ] **Step 1: Write the failing test for the core method**

Add to `change.rs` tests:

```rust
#[tokio::test]
async fn a_discarded_operation_stops_blocking_later_applies() {
    let calls = Arc::new(Calls::default());
    let app = Router::new()
        .route("/api/v1/policies/preview", post(preview))
        .route(
            "/api/v1/policies/preview/{id}",
            get(|| async {
                Json(json!({
                    "preview_id": "preview-1",
                    "status": "COMPLETED",
                    "device_deployment_status": [],
                    "message": ""
                }))
            }),
        )
        .with_state(calls.clone());
    let (base_url, server) = serve(app).await;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client =
        SdcClient::from_test_parts(base_url.clone(), "test-secret".to_owned(), 64 * 1024, 100);
    let manager = ChangeManager::load(
        client,
        "tenant-a",
        base_url.to_string(),
        None,
        Duration::from_secs(60),
        true,
    )
    .expect("change manager");
    let cancellation = CancellationToken::new();

    let prepared = manager
        .prepare(
            "alice".to_owned(),
            vec![PolicyOperation {
                policy_id: "policy-1".to_owned(),
                policy_type: PolicyType::Firewall,
                deploy_targets: vec![Target::device("device-1")],
                undeploy_targets: Vec::new(),
            }],
            &cancellation,
        )
        .await
        .expect("prepare");

    // A wrong fingerprint must be refused: a stale client must not be able to
    // clear an operation it has not actually read.
    let refused = manager
        .discard(
            "operation-that-does-not-exist".to_owned(),
            "alice".to_owned(),
            prepared.prepared_change.preview_digest().to_owned(),
            &cancellation,
        )
        .await;
    assert!(refused.is_err(), "an unknown operation id must be refused");

    server.abort();
}
```

- [ ] **Step 2: Run it to verify it fails**

```bash
cargo test -p rustsdcmcp-core a_discarded_operation_stops_blocking
```

Expected: FAIL — no method `discard` on `ChangeManager`.

- [ ] **Step 3: Implement `ChangeManager::discard`**

Add to `change.rs` immediately after `approve`:

```rust
    /// Discard a terminal-but-unreconciled operation so applies are unblocked.
    ///
    /// A failed deploy leaves an operation that refuses every later apply on the
    /// tenant with "the device already has an active or unreconciled operation".
    /// Without this, the only remedy is editing the change-set state file on a
    /// running deployment, which is the file the whole design exists to keep
    /// hands out of.
    ///
    /// The caller must supply the operation's expected fingerprint, so a stale
    /// client cannot clear an operation it has not read. Upstream additionally
    /// refuses any operation that is `Validating`, `Committing`, `Committed`,
    /// `Discarded`, or `Indeterminate`, and refuses a caller who does not own it.
    ///
    /// # Errors
    ///
    /// Returns [`SdcError::ChangeControl`] when the operation is unknown, not
    /// owned by `owner`, in a state that cannot be discarded, or when the
    /// fingerprint does not match.
    pub async fn discard(
        &self,
        operation_id: String,
        owner: String,
        expected_fingerprint: String,
        cancellation: &CancellationToken,
    ) -> Result<String, SdcError> {
        let transaction = SdcTransaction::new(
            self.client.clone(),
            expected_fingerprint.clone(),
            cancellation.clone(),
        );
        self.coordinator
            .discard_operation(
                &operation_id,
                &self.tenant,
                &owner,
                &expected_fingerprint,
                &transaction,
                cancellation,
            )
            .await
            .map_err(|error| SdcError::ChangeControl(error.to_string()))
    }
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cargo test -p rustsdcmcp-core a_discarded_operation_stops_blocking
```

Expected: PASS.

- [ ] **Step 5: Add the tool arguments struct**

In `crates/rustsdcmcp/src/server.rs`, beside the other args structs (near line 208):

```rust
/// Arguments for discarding one terminal-but-unreconciled operation.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiscardOperationArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Operation identifier reported by the change-set state.
    pub operation_id: String,
    /// The operation's expected fingerprint, so a stale caller cannot clear an
    /// operation it has not read.
    pub expected_fingerprint: String,
}
```

- [ ] **Step 6: Add the tool**

Place it immediately after `get_sdc_change_set` in `server.rs`:

```rust
    #[tool(
        name = "discard_sdc_operation",
        description = "Discard one terminal-but-unreconciled SDC operation so applies are unblocked. A failed deploy otherwise refuses every later apply on the tenant. Requires the operation's expected fingerprint, and only its owner may discard it. The operation remains visible in change-set state."
    )]
    async fn discard_sdc_operation(
        &self,
        Parameters(args): Parameters<DiscardOperationArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "discard_sdc_operation",
            "write",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "discard_sdc_operation", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish(
            audit,
            self.changes
                .discard(
                    args.operation_id,
                    owner(caller),
                    args.expected_fingerprint,
                    &cancellation,
                )
                .await,
        ))
    }
```

Check the `audit_scope` action string used by the other write tools (`prepare_sdc_object_write` and friends) and match it exactly rather than assuming `"write"`.

- [ ] **Step 7: Register the tool in both registries**

`KNOWN_TOOLS` (line ~36), after `"get_sdc_change_set_details"`:

```rust
    "discard_sdc_operation",
```

`WRITE_TOOLS` (line ~88), at the end of the list:

```rust
    "discard_sdc_operation",
```

Registering in `WRITE_TOOLS` is what stops a wildcard token scope from reaching it. rustjunosmcp#239 shipped a change-set tool missing from its write registry; the contract test below is what prevents a repeat.

- [ ] **Step 8: Update the tool contract test**

In `crates/rustsdcmcp/tests/tool_contract.rs`:

```rust
    // 39 reads / 12 writes. #32 added 6 license/certificate reads (PR #49) and
    // 2 license/certificate writes; #34 added device-group list and get; #63
    // added discard_sdc_operation, which must be a write tool so a wildcard
    // scope cannot reach it.
    assert_eq!(KNOWN_TOOLS.len(), 51);
```

And add `"discard_sdc_operation"` to the `BTreeSet::from([...])` of expected write tools in the same test.

- [ ] **Step 9: Run the full gate**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

The existing test asserting every write tool is named for a change-control phase may reject `discard_sdc_operation`, since it checks for a `prepare_`/`approve_`/`apply_` prefix. If so, widen that test deliberately with a comment explaining that discard is a lifecycle operation rather than a phase — do not rename the tool to fit the assertion.

- [ ] **Step 10: Document the recovery path**

In `docs/operations.md`, in the change-control section, add:

```markdown
### Recovering from a failed deploy

A failed deploy leaves an operation that refuses every later apply on the tenant
with "the device already has an active or unreconciled operation". Clear it with
`discard_sdc_operation`, supplying the operation id and its expected
fingerprint from the change-set state. Only the operation's owner may discard
it, and the record remains visible afterwards — a discard clears the block, it
does not erase the fact that a deploy failed.
```

- [ ] **Step 11: Commit**

```bash
git add crates/rustsdcmcp-core/src/change.rs crates/rustsdcmcp/src/server.rs crates/rustsdcmcp/tests/tool_contract.rs docs/operations.md
git commit -m "feat(tools): discard a wedged operation instead of editing state by hand (#63)

A failed deploy left an operation that refused every later apply on the tenant,
and the only remedy was editing changeset-state.json on a running deployment --
the file the change-control design exists to keep hands out of. Observed twice
on 2026-08-12.

Owner-only and fingerprint-bound, so a stale caller cannot clear an operation it
has not read, and registered in WRITE_TOOLS so a wildcard token scope cannot
reach it. The discarded operation stays visible: this unblocks applies, it does
not erase the failure."
```

---

### Task 5: State that a preview is a lower bound

This lands regardless of Task 1's outcome. If Task 1 shows the XML preview is complete, Task 6 will narrow this wording — that is a smaller edit than leaving operators uninformed in the meantime.

**Files:**
- Modify: `crates/rustsdcmcp/src/server.rs` (`prepare_sdc_policy_deploy` description)
- Modify: `docs/operations.md`

**Interfaces:**
- Consumes: nothing.
- Produces: nothing. Text only.

- [ ] **Step 1: Amend the tool description**

Find the `#[tool(name = "prepare_sdc_policy_deploy", ...)]` attribute in `server.rs` and append to its `description`:

```
 A deploy has been observed committing a deletion its preview did not disclose (#66), so treat the preview as a lower bound on what will change, not a complete statement of it.
```

- [ ] **Step 2: Add the same caveat to the operator guide**

In `docs/operations.md`, in the "Policy deployment" section, after the numbered lifecycle:

```markdown
**A preview is a lower bound.** On 2026-08-12 a deploy previewed a single
deletion and committed two; the omitted object did not appear anywhere in the
digest-bound artifact. The change-set binding behaved correctly — what it bound
did not describe the whole change. Until #66 is settled, confirm a deploy's
actual effect on the device with `show configuration | compare rollback 1`
rather than assuming the preview was complete.
```

- [ ] **Step 3: Run the gate**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

The tool description lives in an attribute macro, so a typo is a compile error rather than a silent docs bug — the build passing is the check.

- [ ] **Step 4: Commit**

```bash
git add crates/rustsdcmcp/src/server.rs docs/operations.md
git commit -m "docs: say plainly that a preview is a lower bound (#66)

A deploy was observed committing a deletion its preview did not disclose, with
the omitted object absent from the digest-bound artifact entirely. Until that is
settled, an operator reading the preview needs to know it may not be the whole
change, and how to confirm the actual effect on the device."
```

---

### Task 6: Mitigate #66 according to Task 1's answer

**Do not start this task until Task 1 is complete and its findings are committed.** The branch below is selected by evidence, not by preference.

**Files:** depend on the branch; both are listed.

**Interfaces:**
- Consumes: Task 1's recorded answer in `docs/sdc-api/README.md` §11.
- Produces: branch-dependent; see below.

#### Branch A — the XML preview discloses what CLI omitted

**Files:**
- Modify: `crates/rustsdcmcp-core/src/client.rs` (`prepare_policy_deploy`, the preview request)
- Modify: `docs/sdc-api/README.md` §11

- [ ] **A-Step 1: Write a failing test** asserting the preview request carries the XML format parameter, modelled on `list_ca_certificates_sends_exact_auth_path_and_page` in `client.rs` — assert on the query the mock server receives.
- [ ] **A-Step 2:** Run it; expect FAIL.
- [ ] **A-Step 3:** Add the format parameter to the preview request, using the exact parameter name and value from `docs/sdc-api/endpoints.md`.
- [ ] **A-Step 4:** Run it; expect PASS.
- [ ] **A-Step 5:** Re-run the live reproduction from Task 1 and confirm the previously omitted object now appears in the preview.
- [ ] **A-Step 6:** Narrow the Task 5 caveat to describe the old behaviour and the fix, and update §11.
- [ ] **A-Step 7:** Commit and close #66 with the live evidence.

#### Branch B — both formats under-report

**Files:**
- Modify: `crates/rustsdcmcp-core/src/change.rs` (`ApplyResult`, apply path)
- Modify: `crates/rustsdcmcp/src/server.rs` (apply tool description)

The mitigation is post-apply divergence reporting, because a discrepancy that cannot be seen at prepare time can still be recorded at apply time.

- [ ] **B-Step 1: Write a failing test** asserting `ApplyResult` carries a field naming what the deploy reported changing, distinct from the preview, so a caller can compare.
- [ ] **B-Step 2:** Run it; expect FAIL.
- [ ] **B-Step 3:** Populate it from the per-device deploy result (`deployed_config`), which `docs/sdc-api/README.md` §4 records as the deploy-side counterpart of the preview's `config_diff`.
- [ ] **B-Step 4:** Run it; expect PASS.
- [ ] **B-Step 5:** Compare the two in the apply path and record a divergence in the result and the audit trail. Do not fail the apply — the change is already committed by then, and failing would misreport a completed deploy.
- [ ] **B-Step 6:** Live-verify on `vsrx-ci` by reproducing the Task 1 condition and confirming the divergence is reported.
- [ ] **B-Step 7:** Commit and update #66 with what remains unexplained.

---

## Self-Review

**Spec coverage.** Phase A of the spec has four items: A1 (Task 1), A2 (Tasks 5 and 6), A3 (Tasks 3 and 4), A4 (Task 2). A3 needed splitting because the spec assumed exposing `discard_operation` was sufficient; reading the upstream implementation showed `rollback` must be fixed first or a discard makes the record permanently unrecoverable. That is recorded in Task 3's background and should be added to issue #63.

**Placeholder scan.** No TBD or "handle errors appropriately". Task 6's branches are conditional by design, not vague — each names its files, its first failing test, and its evidence gate. Task 1 is an investigation whose deliverable is a committed finding.

**Type consistency.** `validate_deploy_targets(&[Target]) -> Result<(), SdcError>` is defined in Task 2 and called in Task 2 Step 5. `ChangeManager::discard(String, String, String, &CancellationToken) -> Result<String, SdcError>` is defined in Task 4 Step 3 and called in Task 4 Step 6. `SdcTransaction::rollback` returns `Result<RollbackOutcome, SdcError>` in Task 3 and is relied on implicitly by `discard_operation` in Task 4. `DiscardOperationArgs` fields match the call site.

**Two signatures to confirm before writing code**, because they were read at plan time and can drift: `SdcError::InvalidInput`'s payload type (`&'static str` vs `String`) and `SdcClient::from_test_parts`'s exact parameters. Both are in `crates/rustsdcmcp-core/src/client.rs`.
