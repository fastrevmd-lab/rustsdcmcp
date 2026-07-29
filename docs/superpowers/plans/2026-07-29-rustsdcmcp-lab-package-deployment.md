# rustsdcmcp Lab Package and Deployment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the invalid mecmcp dependency with a fully traceable temporary compatibility layer, produce a verified lab-only Debian artifact, and deploy it read-only to VMID 606 on `pve2`.

**Architecture:** SDC-specific API behavior remains in `rustsdcmcp`. Missing vendor-neutral handler and HTTP composition APIs are implemented in small internal compatibility modules, with one dedicated mecmcp issue and source marker per temporary symbol. The verified package is installed into a hardened, loopback-only Debian 13 LXC; the SDC credential and MCP client token remain outside Git and package artifacts.

**Tech Stack:** Rust 1.97 build toolchain with MSRV 1.88, rmcp 2, Axum 0.8, rustls 0.23 with ring, mecmcp `changeset-v0.3.6`, Bash packaging, systemd, Proxmox VE 9, UniFi, Debian 13.

## Global Constraints

- Work only in `/home/mharman/Projects/rustsdcmcp/.worktrees/lab-release-deployment-design`; keep the main checkout untouched.
- Rename the branch to `feat/lab-package-deploy` before the first implementation commit.
- Do not modify mecmcp code, documentation, branches, or pull requests. Only create issues in `fastrevmd-lab/mecmcp`.
- Every temporary function, method, and reusable type gets one unique dedicated mecmcp issue. Two symbols may not share an issue.
- Every temporary declaration contains `mecmcp-compat:` with its full issue URL and target upstream symbol.
- SDC endpoints, headers, models, polling, tenant validation, preview/deploy behavior, and sanitized errors remain in this repository.
- Pin every mecmcp dependency to the single immutable tag `changeset-v0.3.6`; never mix refs.
- Do not restore the discarded revision `75a1e9db10a21a85876f337313ba47bc0329d74d` or `mecmcp-server`.
- No public tag, GitHub release, or release image is allowed while compatibility code exists.
- The lab artifact is amd64, lab-only, source-commit-addressed, checksummed, and contains a CycloneDX SBOM.
- Secrets must never appear in Git, archives, command output, logs, issue bodies, PR bodies, or chat.
- Source credential: `/home/mharman/.config/rustsdcmcp/credentials.env`, directory mode `0700`, file mode `0600`.
- Deployment target: node `pve2`, VMID `606`, hostname `rustsdcmcp-606`, IP `192.168.1.211/24`, gateway `192.168.1.1`, DNS `rustsdcmcp.mechub.org`.
- Never touch VMID `602`; it is the running `journal-collector` LXC on `pve3`.
- LXC: Debian 13, unprivileged, `nesting=1`, one core, 512 MiB RAM, 512 MiB swap, 4 GiB `local-lvm`, firewall and on-boot enabled.
- MCP binds only to `127.0.0.1:30032`.
- The initial MCP token contains only the 14 read tools. Never call prepare, approve, apply, preview submission, or deploy submission.
- On infrastructure failure, preserve VMID 606 and diagnostics; never auto-delete the container.
- Use sub-agents in parallel only for non-conflicting read-only review, CI-log inspection, package inspection, or infrastructure preflight. Keep source and configuration edits serialized in this worktree.

## File and Component Map

| Path | Responsibility |
| --- | --- |
| `docs/mecmcp-compatibility.tsv` | Machine-checkable one-symbol/one-issue migration ledger |
| `docs/mecmcp-compatibility.md` | Human migration procedure and upstream replacement rules |
| `crates/rustsdcmcp-core/src/compat.rs` | Temporary UTF-8-safe bounded text support used by the SDC client |
| `crates/rustsdcmcp/src/compat/server.rs` | Caller extraction, authorization, audit, tool filtering, bounded MCP results |
| `crates/rustsdcmcp/src/compat/bearer.rs` | Bounded bearer parsing and authenticated Axum boundary |
| `crates/rustsdcmcp/src/compat/preflight.rs` | Generic tool/tenant scope preflight using released mecmcp traits |
| `crates/rustsdcmcp/src/compat/http.rs` | Host/Origin policy, rmcp router composition, listener bootstrap |
| `crates/rustsdcmcp/src/compat/mod.rs` | Internal compatibility exports only |
| `crates/rustsdcmcp/tests/compat_issue_contract.rs` | Enforces 59 unique issue URLs and source/ledger agreement |
| `packaging/lxc/install.sh` | Idempotent staged/live LXC installer |
| `packaging/systemd/rustsdcmcp.service` | Loopback-only hardened service |
| `packaging/systemd/rustsdcmcp.sysusers` | Dedicated service account |
| `packaging/systemd/rustsdcmcp.tmpfiles` | Protected config/state directories |
| `packaging/journald/mecmcp.conf` | Persistent 512 MiB journal |
| `packaging/tests/package-smoke.sh` | Archive layout, preservation, modes, unit, and installer smoke |
| `scripts/build-lab-package.sh` | Lab archive, BUILD-INFO, SBOM, and checksum |
| `scripts/verify-packaging.sh` | Static packaging-policy verification |
| `.github/workflows/ci.yml` | Rust, MSRV, packaging, and artifact gates |
| `.github/workflows/security.yml` | Secret, advisory, source, and filesystem scans |
| `docs/lab-deployment-606.md` | Sanitized artifact and deployment acceptance record |

---

### Task 1: Create the One-to-One Upstream Issue Ledger

**Files:**
- Create: `docs/mecmcp-compatibility.tsv`
- Create: `docs/mecmcp-compatibility.md`
- Modify: `docs/superpowers/specs/2026-07-29-rustsdcmcp-lab-release-deployment-design.md`

**Interfaces:**
- Consumes: the 59-symbol inventory in Appendix A.
- Produces: 59 unique mecmcp issue URLs used by every later compatibility declaration.

- [ ] **Step 1: Rename the branch and verify the worktree**

Run:

```bash
git branch -m feat/lab-package-deploy
git status --short --branch
git rev-parse --show-toplevel
```

Expected: branch `feat/lab-package-deploy`, clean status, and worktree root ending in `.worktrees/lab-release-deployment-design`.

- [ ] **Step 2: Search mecmcp issues for exact-title duplicates**

Use the connected GitHub issue search against `fastrevmd-lab/mecmcp` for every exact title in Appendix A. Reuse an issue only if it is already dedicated to that one symbol and has matching acceptance criteria. General issues such as #32, #90, and #91 are references, not substitutes for symbol-specific issues.

Expected: a 59-row local inventory in which every row is either “create” or one exact reusable issue.

- [ ] **Step 3: Create every missing mecmcp issue**

For each Appendix A row, create one issue with this exact body structure and the row-specific semantics:

```markdown
## Consumer need

rustsdcmcp must temporarily provide this vendor-neutral Rust symbol because the
coherent mecmcp release `changeset-v0.3.6` does not contain it.

## Proposed shared API

- Target symbol: copy the exact Appendix A symbol for this issue title
- Semantics: copy the matching Appendix A acceptance semantics verbatim
- Vendor boundary: no Security Director Cloud names, paths, headers, models, or statuses

## Acceptance

- The symbol is implemented and documented in the target mecmcp crate.
- Unit and contract tests cover the stated semantics and failure behavior.
- Errors and logs never retain or expose bearer credentials.
- The API is included in one coherent mecmcp release usable by all shared crates.

## Downstream migration

rustsdcmcp will replace its issue-linked temporary symbol with this upstream
symbol and delete the corresponding ledger row after that coherent release.
```

Do not create a branch, commit, or PR in mecmcp.

- [ ] **Step 4: Write the machine ledger**

Create a tab-separated file with this exact header:

```text
kind	local_symbol	issue_url	upstream_symbol	removal_condition
```

Add one row per Appendix A symbol. `issue_url` must be the full numeric URL returned by GitHub. Every `removal_condition` is:

```text
first coherent mecmcp release containing this issue
```

- [ ] **Step 5: Write the human migration guide**

Document:

```markdown
# Temporary mecmcp Compatibility Ledger

This repository has 59 temporary vendor-neutral compatibility symbols:
37 functions/methods and 22 types. Each symbol has exactly one dedicated
mecmcp issue in `docs/mecmcp-compatibility.tsv`.

No compatibility declaration may be added without first creating its dedicated
issue and ledger row. No two rows may share an issue URL.

Migration is all-or-nothing: wait for one coherent mecmcp release containing
every row, pin all mecmcp crates to that single ref, replace imports, delete
`compat`, delete this ledger, and rerun every release gate.
```

Reference mecmcp #90 for generic cloud-client work and #91 for neutral target vocabulary without treating either as a symbol issue.

- [ ] **Step 6: Verify the ledger**

Run:

```bash
python3 - <<'PY'
from pathlib import Path

path = Path("docs/mecmcp-compatibility.tsv")
rows = [line.split("\t") for line in path.read_text().splitlines() if line.strip()]
assert rows[0] == ["kind", "local_symbol", "issue_url", "upstream_symbol", "removal_condition"]
data = rows[1:]
assert len(data) == 59, len(data)
symbols = [row[1] for row in data]
urls = [row[2] for row in data]
assert len(symbols) == len(set(symbols))
assert len(urls) == len(set(urls))
assert all(url.startswith("https://github.com/fastrevmd-lab/mecmcp/issues/") for url in urls)
assert all(url.rsplit("/", 1)[1].isdigit() for url in urls)
print("59 unique symbols and issue URLs")
PY
```

Expected: `59 unique symbols and issue URLs`.

- [ ] **Step 7: Commit the ledger**

```bash
git add docs/mecmcp-compatibility.tsv docs/mecmcp-compatibility.md \
  docs/superpowers/specs/2026-07-29-rustsdcmcp-lab-release-deployment-design.md
git commit -m "docs: track temporary mecmcp compatibility symbols"
```

---

### Task 2: Re-pin mecmcp and Add Server Compatibility

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `crates/rustsdcmcp-core/Cargo.toml`
- Modify: `crates/rustsdcmcp-core/src/lib.rs`
- Create: `crates/rustsdcmcp-core/src/compat.rs`
- Modify: `crates/rustsdcmcp-core/src/client.rs`
- Modify: `crates/rustsdcmcp/Cargo.toml`
- Modify: `crates/rustsdcmcp/src/lib.rs`
- Create: `crates/rustsdcmcp/src/compat/mod.rs`
- Create: `crates/rustsdcmcp/src/compat/server.rs`
- Modify: `crates/rustsdcmcp/src/server.rs`

**Interfaces:**
- Consumes: `mecmcp_auth::{CallerCtx, Grant, NoGrant}`, `mecmcp_audit::AuditScope`, rmcp `Extensions`, `Tool`, `CallToolResult`.
- Produces: `compat::server::{audit_scope, authorize_call, caller_from_extensions, filter_tools_for_scope, tool_error, tool_result, ResultFormat, ResultLimits}` and core `compat::bounded_text`.

- [ ] **Step 1: Add failing compatibility behavior tests**

Add the authorization and result tests below `#[cfg(test)]` in
`compat/server.rs`, and the UTF-8 test below `#[cfg(test)]` in the core
`compat.rs`:

```rust
fn caller_with(devices: ScopeSet, tools: ScopeSet) -> CallerCtx<NoGrant> {
    CallerCtx {
        token_name: "reader".to_owned(),
        devices,
        tools,
        grant: None,
        provider: None,
        provider_tier: None,
        on_behalf_of: None,
        actor_type: mecmcp_auth::ActorType::Human,
    }
}

#[test]
fn wildcard_scope_excludes_consumer_write_tools() {
    let caller = caller_with(
        ScopeSet::Wildcard,
        ScopeSet::Wildcard,
    );
    assert!(authorize_call(
        Some(&caller),
        "get_sdc_tenant_scope",
        Some("production"),
        crate::WRITE_TOOLS,
    ).is_ok());
    assert!(matches!(
        authorize_call(
            Some(&caller),
            "apply_sdc_change_set",
            Some("production"),
            crate::WRITE_TOOLS,
        ),
        Err(AuthorizationError::ToolNotInScope { .. })
    ));
}

#[test]
fn bounded_text_never_splits_utf8() {
    let bounded = bounded_text("abé", 3);
    assert_eq!(bounded.text, "ab");
    assert!(bounded.truncated);
    assert_eq!(bounded.original_bytes, 4);
    assert_eq!(bounded.omitted_bytes, 2);
}

#[test]
fn oversized_success_is_an_mcp_error() {
    let result = tool_result::<_, std::convert::Infallible>(
        Ok("0123456789"),
        ResultFormat::StringOrPrettyJson,
        ResultLimits { max_text_bytes: 4, max_json_bytes: 32 },
    );
    assert_eq!(result.is_error, Some(true));
}
```

- [ ] **Step 2: Run the tests to verify failure**

Run:

```bash
cargo test -p rustsdcmcp-core bounded_text_never_splits_utf8
cargo test -p rustsdcmcp wildcard_scope_excludes_consumer_write_tools
```

Expected: compilation fails because the compatibility modules and symbols do not exist.

- [ ] **Step 3: Re-pin all mecmcp crates**

Replace every mecmcp workspace dependency with:

```toml
mecmcp-audit = { version = "0.3.6", git = "https://github.com/fastrevmd-lab/mecmcp", tag = "changeset-v0.3.6" }
mecmcp-auth = { version = "0.3.6", git = "https://github.com/fastrevmd-lab/mecmcp", tag = "changeset-v0.3.6" }
mecmcp-changeset = { version = "0.3.6", git = "https://github.com/fastrevmd-lab/mecmcp", tag = "changeset-v0.3.6" }
mecmcp-runtime = { version = "0.3.6", git = "https://github.com/fastrevmd-lab/mecmcp", tag = "changeset-v0.3.6" }
mecmcp-transport = { version = "0.3.6", git = "https://github.com/fastrevmd-lab/mecmcp", tag = "changeset-v0.3.6" }
```

Delete `mecmcp-server` from the workspace and both consumer manifests. Regenerate only through:

```bash
cargo update
```

Verify:

```bash
rg -n '75a1e9db|mecmcp-server|rev = ' Cargo.toml Cargo.lock crates
```

Expected: no matches.

- [ ] **Step 4: Implement core bounded text compatibility**

Implement `BoundedText` and `bounded_text` with the exact UTF-8 boundary algorithm:

```rust
pub(crate) fn bounded_text(input: &str, max_bytes: usize) -> BoundedText {
    let original_bytes = input.len();
    if original_bytes <= max_bytes {
        return BoundedText {
            text: input.to_owned(),
            truncated: false,
            original_bytes,
            omitted_bytes: 0,
        };
    }
    let mut end = max_bytes.min(original_bytes);
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    BoundedText {
        text: input[..end].to_owned(),
        truncated: true,
        original_bytes,
        omitted_bytes: original_bytes - end,
    }
}
```

Place the exact numeric issue markers from the ledger immediately before `BoundedText` and `bounded_text`. Change `client.rs::bound_text` to call `crate::compat::bounded_text(value, 512).text`.

- [ ] **Step 5: Implement handler compatibility**

Port only the required server behavior listed in Appendix A:

- `audit_scope` selects `AuditScope::from_caller` or `AuditScope::stdio`.
- `authorize_tool` calls `ScopeSet::allows_tool(tool, write_tools)`.
- `authorize_target` calls `ScopeSet::allows(target)` without inventory lookup.
- `authorize_call` checks tool before target.
- `caller_from_extensions` reads nested `http::request::Parts`.
- `bounded_text` is not duplicated here; MCP result bounding uses `ResultLimits`.
- `tool_error` returns one `ContentBlock::text`.
- `tool_result` converts domain and serialization failures to MCP errors and refuses oversized success values.
- `filter_tools_for_scope` uses the same write-aware tool predicate.

Every declaration, including private `SerializedValue` and `serialize_value`, receives the exact issue marker from the ledger. Do not add any untracked helper function.

- [ ] **Step 6: Switch consumers to local compatibility imports**

Use:

```rust
use crate::compat::server::{
    ResultFormat, ResultLimits, audit_scope, authorize_call,
    caller_from_extensions, filter_tools_for_scope, tool_error, tool_result,
};
```

Keep the SDC-specific `authorize_request`, `owner`, `attribution`, `finish`, `KNOWN_TOOLS`, and `WRITE_TOOLS` in `server.rs`.

- [ ] **Step 7: Run focused and workspace tests**

```bash
cargo test -p rustsdcmcp-core
cargo test -p rustsdcmcp
cargo test --workspace
```

Expected: all existing 13 tests plus the new compatibility tests pass.

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml Cargo.lock crates/rustsdcmcp-core crates/rustsdcmcp
git commit -m "feat: add issue-linked server compatibility"
```

---

### Task 3: Add Bearer Parsing and Scope Preflight Compatibility

**Files:**
- Create: `crates/rustsdcmcp/src/compat/bearer.rs`
- Create: `crates/rustsdcmcp/src/compat/preflight.rs`
- Modify: `crates/rustsdcmcp/src/compat/mod.rs`

**Interfaces:**
- Consumes: `TokenStoreFile<NoGrant>`, released `mecmcp_transport::{OptionalPreflight, ScopePreflight}` and `preflight::run_preflight`.
- Produces: strict bounded bearer parsing, `BearerAuthenticator`, `BearerBoundary`, `TargetField`, and `ToolScopePreflight`.

Use these exact local shapes:

```rust
pub(crate) enum BearerSyntax { Strict, Trimmed }
pub(crate) enum BearerHeaderError {
    TooLarge,
    InvalidCharacters,
    WrongScheme,
    Empty,
    EmbeddedWhitespace,
}
type Authenticate =
    dyn Fn(&str) -> Option<CallerCtx<NoGrant>> + Send + Sync;
pub(crate) struct BearerAuthenticator {
    syntax: BearerSyntax,
    authenticate: Arc<Authenticate>,
}
pub(crate) struct BearerResponseProfile {
    realm: String,
    style: BearerResponseStyle,
}
pub(crate) enum BearerResponseStyle { Detailed, Compact }
pub(crate) struct BearerBoundary {
    authenticator: BearerAuthenticator,
    responses: BearerResponseProfile,
    body_limit: usize,
    preflight: OptionalPreflight,
}
pub(crate) enum MalformedArgumentsPolicy { Deny, Ignore }
pub(crate) enum MalformedTargetPolicy { Deny, Ignore }
pub(crate) enum TargetValueShape { Scalar, NonEmptyArray }
pub(crate) struct TargetField {
    name: &'static str,
    shape: TargetValueShape,
    malformed: MalformedTargetPolicy,
}
pub(crate) struct ToolScopePreflight {
    write_tools: &'static [&'static str],
    target_fields: Vec<TargetField>,
    malformed_arguments: MalformedArgumentsPolicy,
}
```

- [ ] **Step 1: Write failing parser and preflight tests**

Add tests below `#[cfg(test)]` in `compat/bearer.rs` for all credential-free parser outcomes:

```rust
#[test]
fn strict_bearer_parser_is_bounded_and_credential_free() {
    assert_eq!(
        parse_bearer_header("Bearer abc", BearerSyntax::Strict),
        Ok("abc"),
    );
    assert_eq!(
        parse_bearer_header(" Bearer abc", BearerSyntax::Strict),
        Err(BearerHeaderError::WrongScheme),
    );
    assert_eq!(
        parse_bearer_header("Bearer a b", BearerSyntax::Strict),
        Err(BearerHeaderError::EmbeddedWhitespace),
    );
    let oversized = format!("Bearer {}", "x".repeat(4096));
    assert_eq!(
        parse_bearer_header(&oversized, BearerSyntax::Strict),
        Err(BearerHeaderError::TooLarge),
    );
    assert!(!BearerHeaderError::EmbeddedWhitespace.to_string().contains("a b"));
}
```

Add tests below `#[cfg(test)]` in `compat/preflight.rs` using `CallerCtx<NoGrant>`:

```rust
fn caller_with(devices: ScopeSet, tools: ScopeSet) -> CallerCtx<NoGrant> {
    CallerCtx {
        token_name: "reader".to_owned(),
        devices,
        tools,
        grant: None,
        provider: None,
        provider_tier: None,
        on_behalf_of: None,
        actor_type: mecmcp_auth::ActorType::Human,
    }
}

#[test]
fn preflight_rejects_out_of_scope_tenant_and_write_wildcard() {
    let preflight = ToolScopePreflight::new(
        crate::WRITE_TOOLS,
        [TargetField::scalar("tenant")],
        MalformedArgumentsPolicy::Deny,
    );
    let caller = caller_with(
        ScopeSet::Allowlist(vec!["production".to_owned()]),
        ScopeSet::Wildcard,
    );
    assert!(preflight.check(
        br#"{"method":"tools/call","params":{"name":"get_sdc_tenant_scope","arguments":{"tenant":"other"}}}"#,
        &caller,
    ).is_err());
    assert!(preflight.check(
        br#"{"method":"tools/call","params":{"name":"apply_sdc_change_set","arguments":{"tenant":"production"}}}"#,
        &caller,
    ).is_err());
}
```

- [ ] **Step 2: Run tests to verify failure**

```bash
cargo test -p rustsdcmcp strict_bearer_parser_is_bounded_and_credential_free
cargo test -p rustsdcmcp preflight_rejects_out_of_scope_tenant_and_write_wildcard
```

Expected: compilation fails because the bearer and preflight modules do not exist.

- [ ] **Step 3: Implement bounded bearer parsing**

Implement:

```rust
const MAX_AUTHORIZATION_HEADER_BYTES: usize = 4096;

pub(crate) fn parse_bearer_header(
    value: &str,
    syntax: BearerSyntax,
) -> Result<&str, BearerHeaderError> {
    if value.len() > MAX_AUTHORIZATION_HEADER_BYTES {
        return Err(BearerHeaderError::TooLarge);
    }
    if !value.bytes().all(
        |byte| byte == b'\t' || (byte.is_ascii() && !byte.is_ascii_control()),
    ) {
        return Err(BearerHeaderError::InvalidCharacters);
    }
    let value = match syntax {
        BearerSyntax::Strict => value,
        BearerSyntax::Trimmed => {
            value.trim_matches(|character: char| character.is_ascii_whitespace())
        }
    };
    let Some(separator) = value.find(|character: char| character.is_ascii_whitespace()) else {
        return if value.eq_ignore_ascii_case("bearer") {
            Err(BearerHeaderError::Empty)
        } else {
            Err(BearerHeaderError::WrongScheme)
        };
    };
    let (scheme, remainder) = value.split_at(separator);
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(BearerHeaderError::WrongScheme);
    }
    let credential =
        remainder.trim_matches(|character: char| character.is_ascii_whitespace());
    if credential.is_empty() {
        return Err(BearerHeaderError::Empty);
    }
    if credential.chars().any(|character| character.is_ascii_whitespace()) {
        return Err(BearerHeaderError::EmbeddedWhitespace);
    }
    Ok(credential)
}
```

Implement only `Strict` use in SDC composition, while retaining `Trimmed` because it is part of the upstream issue contract. Error `Display` strings must never contain the presented value.

- [ ] **Step 4: Implement preflight with released mecmcp contracts**

Reuse these unchanged:

```rust
use mecmcp_transport::{
    OptionalPreflight, ScopePreflight,
    preflight::run_preflight,
};
```

Do not implement `CallerScopes`, another `ScopePreflight`, another `OptionalPreflight`, or another `run_preflight`. Implement `ToolScopePreflight` for the released `ScopePreflight`, accepting `&CallerCtx<NoGrant>`.

The check must:

1. Ignore empty and malformed JSON so rmcp reports protocol errors.
2. Check only `tools/call`.
3. Reject a tool outside scope before inspecting the tenant.
4. Deny malformed `params.arguments` under `MalformedArgumentsPolicy::Deny`.
5. Support one JSON-RPC object or a batch.
6. Deny the whole batch if any member exceeds scope.

- [ ] **Step 5: Implement the bearer boundary**

The Axum middleware must:

1. Reject missing, duplicate, non-UTF-8, malformed, and invalid credentials.
2. Read at most the configured body ceiling with `axum::body::to_bytes`.
3. Run released `run_preflight` before dispatch.
4. Insert `CallerCtx<NoGrant>` into request extensions.
5. Reconstruct the original body bytes unchanged.
6. Return stable JSON `401`, `403`, and `413` bodies without credential material.

Use `#[derive(Clone)]` for the authenticator and boundary. Do not copy the discarded explicit clone methods, compact profile, optional-preflight builder, buffered-body type, authenticated-token type, caller-scope type, or unused target constructors.

- [ ] **Step 6: Run focused tests**

```bash
cargo test -p rustsdcmcp strict_bearer_parser_is_bounded_and_credential_free
cargo test -p rustsdcmcp preflight_rejects_out_of_scope_tenant_and_write_wildcard
cargo test -p rustsdcmcp --test tool_contract
```

Expected: parser, preflight, and bearer tests pass; existing tool contract remains green.

- [ ] **Step 7: Commit**

```bash
git add crates/rustsdcmcp/src/compat
git commit -m "feat: add issue-linked bearer boundary"
```

---

### Task 4: Compose the Streamable HTTP Router and Enforce the Ledger

**Files:**
- Create: `crates/rustsdcmcp/src/compat/http.rs`
- Modify: `crates/rustsdcmcp/src/compat/mod.rs`
- Modify: `crates/rustsdcmcp/src/http_transport.rs`
- Modify: `crates/rustsdcmcp/src/main.rs`
- Modify: `Cargo.toml`
- Modify: `crates/rustsdcmcp/Cargo.toml`
- Create: `crates/rustsdcmcp/tests/compat_issue_contract.rs`

**Interfaces:**
- Consumes: released mecmcp limits, metrics, rate, concurrency, and session primitives plus Task 3 bearer boundary.
- Produces: `build_streamable_http_router`, `serve_router`, and a compile/test gate proving all 59 declarations are issue-linked.

Use these exact signatures:

```rust
pub(crate) enum HostOriginPolicy {
    Enforced {
        allowed_hosts: Vec<String>,
        allowed_origins: Vec<String>,
    },
}

pub(crate) struct HttpTransportConfig {
    identity: TransportIdentity,
    limits: LimitsConfig,
    host_origin: HostOriginPolicy,
    bearer: Option<BearerBoundary>,
    enable_metrics: bool,
}

pub(crate) fn build_streamable_http_router<S>(
    service_factory: impl Fn() -> Result<S, std::io::Error> + Send + Sync + 'static,
    config: HttpTransportConfig,
) -> Result<Router, HttpTransportBuildError>
where
    S: rmcp::Service<RoleServer> + Send + 'static;

pub(crate) async fn serve_router(
    router: Router,
    address: SocketAddr,
    tls: Option<Arc<rustls::ServerConfig>>,
) -> Result<(), HttpServeError>;
```

- [ ] **Step 1: Add failing router tests**

Add unit tests below `#[cfg(test)]` in `compat/http.rs` for these outcomes:

```rust
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use mecmcp_auth::{ActorType, CallerCtx, NoGrant, ScopeSet};
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
    )
    .with_bearer(BearerBoundary::new(
        authenticator,
        BearerResponseProfile::detailed("test"),
        max_request_body_bytes,
    ));
    build_streamable_http_router(
        || Ok::<_, std::io::Error>(EmptyServer),
        config,
    )
    .expect("router")
}

#[test]
fn host_origin_policy_preserves_loopback_defaults() {
    let policy =
        HostOriginPolicy::enforced(["mcp.example.test"], ["https://client.example.test"]);
    let config = streamable_http_server_config(&policy);
    assert!(config.allowed_hosts.contains(&"localhost".to_owned()));
    assert!(config.allowed_hosts.contains(&"mcp.example.test".to_owned()));
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
```

The fixed string `secret` is test-only and must never appear in assertion
messages or production logs.

- [ ] **Step 2: Verify router tests fail**

```bash
cargo test -p rustsdcmcp host_origin_policy_preserves_loopback_defaults
cargo test -p rustsdcmcp router_requires_bearer
cargo test -p rustsdcmcp router_rejects_body_over_limit_before_rmcp_dispatch
```

Expected: compilation fails because `compat::http` does not exist.

- [ ] **Step 3: Add direct dependencies needed by local composition**

Add both entries to `[workspace.dependencies]`:

```toml
axum-server = { version = "0.8", default-features = false, features = ["tls-rustls-no-provider"] }
tower = { version = "0.5", features = ["util"] }
```

Add rmcp features:

```toml
"transport-streamable-http-server-session"
```

Add `axum-server.workspace = true` to
`crates/rustsdcmcp/Cargo.toml` dependencies and `tower.workspace = true` to
that crate's dev-dependencies.

Do not add another metrics, concurrency, rate-limit, or body-limit implementation.

- [ ] **Step 4: Implement Host/Origin configuration**

`HostOriginPolicy::enforced` must preserve rmcp loopback defaults, extend exact allowed hosts, and set exact Origins only when non-empty. No disabled-host variant is needed locally.

- [ ] **Step 5: Implement router composition**

Use released primitives:

```rust
use mecmcp_transport::{
    ConcurrencyState, LimitedSessionManager, LimitsConfig, LimitsConfigError,
    PrometheusRuntime, TransportIdentity, apply_body_limit, apply_rate_limit,
    concurrency_middleware,
};
```

Compose layers so request execution is:

```text
body limit -> bearer and preflight -> rate limit -> concurrency/session -> rmcp
```

Build the rmcp service with `LimitedSessionManager<LocalSessionManager>`. Merge metrics only when explicitly enabled. In this lab configuration metrics remain disabled.

- [ ] **Step 6: Implement listener bootstrap**

Plain HTTP:

```rust
let listener = tokio::net::TcpListener::bind(address)
    .await
    .map_err(|error| HttpServeError::Bind { address, error })?;
axum::serve(
    listener,
    router.into_make_service_with_connect_info::<SocketAddr>(),
).await?;
```

TLS uses `axum_server::tls_rustls::RustlsConfig::from_config` and the supplied rustls provider-selected configuration. Do not choose a provider inside compatibility code.

- [ ] **Step 7: Switch SDC transport composition**

Import the local types/functions in `http_transport.rs`. Keep:

```rust
TransportIdentity::new("sdcmcp", "sdc", "rustsdcmcp", ["tenant"])
```

Use strict bearer parsing, target field `tenant`, deny malformed arguments, detailed realm `sdcmcp`, and `WRITE_TOOLS`.

- [ ] **Step 8: Add the 59-symbol issue contract**

The contract test must:

1. Load `docs/mecmcp-compatibility.tsv`.
2. Assert exactly 59 data rows.
3. Assert unique symbols and unique numeric issue URLs.
4. Load every production compatibility source file.
5. Ignore declarations below `#[cfg(test)]`.
6. Require an immediately preceding line in this exact form:

The line begins with the literal `/// mecmcp-compat:` and then contains,
in order, the ledger kind, the complete local symbol, and that row's full
numeric GitHub issue URL.

7. Assert source markers and ledger `(kind, local_symbol, issue_url)` sets are identical.
8. Fail on any unmarked `fn`, `struct`, `enum`, `trait`, or `type` declaration in compatibility code.

Run:

```bash
cargo test -p rustsdcmcp --test compat_issue_contract
```

Expected: `59` markers, `59` rows, and PASS.

- [ ] **Step 9: Run all Rust gates**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
```

Expected: all commands exit zero.

- [ ] **Step 10: Commit**

```bash
git add Cargo.toml Cargo.lock crates/rustsdcmcp
git commit -m "feat: compose issue-linked HTTP transport"
```

---

### Task 5: Add the mecmcp-Standard LXC Package

**Files:**
- Create: `packaging/lxc/install.sh`
- Create: `packaging/systemd/rustsdcmcp.service`
- Create: `packaging/systemd/rustsdcmcp.sysusers`
- Create: `packaging/systemd/rustsdcmcp.tmpfiles`
- Create: `packaging/journald/mecmcp.conf`
- Create: `packaging/tests/package-smoke.sh`
- Create: `scripts/build-lab-package.sh`
- Create: `scripts/verify-packaging.sh`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: release binary, `examples/sdc.example.json`, source commit, Trivy 0.70.0.
- Produces: `dist/${GIT_COMMIT}/rustsdcmcp_0.1.0-lab.20260729.${GIT_SHA12}_amd64.tar.gz`, checksum, SBOM, BUILD-INFO. Every consumer selects exactly that full-commit directory and requires exactly one archive/checksum pair.

- [ ] **Step 1: Write the package smoke test first**

The smoke test must fail unless the archive contains exactly one root and these files:

```text
bin/rustsdcmcp
config/sdc.json.example
packaging/lxc/install.sh
packaging/systemd/rustsdcmcp.service
packaging/systemd/rustsdcmcp.sysusers
packaging/systemd/rustsdcmcp.tmpfiles
packaging/journald/mecmcp.conf
BUILD-INFO
SBOM.cdx.json
README.md
LICENSE
SECURITY.md
docs/operations.md
```

It must stage-install twice and compare checksums of pre-existing:

```text
/etc/rustsdcmcp/sdc.json
/etc/rustsdcmcp/credentials.env
/etc/rustsdcmcp/tokens.json
/etc/rustsdcmcp/audit-hmac.key
/var/lib/rustsdcmcp/changeset-state.json
/etc/systemd/system/rustsdcmcp.service
```

It must assert no live `sdc.json` or `credentials.env` is created on a fresh install.

- [ ] **Step 2: Verify the smoke test initially fails**

```bash
packaging/tests/package-smoke.sh dist/nonexistent.tar.gz
```

Expected: nonzero with `archive not found`.

- [ ] **Step 3: Add sysusers, tmpfiles, and journald declarations**

Use exactly:

```text
u rustsdcmcp - "rustsdcmcp service" /var/lib/rustsdcmcp /usr/sbin/nologin
```

```text
d /etc/rustsdcmcp 0750 root rustsdcmcp -
d /var/lib/rustsdcmcp 0700 rustsdcmcp rustsdcmcp -
```

```ini
[Journal]
Storage=persistent
SystemMaxUse=512M
```

- [ ] **Step 4: Add the hardened service**

Use one token path everywhere: `/etc/rustsdcmcp/tokens.json`.

```ini
[Unit]
Description=Security Director Cloud MCP server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=rustsdcmcp
Group=rustsdcmcp
EnvironmentFile=/etc/rustsdcmcp/credentials.env
Environment=RUST_LOG=info
ExecStart=/usr/local/bin/rustsdcmcp \
    --device-mapping /etc/rustsdcmcp/sdc.json \
    --transport streamable-http \
    --host 127.0.0.1 \
    --port 30032 \
    --tokens-file /etc/rustsdcmcp/tokens.json \
    --audit-format json \
    --audit-journald \
    --audit-redact devices=hmac \
    --audit-hmac-key-file /etc/rustsdcmcp/audit-hmac.key
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s
TimeoutStopSec=30s
KillSignal=SIGTERM
UMask=0077
StateDirectory=rustsdcmcp
StateDirectoryMode=0700
RuntimeDirectory=rustsdcmcp
RuntimeDirectoryMode=0700
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/etc/rustsdcmcp
ReadWritePaths=/var/lib/rustsdcmcp
PrivateTmp=true
PrivateDevices=true
CapabilityBoundingSet=
AmbientCapabilities=
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectProc=invisible
ProcSubset=pid
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true
RemoveIPC=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
TasksMax=256
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 5: Implement the idempotent installer**

The installer must:

- Validate the full payload before changing target state.
- Support `SDCMCP_INSTALL_ROOT`, `SDCMCP_INSTALL_SKIP_USER`, `SDCMCP_INSTALL_SKIP_SYSTEMD_RELOAD`, `SDCMCP_INSTALL_SKIP_RUNTIME_DEPS`, and `SDCMCP_FORCE_UNIT`.
- Use systemd-sysusers and systemd-tmpfiles for a live install.
- Install only `sdc.json.example`, never `sdc.json` or `credentials.env`.
- Create `tokens.json` only when absent; set owner `rustsdcmcp`, mode `0600`.
- Create a 32-byte audit HMAC key only when absent; set owner `rustsdcmcp`, mode `0600`.
- Never create or overwrite `changeset-state.json`.
- Preserve a customized unit unless `SDCMCP_FORCE_UNIT=1`.
- Install `curl` and `ca-certificates` for a live Debian install.
- Reload systemd but do not enable a nonbootable service.
- Print the exact next steps and `http://127.0.0.1:30032/mcp`.

- [ ] **Step 6: Implement the lab package builder**

The builder must:

1. Refuse a dirty tree unless `SDCMCP_ALLOW_DIRTY=1`.
2. Build `cargo build --release -p rustsdcmcp --locked`.
3. Use commit date as `SOURCE_DATE_EPOCH`.
4. Create one package root named with date and 12-character commit.
5. Generate `SBOM.cdx.json` with local Trivy 0.70.0.
6. Write `BUILD-INFO` containing:

```text
release_status=lab-only
version=0.1.0
git_commit=${GIT_COMMIT}
source_date_epoch=${SOURCE_DATE_EPOCH}
target=x86_64-unknown-linux-gnu
mecmcp_ref=changeset-v0.3.6
glibc_floor=${GLIBC_FLOOR}
rustc=${RUSTC_VERSION_METADATA}
```

The builder sets `GIT_COMMIT` from `git rev-parse HEAD`, `GIT_SHA12` from its
first 12 characters, `SOURCE_DATE_EPOCH` from `git show -s --format=%ct HEAD`,
`GLIBC_FLOOR` from `objdump -T`, and `RUSTC_VERSION_METADATA` from `rustc -vV`.

7. Normalize tar member order, numeric ownership, and mtime.
8. Write the archive and sibling `.sha256`.

The CycloneDX document contains generated identifiers and timestamps, so do not claim byte-for-byte reproducibility for this lab artifact. The checksum binds the exact artifact.

- [ ] **Step 7: Add packaging policy verification**

`verify-packaging.sh` must assert:

- No `Command::new`, `std::process`, or `tokio::process` in production Rust.
- Service binds `127.0.0.1:30032`.
- All four audit flags exist.
- Unit, installer, tmpfiles, sysusers, journal, and config-example paths agree.
- Token path is `/etc/rustsdcmcp/tokens.json` everywhere.
- No credential or live config is packaged.
- `systemd-analyze verify` passes.
- Shell scripts pass `bash -n`.

- [ ] **Step 8: Build and test the package**

```bash
bash -n scripts/build-lab-package.sh scripts/verify-packaging.sh \
  packaging/lxc/install.sh packaging/tests/package-smoke.sh
scripts/verify-packaging.sh
scripts/build-lab-package.sh
source_commit="$(git rev-parse HEAD)"
artifact_dir="dist/$source_commit"
mapfile -t archives < <(find "$artifact_dir" -maxdepth 1 -type f -name 'rustsdcmcp_*_amd64.tar.gz' -print)
test "${#archives[@]}" -eq 1
(cd "$artifact_dir" && sha256sum -c "$(basename "${archives[0]}").sha256")
packaging/tests/package-smoke.sh "${archives[0]}"
```

Expected: all commands pass. Record the archive filename and checksum without exposing secrets.

- [ ] **Step 9: Commit**

```bash
git add .gitignore packaging scripts
git commit -m "build: add lab LXC package"
```

---

### Task 6: Add CI, Security Gates, and Operator Documentation

**Files:**
- Create: `.github/workflows/ci.yml`
- Create: `.github/workflows/security.yml`
- Modify: `README.md`
- Modify: `docs/operations.md`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: Tasks 2–5.
- Produces: reviewable CI artifact and explicit public-release blocker.

- [ ] **Step 1: Add the CI workflow**

Jobs:

1. `rust`: format, clippy, build, tests, docs on Rust 1.97.
2. `msrv`: `cargo +1.88 check --workspace --all-targets --locked`.
3. `packaging`: install shellcheck and Trivy 0.70.0, verify scripts, build package, smoke test, inspect glibc, upload `dist/<full-source-commit>/*`.

Use `ubuntu-24.04` so its glibc floor remains compatible with Debian 13. For pull requests, checkout `github.event.pull_request.head.sha`; for pushes, checkout `github.sha`; record `git rev-parse HEAD`, build only `dist/<that-full-source-commit>/`, and upload it as `rustsdcmcp-lab-<that-full-source-commit>` with `if-no-files-found: error`.

- [ ] **Step 2: Add the security workflow**

Include:

- Gitleaks over full history with artifacts disabled.
- `cargo audit --deny warnings`.
- `cargo deny check licenses bans sources`.
- `trivy fs --scanners vuln,misconfig,secret --exit-code 1 .`.

Use read-only contents permission except the minimum checks permission required by cargo-audit.

- [ ] **Step 3: Update operator documentation**

Document:

- mecmcp `changeset-v0.3.6` plus the temporary 59-symbol ledger.
- Lab-only archive naming and checksum verification.
- `/etc/rustsdcmcp/{sdc.json,credentials.env,tokens.json,audit-hmac.key}` and `/var/lib/rustsdcmcp/changeset-state.json`.
- Loopback endpoint and SSH tunnel.
- Read-only initial token.
- Persistent journald and the lab exception for remote forwarding.
- Explicit public `v0.1.0` blocker.
- Exact DNS name `rustsdcmcp.mechub.org`.

- [ ] **Step 4: Run local gates**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo +1.88 check --workspace --all-targets --locked
cargo audit --deny warnings
cargo deny check licenses bans sources
trivy fs --scanners vuln,misconfig,secret --exit-code 1 .
scripts/verify-packaging.sh
```

Expected: all commands exit zero.

- [ ] **Step 5: Commit**

```bash
git add .github README.md docs/operations.md CHANGELOG.md
git commit -m "ci: gate lab packaging and security"
```

---

### Task 7: Review, Push a Draft PR, and Obtain the CI Artifact

**Files:**
- No new source files.
- Output: CI artifact under local `dist/`.

**Interfaces:**
- Consumes: verified branch.
- Produces: draft PR, green checks, CI-built artifact tied to exact commit.

- [ ] **Step 1: Run two safe parallel read-only reviews**

Dispatch:

1. A compatibility reviewer to compare all 59 ledger rows, declarations, issue URLs, and dependency pins.
2. A packaging/security reviewer to inspect archive exclusions, installer idempotency, unit hardening, and CI gates.

Neither reviewer may edit files. Resolve findings serially in the worktree and rerun affected tests.

- [ ] **Step 2: Run final verification from a clean tree**

```bash
git status --short
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo +1.88 check --workspace --all-targets --locked
cargo audit --deny warnings
cargo deny check licenses bans sources
trivy fs --scanners vuln,misconfig,secret --exit-code 1 .
scripts/verify-packaging.sh
scripts/build-lab-package.sh
source_commit="$(git rev-parse HEAD)"
artifact_dir="dist/$source_commit"
mapfile -t archives < <(find "$artifact_dir" -maxdepth 1 -type f -name 'rustsdcmcp_*_amd64.tar.gz' -print)
test "${#archives[@]}" -eq 1
packaging/tests/package-smoke.sh "${archives[0]}"
```

Expected: clean source tree except ignored `dist/`; all gates pass.

- [ ] **Step 3: Push and create a draft PR**

Use the `github:yeet` workflow. PR title:

```text
Implement and package the Security Director Cloud MCP server
```

The PR body must state:

- Lab deployment only.
- 59 dedicated mecmcp issue links in the ledger.
- Public release blocked until one coherent upstream release replaces compatibility code.
- No SDC mutation was tested.
- Planned target VMID 606 on `pve2`.

- [ ] **Step 4: Wait for every required check**

Use GitHub Actions status/log tooling. Fix failures with the systematic-debugging workflow, commit, push, and wait again. Do not deploy a red commit.

- [ ] **Step 5: Download and verify the CI artifact**

Download the packaging-job artifact for the exact PR head. Verify:

```bash
source_commit="<exact PR head SHA>"
artifact_dir="dist/$source_commit"
mapfile -t archives < <(find "$artifact_dir" -maxdepth 1 -type f -name 'rustsdcmcp_*_amd64.tar.gz' -print)
test "${#archives[@]}" -eq 1
(cd "$artifact_dir" && sha256sum -c "$(basename "${archives[0]}").sha256")
mapfile -t build_infos < <(tar -tzf "${archives[0]}" | grep -E '/BUILD-INFO$')
test "${#build_infos[@]}" -eq 1
tar -xOf "${archives[0]}" "${build_infos[0]}"
```

Expected: `release_status=lab-only`, exact PR source commit, `mecmcp_ref=changeset-v0.3.6`, and a glibc floor no newer than the Debian 13 runtime.

- [ ] **Step 6: Confirm no release exists**

Verify there is no new tag or GitHub release. This task ends with a draft PR and CI artifact only.

---

### Task 8: Provision VMID 606 on pve2 and Register DNS

**Files:**
- External state: Proxmox VMID 606 and UniFi reservation/DNS.

**Interfaces:**
- Consumes: approved infrastructure values and CI artifact metadata.
- Produces: running Debian 13 LXC at `192.168.1.211`, DNS `rustsdcmcp.mechub.org`.

- [ ] **Step 1: Perform the cluster-wide hard stop preflight**

```bash
ssh root@192.168.1.202 \
  'pvesh get /cluster/resources --type vm --output-format json' \
  | jq -e 'all(.[]; .vmid != 606)' >/dev/null
```

Expected: exit zero. Any row for 606 stops all infrastructure work.

- [ ] **Step 2: Recheck address and DNS without mutation**

Verify all of:

- No Proxmox config contains `192.168.1.211`.
- UniFi has no client, device, or reservation for the address.
- `ip neigh` has no entry.
- Two pings receive no response.
- `rustsdcmcp.mechub.org` does not resolve.

Any positive result stops before creation.

- [ ] **Step 3: Stage the SSH public key**

```bash
scp -p /home/mharman/.ssh/id_ed25519.pub \
  root@192.168.1.202:/root/rustsdcmcp-lab.pub
```

- [ ] **Step 4: Create VMID 606 on pve2**

```bash
ssh root@192.168.1.202 \
  pct create 606 \
  local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst \
  --hostname rustsdcmcp-606 \
  --arch amd64 \
  --cores 1 \
  --memory 512 \
  --swap 512 \
  --rootfs local-lvm:4 \
  --unprivileged 1 \
  --features nesting=1 \
  --onboot 1 \
  --net0 name=eth0,bridge=vmbr0,firewall=1,gw=192.168.1.1,ip=192.168.1.211/24,type=veth \
  --ssh-public-keys /root/rustsdcmcp-lab.pub
```

Extract the exact artifact commit before setting the description:

```bash
source_commit="<approved CI source commit>"
artifact_dir="dist/$source_commit"
mapfile -t archives < <(find "$artifact_dir" -maxdepth 1 -type f -name 'rustsdcmcp_*_amd64.tar.gz' -print)
test "${#archives[@]}" -eq 1
archive_path="${archives[0]}"
mapfile -t build_infos < <(tar -tzf "$archive_path" | grep -E '/BUILD-INFO$')
test "${#build_infos[@]}" -eq 1
artifact_commit="$(tar -xOf "$archive_path" "${build_infos[0]}" \
  | sed -n 's/^git_commit=//p')"
test "$artifact_commit" = "$source_commit"
ssh root@192.168.1.202 \
  "pct set 606 --description 'rustsdcmcp lab-only build $artifact_commit; Debian 13; no public release'"
ssh root@192.168.1.202 'pct start 606'
ssh root@192.168.1.202 'pct config 606'
ssh root@192.168.1.202 'pct exec 606 -- systemctl is-system-running --wait'
ssh root@192.168.1.202 'rm -f /root/rustsdcmcp-lab.pub'
```

- [ ] **Step 5: Register the generated MAC and DNS in UniFi**

Read and validate the MAC:

```bash
lxc_mac="$(ssh root@192.168.1.202 'pct config 606' \
  | sed -n 's/^net0:.*hwaddr=\\([^,]*\\).*/\\1/p')"
printf '%s\n' "$lxc_mac" | grep -Eq '^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$'
```

Call UniFi `create_dhcp_reservation` first with `dry_run: true`, then with the
validated value of `lxc_mac` as `mac` and these exact remaining fields:

```json
{
  "site_id": "88f7af54-98f8-306a-a1c7-c9349722b1f6",
  "network_id": "68ed376d6b07201bd54246de",
  "fixed_ip": "192.168.1.211",
  "name": "rustsdcmcp",
  "local_dns_record": "rustsdcmcp.mechub.org",
  "local_dns_record_enabled": true,
  "dry_run": false,
  "confirm": true
}
```

Verify the reservation by MAC and:

```bash
getent ahostsv4 rustsdcmcp.mechub.org
```

Expected: only `192.168.1.211`.

- [ ] **Step 6: Verify container configuration**

Assert from `pct config 606`: pve2 placement, hostname, resources, `local-lvm:4`, unprivileged, `nesting=1`, firewall, static IP, gateway, and onboot.

---

### Task 9: Install the Artifact and Configure Secrets

**Files:**
- External LXC paths under `/usr/local/bin`, `/etc/rustsdcmcp`, and `/var/lib/rustsdcmcp`.
- Local secret output: `/home/mharman/.config/rustsdcmcp/mcp-token`.

**Interfaces:**
- Consumes: CI archive/checksum and protected SDC credential.
- Produces: installed service configuration and one read-only MCP token.

- [ ] **Step 1: Transfer and verify the archive**

```bash
source_commit="<approved CI source commit>"
artifact_dir="dist/$source_commit"
mapfile -t archives < <(find "$artifact_dir" -maxdepth 1 -type f -name 'rustsdcmcp_*_amd64.tar.gz' -print)
test "${#archives[@]}" -eq 1
archive_path="${archives[0]}"
checksum_path="${archive_path}.sha256"
test -f "$checksum_path"
archive_name="$(basename "$archive_path")"
checksum_name="$(basename "$checksum_path")"
scp -p "$archive_path" "$checksum_path" root@192.168.1.202:/root/
ssh root@192.168.1.202 \
  "pct push 606 /root/$archive_name /root/$archive_name \
   --perms 0600 --user root --group root"
ssh root@192.168.1.202 \
  "pct push 606 /root/$checksum_name /root/$checksum_name \
   --perms 0600 --user root --group root"
ssh root@192.168.1.202 \
  "pct exec 606 -- bash -lc 'cd /root && sha256sum -c $checksum_name'"
ssh root@192.168.1.202 \
  "rm -f /root/$archive_name /root/$checksum_name"
```

Expected: checksum reports `OK` inside VMID 606 before extraction.

- [ ] **Step 2: Run the installer twice**

```bash
source_commit="<approved CI source commit>"
artifact_dir="dist/$source_commit"
mapfile -t archives < <(find "$artifact_dir" -maxdepth 1 -type f -name 'rustsdcmcp_*_amd64.tar.gz' -print)
test "${#archives[@]}" -eq 1
archive_path="${archives[0]}"
archive_name="$(basename "$archive_path")"
package_root="$(tar -tzf "$archive_path" | sed -n '1s#/.*##p')"
test -n "$package_root"
ssh root@192.168.1.202 \
  "pct exec 606 -- tar -xzf /root/$archive_name -C /root"
ssh root@192.168.1.202 \
  "pct exec 606 -- /root/$package_root/packaging/lxc/install.sh"
ssh root@192.168.1.202 \
  "pct exec 606 -- /root/$package_root/packaging/lxc/install.sh"
```

Expected: no live SDC config or credential is created, and the second run
preserves tokens, HMAC key, state, and unit.

- [ ] **Step 3: Transfer the credential without displaying it**

```bash
scp -p /home/mharman/.config/rustsdcmcp/credentials.env \
  root@192.168.1.202:/root/rustsdcmcp-606.credentials.env
ssh root@192.168.1.202 \
  'pct push 606 /root/rustsdcmcp-606.credentials.env \
   /etc/rustsdcmcp/credentials.env --perms 0600 --user root --group root'
ssh root@192.168.1.202 \
  'rm -f /root/rustsdcmcp-606.credentials.env'
```

Use `stat` only; never read the installed credential back.

- [ ] **Step 4: Perform the read-only tenant probe and write live config**

Inside VMID 606, use a mode-`0600` temporary header file so the API key is
absent from the curl command line:

```bash
ssh root@192.168.1.202 'pct exec 606 -- bash -s' <<'REMOTE'
set -euo pipefail
set +x
umask 077
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends jq
jq --version
set -a
. /etc/rustsdcmcp/credentials.env
set +a
header_file=/run/rustsdcmcp-sdc-header
response_file=/run/rustsdcmcp-tenant.json
config_file=/run/rustsdcmcp-sdc.json
trap 'rm -f "$header_file" "$response_file" "$config_file"; unset SDC_API_TOKEN' EXIT
printf 'x-api-key: %s\n' "$SDC_API_TOKEN" >"$header_file"
chmod 0600 "$header_file"
curl --silent --show-error --fail \
  -H "@$header_file" \
  -o "$response_file" \
  https://api.sdcloud.juniperclouds.net/api/v2/tenant/tenant-id
tenant_id="$(jq -er '.tenant_id | select(type == "string" and length > 0)' "$response_file")"
jq --arg tenant_id "$tenant_id" \
  '
  .tenant = "production"
  | .expected_tenant_id = $tenant_id
  | .credential_env = "SDC_API_TOKEN"
  | .auth_scheme = "api_key"
  | .endpoint = "https://api.sdcloud.juniperclouds.net/"
  | .changeset_state_file = "/var/lib/rustsdcmcp/changeset-state.json"
  ' \
  /etc/rustsdcmcp/sdc.json.example >"$config_file"
install -o root -g rustsdcmcp -m 0640 "$config_file" /etc/rustsdcmcp/sdc.json
REMOTE
```

The packaged example already supplies the approved numeric limits and TTL.
Require HTTPS success and a non-empty JSON `.tenant_id`. The tenant ID may be
recorded in config but not printed in the handoff.

- [ ] **Step 5: Mint the explicit read-only MCP token**

Create the local output file first:

```bash
install -m 0600 /dev/null /home/mharman/.config/rustsdcmcp/mcp-token
```

Run the token command as root and redirect stdout directly to that file. mecmcp
atomically replaces `tokens.json` in its existing directory, so root must perform
the same-directory write while preserving the existing `rustsdcmcp`-owned `0600`
destination:

```bash
ssh root@192.168.1.202 \
  'pct exec 606 -- /usr/local/bin/rustsdcmcp token add \
   --tokens-file /etc/rustsdcmcp/tokens.json \
   --device-mapping /etc/rustsdcmcp/sdc.json \
   --name lab-read \
   --devices production \
   --tools get_sdc_tenant_scope,list_sdc_devices,get_sdc_device,list_sdc_firewall_policies,get_sdc_firewall_policy,list_sdc_nat_policies,get_sdc_nat_policy,list_sdc_resources,get_sdc_resource,get_sdc_preview_status,get_sdc_deploy_status,get_sdc_preview_device_result,get_sdc_deploy_device_result,get_sdc_change_set \
   --actor-type human' \
  > /home/mharman/.config/rustsdcmcp/mcp-token
chmod 0600 /home/mharman/.config/rustsdcmcp/mcp-token
```

Do not use wildcard tools and do not display the file.

- [ ] **Step 6: Verify protected paths**

Expected:

```text
0600 root:root /etc/rustsdcmcp/credentials.env
0600 rustsdcmcp:rustsdcmcp /etc/rustsdcmcp/tokens.json
0600 rustsdcmcp:rustsdcmcp /etc/rustsdcmcp/audit-hmac.key
0640 root:rustsdcmcp /etc/rustsdcmcp/sdc.json
0700 rustsdcmcp:rustsdcmcp /var/lib/rustsdcmcp
```

---

### Task 10: Start the Service and Run Read-Only Acceptance

**Files:**
- External runtime state only.

**Interfaces:**
- Consumes: configured VMID 606 and local read-only token.
- Produces: sanitized acceptance evidence.

- [ ] **Step 1: Enable persistent journald and the service**

Restart journald after installing the drop-in. Then:

```bash
ssh root@192.168.1.202 \
  'pct exec 606 -- systemctl enable --now rustsdcmcp.service'
```

Expected: active and enabled.

- [ ] **Step 2: Verify process and listener isolation**

Check:

```bash
ssh root@192.168.1.202 \
  'pct exec 606 -- systemctl show rustsdcmcp.service \
   -p User -p Group -p MainPID -p ExecMainStatus'
ssh root@192.168.1.202 \
  "pct exec 606 -- ss -lntp 'sport = :30032'"
```

Expected: user/group `rustsdcmcp`, status zero, only `127.0.0.1:30032`.

From the LAN:

```bash
nc -zvw2 rustsdcmcp.mechub.org 30032
```

Expected: connection fails.

- [ ] **Step 3: Open a temporary SSH tunnel**

Use local port `39032`:

```bash
ssh -N -L 39032:127.0.0.1:30032 root@rustsdcmcp.mechub.org
```

Keep its PID for cleanup. Endpoint: `http://127.0.0.1:39032/mcp`.

- [ ] **Step 4: Verify missing and invalid bearer rejection**

Send MCP initialize without Authorization and with a fixed invalid test token. Expected: HTTP `401`, credential-free JSON, and a Bearer challenge.

- [ ] **Step 5: Initialize with the protected token**

Construct a mode-`0600` temporary curl header file from the protected token without printing it. Send:

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"rustsdcmcp-lab-smoke","version":"1"}}}
```

Require HTTP `200`, capture `Mcp-Session-Id`, and send `notifications/initialized`.

- [ ] **Step 6: Verify the advertised read-only tool surface**

Send `tools/list`. Assert all 14 explicitly granted read tools appear and these never appear:

```text
prepare_sdc_policy_deploy
approve_sdc_change_set
apply_sdc_change_set
```

- [ ] **Step 7: Call only bounded read tools**

Call:

```json
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_sdc_tenant_scope","arguments":{"tenant":"production"}}}
```

Then:

```json
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"list_sdc_devices","arguments":{"tenant":"production","from":0,"size":1}}}
```

Optionally call `list_sdc_firewall_policies` with `size: 1` only if the first two reads succeed. Never call a write tool even to test denial.

- [ ] **Step 8: Verify audit and restart behavior**

Check the journal for initialize/tool attribution, success/failure outcome, and HMAC-redacted target. Assert the literal target alias is absent from the audit target field. Restart the service and repeat authenticated initialize plus tenant scope.

- [ ] **Step 9: Remove temporary local test material**

Stop the SSH tunnel and securely remove temporary header/body files. Keep the protected MCP token file. Do not delete the LXC or its diagnostics.

---

### Task 11: Record the Deployment and Update the Draft PR

**Files:**
- Create: `docs/lab-deployment-606.md`

**Interfaces:**
- Consumes: exact artifact and sanitized acceptance output.
- Produces: durable, non-secret handoff record.

- [ ] **Step 1: Write the deployment record**

Record:

- Date and operator.
- Draft PR URL.
- Source commit from BUILD-INFO.
- Archive filename and SHA-256.
- `mecmcp_ref=changeset-v0.3.6`.
- 59 issue-linked compatibility symbols.
- Node `pve2`, VMID `606`, hostname `rustsdcmcp-606`.
- IP `192.168.1.211`, DNS `rustsdcmcp.mechub.org`.
- Debian version and LXC resources.
- Service user, loopback port, hardening result.
- Sanitized MCP/auth/read/audit/restart results.
- Remote journal forwarding lab exception.
- Explicit statement that no SDC mutation was attempted.
- Explicit public release blocker.

Do not record tenant ID, API key, MCP token, HMAC key, token digest, or unredacted audit targets.

- [ ] **Step 2: Commit and push the record**

```bash
git add docs/lab-deployment-606.md
git commit -m "docs: record VMID 606 lab deployment"
git push
```

- [ ] **Step 3: Update the draft PR**

Add the sanitized acceptance summary and deployed artifact commit/checksum. Leave the PR in draft and do not create a tag or release.

- [ ] **Step 4: Final read-only status checks**

Confirm:

- VMID 606 remains running on `pve2`.
- DNS resolves only to `192.168.1.211`.
- Service is active and loopback-only.
- Draft PR is open.
- No public rustsdcmcp release or tag was created.
- VMID 602 remains unchanged on `pve3`.

## Appendix A: Exact 59-Symbol Upstream Issue Inventory

### Types: 22

| Kind | Local/upstream symbol | Exact issue title | Acceptance semantics |
| --- | --- | --- | --- |
| type | `mecmcp_auth::BearerSyntax` | `[auth] Add BearerSyntax compatibility policy` | Strict and outer-whitespace-trimmed modes |
| type | `mecmcp_auth::BearerHeaderError` | `[auth] Add BearerHeaderError` | Credential-free excessive-length, character, scheme, empty, and whitespace failures |
| type | `mecmcp_server::AuthorizationError` | `[server] Add AuthorizationError` | Separate tool/target variants without inventory disclosure |
| type | `mecmcp_server::ResultFormat` | `[server] Add ResultFormat` | Pretty JSON and raw-string-or-pretty-JSON modes |
| type | `mecmcp_server::ResultLimits` | `[server] Add ResultLimits` | Independent text and serialized JSON ceilings |
| type | `mecmcp_server::BoundedText` | `[server] Add BoundedText` | UTF-8-safe prefix and exact truncation metadata |
| type | `mecmcp_server::SerializedValue` | `[server/internal] Add SerializedValue` | Internal rendered text plus JSON byte count |
| type | `mecmcp_transport::Authenticate` | `[transport/internal] Add Authenticate callback type` | Thread-safe opaque credential to `CallerCtx<G>` callback |
| type | `mecmcp_transport::BearerAuthenticator` | `[transport] Add BearerAuthenticator` | Syntax plus reload-safe authentication callback |
| type | `mecmcp_transport::BearerResponseProfile` | `[transport] Add BearerResponseProfile` | Realm and response compatibility without credentials |
| type | `mecmcp_transport::BearerResponseStyle` | `[transport/internal] Add BearerResponseStyle` | Detailed and compact response semantics |
| type | `mecmcp_transport::BearerBoundary` | `[transport] Add BearerBoundary` | Authenticator, profile, body ceiling, optional preflight |
| type | `mecmcp_transport::PresentationError` | `[transport/internal] Add PresentationError` | Missing versus malformed presentation without credential retention |
| type | `mecmcp_transport::MalformedArgumentsPolicy` | `[transport] Add MalformedArgumentsPolicy` | Deny or defer malformed arguments |
| type | `mecmcp_transport::MalformedTargetPolicy` | `[transport] Add MalformedTargetPolicy` | Deny or defer malformed target values |
| type | `mecmcp_transport::TargetValueShape` | `[transport] Add TargetValueShape` | Scalar and non-empty string-array target shapes |
| type | `mecmcp_transport::TargetField` | `[transport] Add TargetField` | Consumer field, shape, and malformed policy |
| type | `mecmcp_transport::ToolScopePreflight` | `[transport] Add ToolScopePreflight` | Write registry, target fields, malformed policy |
| type | `mecmcp_transport::HostOriginPolicy` | `[transport] Add HostOriginPolicy` | Exact neutral Host and Origin policy |
| type | `mecmcp_transport::HttpTransportConfig` | `[transport] Add HttpTransportConfig` | Identity, limits, policy, bearer, and metrics switch |
| type | `mecmcp_transport::HttpTransportBuildError` | `[transport] Add HttpTransportBuildError` | Typed limits and metrics construction failures |
| type | `mecmcp_transport::HttpServeError` | `[transport] Add HttpServeError` | Typed bind and serve failures with address |

### Functions and methods: 37

| Kind | Local/upstream symbol | Exact issue title | Acceptance semantics |
| --- | --- | --- | --- |
| function | `mecmcp_auth::parse_bearer_header` | `[auth] Add parse_bearer_header` | Case-insensitive, 4096-byte, visible-ASCII, allocation-free parser |
| function | `mecmcp_server::audit_scope` | `[server] Add audit_scope` | Caller or stdio scope without borrowing caller |
| function | `mecmcp_server::authorize_tool` | `[server] Add authorize_tool` | Write-aware wildcard authorization |
| function | `mecmcp_server::authorize_target` | `[server] Add authorize_target` | Exact target scope without inventory lookup |
| function | `mecmcp_server::authorize_call` | `[server] Add authorize_call` | Tool check before optional target |
| function | `mecmcp_server::caller_from_extensions` | `[server] Add caller_from_extensions` | Nested HTTP-parts extraction; stdio returns none |
| function | `mecmcp_server::bounded_text` | `[server] Add bounded_text` | Byte limit without splitting UTF-8 |
| function | `mecmcp_server::tool_error` | `[server] Add tool_error` | One stable safe MCP error block |
| function | `mecmcp_server::tool_result` | `[server] Add tool_result` | Domain/serialization errors and oversize refusal |
| function | `mecmcp_server::serialize_value` | `[server/internal] Add serialize_value` | Both formats plus independent JSON size |
| function | `mecmcp_server::filter_tools_for_scope` | `[server] Add filter_tools_for_scope` | Same write-aware predicate as invocation |
| method | `BearerAuthenticator::new` | `[transport] Add BearerAuthenticator::new` | Syntax and Send+Sync lookup closure |
| method | `BearerAuthenticator::authenticate` | `[transport/internal] Add BearerAuthenticator::authenticate` | Invoke callback without logging candidate |
| method | `BearerResponseProfile::detailed` | `[transport] Add BearerResponseProfile::detailed` | Distinct RFC 6750 invalid-request/token responses |
| method | `BearerBoundary::new` | `[transport] Add BearerBoundary::new` | Body ceiling and no preflight by default |
| method | `BearerBoundary::with_preflight` | `[transport] Add BearerBoundary::with_preflight` | Immutable synchronous preflight builder |
| function | `mecmcp_transport::apply_bearer_boundary` | `[transport] Add apply_bearer_boundary` | Deterministic Axum layer |
| function | `mecmcp_transport::bearer_boundary` | `[transport/internal] Add bearer_boundary middleware` | Auth, bounded body, preflight, caller insertion, body reconstruction |
| function | `mecmcp_transport::bearer_candidate` | `[transport/internal] Add bearer_candidate` | Reject missing, duplicate, non-UTF-8, oversized, malformed headers |
| function | `mecmcp_transport::unauthorized` | `[transport/internal] Add unauthorized response` | Safe detailed 401 invalid_request |
| function | `mecmcp_transport::invalid_token` | `[transport/internal] Add invalid_token response` | Credential-free 401 invalid_token |
| function | `mecmcp_transport::forbidden` | `[transport/internal] Add forbidden response` | 403 insufficient_scope with realm |
| function | `mecmcp_transport::response` | `[transport/internal] Add bearer JSON response builder` | Central status, challenge, and JSON response |
| function | `mecmcp_transport::payload_too_large` | `[transport/internal] Add payload_too_large response` | Stable 413 request_too_large |
| method | `TargetField::scalar` | `[transport] Add TargetField::scalar` | Scalar string target denying malformed values |
| method | `ToolScopePreflight::new` | `[transport] Add ToolScopePreflight::new` | Static writes, target fields, malformed policy |
| method | `ToolScopePreflight::request_exceeds_scope` | `[transport/internal] Add ToolScopePreflight::request_exceeds_scope` | tools/call only; tool check before target |
| method | `ToolScopePreflight::check` | `[transport] Implement ScopePreflight for ToolScopePreflight` | Single/batch JSON-RPC and deny-any batch behavior |
| function | `mecmcp_transport::target_value_in_scope` | `[transport/internal] Add target_value_in_scope` | Exact scalar/array scope and malformed policy |
| function | `mecmcp_transport::value_has_shape` | `[transport/internal] Add value_has_shape` | Scalar and non-empty all-string array validation |
| method | `HostOriginPolicy::enforced` | `[transport] Add HostOriginPolicy::enforced` | Extend loopback hosts and exact Origins |
| function | `mecmcp_transport::streamable_http_server_config` | `[transport/internal] Add streamable_http_server_config` | Neutral policy to rmcp config |
| method | `HttpTransportConfig::new` | `[transport] Add HttpTransportConfig::new` | No bearer and metrics disabled initially |
| method | `HttpTransportConfig::with_bearer` | `[transport] Add HttpTransportConfig::with_bearer` | Install typed bearer boundary |
| method | `HttpTransportConfig::with_metrics` | `[transport] Add HttpTransportConfig::with_metrics` | Explicit metrics switch |
| function | `mecmcp_transport::build_streamable_http_router` | `[transport] Add build_streamable_http_router` | Validate limits and compose exact middleware order |
| function | `mecmcp_transport::serve_router` | `[transport] Add serve_router` | Plain or supplied-rustls listener with typed failures |
