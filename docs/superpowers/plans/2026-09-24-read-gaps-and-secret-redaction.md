# Read Gaps and Secret Redaction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close issue #156 by adding bespoke read tools for the families the generic catalog cannot express. On the way, fix two defects found while planning: credential fields passing through catalog reads, and v2 list endpoints ignoring our page bounds.

**Architecture:** Client methods in `rustsdcmcp-core` return upstream JSON verbatim, as every reader does today. Two new behaviours sit beside them. Credential redaction runs at the MCP tool boundary, the same place `projection.rs` applies its allowlists. v2 pagination goes through a new `list_v2` helper that sends `spec.from`/`spec.size`. Each new tool copies the existing handler shape exactly: authorize, audit, call, `finish`.

**Tech Stack:** Rust 1.89 (MSRV), rmcp, reqwest, serde_json, axum (test-only fake SDC), `mecmcp-*` 0.23.0.

**Spec:** GitHub issue fastrevmd-lab/rustsdcmcp#156, plus the two defects below. Pinned API facts come from `docs/sdc-api/security-director-cloud-apis-openapi3.json`. Read `docs/sdc-api/README.md` before writing any client code.

## Defects found while planning (verified against the vendored spec, 2026-09-24)

1. **ICAP server passwords reach callers.** `IcapServer` declares `password_base64` and `password_ascii`. `icap_servers` is in `ResourceKind`, so `list_sdc_resources` / `get_sdc_resource` would return them verbatim. The lab tenant has not been checked for ICAP servers, so this has not been observed live. No other catalog family declares a credential field (a scan of every catalog collection's response schema closure for `passw|secret|psk|pre_shared|passphrase|private_key|api_key|token|credential` hit only `icap_servers`). `icap_servers` is not in `WritableResource`, so redacting its reads cannot corrupt a read-modify-write.
2. **v2 lists send the wrong page parameters.** `ListTunnels` and `GetSiteList` declare `spec.from` / `spec.size`. `list_tunnels` sends `from` / `size` through the shared `list()` helper. An unrecognised parameter is ignored, so `list_sdc_tunnels` is bounded only by `max_response_bytes`, not by `size`. The lab tenant has zero tunnels (`list_sdc_tunnels size=1` returned `{}` on 2026-09-24), so this is spec-derived and unconfirmed live.

## Global Constraints

- MSRV `1.89`. Nothing newer than `rust-version` in `Cargo.toml`.
- Every verification runs the repo's CI commands, not plain `cargo test`:
  `cargo fmt --all -- --check && cargo clippy --workspace --all-targets --all-features --locked -- -D warnings && cargo test --workspace --locked && RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked`
- Every new tool is read-only. It is **never** added to `WRITE_TOOLS`, and its name starts with `list_sdc_` or `get_sdc_`.
- Every new tool name goes into `KNOWN_TOOLS` in `crates/rustsdcmcp/src/server.rs`. The count in `crates/rustsdcmcp/tests/tool_contract.rs` (`assert_eq!(KNOWN_TOOLS.len(), N)`) and the "**N MCP tools**: R bounded read tools" line in `README.md` move in the same commit.
- Every path identifier goes through `validate_atom(...)` before use.
- Every list takes an explicit `size` through `ListRequest::new(from, size, self.client.max_page_size())`. `size=0` is refused.
- Client methods return upstream JSON verbatim. Redaction happens only in `server.rs`.
- Each task is one commit and gets the Codex gate: `codex exec review --commit <sha>`. No verdict means the gate did not run; say so, don't count it as a pass.
- **Sabotage every fix once, one at a time.** Revert the fix line, confirm the named test fails, restore it, confirm it passes. `cargo test` stops at the first failing target, so never batch sabotage.
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`
- Branch: `feat/read-gaps-156` from `origin/main` (`git fetch && git switch -c feat/read-gaps-156 origin/main`). One agent in this checkout at a time.

## Tool count ledger

| After task | New tools | `KNOWN_TOOLS.len()` | Reads |
|---|---|---:|---:|
| start | — | 54 | 40 |
| 3 | `list_sdc_sites`, `get_sdc_site` | 56 | 42 |
| 4 | `list_sdc_ips_rules`, `get_sdc_ips_rule`, `list_sdc_ips_exempt_rules`, `get_sdc_ips_exempt_rule` | 60 | 46 |
| 5 | `list_sdc_ecf_rule_sets`, `list_sdc_ecf_rules` | 62 | 48 |
| 6 | `get_sdc_firewall_global_settings`, `get_sdc_firewall_global_profile`, `get_sdc_content_security_settings`, `list_sdc_device_global_settings` | 66 | 52 |

## File map

- Create `crates/rustsdcmcp-core/src/redact.rs`: recursive credential redaction for tool output.
- Modify `crates/rustsdcmcp-core/src/lib.rs`: `mod redact;` and `pub use redact::{REDACTED, redact_secrets};`
- Modify `crates/rustsdcmcp-core/src/client.rs`: `list_v2`, plus new client methods and their axum tests in the existing `mod tests`.
- Modify `crates/rustsdcmcp/src/server.rs`: arg structs, handlers, `KNOWN_TOOLS`, and a `finish_redacted` helper.
- Modify `crates/rustsdcmcp/tests/tool_contract.rs`: tool count and comment.
- Modify `crates/rustsdcmcp-core/src/catalog.rs`: header comment (Task 7).
- Modify `README.md`, `CHANGELOG.md`, `CLAUDE.md`, `docs/sdc-api/README.md`: Task 7, except for the count line, which moves with each task.

---

### Task 1: Redact credential fields in tool output (ICAP servers)

**Files:**
- Create: `crates/rustsdcmcp-core/src/redact.rs`
- Modify: `crates/rustsdcmcp-core/src/lib.rs`
- Modify: `crates/rustsdcmcp/src/server.rs` (`finish` area ~line 185; `list_sdc_resources` ~1848; `get_sdc_resource` ~1881)

**Interfaces:**
- Produces: `rustsdcmcp_core::redact_secrets(value: serde_json::Value) -> serde_json::Value`, `rustsdcmcp_core::REDACTED: &str`, and in `server.rs` `fn finish_redacted(audit: AuditScope, result: Result<Value, SdcError>) -> CallToolResult`. Tasks 3 and 6 use `finish_redacted`.

- [ ] **Step 1: Write the failing tests** in the new file `crates/rustsdcmcp-core/src/redact.rs`

```rust
//! Credential redaction for tool output.
//!
//! Applied at the MCP tool boundary only, never inside [`crate::SdcClient`],
//! for the reason `projection.rs` gives: change-control reads the same
//! endpoints to capture before-state, and redacting there would hide drift.
//!
//! This is a **denylist**, unlike the certificate allowlists. The families it
//! guards (ICAP servers, v2 sites) are deeply nested and have never been
//! observed on the lab tenant, so there is no observed field set to allowlist.
//! A present-but-redacted marker is used instead of removal so a caller can
//! see the field exists without learning its value.

use serde_json::Value;

/// Marker substituted for a redacted value.
pub const REDACTED: &str = "[REDACTED]";

/// Keys whose values are credentials, compared case-insensitively.
///
/// `site_config` is not itself a credential. It is a rendered device
/// configuration body, and SDC-generated IPsec config carries the IKE
/// pre-shared key, so it is withheld as a whole.
const SECRET_KEYS: &[&str] = &[
    "password",
    "password_ascii",
    "password_base64",
    "passphrase",
    "psk",
    "pre_shared_key",
    "site_config",
];

/// Replace every credential-bearing value in `value`, at any depth.
///
/// `null` stays `null`: it carries no secret, and rewriting it would claim
/// one existed.
#[must_use]
pub fn redact_secrets(mut value: Value) -> Value {
    redact_in_place(&mut value);
    value
}

fn redact_in_place(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                let lowered = key.to_ascii_lowercase();
                if SECRET_KEYS.contains(&lowered.as_str()) {
                    if !child.is_null() {
                        *child = Value::String(REDACTED.to_owned());
                    }
                } else {
                    redact_in_place(child);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(redact_in_place),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn icap_server_passwords_are_redacted_in_a_list_envelope() {
        let listed = json!({"items": [{
            "uuid": "u1", "name": "icap", "host": "10.0.0.1",
            "password_ascii": "hunter2", "password_base64": "aHVudGVyMg=="
        }], "count": 1});
        let out = redact_secrets(listed);
        assert_eq!(out["items"][0]["password_ascii"], REDACTED);
        assert_eq!(out["items"][0]["password_base64"], REDACTED);
        assert_eq!(out["items"][0]["host"], "10.0.0.1");
        assert_eq!(out["count"], 1);
    }

    #[test]
    fn nested_site_psk_and_config_body_are_redacted() {
        let site = json!({"site": {"site_name": "s1", "cpe_devices": [{
            "name": "cpe", "cpe_interfaces": [{
                "psk": "shared", "ike_id": "id",
                "site_config": {"body": "set security ike ... pre-shared-key", "format": "set"}
            }]
        }]}});
        let out = redact_secrets(site);
        let iface = &out["site"]["cpe_devices"][0]["cpe_interfaces"][0];
        assert_eq!(iface["psk"], REDACTED);
        assert_eq!(iface["site_config"], REDACTED);
        assert_eq!(iface["ike_id"], "id");
    }

    #[test]
    fn key_match_is_case_insensitive_and_null_is_left_alone() {
        let out = redact_secrets(json!({"PSK": "x", "password": null}));
        assert_eq!(out["PSK"], REDACTED);
        assert!(out["password"].is_null());
    }

    #[test]
    fn a_value_without_credentials_is_unchanged() {
        let original = json!({"items": [{"name": "a", "keysize": "2048"}]});
        assert_eq!(redact_secrets(original.clone()), original);
    }
}
```

- [ ] **Step 2: Wire the module** into `crates/rustsdcmcp-core/src/lib.rs`. Add `mod redact;` after `mod projection;`, and `pub use redact::{REDACTED, redact_secrets};` after the `pub use projection::…` block.

- [ ] **Step 3: Run the tests**

Run: `cargo test -p rustsdcmcp-core --locked redact::`
Expected: 4 passed.

- [ ] **Step 4: Sabotage the redactor.** Change `*child = Value::String(REDACTED.to_owned());` to `let _ = child;`, run Step 3, and expect `icap_server_passwords_are_redacted_in_a_list_envelope` to FAIL. Restore the line and rerun: PASS.

- [ ] **Step 5: Apply it at the tool boundary.** In `server.rs`, add `redact_secrets` to the `rustsdcmcp_core::{…}` import, then add this below `fn finish`:

```rust
/// `finish`, for reads whose upstream shape may carry credentials.
fn finish_redacted(audit: AuditScope, result: Result<Value, SdcError>) -> CallToolResult {
    finish(audit, result.map(redact_secrets))
}
```

In `list_sdc_resources`, change the last line to `Ok(finish_redacted(audit, result))`. In `get_sdc_resource`, change `Ok(finish(` to `Ok(finish_redacted(`. This redacts every catalog family, not only ICAP. That is deliberate: it costs nothing, and it covers a credential field upstream adds to another family later.

- [ ] **Step 6: Sabotage the call site.** No test drives a handler against a fake SDC: `SdcClient::new` is HTTPS-only, and `from_test_parts` is `pub(crate)` to core. So revert `list_sdc_resources` to `finish` and run the full CI command. Expect it to **still pass**. That proves the call site is uncovered. Record it in the commit body as "call site not covered by tests; verified by review and by the live check in Task 7". Restore.

- [ ] **Step 7: Run the full CI command** from Global Constraints. Expected: green.

- [ ] **Step 8: Commit**

```bash
git add crates/rustsdcmcp-core/src/redact.rs crates/rustsdcmcp-core/src/lib.rs crates/rustsdcmcp/src/server.rs
git commit -m "fix: redact credential fields from catalog reads

IcapServer declares password_ascii and password_base64, and icap_servers
is in the read catalog, so list/get_sdc_resource returned them verbatim.
Redaction runs at the tool boundary, like projection.rs, so change-control
before-state is untouched. The handler call site is not covered by tests
(no handler-level fake SDC exists); verified by review.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

Then run `codex exec review --commit HEAD`.

---

### Task 2: Send `spec.from`/`spec.size` on v2 lists (tunnels)

**Files:**
- Modify: `crates/rustsdcmcp-core/src/client.rs` (`list_tunnels` ~736; private helpers ~1591; `mod tests`)

**Interfaces:**
- Produces: `async fn list_v2(&self, segments: &[&str], page: ListRequest, cancellation: &CancellationToken) -> Result<Value, SdcError>`, private to `SdcClient`. Task 3 uses it.

- [ ] **Step 1: Write the failing test** in `client.rs` `mod tests`:

```rust
    #[tokio::test]
    async fn v2_tunnel_list_sends_spec_prefixed_page_parameters() {
        // ListTunnels declares `spec.from`/`spec.size`. Plain `from`/`size`
        // are ignored upstream, leaving the list bounded only by bytes.
        let app = Router::new().route(
            "/api/v2/tunnels",
            get(|Query(query): Query<HashMap<String, String>>| async move {
                assert_eq!(query.get("spec.from").map(String::as_str), Some("5"));
                assert_eq!(query.get("spec.size").map(String::as_str), Some("7"));
                assert!(!query.contains_key("from"), "unprefixed from sent: {query:?}");
                assert!(!query.contains_key("size"), "unprefixed size sent: {query:?}");
                Json(serde_json::json!({"tunnels": [], "total": 0}))
            }),
        );
        let (base_url, server) = serve(app).await;
        let result = client(base_url, 4096)
            .list_tunnels(
                ListRequest::new(5, 7, 100).expect("test page"),
                &CancellationToken::new(),
            )
            .await
            .expect("list succeeds");
        assert_eq!(result["total"], 0);
        server.abort();
    }
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `cargo test -p rustsdcmcp-core --locked v2_tunnel_list_sends_spec_prefixed_page_parameters`
Expected: FAIL. The axum handler's assertion panics, so the client sees a 500 and the test reports the `expect("list succeeds")` failure.

- [ ] **Step 3: Implement.** Add after `list_projected`:

```rust
    /// Bounded list for `/api/v2/` collections, which prefix their page
    /// parameters (`spec.from`, `spec.size`) and accept no `fields`.
    async fn list_v2(
        &self,
        segments: &[&str],
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        let page = ListRequest::new(page.from, page.size, self.max_page_size)?;
        let from = page.from.to_string();
        let size = page.size.to_string();
        self.get(
            segments,
            &[("spec.from", from.as_str()), ("spec.size", size.as_str())],
            cancellation,
        )
        .await
    }
```

In `list_tunnels`, change `self.list(&["api", "v2", "tunnels"], page, cancellation)` to `self.list_v2(&["api", "v2", "tunnels"], page, cancellation)`. Leave `list_ipsec_profiles` alone: `GetIpsecProfileList` declares no parameters at all, and changing what it sends is out of scope. Task 7 records this in the docs.

- [ ] **Step 4: Run it and confirm it passes.** Same command. Expected: PASS.

- [ ] **Step 5: Sabotage.** Put `self.list(` back in `list_tunnels` and confirm FAIL. Restore and confirm PASS.

- [ ] **Step 6: Run the full CI command.**

- [ ] **Step 7: Commit**

```bash
git add crates/rustsdcmcp-core/src/client.rs
git commit -m "fix: send spec.from/spec.size on the v2 tunnel list

ListTunnels declares spec-prefixed page parameters; unprefixed from/size
were ignored, so size did not bound the response. Spec-derived: the lab
tenant has no tunnels to confirm it live.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: v2 sites (`list_sdc_sites`, `get_sdc_site`), redacted

**Files:**
- Modify: `crates/rustsdcmcp-core/src/client.rs`
- Modify: `crates/rustsdcmcp/src/server.rs`
- Modify: `crates/rustsdcmcp/tests/tool_contract.rs`, `README.md` (count 54→56, reads 40→42)

**Interfaces:**
- Consumes: `list_v2` (Task 2), `finish_redacted` (Task 1).
- Produces: `SdcClient::list_sites(page, &ct)`, `SdcClient::get_site(site_name: &str, &ct)`, `SiteArgs { tenant, site_name }`.

- [ ] **Step 1: Write the failing client tests**

```rust
    #[tokio::test]
    async fn list_sites_uses_the_v2_page_parameters() {
        let app = Router::new().route(
            "/api/v2/sites",
            get(|Query(query): Query<HashMap<String, String>>| async move {
                assert_eq!(query.get("spec.from").map(String::as_str), Some("0"));
                assert_eq!(query.get("spec.size").map(String::as_str), Some("3"));
                Json(serde_json::json!({"sites": [], "total": 0}))
            }),
        );
        let (base_url, server) = serve(app).await;
        let result = client(base_url, 4096)
            .list_sites(
                ListRequest::new(0, 3, 100).expect("test page"),
                &CancellationToken::new(),
            )
            .await
            .expect("list succeeds");
        assert_eq!(result["total"], 0);
        server.abort();
    }

    #[tokio::test]
    async fn get_site_addresses_the_site_by_one_encoded_name_segment() {
        let app = Router::new().route(
            "/api/v2/site/{site_name}",
            get(|axum::extract::Path(site_name): axum::extract::Path<String>| async move {
                Json(serde_json::json!({"site": {"site_name": site_name}}))
            }),
        );
        let (base_url, server) = serve(app).await;
        let result = client(base_url, 4096)
            .get_site("branch/../1", &CancellationToken::new())
            .await
            .expect("get succeeds");
        assert_eq!(result["site"]["site_name"], "branch/../1");
        server.abort();
    }
```

- [ ] **Step 2: Run and confirm FAIL** with `cargo test -p rustsdcmcp-core --locked site`. Expected: compile error, because `list_sites` and `get_site` do not exist yet.

- [ ] **Step 3: Implement the client methods** after `tunnel_count`:

```rust
    /// List sites with bounded pagination (`/api/v2/`, `spec.from`/`spec.size`).
    ///
    /// Site objects embed CPE interfaces carrying IKE pre-shared keys. The
    /// client returns them verbatim; the tool boundary redacts.
    pub async fn list_sites(
        &self,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        self.list_v2(&["api", "v2", "sites"], page, cancellation)
            .await
    }

    /// Fetch one site by name (`/api/v2/site/{site_name}`).
    pub async fn get_site(
        &self,
        site_name: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("site_name", site_name)?;
        self.get(&["api", "v2", "site", site_name], &[], cancellation)
            .await
    }
```

- [ ] **Step 4: Run and confirm PASS.**

- [ ] **Step 5: Add the tools.** In `server.rs`, add `"list_sdc_sites", "get_sdc_site",` to `KNOWN_TOOLS` after `"get_sdc_tunnel_count",`. Add the arg struct after `TunnelArgs`:

```rust
/// Arguments for one site.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SiteArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Site name; sites are addressed by name, not UUID.
    pub site_name: String,
}
```

Add the handlers after `get_sdc_tunnel_count`:

```rust
    #[tool(
        name = "list_sdc_sites",
        description = "List sites with bounded pagination. Pre-shared keys and rendered site config are redacted."
    )]
    async fn list_sdc_sites(
        &self,
        Parameters(args): Parameters<ListArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(caller, "list_sdc_sites", "read", vec![args.tenant.clone()]);
        if let Err(error) = self.authorize(caller, "list_sdc_sites", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        let result = ListRequest::new(args.from, args.size, self.client.max_page_size())
            .map_err(SdcError::from);
        let result = match result {
            Ok(page) => self.client.list_sites(page, &cancellation).await,
            Err(error) => Err(error),
        };
        Ok(finish_redacted(audit, result))
    }

    #[tool(
        name = "get_sdc_site",
        description = "Get one site by name. Pre-shared keys and rendered site config are redacted."
    )]
    async fn get_sdc_site(
        &self,
        Parameters(args): Parameters<SiteArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(caller, "get_sdc_site", "read", vec![args.tenant.clone()]);
        if let Err(error) = self.authorize(caller, "get_sdc_site", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish_redacted(
            audit,
            self.client.get_site(&args.site_name, &cancellation).await,
        ))
    }
```

In `tool_contract.rs`, change `assert_eq!(KNOWN_TOOLS.len(), 54);` to `56` and append to the comment: `#156 added list/get_sdc_sites (redacted).` In `README.md`, change `**54 MCP tools**: 40 bounded read tools` to `**56 MCP tools**: 42 bounded read tools`.

- [ ] **Step 6: Run the full CI command.** `known_tools_matches_the_registered_router_exactly` proves registration and `KNOWN_TOOLS` agree. Sabotage it once: delete `"get_sdc_site",` from `KNOWN_TOOLS` and confirm that test FAILS. Restore.

- [ ] **Step 7: Commit** `feat: list and get v2 sites, with PSKs redacted (#156)` plus the trailer. Then run the Codex gate.

---

### Task 4: IPS rules and exempt rules (4 tools)

The paths are `/api/v1/ips_profiles/{profile_uuid}/ips_rules[/{rule_uuid}]` and `/api/v1/ips_profiles/{profile_uuid}/exempt_rules[/{rule_uuid}]`. The collection segment is **`ips_rules`**, not `rules`. The `catalog.rs` header wrote `…/` and never named it. Both list endpoints take `from`/`size`, so use the existing `list`.

**Files:** `client.rs`, `server.rs`, `tool_contract.rs` (56→60), `README.md` (reads 42→46)

**Interfaces:**
- Produces: `SdcClient::list_ips_rules(profile_uuid, page, &ct)`, `get_ips_rule(profile_uuid, rule_uuid, &ct)`, `list_ips_exempt_rules(profile_uuid, page, &ct)`, `get_ips_exempt_rule(profile_uuid, rule_uuid, &ct)`, and `IpsRuleListArgs { tenant, profile_uuid, from, size }`, `IpsRuleArgs { tenant, profile_uuid, rule_uuid }`.

- [ ] **Step 1: Write the failing client tests**

```rust
    #[tokio::test]
    async fn ips_rule_reads_use_the_ips_rules_and_exempt_rules_segments() {
        let app = Router::new()
            .route(
                "/api/v1/ips_profiles/{profile}/ips_rules",
                get(|Query(query): Query<HashMap<String, String>>| async move {
                    assert_eq!(query.get("size").map(String::as_str), Some("2"));
                    Json(serde_json::json!({"items": [], "count": 0, "kind": "ips"}))
                }),
            )
            .route(
                "/api/v1/ips_profiles/{profile}/ips_rules/{rule}",
                get(|axum::extract::Path((p, r)): axum::extract::Path<(String, String)>| async move {
                    Json(serde_json::json!({"profile": p, "rule": r}))
                }),
            )
            .route(
                "/api/v1/ips_profiles/{profile}/exempt_rules",
                get(|| async { Json(serde_json::json!({"items": [], "count": 0, "kind": "exempt"})) }),
            )
            .route(
                "/api/v1/ips_profiles/{profile}/exempt_rules/{rule}",
                get(|axum::extract::Path((p, r)): axum::extract::Path<(String, String)>| async move {
                    Json(serde_json::json!({"profile": p, "exempt": r}))
                }),
            );
        let (base_url, server) = serve(app).await;
        let sdc = client(base_url, 4096);
        let ct = CancellationToken::new();
        let page = || ListRequest::new(0, 2, 100).expect("test page");
        assert_eq!(sdc.list_ips_rules("p1", page(), &ct).await.expect("list")["kind"], "ips");
        assert_eq!(sdc.get_ips_rule("p1", "r1", &ct).await.expect("get")["rule"], "r1");
        assert_eq!(
            sdc.list_ips_exempt_rules("p1", page(), &ct).await.expect("list")["kind"],
            "exempt"
        );
        assert_eq!(
            sdc.get_ips_exempt_rule("p1", "e1", &ct).await.expect("get")["exempt"],
            "e1"
        );
        server.abort();
    }

    #[tokio::test]
    async fn ips_rule_reads_refuse_empty_identifiers() {
        let sdc = client(Url::parse("http://127.0.0.1:9/").expect("url"), 4096);
        let ct = CancellationToken::new();
        assert!(matches!(
            sdc.get_ips_rule("", "r1", &ct).await,
            Err(SdcError::InvalidIdentifier { field: "profile_uuid" })
        ));
        assert!(matches!(
            sdc.get_ips_exempt_rule("p1", "", &ct).await,
            Err(SdcError::InvalidIdentifier { field: "rule_uuid" })
        ));
    }
```

- [ ] **Step 2: Run and confirm FAIL** with `cargo test -p rustsdcmcp-core --locked ips_rule`. Expected: compile error.

- [ ] **Step 3: Implement the client methods** after `get_resource`:

```rust
    /// List the IPS rules of one IPS profile with bounded pagination.
    pub async fn list_ips_rules(
        &self,
        profile_uuid: &str,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("profile_uuid", profile_uuid)?;
        self.list(
            &["api", "v1", "ips_profiles", profile_uuid, "ips_rules"],
            page,
            cancellation,
        )
        .await
    }

    /// Fetch one IPS rule of one IPS profile.
    pub async fn get_ips_rule(
        &self,
        profile_uuid: &str,
        rule_uuid: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("profile_uuid", profile_uuid)?;
        validate_atom("rule_uuid", rule_uuid)?;
        self.get(
            &["api", "v1", "ips_profiles", profile_uuid, "ips_rules", rule_uuid],
            &[],
            cancellation,
        )
        .await
    }

    /// List the exempt rules of one IPS profile with bounded pagination.
    pub async fn list_ips_exempt_rules(
        &self,
        profile_uuid: &str,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("profile_uuid", profile_uuid)?;
        self.list(
            &["api", "v1", "ips_profiles", profile_uuid, "exempt_rules"],
            page,
            cancellation,
        )
        .await
    }

    /// Fetch one exempt rule of one IPS profile.
    pub async fn get_ips_exempt_rule(
        &self,
        profile_uuid: &str,
        rule_uuid: &str,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("profile_uuid", profile_uuid)?;
        validate_atom("rule_uuid", rule_uuid)?;
        self.get(
            &["api", "v1", "ips_profiles", profile_uuid, "exempt_rules", rule_uuid],
            &[],
            cancellation,
        )
        .await
    }
```

- [ ] **Step 4: Run and confirm PASS.** Then sabotage: change `"ips_rules"` to `"rules"` in `list_ips_rules` and confirm FAIL. Restore.

- [ ] **Step 5: Add the tools.** Append `"list_sdc_ips_rules", "get_sdc_ips_rule", "list_sdc_ips_exempt_rules", "get_sdc_ips_exempt_rule",` to `KNOWN_TOOLS` after `"get_sdc_resource",`. Add the arg structs after `ResourceArgs`:

```rust
/// Arguments for listing the rules nested under one IPS profile.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IpsRuleListArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Parent IPS profile UUID.
    pub profile_uuid: String,
    /// Zero-based offset.
    #[serde(default)]
    pub from: u64,
    /// Explicit positive page size.
    pub size: u32,
}

/// Arguments for one rule nested under one IPS profile.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IpsRuleArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Parent IPS profile UUID.
    pub profile_uuid: String,
    /// Rule UUID.
    pub rule_uuid: String,
}
```

Add the four handlers after `get_sdc_resource`:

```rust
    #[tool(
        name = "list_sdc_ips_rules",
        description = "List the IPS rules of one IPS profile with bounded pagination."
    )]
    async fn list_sdc_ips_rules(
        &self,
        Parameters(args): Parameters<IpsRuleListArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(caller, "list_sdc_ips_rules", "read", vec![args.tenant.clone()]);
        if let Err(error) = self.authorize(caller, "list_sdc_ips_rules", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        let result = ListRequest::new(args.from, args.size, self.client.max_page_size())
            .map_err(SdcError::from);
        let result = match result {
            Ok(page) => {
                self.client
                    .list_ips_rules(&args.profile_uuid, page, &cancellation)
                    .await
            }
            Err(error) => Err(error),
        };
        Ok(finish(audit, result))
    }

    #[tool(name = "get_sdc_ips_rule", description = "Get one IPS rule of one IPS profile.")]
    async fn get_sdc_ips_rule(
        &self,
        Parameters(args): Parameters<IpsRuleArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(caller, "get_sdc_ips_rule", "read", vec![args.tenant.clone()]);
        if let Err(error) = self.authorize(caller, "get_sdc_ips_rule", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish(
            audit,
            self.client
                .get_ips_rule(&args.profile_uuid, &args.rule_uuid, &cancellation)
                .await,
        ))
    }

    #[tool(
        name = "list_sdc_ips_exempt_rules",
        description = "List the exempt rules of one IPS profile with bounded pagination."
    )]
    async fn list_sdc_ips_exempt_rules(
        &self,
        Parameters(args): Parameters<IpsRuleListArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "list_sdc_ips_exempt_rules",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "list_sdc_ips_exempt_rules", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        let result = ListRequest::new(args.from, args.size, self.client.max_page_size())
            .map_err(SdcError::from);
        let result = match result {
            Ok(page) => {
                self.client
                    .list_ips_exempt_rules(&args.profile_uuid, page, &cancellation)
                    .await
            }
            Err(error) => Err(error),
        };
        Ok(finish(audit, result))
    }

    #[tool(
        name = "get_sdc_ips_exempt_rule",
        description = "Get one exempt rule of one IPS profile."
    )]
    async fn get_sdc_ips_exempt_rule(
        &self,
        Parameters(args): Parameters<IpsRuleArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "get_sdc_ips_exempt_rule",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "get_sdc_ips_exempt_rule", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish(
            audit,
            self.client
                .get_ips_exempt_rule(&args.profile_uuid, &args.rule_uuid, &cancellation)
                .await,
        ))
    }
```

Set the count to `60` in `tool_contract.rs`, add `#156 added IPS rule and exempt-rule reads.` to its comment, and set the README to `**60 MCP tools**: 46 bounded read tools`.

- [ ] **Step 6: Run the full CI command.**
- [ ] **Step 7: Commit** `feat: read IPS rules and exempt rules per profile (#156)` plus the trailer, then run the Codex gate.

---

### Task 5: Enhanced content-filtering rule sets and rules (2 tools)

The spec has **no** single-rule-set GET, so the only reads are the rule-set list and the rule list below it. Both take `from`/`size`.

**Files:** `client.rs`, `server.rs`, `tool_contract.rs` (60→62), `README.md` (reads 46→48)

**Interfaces:**
- Produces: `SdcClient::list_ecf_rule_sets(profile_uuid, page, &ct)` and `list_ecf_rules(profile_uuid, rule_set_uuid, page, &ct)`, plus `EcfRuleSetListArgs { tenant, profile_uuid, from, size }` and `EcfRuleListArgs { tenant, profile_uuid, rule_set_uuid, from, size }`.

- [ ] **Step 1: Write the failing client test**

```rust
    #[tokio::test]
    async fn ecf_reads_nest_rule_sets_under_the_profile_and_rules_under_the_set() {
        let app = Router::new()
            .route(
                "/api/v1/enhanced_content_filtering_profiles/{p}/rule_sets",
                get(|axum::extract::Path(p): axum::extract::Path<String>| async move {
                    Json(serde_json::json!({"items": [], "count": 0, "profile": p}))
                }),
            )
            .route(
                "/api/v1/enhanced_content_filtering_profiles/{p}/rule_sets/{s}/rules",
                get(|axum::extract::Path((p, s)): axum::extract::Path<(String, String)>,
                     Query(query): Query<HashMap<String, String>>| async move {
                    assert_eq!(query.get("size").map(String::as_str), Some("4"));
                    Json(serde_json::json!({"items": [], "count": 0, "profile": p, "set": s}))
                }),
            );
        let (base_url, server) = serve(app).await;
        let sdc = client(base_url, 4096);
        let ct = CancellationToken::new();
        let page = || ListRequest::new(0, 4, 100).expect("test page");
        assert_eq!(sdc.list_ecf_rule_sets("p1", page(), &ct).await.expect("sets")["profile"], "p1");
        let rules = sdc.list_ecf_rules("p1", "s1", page(), &ct).await.expect("rules");
        assert_eq!((rules["profile"].as_str(), rules["set"].as_str()), (Some("p1"), Some("s1")));
        server.abort();
    }
```

- [ ] **Step 2: Run and confirm FAIL** with `cargo test -p rustsdcmcp-core --locked ecf_reads`. Expected: compile error.

- [ ] **Step 3: Implement** after `get_ips_exempt_rule`:

```rust
    /// List the rule sets of one enhanced content-filtering profile.
    pub async fn list_ecf_rule_sets(
        &self,
        profile_uuid: &str,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("profile_uuid", profile_uuid)?;
        self.list(
            &["api", "v1", "enhanced_content_filtering_profiles", profile_uuid, "rule_sets"],
            page,
            cancellation,
        )
        .await
    }

    /// List the rules of one rule set of one enhanced content-filtering profile.
    pub async fn list_ecf_rules(
        &self,
        profile_uuid: &str,
        rule_set_uuid: &str,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        validate_atom("profile_uuid", profile_uuid)?;
        validate_atom("rule_set_uuid", rule_set_uuid)?;
        self.list(
            &[
                "api",
                "v1",
                "enhanced_content_filtering_profiles",
                profile_uuid,
                "rule_sets",
                rule_set_uuid,
                "rules",
            ],
            page,
            cancellation,
        )
        .await
    }
```

- [ ] **Step 4: Run and confirm PASS.** Sabotage: swap `profile_uuid` and `rule_set_uuid` in the `list_ecf_rules` segment array and confirm FAIL. Restore.

- [ ] **Step 5: Add the tools.** Append `"list_sdc_ecf_rule_sets", "list_sdc_ecf_rules",` to `KNOWN_TOOLS` after `"get_sdc_ips_exempt_rule",`. Arg structs:

```rust
/// Arguments for listing the rule sets of one enhanced content-filtering profile.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EcfRuleSetListArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Parent enhanced content-filtering profile UUID.
    pub profile_uuid: String,
    /// Zero-based offset.
    #[serde(default)]
    pub from: u64,
    /// Explicit positive page size.
    pub size: u32,
}

/// Arguments for listing the rules of one rule set.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EcfRuleListArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Parent enhanced content-filtering profile UUID.
    pub profile_uuid: String,
    /// Parent rule-set UUID.
    pub rule_set_uuid: String,
    /// Zero-based offset.
    #[serde(default)]
    pub from: u64,
    /// Explicit positive page size.
    pub size: u32,
}
```

Handlers:

```rust
    #[tool(
        name = "list_sdc_ecf_rule_sets",
        description = "List the rule sets of one enhanced content-filtering profile with bounded pagination."
    )]
    async fn list_sdc_ecf_rule_sets(
        &self,
        Parameters(args): Parameters<EcfRuleSetListArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "list_sdc_ecf_rule_sets",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) = self.authorize(caller, "list_sdc_ecf_rule_sets", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        let result = ListRequest::new(args.from, args.size, self.client.max_page_size())
            .map_err(SdcError::from);
        let result = match result {
            Ok(page) => {
                self.client
                    .list_ecf_rule_sets(&args.profile_uuid, page, &cancellation)
                    .await
            }
            Err(error) => Err(error),
        };
        Ok(finish(audit, result))
    }

    #[tool(
        name = "list_sdc_ecf_rules",
        description = "List the rules of one enhanced content-filtering rule set with bounded pagination."
    )]
    async fn list_sdc_ecf_rules(
        &self,
        Parameters(args): Parameters<EcfRuleListArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(caller, "list_sdc_ecf_rules", "read", vec![args.tenant.clone()]);
        if let Err(error) = self.authorize(caller, "list_sdc_ecf_rules", &args.tenant) {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        let result = ListRequest::new(args.from, args.size, self.client.max_page_size())
            .map_err(SdcError::from);
        let result = match result {
            Ok(page) => {
                self.client
                    .list_ecf_rules(&args.profile_uuid, &args.rule_set_uuid, page, &cancellation)
                    .await
            }
            Err(error) => Err(error),
        };
        Ok(finish(audit, result))
    }
```

Set the count to `62`, add `#156 added ECF rule-set and rule reads.` to the comment, and set the README to `**62 MCP tools**: 48 bounded read tools`.

- [ ] **Step 6: Run the full CI command.**
- [ ] **Step 7: Commit** `feat: read enhanced content-filtering rule sets and rules (#156)` plus the trailer, then run the Codex gate.

---

### Task 6: Global-settings singletons and device global settings (4 tools)

`catalog.rs` excluded these as "not boundable". They are bounded the same way `list_config_versions` already is: by `max_response_bytes`, which fails closed with `SdcError::ResponseTooLarge` and never truncates. `ListDeviceGlobalSettings` pages with **`offset`/`limit`**, not `from`/`size`, and takes an optional `device_id` filter.

**Files:** `client.rs`, `server.rs`, `tool_contract.rs` (62→66), `README.md` (reads 48→52)

**Interfaces:**
- Produces: `SdcClient::get_firewall_global_settings(&ct)`, `get_firewall_global_profile(&ct)`, `get_content_security_settings(&ct)`, `list_device_global_settings(device_id: Option<&str>, page, &ct)`, and `DeviceGlobalSettingsListArgs { tenant, device_id: Option<String>, from, size }`.

- [ ] **Step 1: Write the failing client tests**

```rust
    #[tokio::test]
    async fn singleton_reads_send_no_query_and_refuse_an_oversized_body() {
        let app = Router::new()
            .route(
                "/api/v1/firewall_global_settings",
                get(|Query(query): Query<HashMap<String, String>>| async move {
                    assert!(query.is_empty(), "singleton sent a query: {query:?}");
                    Json(serde_json::json!({"ok": "settings"}))
                }),
            )
            .route(
                "/api/v1/firewall_global_profiles",
                get(|| async { Json(serde_json::json!({"ok": "profile"})) }),
            )
            .route(
                "/api/v1/content_security_settings",
                get(|| async { Json(serde_json::json!({"padding": "x".repeat(512)})) }),
            );
        let (base_url, server) = serve(app).await;
        let ct = CancellationToken::new();
        let roomy = client(base_url.clone(), 4096);
        assert_eq!(roomy.get_firewall_global_settings(&ct).await.expect("settings")["ok"], "settings");
        assert_eq!(roomy.get_firewall_global_profile(&ct).await.expect("profile")["ok"], "profile");
        let tight = client(base_url, 64);
        assert!(matches!(
            tight.get_content_security_settings(&ct).await,
            Err(SdcError::ResponseTooLarge { limit: 64 })
        ));
        server.abort();
    }

    #[tokio::test]
    async fn device_global_settings_page_with_offset_and_limit() {
        let app = Router::new().route(
            "/api/v1/firewall_device_global_settings",
            get(|Query(query): Query<HashMap<String, String>>| async move {
                assert_eq!(query.get("offset").map(String::as_str), Some("2"));
                assert_eq!(query.get("limit").map(String::as_str), Some("5"));
                assert_eq!(query.get("device_id").map(String::as_str), Some("d1"));
                assert!(!query.contains_key("size"), "from/size vocabulary leaked: {query:?}");
                Json(serde_json::json!({"items": [], "count": 0}))
            }),
        );
        let (base_url, server) = serve(app).await;
        client(base_url, 4096)
            .list_device_global_settings(
                Some("d1"),
                ListRequest::new(2, 5, 100).expect("test page"),
                &CancellationToken::new(),
            )
            .await
            .expect("list succeeds");
        server.abort();
    }
```

- [ ] **Step 2: Run and confirm FAIL** with `cargo test -p rustsdcmcp-core --locked -- singleton_reads device_global_settings`. Expected: compile error.

- [ ] **Step 3: Implement**

```rust
    /// Fetch the tenant's firewall global settings (a singleton).
    ///
    /// No pagination exists; the response is bounded by `max_response_bytes`
    /// and refused, never truncated, above it.
    pub async fn get_firewall_global_settings(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        self.get(&["api", "v1", "firewall_global_settings"], &[], cancellation)
            .await
    }

    /// Fetch the tenant's firewall global profile (a singleton).
    pub async fn get_firewall_global_profile(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        self.get(&["api", "v1", "firewall_global_profiles"], &[], cancellation)
            .await
    }

    /// Fetch the tenant's content-security settings (a singleton).
    pub async fn get_content_security_settings(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        self.get(&["api", "v1", "content_security_settings"], &[], cancellation)
            .await
    }

    /// List per-device firewall global settings.
    ///
    /// Unlike the rest of `/api/v1/`, this endpoint pages with `offset` and
    /// `limit`. `device_id` narrows to one device when given.
    pub async fn list_device_global_settings(
        &self,
        device_id: Option<&str>,
        page: ListRequest,
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        let page = ListRequest::new(page.from, page.size, self.max_page_size)?;
        let offset = page.from.to_string();
        let limit = page.size.to_string();
        let mut query = vec![("offset", offset.as_str()), ("limit", limit.as_str())];
        if let Some(device_id) = device_id {
            validate_atom("device_id", device_id)?;
            query.push(("device_id", device_id));
        }
        self.get(
            &["api", "v1", "firewall_device_global_settings"],
            &query,
            cancellation,
        )
        .await
    }
```

- [ ] **Step 4: Run and confirm PASS.** Sabotage: rename `"limit"` to `"size"` and confirm FAIL. Restore.

- [ ] **Step 5: Add the tools.** Append `"get_sdc_firewall_global_settings", "get_sdc_firewall_global_profile", "get_sdc_content_security_settings", "list_sdc_device_global_settings",` to `KNOWN_TOOLS`. Arg struct:

```rust
/// Arguments for listing per-device firewall global settings.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceGlobalSettingsListArgs {
    /// Configured tenant alias.
    pub tenant: String,
    /// Optional device ID to narrow the list to one device.
    #[serde(default)]
    pub device_id: Option<String>,
    /// Zero-based offset (sent upstream as `offset`).
    #[serde(default)]
    pub from: u64,
    /// Explicit positive page size (sent upstream as `limit`).
    pub size: u32,
}
```

Handlers. The three singletons use `finish_redacted`: they are unobserved, and redaction is free.

```rust
    #[tool(
        name = "get_sdc_firewall_global_settings",
        description = "Get the tenant's firewall global settings. Refused, not truncated, above the response size cap."
    )]
    async fn get_sdc_firewall_global_settings(
        &self,
        Parameters(args): Parameters<TenantArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "get_sdc_firewall_global_settings",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) =
            self.authorize(caller, "get_sdc_firewall_global_settings", &args.tenant)
        {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish_redacted(
            audit,
            self.client.get_firewall_global_settings(&cancellation).await,
        ))
    }

    #[tool(
        name = "get_sdc_firewall_global_profile",
        description = "Get the tenant's firewall global profile. Refused, not truncated, above the response size cap."
    )]
    async fn get_sdc_firewall_global_profile(
        &self,
        Parameters(args): Parameters<TenantArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "get_sdc_firewall_global_profile",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) =
            self.authorize(caller, "get_sdc_firewall_global_profile", &args.tenant)
        {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish_redacted(
            audit,
            self.client.get_firewall_global_profile(&cancellation).await,
        ))
    }

    #[tool(
        name = "get_sdc_content_security_settings",
        description = "Get the tenant's content-security settings. Refused, not truncated, above the response size cap."
    )]
    async fn get_sdc_content_security_settings(
        &self,
        Parameters(args): Parameters<TenantArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "get_sdc_content_security_settings",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) =
            self.authorize(caller, "get_sdc_content_security_settings", &args.tenant)
        {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        Ok(finish_redacted(
            audit,
            self.client.get_content_security_settings(&cancellation).await,
        ))
    }

    #[tool(
        name = "list_sdc_device_global_settings",
        description = "List per-device firewall global settings with bounded pagination, optionally for one device."
    )]
    async fn list_sdc_device_global_settings(
        &self,
        Parameters(args): Parameters<DeviceGlobalSettingsListArgs>,
        extensions: Extensions,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<NoGrant>(&extensions);
        let mut audit = audit_scope(
            caller,
            "list_sdc_device_global_settings",
            "read",
            vec![args.tenant.clone()],
        );
        if let Err(error) =
            self.authorize(caller, "list_sdc_device_global_settings", &args.tenant)
        {
            audit.deny("scope");
            return Ok(tool_error(error));
        }
        let result = ListRequest::new(args.from, args.size, self.client.max_page_size())
            .map_err(SdcError::from);
        let result = match result {
            Ok(page) => {
                self.client
                    .list_device_global_settings(args.device_id.as_deref(), page, &cancellation)
                    .await
            }
            Err(error) => Err(error),
        };
        Ok(finish_redacted(audit, result))
    }
```

Set the count to `66`, add `#156 added three global-settings singletons and the device global-settings list.` to the comment, and set the README to `**66 MCP tools**: 52 bounded read tools`.

- [ ] **Step 6: Run the full CI command.**
- [ ] **Step 7: Commit** `feat: read global-settings singletons and device global settings (#156)` plus the trailer, then run the Codex gate.

---

### Task 7: Documentation, then live check

**Files:** `crates/rustsdcmcp-core/src/catalog.rs` (header lines 1–31), `CLAUDE.md`, `docs/sdc-api/README.md`, `CHANGELOG.md`

- [ ] **Step 1: Rewrite the `catalog.rs` header's two exclusion lists.** Keep the reasons, and add where each family is served now:

```rust
//! **Not expressible as a flat collection path** — served by bespoke tools:
//!
//! - `IPSRule`, `IPSExemptRule` — `/api/v1/ips_profiles/{profile_uuid}/ips_rules`
//!   and `…/exempt_rules`: `list_sdc_ips_rules`, `list_sdc_ips_exempt_rules`
//!   and their `get_` pairs
//! - `EnhancedContentFilteringProfileSet` — `…/{profile_uuid}/rule_sets` and
//!   `…/rule_sets/{rule_set_uuid}/rules`: `list_sdc_ecf_rule_sets`,
//!   `list_sdc_ecf_rules` (the spec has no single-rule-set GET)
//!
//! **Not pageable** — served by bespoke tools bounded by `max_response_bytes`,
//! which refuses rather than truncates:
//!
//! - `GlobalProfile`, `GlobalSettings`, `ContentSecuritySettings` — singletons:
//!   `get_sdc_firewall_global_profile`, `get_sdc_firewall_global_settings`,
//!   `get_sdc_content_security_settings`
//! - `DeviceGlobalSettings` — pages with `offset`/`limit`, not `from`/`size`:
//!   `list_sdc_device_global_settings`
```

- [ ] **Step 2: Add to `docs/sdc-api/README.md` under "Pagination, filtering, and result shaping":**

```markdown
- **`/api/v2/` lists page with `spec.from`/`spec.size`** (`ListTunnels`,
  `GetSiteList`). Unprefixed `from`/`size` are ignored upstream, so the list is
  bounded only by bytes. `GetIpsecProfileList` declares no page parameters at
  all. `ListDeviceGlobalSettings` is the one `/api/v1/` list that pages with
  `offset`/`limit`.
- **Credential fields in read responses.** `IcapServer` (`password_ascii`,
  `password_base64`) and v2 sites (`psk`, and `site_config` bodies that render
  IKE config) are redacted at the tool boundary by
  `rustsdcmcp_core::redact_secrets`.
```

- [ ] **Step 3: Add under `## Unreleased` in `CHANGELOG.md`:**

```markdown
### Security
- ICAP server passwords (`password_ascii`, `password_base64`) are redacted from
  `list_sdc_resources` / `get_sdc_resource`. The spec declares them; the lab
  tenant has not been checked for them.

### Fixed
- `list_sdc_tunnels` now sends `spec.from`/`spec.size`. The unprefixed
  parameters were ignored, so `size` did not bound the response.

### Added (#156)
- 12 read tools: `list/get_sdc_sites` (PSKs redacted), IPS rule and exempt-rule
  list/get, ECF rule-set and rule lists, three global-settings singletons, and
  `list_sdc_device_global_settings`.
- **Operators:** tokens minted with explicit tool lists do not gain these tools.
  Re-mint or widen scopes to use them.
```

- [ ] **Step 4: Run the full CI command, then commit** `docs: record #156 read families, v2 paging and redaction` plus the trailer. Run the Codex gate.

- [ ] **Step 5: Open the PR** with `Closes #156` and a "Not verified" section listing: tunnel paging (lab has no tunnels), site PSK redaction and ICAP redaction (no sites or ICAP servers seen on lab), and the untested redaction call sites.

- [ ] **Step 6: Live check after deploy to a test rig.** The test rigs are stopped by default. Start `test-labmode-sdc`, call every new tool once, and record which return data versus empty. Call `list_sdc_resources resource=icap_servers size=1`. If one exists, confirm both password fields read `[REDACTED]`. Stop the rig again.
