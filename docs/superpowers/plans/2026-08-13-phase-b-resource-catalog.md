# Phase B — Resource Catalog Split and Read Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make read coverage expandable without making writes expandable — split `ResourceKind` into a 27-family read catalog and a 4-family write catalog enforced by the compiler, then add the 23 new read families and a `fields` projection.

**Architecture:** `crates/rustsdcmcp-core/src/catalog.rs` gains a second enum, `WritableResource`, convertible into `ResourceKind` one way only. The type gate sits on `SdcClient::{create,update,delete}_resource` — the lowest level — so `object_write.rs`, `change.rs`, and `server.rs` inherit it rather than each re-asserting it. Read coverage then grows by adding enum variants and match arms, which cannot reach a write path.

**Tech Stack:** Rust edition 2024, MSRV 1.88, `serde`, `schemars` (JSON Schema for MCP tool args), `rmcp` (MCP handler macros), `wiremock` (mock SDC server in tests), `tokio`.

**Spec:** `docs/superpowers/specs/2026-08-13-phase-b-resource-catalog-design.md`

## Global Constraints

- Rust edition 2024, MSRV 1.88, toolchain pinned in `rust-toolchain.toml`.
- Workspace lints: `missing_docs = "warn"`, `unsafe_code = "forbid"`, `clippy::all` warn, `dbg_macro`/`todo` deny, `unwrap_used` warn. **Every public item needs a doc comment**, including every enum variant.
- **Never modify `~/Projects/mecmcp` from this repository.** File issues only.
- **Never restate an endpoint, header, or parameter from memory.** `docs/sdc-api/README.md` and the vendored OpenAPI document `docs/sdc-api/security-director-cloud-apis-openapi3.json` are the authority. Every collection path in this plan was extracted from that document and is reproduced verbatim below.
- **`docs/sdc-api/endpoints.md` is generated — never hand-edit it.**
- Mutating tools stay reachable only through the `mecmcp-changeset` plan → digest → approve → apply → verify lifecycle.
- **The write catalog stays at exactly four families.** No task in this plan adds a fifth.
- **No default `fields` projection is invented for any family.** When `fields` is empty the query parameter is omitted entirely.
- The verification gate is **four commands**, run at every commit:
  ```
  cargo fmt --all --check
  cargo clippy --workspace --all-targets -- -D warnings
  cargo test --workspace
  RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
  ```
  All four. A broken intra-doc link reached CI once because the last was omitted.
- Commit messages end with:
  ```
  Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
  ```

## Naming note for the implementer

The client method is `list_resource` (singular), not `list_resources`. The MCP tool is `list_sdc_resources` (plural). Both spellings are correct in their own layer; do not "fix" either.

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `crates/rustsdcmcp-core/src/catalog.rs` | Both capability enums, their path tables, and the invariant tests | Grows from 31 lines to hold two enums plus a `#[cfg(test)] mod tests` |
| `crates/rustsdcmcp-core/src/lib.rs` | Crate re-exports | Add `WritableResource` to the existing `pub use catalog::…` |
| `crates/rustsdcmcp-core/src/client.rs` | SDC REST client; holds the type gate | Three write signatures change type; `list_resource` gains a `fields` parameter |
| `crates/rustsdcmcp-core/src/object_write.rs` | Prepared object-write envelope and its transaction | `resource` field and constructor change type; two call sites gain `.into()` |
| `crates/rustsdcmcp-core/src/change.rs` | Change-manager adapter | `prepare_object_write`'s `resource` parameter changes type; one call site gains `.into()` |
| `crates/rustsdcmcp/src/server.rs` | MCP tool surface | Two args structs change `resource` type; one gains `fields`; two descriptions become general prose |
| `README.md`, `CHANGELOG.md`, `docs/sdc-api/README.md` | User-facing record | Coverage note, changelog entry, unverified-payload note |

`crates/rustsdcmcp/tests/tool_contract.rs` needs **no change**: it pins tool names and counts, and this plan changes neither. Do not edit it.

---

### Task 1: Split the catalog by capability

Introduce `WritableResource` and move the write path onto it. **No new read families in this task** — the read catalog still holds exactly the four it holds today. This task is about the type gate and nothing else, so a reviewer can judge the gate on its own.

**Files:**
- Modify: `crates/rustsdcmcp-core/src/catalog.rs`
- Modify: `crates/rustsdcmcp-core/src/lib.rs:18`
- Modify: `crates/rustsdcmcp-core/src/client.rs` (`create_resource`, `update_resource`, `delete_resource`)
- Modify: `crates/rustsdcmcp-core/src/object_write.rs` (struct field, `new`, `plan_artifact`, `resource()`, lines ~295 and ~389)
- Modify: `crates/rustsdcmcp-core/src/change.rs:340` and its `get_resource` call
- Modify: `crates/rustsdcmcp/src/server.rs:411` and `:538` and `:672`
- Test: `crates/rustsdcmcp-core/src/catalog.rs` (new `#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `pub enum WritableResource { Addresses, Applications, Services, Schedulers }` — derives `Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema`, with `#[serde(rename_all = "snake_case")]`.
  - `impl From<WritableResource> for ResourceKind`
  - `pub const ResourceKind::ALL: &'static [ResourceKind]`
  - `pub const WritableResource::ALL: &'static [WritableResource]`
  - `SdcClient::create_resource(&self, kind: WritableResource, body: &Value, cancellation: &CancellationToken)`
  - `SdcClient::update_resource(&self, kind: WritableResource, uuid: &str, body: &Value, cancellation: &CancellationToken)`
  - `SdcClient::delete_resource(&self, kind: WritableResource, uuid: &str, cancellation: &CancellationToken)`
  - `SdcPreparedObjectWrite::resource(&self) -> WritableResource`
  - `ChangeManager::prepare_object_write(…, resource: WritableResource, …)`

- [ ] **Step 1: Write the failing tests**

Append to `crates/rustsdcmcp-core/src/catalog.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::{ResourceKind, WritableResource};
    use serde_json::json;

    /// Every writable family must also be readable.
    ///
    /// The conversion is one-way by construction, but this pins that it
    /// resolves to the *same* collection — a write and its drift-detection
    /// read must never address different paths.
    #[test]
    fn every_writable_family_reads_from_the_same_collection() {
        for writable in WritableResource::ALL {
            let readable = ResourceKind::from(*writable);
            assert_eq!(
                writable.collection_segments(),
                readable.collection_segments(),
                "{writable:?} writes and reads different collections"
            );
        }
    }

    /// The write catalog is deliberately four families wide.
    ///
    /// Widening it is a decision, not a side effect of widening reads, so it
    /// must fail here first.
    #[test]
    fn the_write_catalog_stays_at_four_families() {
        assert_eq!(WritableResource::ALL.len(), 4);
    }

    /// `WritableResource` serialises identically to `ResourceKind`.
    ///
    /// `plan_artifact` embeds the resource in the digested plan, and prepared
    /// object writes are persisted in `changeset-state.json`. A different wire
    /// name would change every digest and orphan every persisted change set.
    #[test]
    fn the_two_catalogs_agree_on_wire_names() {
        for writable in WritableResource::ALL {
            let readable = ResourceKind::from(*writable);
            assert_eq!(
                json!(writable),
                json!(readable),
                "{writable:?} changed its serialised name"
            );
        }
        assert_eq!(json!(WritableResource::Addresses), json!("addresses"));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p rustsdcmcp-core catalog::tests`

Expected: FAIL to compile — `cannot find type WritableResource in this scope`.

- [ ] **Step 3: Add `WritableResource` and the conversion**

Replace the whole of `crates/rustsdcmcp-core/src/catalog.rs` above the test module with:

```rust
//! Allowlisted generic resource catalogs, split by capability.
//!
//! [`ResourceKind`] lists every family this server may **read**.
//! [`WritableResource`] lists the far smaller set it may also **write**, and
//! converts into [`ResourceKind`] one way only. Exposing a family for reading
//! therefore cannot expose it for writing: there is no
//! `TryFrom<ResourceKind> for WritableResource`, and no runtime `writable()`
//! predicate a call site could forget to consult.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Uniform SDC resource collections this server may read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    /// Address objects.
    Addresses,
    /// Application objects.
    Applications,
    /// Service objects.
    Services,
    /// Scheduler objects.
    Schedulers,
}

impl ResourceKind {
    /// Every readable family, for exhaustive iteration in tests and tooling.
    pub const ALL: &'static [Self] = &[
        Self::Addresses,
        Self::Applications,
        Self::Services,
        Self::Schedulers,
    ];

    /// Exact collection path segments from the pinned OpenAPI document.
    #[must_use]
    pub const fn collection_segments(self) -> &'static [&'static str] {
        match self {
            Self::Addresses => &["api", "v1", "addresses"],
            Self::Applications => &["api", "v1", "applications"],
            Self::Services => &["api", "v1", "services"],
            Self::Schedulers => &["api", "v1", "schedulers"],
        }
    }
}

/// SDC resource collections this server may create, update, and delete.
///
/// Deliberately far narrower than [`ResourceKind`]. A family belongs here only
/// once its write path has been exercised against a live tenant; SDC is a
/// management plane, so an unvalidated write can move policy across an estate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WritableResource {
    /// Address objects.
    Addresses,
    /// Application objects.
    Applications,
    /// Service objects.
    Services,
    /// Scheduler objects.
    Schedulers,
}

impl WritableResource {
    /// Every writable family, for exhaustive iteration in tests and tooling.
    pub const ALL: &'static [Self] = &[
        Self::Addresses,
        Self::Applications,
        Self::Services,
        Self::Schedulers,
    ];

    /// Exact collection path segments, delegated to the read catalog.
    ///
    /// Delegating keeps one table authoritative: a writable family cannot
    /// drift onto a different path from the read used to detect drift on it.
    #[must_use]
    pub const fn collection_segments(self) -> &'static [&'static str] {
        ResourceKind::from_writable(self).collection_segments()
    }
}

impl ResourceKind {
    /// Widen a writable family to its readable counterpart.
    ///
    /// A `const fn` because [`WritableResource::collection_segments`] is
    /// `const`; [`From`] is not usable in const context.
    #[must_use]
    pub const fn from_writable(resource: WritableResource) -> Self {
        match resource {
            WritableResource::Addresses => Self::Addresses,
            WritableResource::Applications => Self::Applications,
            WritableResource::Services => Self::Services,
            WritableResource::Schedulers => Self::Schedulers,
        }
    }
}

impl From<WritableResource> for ResourceKind {
    fn from(resource: WritableResource) -> Self {
        Self::from_writable(resource)
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p rustsdcmcp-core catalog::tests`

Expected: PASS, 3 tests.

- [ ] **Step 5: Re-export the new type**

In `crates/rustsdcmcp-core/src/lib.rs:18`, change:

```rust
pub use catalog::ResourceKind;
```

to:

```rust
pub use catalog::{ResourceKind, WritableResource};
```

- [ ] **Step 6: Move the three client write methods onto the narrow type**

In `crates/rustsdcmcp-core/src/client.rs`, change the `kind` parameter type on `create_resource`, `update_resource`, and `delete_resource` from `ResourceKind` to `WritableResource`. Their bodies already call `kind.collection_segments()`, which `WritableResource` now provides, so **no body changes are needed**.

Add `WritableResource` to the `use crate::{…}` import list at the top of the file (the list at `client.rs:8`).

Add this sentence to each of the three methods' doc comments, immediately after the existing summary line:

```rust
    /// Takes [`WritableResource`], not [`ResourceKind`]: adding a family to the
    /// read catalog must not make it writable.
```

- [ ] **Step 7: Update the prepared-write envelope**

In `crates/rustsdcmcp-core/src/object_write.rs`:

1. Add `WritableResource` to the `use crate::{…}` import at line 8 and drop `ResourceKind` from it if nothing else in the file uses it.
2. Change the struct field: `resource: ResourceKind` → `resource: WritableResource`.
3. Change `SdcPreparedObjectWrite::new`'s parameter: `resource: ResourceKind` → `resource: WritableResource`.
4. Change the accessor's return type: `pub const fn resource(&self) -> WritableResource`.
5. Change `plan_artifact`'s parameter: `resource: ResourceKind` → `resource: WritableResource`. Its body is unchanged — `json!` serialises the value, and Step 1's `the_two_catalogs_agree_on_wire_names` test pins that the serialisation is identical, so **existing plan digests do not change**.
6. At the `get_resource` call (around line 295), widen the argument:

```rust
            .get_resource(staged.resource().into(), uuid, &self.cancellation)
```

7. At line ~389, `let resource = staged.resource();` now yields a `WritableResource`, which is exactly what `create_resource`, `update_resource`, and `delete_resource` now want. Leave it.

- [ ] **Step 8: Update the change manager**

In `crates/rustsdcmcp-core/src/change.rs`:

1. Add `WritableResource` to the `use crate::{…}` import at line 5.
2. Change `prepare_object_write`'s parameter at line 340: `resource: ResourceKind` → `resource: WritableResource`.
3. In the same function, widen the drift-detection read:

```rust
                self.client
                    .get_resource(resource.into(), identifier, cancellation)
                    .await?
```

4. Leave the `SdcPreparedObjectWrite::new(action, resource, uuid, request, before)` call as-is — it now passes a `WritableResource` to a constructor that wants one.

`ResourceKind` is still used elsewhere in this file's tests; keep the import.

- [ ] **Step 9: Update the three write-tool args structs**

In `crates/rustsdcmcp/src/server.rs`:

1. Add `WritableResource` to the `use rustsdcmcp_core::{…}` import at line 21.
2. At line 411 (`ResourceListArgs`) — **leave this one as `ResourceKind`.** It is the read tool.
3. At line 538 and line 672, change `pub resource: ResourceKind` to `pub resource: WritableResource`. These are the prepare/apply object-write args.
4. Update those two fields' doc comments from `/// Allowlisted resource family.` to:

```rust
    /// Allowlisted **writable** resource family.
    ///
    /// Narrower than the read catalog: most readable families have no
    /// validated write path.
```

5. At line 534 (`ResourceArgs`, used by `get_sdc_resource`) — **leave as `ResourceKind`.** It is a read.

> If the compiler reports a `resource: ResourceKind` at a line number other than those listed, trust the compiler: read tools keep `ResourceKind`, `prepare_sdc_object_write` and `apply_sdc_object_write` take `WritableResource`.

- [ ] **Step 10: Fix the test call sites**

`cargo test --workspace` will report type mismatches in existing tests that pass `ResourceKind::Addresses` (and similar) to write methods — `client.rs` around lines 2144, 2166, 2185, 2204, 2238 and `change.rs` around lines 1833–1895. Change each of those **write-path** arguments to the `WritableResource` spelling, e.g. `ResourceKind::Addresses` → `WritableResource::Addresses`. Leave read-path arguments alone. Add `WritableResource` to each test module's `use` list.

- [ ] **Step 11: Run the full gate**

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
```

Expected: all four clean. If clippy flags `ResourceKind` as unused in a file, remove it from that file's import — do not add `#[allow]`.

- [ ] **Step 12: Commit**

```bash
git add crates/
git commit -m "refactor(catalog): split the resource catalog by capability

ResourceKind gated writes as well as reads, so adding a family to make it
readable made it writable in the same commit. WritableResource is the narrow
write catalog, convertible into ResourceKind one way only, and the gate sits
on SdcClient so object_write, change, and server inherit it.

Wire names are identical across both enums, so prepared object writes already
persisted in changeset-state.json deserialize unchanged and plan digests do
not move. A test pins that.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Add the 23 new read families

**Files:**
- Modify: `crates/rustsdcmcp-core/src/catalog.rs`
- Modify: `crates/rustsdcmcp/src/server.rs` (two tool descriptions)
- Test: `crates/rustsdcmcp-core/src/catalog.rs` (extend the `tests` module)
- Test: `crates/rustsdcmcp-core/src/client.rs` (extend the existing test module)

**Interfaces:**
- Consumes: `ResourceKind::ALL`, `ResourceKind::collection_segments`, `WritableResource::ALL` from Task 1.
- Produces: `ResourceKind` with 27 variants. No new functions.

Every path below was extracted from `docs/sdc-api/security-director-cloud-apis-openapi3.json`. Each variant name is chosen so that its `serde` snake_case name **is** its final path segment; Step 1's invariant test enforces that, which is what makes the table checkable rather than merely proofread.

- [ ] **Step 1: Write the failing tests**

Add to the `tests` module in `crates/rustsdcmcp-core/src/catalog.rs`:

```rust
    /// Every readable family's wire name is its own collection segment.
    ///
    /// The catalog is 27 hand-transcribed paths. This turns a transposed or
    /// misspelled path into a test failure instead of a 404 against a live
    /// tenant, because the variant name and the path are checked against each
    /// other rather than both against the author's memory.
    #[test]
    fn every_readable_family_is_named_after_its_collection() {
        for kind in ResourceKind::ALL {
            let segments = kind.collection_segments();
            assert_eq!(
                &segments[..2],
                &["api", "v1"],
                "{kind:?} is not a /api/v1/ collection"
            );
            assert_eq!(segments.len(), 3, "{kind:?} has an unexpected path depth");
            let wire = json!(kind);
            assert_eq!(
                wire.as_str(),
                Some(segments[2]),
                "{kind:?} serialises to {wire} but reads {}",
                segments[2]
            );
        }
    }

    /// `ALL` must not fall behind the enum.
    ///
    /// `schemars` derives the variant list from the type itself, so a variant
    /// added without a matching `ALL` entry fails here. Without this, the two
    /// invariant tests above would silently stop covering the new family --
    /// and the JSON schema is also the client-facing catalog, so the two must
    /// agree for discovery to work at all.
    #[test]
    fn all_covers_every_variant_of_both_catalogs() {
        // schemars 1 renders a unit-only enum as a `oneOf` of one-`const`
        // string subschemas, each carrying the serde-renamed variant name.
        fn schema_names(schema: &serde_json::Value) -> Vec<String> {
            schema["oneOf"]
                .as_array()
                .expect("unit enum renders as a oneOf")
                .iter()
                .map(|variant| {
                    variant["const"]
                        .as_str()
                        .expect("each variant is a const string")
                        .to_owned()
                })
                .collect()
        }

        let read = serde_json::to_value(schemars::schema_for!(ResourceKind))
            .expect("schema serialises");
        let listed: Vec<String> = ResourceKind::ALL
            .iter()
            .map(|kind| json!(kind).as_str().expect("string").to_owned())
            .collect();
        assert_eq!(schema_names(&read), listed);

        let write = serde_json::to_value(schemars::schema_for!(WritableResource))
            .expect("schema serialises");
        let listed: Vec<String> = WritableResource::ALL
            .iter()
            .map(|kind| json!(kind).as_str().expect("string").to_owned())
            .collect();
        assert_eq!(schema_names(&write), listed);
    }

    /// The read catalog covers the 27 uniform five-operation families.
    #[test]
    fn the_read_catalog_covers_twenty_seven_families() {
        assert_eq!(ResourceKind::ALL.len(), 27);
    }
```

> The `oneOf`/`const` shape above was verified against this workspace's `schemars = "1"` before the plan was written; it is not a guess. The comparison is order-sensitive, so keep `ALL` in the same order as the enum's variants.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p rustsdcmcp-core catalog::tests`

Expected: `the_read_catalog_covers_twenty_seven_families` FAILS with `assertion left == right failed: left: 4, right: 27`. The other two pass against the existing four.

- [ ] **Step 3: Add the 23 variants**

In `crates/rustsdcmcp-core/src/catalog.rs`, extend `ResourceKind` — keep the four existing variants first, then add these in the same order as `ALL`:

```rust
    /// Advanced anti-malware profiles.
    AamwProfiles,
    /// Anti-spam profiles.
    AntiSpamProfiles,
    /// Anti-virus profiles.
    AntiVirusProfiles,
    /// Content-filtering profiles.
    ContentFilteringProfiles,
    /// Content-security profiles.
    ContentSecurityProfiles,
    /// Enhanced content-filtering profiles.
    EnhancedContentFilteringProfiles,
    /// Flow-based antivirus profiles.
    FlowBasedAntivirusProfiles,
    /// ICAP profiles.
    IcapProfiles,
    /// ICAP servers.
    IcapServers,
    /// Identity objects.
    IdentityObjects,
    /// IPS profiles.
    IpsProfiles,
    /// Proxy servers.
    ProxyServers,
    /// Redirect profiles.
    RedirectProfiles,
    /// Rule options, referenced by `options.logging` and `options.counter`.
    RuleOptions,
    /// Security-intelligence profiles.
    SecintelProfiles,
    /// Security-intelligence profile groups.
    SecintelProfilesGroups,
    /// SSL initiation profiles.
    SslInitiations,
    /// SSL proxy profiles.
    SslProxyProfiles,
    /// Secure web proxy profiles.
    SwpProfiles,
    /// URL category lists.
    UrlCategoryLists,
    /// URL patterns.
    UrlPatterns,
    /// Variable zones, referenced by `ZoneReference.managed_variable`.
    VariableZones,
    /// Web-filtering profiles.
    WebFilteringProfiles,
```

Extend `ResourceKind::ALL` with the same 23 in the same order:

```rust
        Self::AamwProfiles,
        Self::AntiSpamProfiles,
        Self::AntiVirusProfiles,
        Self::ContentFilteringProfiles,
        Self::ContentSecurityProfiles,
        Self::EnhancedContentFilteringProfiles,
        Self::FlowBasedAntivirusProfiles,
        Self::IcapProfiles,
        Self::IcapServers,
        Self::IdentityObjects,
        Self::IpsProfiles,
        Self::ProxyServers,
        Self::RedirectProfiles,
        Self::RuleOptions,
        Self::SecintelProfiles,
        Self::SecintelProfilesGroups,
        Self::SslInitiations,
        Self::SslProxyProfiles,
        Self::SwpProfiles,
        Self::UrlCategoryLists,
        Self::UrlPatterns,
        Self::VariableZones,
        Self::WebFilteringProfiles,
```

Extend `collection_segments`'s match with the same 23 arms:

```rust
            Self::AamwProfiles => &["api", "v1", "aamw_profiles"],
            Self::AntiSpamProfiles => &["api", "v1", "anti_spam_profiles"],
            Self::AntiVirusProfiles => &["api", "v1", "anti_virus_profiles"],
            Self::ContentFilteringProfiles => &["api", "v1", "content_filtering_profiles"],
            Self::ContentSecurityProfiles => &["api", "v1", "content_security_profiles"],
            Self::EnhancedContentFilteringProfiles => {
                &["api", "v1", "enhanced_content_filtering_profiles"]
            }
            Self::FlowBasedAntivirusProfiles => &["api", "v1", "flow_based_antivirus_profiles"],
            Self::IcapProfiles => &["api", "v1", "icap_profiles"],
            Self::IcapServers => &["api", "v1", "icap_servers"],
            Self::IdentityObjects => &["api", "v1", "identity_objects"],
            Self::IpsProfiles => &["api", "v1", "ips_profiles"],
            Self::ProxyServers => &["api", "v1", "proxy_servers"],
            Self::RedirectProfiles => &["api", "v1", "redirect_profiles"],
            Self::RuleOptions => &["api", "v1", "rule_options"],
            Self::SecintelProfiles => &["api", "v1", "secintel_profiles"],
            Self::SecintelProfilesGroups => &["api", "v1", "secintel_profiles_groups"],
            Self::SslInitiations => &["api", "v1", "ssl_initiations"],
            Self::SslProxyProfiles => &["api", "v1", "ssl_proxy_profiles"],
            Self::SwpProfiles => &["api", "v1", "swp_profiles"],
            Self::UrlCategoryLists => &["api", "v1", "url_category_lists"],
            Self::UrlPatterns => &["api", "v1", "url_patterns"],
            Self::VariableZones => &["api", "v1", "variable_zones"],
            Self::WebFilteringProfiles => &["api", "v1", "web_filtering_profiles"],
```

Finally, extend the module doc comment at the top of the file with a note on what is deliberately absent:

```rust
//!
//! Five families with the same five-operation shape are deliberately absent.
//! `IPSRule` and `IPSExemptRule` nest under
//! `/api/v1/ips_profiles/{profile_uuid}/…`, which a `&'static [&'static str]`
//! cannot express; `NAT Pools` is keyed by `pool_id` and has bespoke tools;
//! `Device Groups` has bespoke tools; and `DeviceGlobalSettings` supports
//! neither `from` nor `fields`, so it cannot be bounded like the rest.
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p rustsdcmcp-core catalog::tests`

Expected: PASS, 6 tests. If `every_readable_family_is_named_after_its_collection` fails, the failure message names the variant and both spellings — fix the path or the variant name so they agree, taking the path from the vendored spec.

- [ ] **Step 5: Write a dispatch test**

A path table that agrees with itself still has to reach the wire. Add to the existing test module in `crates/rustsdcmcp-core/src/client.rs`, following the shape of the tests already there:

```rust
    /// A new family's list reaches its own collection path.
    ///
    /// The catalog's self-consistency tests prove the table agrees with itself.
    /// This proves the table is what the client actually requests.
    #[tokio::test]
    async fn a_new_family_lists_from_its_own_collection() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/rule_options"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"items": []})))
            .expect(1)
            .mount(&server)
            .await;

        let client = test_client(&server).await;
        let listed = client
            .list_resource(
                ResourceKind::RuleOptions,
                ListRequest::new(0, 10, 200).expect("page"),
                &CancellationToken::new(),
            )
            .await
            .expect("list succeeds");

        assert_eq!(listed["items"], json!([]));
    }
```

> This calls `list_resource` with **three** arguments, which is its signature today. Task 3 adds a `fields` parameter and updates this call site to pass `&[]`. Do not anticipate that change here — Task 2 must compile and pass on its own.
>
> Match the surrounding tests for how the client is constructed and which `use` items are in scope — `test_client`, `MockServer`, `Mock`, `method`, `path`, `ResponseTemplate`, `ListRequest`, `CancellationToken`, and `json!` all already appear in that module. Reuse the existing helper rather than writing a new one.

- [ ] **Step 6: Run the dispatch test**

Run: `cargo test -p rustsdcmcp-core a_new_family_lists_from_its_own_collection`

Expected: PASS.

- [ ] **Step 7: Generalise the two read-tool descriptions**

In `crates/rustsdcmcp/src/server.rs`, the descriptions enumerate four families and no longer can. Change line 1729 from:

```rust
        description = "List an allowlisted SDC address, application, service, or scheduler collection."
```

to:

```rust
        description = "List one allowlisted SDC resource collection. The `resource` enum in this schema is the catalog of available families."
```

And line 1763 from:

```rust
        description = "Get one allowlisted SDC address, application, service, or scheduler object."
```

to:

```rust
        description = "Get one object from an allowlisted SDC resource collection by UUID. The `resource` enum in this schema is the catalog of available families."
```

Leave `prepare_sdc_object_write`'s description at line 2135 enumerating the four families — that tool really does accept only those four, and naming them is now the accurate thing to do rather than the lazy thing.

- [ ] **Step 8: Run the full gate**

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
```

Expected: all four clean.

- [ ] **Step 9: Commit**

```bash
git add crates/
git commit -m "feat(catalog): add 23 read-only resource families

Every uniform five-operation family in the pinned spec that was not already
covered: /api/v1 collections keyed by uuid with from/size/fields. The write
catalog is unchanged at four, which the split in the previous commit makes a
type error rather than a discipline.

Each variant is named so its serde name is its own collection segment, and a
test pins that, so a transposed path fails the suite instead of 404-ing.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Project the generic list reader with `fields`

Profile families embed rule and pattern lists. `size` bounds how many objects come back, not how large each is, so an estate-scale profile list can exceed `max_response_bytes` even at `size=1` — which refuses the read rather than truncating it. `fields` is the API's own remedy, and `list_projected` already implements it for device groups.

**Files:**
- Modify: `crates/rustsdcmcp-core/src/client.rs` (`list_resource`)
- Modify: `crates/rustsdcmcp/src/server.rs` (`ResourceListArgs`, `list_sdc_resources`)
- Test: `crates/rustsdcmcp-core/src/client.rs`

**Interfaces:**
- Consumes: `ResourceKind` (27 variants) from Task 2; the private `SdcClient::list_projected(&self, segments: &[&str], page: ListRequest, fields: &[String], cancellation: &CancellationToken)` at `client.rs:1466`.
- Produces: `SdcClient::list_resource(&self, kind: ResourceKind, page: ListRequest, fields: &[String], cancellation: &CancellationToken) -> Result<Value, SdcError>` and a `fields: Vec<String>` field on `ResourceListArgs`.

- [ ] **Step 1: Write the failing test**

Add to the test module in `crates/rustsdcmcp-core/src/client.rs`:

```rust
    /// The generic reader projects with an exploded `fields` array, and omits
    /// the parameter entirely when no projection is asked for.
    ///
    /// The spec declares `fields` as `style: form, explode: true`, so
    /// `fields=uuid&fields=name` is the request and one comma-joined value
    /// would read as a single unknown field name. Omitting it when empty
    /// matters just as much: no default projection is invented for any
    /// family, because field names belong to the API and guessing them
    /// silently drops data.
    #[tokio::test]
    async fn a_resource_list_can_project_fields_and_omits_the_param_otherwise() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/ips_profiles"))
            .respond_with(|request: &wiremock::Request| {
                let collected: Vec<String> = request
                    .url
                    .query_pairs()
                    .filter(|(key, _)| key == "fields")
                    .map(|(_, value)| value.into_owned())
                    .collect();
                ResponseTemplate::new(200).set_body_json(json!({ "fields": collected }))
            })
            .expect(2)
            .mount(&server)
            .await;

        let client = test_client(&server).await;

        let projected = client
            .list_resource(
                ResourceKind::IpsProfiles,
                ListRequest::new(0, 10, 200).expect("page"),
                &["uuid".to_owned(), "name".to_owned()],
                &CancellationToken::new(),
            )
            .await
            .expect("projected list succeeds");
        assert_eq!(projected["fields"], json!(["uuid", "name"]));

        let unprojected = client
            .list_resource(
                ResourceKind::IpsProfiles,
                ListRequest::new(0, 10, 200).expect("page"),
                &[],
                &CancellationToken::new(),
            )
            .await
            .expect("unprojected list succeeds");
        assert_eq!(unprojected["fields"], json!([]));
    }
```

> Match how `a_device_group_list_can_project_fields_and_omits_the_param_otherwise` (around `client.rs:2341`) reads the query string — reuse its technique verbatim rather than the sketch above if it differs. That test is known to work against this mock setup.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p rustsdcmcp-core a_resource_list_can_project_fields`

Expected: FAIL to compile — `list_resource` takes 3 arguments, 4 supplied.

- [ ] **Step 3: Route `list_resource` through `list_projected`**

In `crates/rustsdcmcp-core/src/client.rs`, replace `list_resource` with:

```rust
    /// List one allowlisted generic resource family.
    ///
    /// `size` bounds how many objects come back, not how large each one is,
    /// and profile families embed rule and pattern lists. Pass `fields` to
    /// apply the API's server-side projection; pass an empty slice to omit the
    /// parameter entirely. No default projection is invented — field names
    /// belong to the API, and guessing them silently drops data.
    pub async fn list_resource(
        &self,
        kind: ResourceKind,
        page: ListRequest,
        fields: &[String],
        cancellation: &CancellationToken,
    ) -> Result<Value, SdcError> {
        self.list_projected(kind.collection_segments(), page, fields, cancellation)
            .await
    }
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p rustsdcmcp-core a_resource_list_can_project_fields`

Expected: PASS.

- [ ] **Step 5: Expose `fields` on the tool**

In `crates/rustsdcmcp/src/server.rs`, add to `ResourceListArgs` (line 407), after `size`:

```rust
    /// Optional `fields` projection applied by the API, one entry per field.
    ///
    /// `size` bounds the number of objects, not the size of each one, and
    /// profile families embed rule and pattern lists. Projecting keeps an
    /// estate-scale list readable.
    #[serde(default)]
    pub fields: Vec<String>,
```

Then in `list_sdc_resources`, pass it through:

```rust
                self.client
                    .list_resource(args.resource, page, &args.fields, &cancellation)
                    .await
```

- [ ] **Step 6: Run the full gate**

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
```

Expected: all four clean. Every other call site of `list_resource` needs the new argument: `list_sdc_resources` in `server.rs` gets `&args.fields` (Step 5), and the test added in Task 2, `a_new_family_lists_from_its_own_collection`, gets `&[]` inserted before its `&CancellationToken::new()`.

- [ ] **Step 7: Commit**

```bash
git add crates/
git commit -m "feat(catalog): project the generic resource list with fields

Profile families embed rule and pattern lists, so size bounds the number of
objects and not the size of each. list_resource now routes through
list_projected, the same path device groups established, and the parameter is
omitted entirely when no projection is asked for.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Record what is and is not verified

Read coverage is not validated coverage, and the difference must be written down before anyone reads the changelog and assumes otherwise.

**Files:**
- Modify: `CHANGELOG.md` (the `## Unreleased` section)
- Modify: `docs/sdc-api/README.md` (the "Still unverified" list at the end)

- [ ] **Step 1: Add the changelog entry**

Under `## Unreleased` in `CHANGELOG.md`, add:

```markdown
### Added

- 23 read-only resource families on the generic `list_sdc_resources` /
  `get_sdc_resource` pair, covering every uniform five-operation collection in
  the pinned spec that was not already exposed: AAMW, anti-spam, anti-virus,
  content-filtering, content-security, enhanced content-filtering, flow-based
  antivirus, ICAP profiles and servers, identity objects, IPS profiles, proxy
  servers, redirect profiles, rule options, SecIntel profiles and groups, SSL
  initiations, SSL proxy profiles, SWP profiles, URL category lists, URL
  patterns, variable zones, and web-filtering profiles.
- A `fields` projection on `list_sdc_resources`, matching `list_device_groups`.
  Profile families embed rule and pattern lists, so `size` alone does not bound
  the response.

### Changed

- The resource catalog is split by capability. `ResourceKind` is the read
  catalog; the new `WritableResource` is the write catalog and still holds
  exactly four families. The conversion goes one way only, and the gate sits on
  `SdcClient`, so adding a readable family cannot compile into a writable one.

### Notes

- **No token re-mint is required.** No tool was added, removed, or renamed, so
  an existing scoped token still matches the surface. This is unlike the last
  three releases, where new tools were invisible to tokens minted earlier.
- The new families are verified for **authentication and dispatch only**. The
  lab tenant holds no security-profile objects, so no live response payload has
  been observed for any of the 23. Payload shape stays unverified.
```

- [ ] **Step 2: Add the unverified note**

Append to the "Still unverified" list at the end of `docs/sdc-api/README.md`:

```markdown
- **Response payload shape for the 23 generic read families** added in Phase B
  (security profiles, URL objects, proxy and ICAP servers, rule options,
  variable zones). Their collection paths, `uuid` keying, and
  `from`/`size`/`fields` support are read from the spec; their *responses* have
  not been observed, because the lab tenant holds no objects in any of them.
  Auth and dispatch are confirmed live; payload shape is not.
```

- [ ] **Step 3: Run the gate**

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
```

Expected: all four clean — no code changed, but the gate is cheap and this is the last commit before review.

- [ ] **Step 4: Commit**

```bash
git add CHANGELOG.md docs/sdc-api/README.md
git commit -m "docs: record Phase B coverage and its verification limits

The 23 new families are verified for auth and dispatch only — the lab tenant
holds no security-profile objects, so no response payload has been observed.
Says so in both the changelog and the spec's unverified list rather than
letting the coverage number imply more.

Also records that this release needs no token re-mint, unlike the last three.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## After the plan

Live verification is **not** a task in this plan — it needs a deployed build and the repo's release path, not a code change. Once the branch merges, the sequence is the standing one: build via CI artifact (never a local build — glibc), deploy to 606, smoke `rule_options` and `variable_zones`, then 951.

The expected live result is an empty collection with a 200. That confirms auth, tenant scoping, and path dispatch. It does not confirm payload shape, and the changelog already says so.
