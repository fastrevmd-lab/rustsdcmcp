# Phase B — split the resource catalog by capability, then widen the reads

Date: 2026-08-13

Supersedes the Phase B section of
`2026-08-12-completion-plan-design.md`, which set the direction before the
spec had been surveyed. The direction holds; the scope is now measured
rather than estimated.

## Why this exists

`v0.1.0-lab.7` covers 52 tools against an API of 368 operations. The
uncovered mass is not 368 distinct problems — it is one shape repeated. The
generic `list_sdc_resources` / `get_sdc_resource` pair plus `ResourceKind`
already absorbs that shape for four families, so widening read coverage is
one enum variant and one match arm per family.

The obstacle is that `ResourceKind` gates writes as well as reads.
`prepare_sdc_object_write` takes `resource: ResourceKind`
(`server.rs:411`, `:538`, `:672`), so adding a family to make it *readable*
makes it *writable* in the same commit. Extending the catalog naively would
expose create, update, and delete for 23 families never validated against a
live tenant, on a management plane. That is the #61 defect at 23× scale.

Phase B therefore does the refactor first and the coverage second.

## What the spec actually says

Measured from the vendored OpenAPI document, not estimated:

- **32** tag groups have the five-operation shape with both a collection and
  an item endpoint. All are `/api/v1`; none are `/api/v2`.
- **27** of those are uniform: `/api/v1/<collection>`, `uuid` item
  parameter, `from`/`size`/`fields` on the collection.
- **4** of the 27 are already implemented, leaving **23** new.

The five excluded groups are excluded for stated reasons, not by preference:

| Group | Why excluded |
|---|---|
| `IPSRule`, `IPSExemptRule` | Nested under `/api/v1/ips_profiles/{profile_uuid}/…`. The collection path itself takes a parameter, which `collection_segments() -> &'static [&'static str]` cannot express. Including them would change the catalog's shape for all 27 to serve 2. |
| `NAT Pools` | Item parameter is `pool_id`, not `uuid`; already has bespoke tools. |
| `Device Groups` | Already has bespoke tools, including the `fields` projection this phase generalises. |
| `DeviceGlobalSettings` | No `from` and no `fields` — an unbounded collection, like `ListConfigVersions`. |

Each is a genuinely different shape and is cheap to handle on its own terms
later. None is blocked by this work.

## Architecture

### The split

`crates/rustsdcmcp-core/src/catalog.rs` gains a second enum:

```rust
pub enum ResourceKind { /* 27 readable families */ }

pub enum WritableResource { Addresses, Applications, Services, Schedulers }

impl From<WritableResource> for ResourceKind { … }
```

The conversion goes one way only. There is no `TryFrom<ResourceKind>`, and
no runtime `writable()` predicate — a missed call to such a predicate
reintroduces exactly the bug this phase exists to prevent, and there would
be 23 opportunities to miss it. The compiler enforces it instead.

`ResourceKind` keeps its name because it keeps its meaning: the catalog of
resources this server may read. `WritableResource` is the narrow type, and
is the one that has to justify each entry.

### Where the gate sits

On `SdcClient`, not on the tool handlers:

```rust
impl SdcClient {
    pub async fn list_resources(&self, kind: ResourceKind, …)
    pub async fn get_resource(&self, kind: ResourceKind, …)

    pub async fn create_resource(&self, kind: WritableResource, …)
    pub async fn update_resource(&self, kind: WritableResource, …)
    pub async fn delete_resource(&self, kind: WritableResource, …)
}
```

`object_write.rs`, `change.rs`, and `server.rs` then inherit the guarantee
rather than each re-asserting it. No code path can reach an SDC write for a
family outside the write catalog, and no future edit has to remember the
rule — adding a read family cannot compile into a write.

`SdcPreparedObjectWrite::resource` and `ChangeManager::prepare_object_write`
change to `WritableResource` accordingly.

### Compatibility

This phase requires **no token re-mint**, unlike the last three releases:

- Variant names are unchanged snake_case, so prepared object writes already
  persisted in `changeset-state.json` deserialize unchanged.
- The read enum grows into a strict superset, so existing
  `list_sdc_resources` calls keep working.
- The write enum's four variants are exactly today's four, so existing
  `prepare_sdc_object_write` calls keep working.
- No tool is added, removed, or renamed, so the 52-name allowlist carried by
  every minted token still matches the surface.

The release notes say this explicitly. A scoped token minted against an
earlier surface silently cannot see new tools, and readers have learned to
expect that consequence from recent releases.

## The 23 new families

All `/api/v1/<collection>`, all `uuid`-keyed, all supporting
`from`/`size`/`fields`. Paths are taken from the vendored spec.

| Variant | Collection path |
|---|---|
| `AamwProfiles` | `/api/v1/aamw_profiles` |
| `AntiSpamProfiles` | `/api/v1/anti_spam_profiles` |
| `AntiVirusProfiles` | `/api/v1/anti_virus_profiles` |
| `ContentFilteringProfiles` | `/api/v1/content_filtering_profiles` |
| `ContentSecurityProfiles` | `/api/v1/content_security_profiles` |
| `EnhancedContentFilteringProfiles` | `/api/v1/enhanced_content_filtering_profiles` |
| `FlowBasedAntivirusProfiles` | `/api/v1/flow_based_antivirus_profiles` |
| `IcapProfiles` | `/api/v1/icap_profiles` |
| `IcapServers` | `/api/v1/icap_servers` |
| `IdentityObjects` | `/api/v1/identity_objects` |
| `IpsProfiles` | `/api/v1/ips_profiles` |
| `ProxyServers` | `/api/v1/proxy_servers` |
| `RedirectProfiles` | `/api/v1/redirect_profiles` |
| `RuleOptions` | `/api/v1/rule_options` |
| `SecintelProfiles` | `/api/v1/secintel_profiles` |
| `SecintelProfilesGroups` | `/api/v1/secintel_profiles_groups` |
| `SslInitiations` | `/api/v1/ssl_initiations` |
| `SslProxyProfiles` | `/api/v1/ssl_proxy_profiles` |
| `SwpProfiles` | `/api/v1/swp_profiles` |
| `UrlCategoryLists` | `/api/v1/url_category_lists` |
| `UrlPatterns` | `/api/v1/url_patterns` |
| `VariableZones` | `/api/v1/variable_zones` |
| `WebFilteringProfiles` | `/api/v1/web_filtering_profiles` |

`RuleOptions` and `VariableZones` are the two #31 named as priorities, since
`options.logging` / `options.counter` and `ZoneReference.managed_variable`
make them reachable from rules this server already reads. They are in the
same commit as the rest — the ordering mattered when the families were going
to be split across releases, and they no longer are.

### Naming is load-bearing

Every variant is named so that its serde name **is** its final path segment.
`SslProxyProfiles` serialises to `ssl_proxy_profiles`, which is the
collection. That converts the transcription step into a checkable invariant
(see Testing). Variant names are also the client-facing catalog, so they
must read as the family a client is looking for.

## Discovery

The generic tools' descriptions currently enumerate the four families
("address, application, service, or scheduler"). At 27 that becomes prose:
the tool lists an allowlisted SDC resource collection, and the `kind`
parameter's enum in the JSON schema is the list.

No `list_sdc_resource_kinds` tool. Every MCP client renders the schema, the
variant names are self-describing, and a second list would be one more thing
to drift from the enum with nothing to catch it.

## `fields` projection

`SdcClient::list_projected` (`client.rs:1470`) is already generic over path
segments — device groups established both that `size` bounds the number of
objects and not the size of each, and that `fields` is an exploded array
(`fields=uuid&fields=name`), not a comma-joined value.

`list_resources` routes through `list_projected`, and `list_sdc_resources`
gains an optional `fields: Vec<String>`. Profile families embed rule and
pattern lists, so the bound matters more here than it did for objects.

`get_sdc_resource` is unchanged: the item endpoints declare `uuid` as their
only parameter and do not accept `fields`, verified in the spec for both
`/api/v1/addresses/{uuid}` and `/api/v1/ips_profiles/{uuid}`. Only the
collection reader is projected.

**No default projection is invented for any family.** Field names belong to
the API, and guessing them silently drops data. When `fields` is absent the
parameter is omitted entirely, exactly as `list_device_groups` does.

The existing `max_response_bytes` cap remains the backstop, and it fails
closed rather than truncating.

## Testing

- **Write-catalog invariant.** For every `WritableResource`, the converted
  `ResourceKind` resolves to the same collection path. Exhaustive over the
  enum, so a new write family with no read counterpart fails the suite.
- **Name/path invariant.** For all 27 `ResourceKind` variants, the serde name
  equals the last element of `collection_segments()`, and the first two
  elements are `["api", "v1"]`. A transposed path fails the suite instead of
  404-ing against a live tenant.
- **Dispatch.** Mock-server tests that a `list_sdc_resources` call for a new
  family reaches the expected path.
- **Projection.** A mock-server test that `fields` explodes correctly on the
  generic reader and is omitted when empty — the shape
  `a_device_group_list_can_project_fields_and_omits_the_param_otherwise`
  already pins for device groups.
- **Tool contract.** Re-pinned. The tool *count* does not change; the `kind`
  enum in the schema does.

## Live verification

`vsrx-ci` (VMID 907, pve2, tagged `ci`) is the SDC test device. Deploy 606
first, then 951.

The tenant has no security-profile objects, so a live read of
`rule_options` and `variable_zones` proves **authentication, dispatch, and
an empty-collection response** — not payload shape. The spec and any release
note say that in those words rather than implying broader coverage. Payload
shape for the profile families stays unverified until objects exist, and
belongs on the "Still unverified" list in `docs/sdc-api/README.md`.

## Risks

| Risk | Mitigation |
|---|---|
| Catalog expansion silently exposes writes | The gate is a type on `SdcClient`; an exhaustive test pins that every write kind has a read counterpart |
| A collection path is transcribed wrong | The name/path invariant test, plus paths taken from the vendored spec rather than memory |
| Profile list responses exceed `max_response_bytes` | `fields` on the generic reader; the existing cap fails closed |
| Read coverage is mistaken for validated coverage | Live verification claims are stated as auth-and-dispatch only, and the unverified list is updated |
| The excluded five look like oversights | Each is named above with the reason, so the next reader does not rediscover them |

## Explicitly out of scope

- Writes for any of the 23 new families. The write catalog stays at four.
- The two nested IPS rule families, NAT pools, device groups, and
  `DeviceGlobalSettings`.
- #55, #21's rollback write, #33's template tools, #34's remainder.

## Verification gate

`cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D
warnings`, `cargo test --workspace`, and `RUSTDOCFLAGS="-D warnings" cargo
doc --workspace --no-deps --locked` at every commit. All four — a broken
intra-doc link reached CI once because the last was omitted.
