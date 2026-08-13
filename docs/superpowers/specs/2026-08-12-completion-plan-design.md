# Getting the server substantially more complete

Date: 2026-08-12

## Why this exists

`v0.1.0-lab.6` ships 50 tools — 39 reads and 11 change-control tools — against
an API of 368 operations. Eight issues are open: four defects in the
change-control surface (#66, #63, #61, #55) and four coverage epics (#21, #33,
#31, #34).

The obvious reading is that the defects are small and the coverage epics are
large. The opposite is closer to true, and this document explains why, then
sequences the work accordingly.

## Two facts that reframe the work

### The uncovered mass is one shape repeated, not many problems

#31 alone is roughly 110 operations across about 22 families — `IpsProfile`,
`WebFilteringProfile`, `AntiVirusProfile`, `SSLProxyProfile`, `IcapProfile`, and
so on. Every one of them is the same list/get/create/update/delete.

The pattern is broader than #31. Of the 61 groups in
`docs/sdc-api/endpoints.md`, **36 are exactly five operations** — the same
list/get/create/update/delete. Whatever absorbs #31 absorbs most of the rest of
the API too.

### The repository already has the mechanism to absorb them

`ResourceKind` in `crates/rustsdcmcp-core/src/catalog.rs` plus the generic
`list_sdc_resources` and `get_sdc_resource` tools already cover address,
application, service, and scheduler. `client.rs:591` dispatches purely off
`ResourceKind::collection_segments()`.

Adding a family is **one enum variant and one match arm**. No new tool, no new
handler. Read coverage can therefore expand by a large multiple while the tool
count stays flat, which satisfies CLAUDE.md's "read-only tools land first and
stay the majority" without any special effort.

So the expensive-looking epic is the cheap one.

## The constraint that makes the cheap thing dangerous

**`ResourceKind` gates writes as well as reads.**

`prepare_sdc_object_write` and `apply_sdc_object_write` both take
`resource: ResourceKind` (`server.rs:408`, `:535`, `:656`), and
`object_write.rs` stores it on the prepared change. Adding a family to the
catalog to make it *readable* therefore makes it *writable* in the same commit.

Extending the catalog naively across #31 would expose create, update, and delete
for ~22 security-profile families, none of them validated against a live tenant,
on a management plane, while #66 is open.

That is precisely the defect recorded in #61 — a target type accepted locally
that the API does not support — at twenty-two times the scale. It is also the
same shape as mecmcp#94 and #63: a capability that is reachable when it should
not be.

The fix is to make it a type error rather than a runtime check.

## Phase A — make change control mean what it says

Reads are unaffected by #66. Every **write** tool inherits it, so the write
surface should not grow until the preview question is settled.

### A1. Answer #66 before designing a mitigation

This server requests the CLI preview. `PreviewTemplate` accepts a `format`, and
the spec documents an XML form. A single call asks whether the XML preview
discloses the `feed-server` that the CLI preview omitted.

**This must run before any mitigation is designed.** If XML is complete, the fix
is to request XML and the problem largely disappears; building discrepancy
detection first would be work done against a question nobody asked.

Also open, and answerable on the same lab device in minutes:

- Is the omission specific to a parent object orphaned by the removal of its
  consumer, or does it generalise?
- Did #23's deploy also under-report, unnoticed because the deletions were
  expected?

Record the answers in `docs/sdc-api/README.md` §11.

### A2. Mitigate according to A1

One of:

- **XML is complete** — request it, and treat the CLI form as a display
  convenience.
- **Both under-report** — compare the two at prepare time and surface a
  discrepancy, or capture a device-side `compare rollback` after apply and
  report divergence from the preview.

Either way, `prepare_sdc_policy_deploy`'s description and `docs/operations.md`
state that a preview is a lower bound until proven otherwise. That costs nothing
and should land regardless of which branch A1 selects.

### A3. Expose operation discard (#63)

`mecmcp-changeset::discard_operation` exists
(`crates/mecmcp-changeset/src/operation.rs:719`) and no tool reaches it, so a
single failed deploy blocks every later apply on the tenant until someone edits
`changeset-state.json` by hand. Observed twice on 2026-08-12.

Constraints, from the issue:

- Registered in `WRITE_TOOLS`, so a wildcard token scope cannot reach it.
- Owner-only, matching the waiver rule.
- The discarded operation stays discoverable, and the discard is attributable.
- Requires the operation id and its expected digest, so a stale client cannot
  clear an operation it has not read.

### A4. Refuse a `DEVICE_GROUP` deploy target (#61)

Small, and worth doing before Phase B because it establishes in code the
principle Phase B depends on: a value the API documents as unsupported is
refused locally with a message naming the limitation, rather than sent and
failed downstream. The refusal must be trivial to lift — `DEVICE_GROUP` is a
"future support" value, not a permanently invalid one.

## Phase B — broad reads, safely

### B1. Split the resource catalog by capability

The enabling refactor, and the one decision this plan turns on.

- A read catalog listing every family whose collection this server may read.
- A write catalog listing only families whose create/update/delete have been
  deliberately enabled — today exactly the four that already work.
- The generic read tools accept the read kind; `prepare_sdc_object_write` and
  `apply_sdc_object_write` accept the write kind.

Every write kind must map to a read kind, so a writable family is always
readable. The conversion goes one way only.

The point is that exposing a family for reading **cannot** expose it for
writing, enforced by the compiler rather than by remembering. A runtime
`writable()` predicate was considered and rejected: a missed call reintroduces
exactly the bug this phase exists to avoid, and there would be ~22 opportunities
to miss it.

Tests must include one that fails if a write kind exists with no read
counterpart, and the existing tool-contract test continues to pin the surface.

### B2. Extend the read catalog across #31's families

One enum variant and one match arm per family, with the collection path taken
from `docs/sdc-api/endpoints.md` rather than from memory.

The generic tools' descriptions currently enumerate the four families
("address, application, service, or scheduler"). That does not scale to ~26 and
must become a general description, with the families discoverable from the
enum in the tool's JSON schema.

Prioritise within #31 as that issue asks: `RuleOption` (`/api/v1/rule_options`)
and `VariableZone` (`/api/v1/variable_zones`) first, since
`options.logging`/`options.counter` and `ZoneReference.managed_variable` make
them reachable from rules that already exist here. Both are five-operation
groups, confirmed in the generated inventory.

### B3. Generalise the `fields` projection

Device groups established that `size` bounds the number of objects and not the
size of each, and that `fields` is an exploded array (`fields=uuid&fields=name`),
not a comma-joined value. Profile families embed rule and pattern lists, so the
same bound applies. Lift the projection from `list_device_groups` onto the
generic reader.

No default projection is invented for any family. Field names belong to the API,
and guessing them silently drops data.

## Deferred, with reasons

- **#55** — certificate and licence write tools return raw before-state. Real,
  but no current exposure: the allowlist equals the observed field union. It
  also touches persisted change-set state, so it wants care rather than speed.
- **#21** — device sync. The blocking unknown is answered and the answer
  demoted it: sync reconciles inventory only and does not clear
  `OUT_OF_BAND_CHANGED`, so it is not the remedy the issue wanted. Needs a scope
  decision before implementation.
- **#33 implementation** — the question is answered; template *tools* are a
  separate body of work, and any template write is estate-scale.
- **#34's remainder** and **writes for profile families** — after Phase A.

## Risks

| Risk | Mitigation |
|---|---|
| Catalog expansion silently exposes writes | B1 makes it a type error; a test pins that every write kind has a read counterpart |
| A1 is skipped and a mitigation is built for a problem XML already solves | A1 is one call and gates A2 explicitly |
| Discard becomes a way to erase evidence of a failed deploy | Owner-only, digest-bound, record preserved, attributable, in `WRITE_TOOLS` |
| Profile list responses exceed `max_response_bytes` | B3, plus the existing cap failing closed rather than truncating |
| Collection paths guessed rather than read | Every path taken from `endpoints.md`, which is generated from the pinned spec |

## Verification

`cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D
warnings`, and `cargo test --workspace` at every commit. The tool-contract test
is updated whenever the surface changes, and the token re-mint consequence is
called out in release notes whenever it does — a scoped token minted against an
earlier surface silently cannot see new tools.

Live verification uses `vsrx-ci` (VMID 907, pve2, tagged `ci`), which is the SDC
test device and is meant to be used. Deploy order for anything reaching a
container is 606 first, then 951.
