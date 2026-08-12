# Live verification, lab mode, container 612, and the `v0.1.0-lab.5` release

Date: 2026-08-12

## Why this exists

`main` is green — `cargo fmt --all --check`, `cargo clippy --workspace
--all-targets -- -D warnings`, and `cargo test --workspace` (65 tests) all pass
at `004e357`. There are no open pull requests. The five open issues are feature
epics totalling roughly 180 operations, so "finish the issue list today" was
never available.

What *is* available is more valuable. Three of those issues (#21, #33, #50) are
blocked not on effort but on facts that only a live tenant can supply, and the
tenant is live. Answering them converts blocked work into actionable work and
closes one issue outright.

Separately, the repository's release documentation asserts things that are no
longer true, including a blocker that has already cleared.

## Established facts

Verified during design, not assumed.

### The tenant is live and has one device

`GET /api/v2/tenant/tenant-id` returns `200` with tenant
`ae291b9e-c7a1-4db8-ba69-515b077cfda7`. `GET /api/v1/devices` returns one
device:

| Field | Value |
|---|---|
| `name` | `srx17861259151621` |
| `system_info.host_name` | `vsrx-ci` |
| `os_version` | `24.4R1.9` (`vSRX`, `STANDALONE`) |
| `management_state` | `MANAGED` |
| `login_connection_state` | `DOWN` |
| `combined_state` | `DOWN` |
| `device_sync_status` | `UNKNOWN` |
| `inventory_sync_info.overall_sync_status` | `OUT_OF_SYNC` |
| `device_config_state` | `OUT_OF_BAND_CHANGED` |

This corrects a standing note claiming the tenant had no onboarded devices.

### `vsrx-ci` is down for a device-side reason

`system services outbound-ssh` is configured correctly — client
`EMS-srx.sdcloud.juniperclouds.net`, `device-id` matching the SDC uuid exactly,
`services netconf`, target `srx.sdcloud.juniperclouds.net` port `7804`. But
`inet.0` holds only the connected `192.168.1.0/24`; there is **no default
route**. The device cannot reach SDC, and the log contains zero outbound-ssh
attempts.

### `vsrx-ci` is squatting on the LAN gateway address

`interfaces ge-0/0/0 unit 0 family inet` carries two addresses:

```
address 192.168.1.162/24;
address 192.168.1.1/24;      <- the real LAN default gateway
```

Added `2026-08-11 22:13 by netconf`. The real gateway currently wins the ARP
cache (`0e:ea:14:27:fb:2c`, against the vSRX's `bc:24:11:82:4f:de`), so this is
latent rather than actively breaking the network — but it is a duplicate-IP
conflict on the home gateway and resolves on whichever host answers first.

The shape strongly suggests a prior automated session intended
`set routing-options static route 0.0.0.0/0 next-hop 192.168.1.1` and
configured an interface address instead. Both defects therefore share one fix.

### The `mecmcp` compatibility blocker has cleared

`docs/mecmcp-compatibility.md` and `docs/mecmcp-compatibility.tsv` were both
deleted in `369f9bb`, the mecmcp 0.8.0 adoption commit. The 59 declarations were
replaced, not abandoned. Five places in the docs still assert otherwise, and
`README.md:221` links to one of the deleted files.

`README.md`'s "Relationship to `mecmcp`" section is wrong on four counts
simultaneously: it says five crates (there are six), pinned to `v0.5.0` (they
are pinned to `v0.8.0`), with 59 declarations "remaining" (none remain), linking
to a file that no longer exists.

### Approval identity is the token name

`server.rs:161` — `owner(caller)` returns `caller.token_name`. `change.rs:1553`
asserts that self-approval is refused. Two tokens with different names are two
distinct principals.

### Lab-mode waivers are tamper-evident upstream

`mecmcp-changeset` 0.8.0 implements the waiver as a digest, not a bypass.
`digest.rs:200` `compute_waiver_digest` binds
`(change_set_id, plan_digest, owner, approved_at, "lab-mode-waived")`, and
`apply.rs:190` requires every approval record to carry either an approver or a
waiver. A waived set is cryptographically distinguishable from a genuine
two-person one and cannot be forged or relabelled after the fact.

### The shared CLI standard exists and this repository never adopted it

`main.rs:6` imports `Cli` from `mecmcp_runtime::cli` and `main.rs:68` calls
`Cli::parse()`. An early reading of that concluded no new CLI flag could ship
without modifying `mecmcp`, which CLAUDE.md forbids. **That conclusion was
wrong.**

`mecmcp/docs/PACKAGING.md` at `v0.8.0` standardises `--lab-mode`,
`--state-file`, and `--approval-timeout-secs`, and directs consumers to declare
them in their *own* CLI type: `parse_with_provenance` "parses **your** CLI type,
not the shared `Cli` — the flags this rule exists for are defined by each
server". The pattern is to flatten the shared `Cli` into a local struct.

`parse_for`, `parse_with_provenance`, `was_supplied`, and `was_supplied_in` are
all present at the pinned `v0.8.0` tag. mecmcp#162 was closed specifically to
unblock this repository. No upstream change is required.

Two consequences, both verified:

- `rustsdcmcp --version` fails with `error: unexpected argument '--version'
  found`, because parsing the shared type directly leaves the binary with no
  version of its own (mecmcp#159).
- None of the three standard flags exist here. `config.rs:89,91-92` hold
  `changeset_state_file` and `approval_ttl_secs`; `main.rs:146-147` pass them
  directly to `ChangeManager::load`. There is no CLI layer and no precedence
  rule.

Filed as rustsdcmcp#54. A residual ambiguity in the upstream standard — whether
lab mode may be enabled from product configuration at all — is filed as
mecmcp#267 and does not block adoption.

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Day shape | Verify-heavy, ship `v0.1.0-lab.5` | The live answers unblock three issues; the epics cannot land today regardless |
| Devices onboarded | Fix `vsrx-ci` only | One healthy `MANAGED` device answers all three questions; no bootstrap work |
| Release claims | State the upstream blocker cleared, name what actually remains | The docs currently assert a blocker that does not exist |
| Container 612 | New, protected, TLS on LAN | 606 is loopback-only and therefore unusable as a client endpoint |
| 612 address | `192.168.1.213`, `rustsdcmcp-612.mechub.org` | `.212` is taken by 610; leaves `rustsdcmcp.mechub.org` pointing at 606 so existing docs stay true |
| 612 credential | Separate SDC API key | Independent audit attribution and revocation |
| Lab mode | Ship it as the standard `--lab-mode` flag, adopting the full CLI standard | User decision, reaffirmed after the concern was raised. The sanctioned pattern needs no upstream change |

### On lab mode specifically

The concern was raised that this waives the two-person invariant on a protected
container holding a live credential to an estate-wide management plane, and that
it reverses the decision recorded in the mecmcp 0.3.7 adoption design ("this
adoption must not add `--lab-mode`"). The user reaffirmed the request; it
proceeds.

Two findings make it more defensible than it first appeared. The waiver is
tamper-evident rather than a silent bypass, and it is per-deployment opt-in — it
can be enabled on 612 without affecting 606 or any future deployment.

It ships as the standard `--lab-mode` flag, defaulting to off, as part of
adopting the whole CLI standard (rustsdcmcp#54). The 0.3.7 plan's instruction
not to invent CLI-versus-JSON precedence is satisfied by following the
precedence rule PACKAGING.md now defines, rather than by avoiding the CLI.

PACKAGING.md constrains the implementation in ways worth stating up front: the
waiver is applied **automatically at creation**, not through a separate tool, so
no waive tool is added and the operator's flow stays plan-then-apply exactly as
in production. The record carries `approver: null` alongside `approval_waiver:
"lab-mode"` — both fields, never a sentinel string inside `approver`.

## Phases

Ordering is load-bearing. Phase 0 gates Phase 1. Phase 1's certificate capture
gates Phase 2. Phase 3 is independent of all of them. Phase 5 is last.

### Phase 0 — Restore `vsrx-ci`

Snapshot VM 114 first. One Junos commit, using `commit confirmed` so a mistake
self-reverts:

```
delete interfaces ge-0/0/0 unit 0 family inet address 192.168.1.1/24
set routing-options static route 0.0.0.0/0 next-hop 192.168.1.1
```

Removing `.1/24` does not disturb `.162`, which is how `rust-junosmcp` reaches
the device.

Done when: `inet.0` holds a default route; an established connection to
`srx.sdcloud.juniperclouds.net:7804` exists; SDC reports
`login_connection_state: UP` and `combined_state: UP`.

### Phase 1 — Harvest the live answers

Read-only except where noted. Every finding is written into
`docs/sdc-api/README.md`, moving entries out of **Still unverified**.

**#50 — certificate and licence response shapes.** `GET
/api/v1/devices/local_certificates`, the per-device variant, and the licence
endpoints. Record the actual field names; that set becomes Phase 2's allowlist.
This is exactly option 3 in the issue, which the issue itself calls the honest
prerequisite for options 1 and 2.

**#21 — `BulkSyncDevices` direction.** The blocking unknown is whether sync
imports device config into SDC or pushes SDC's view down to the device. On a
management plane that is the difference between "accept local changes" and
"overwrite the device." `vsrx-ci` sits at `OUT_OF_BAND_CHANGED` right now, which
is precisely the scenario.

This step mutates. It is gated: snapshot first, capture the full device config,
scope the sync to the single device, then diff. If the device config changed,
sync pushes; if only SDC's state advanced to `IN_SYNC`, sync imports.

Issue #21's Notes claim the deploy-path job models are "still unexercised
against a live tenant". **That is stale.** `docs/sdc-api/README.md` records
under "What is not broken" that `JobStatus` and `DeviceStatusEntry` deserialize
correctly against live preview *and* deploy responses, including
`preview_id`/`deploy_id` being mutually exclusive. A full prepare → approve →
apply ran against this tenant on 2026-08-07; #23 exists because of what that
deploy did.

What genuinely remains unknown is narrower: whether `GetSyncStatus` shares the
deploy job shape or has its own. Worth confirming, but it is not the models'
first live contact. #21 should be corrected.

**#33 — template capability.** Read-only template list and get. Determines
whether templates can express interface, routing, and system config, and
`security dynamic-address` in particular — which decides whether #23's
co-management boundary is drawn in the right place.

### Phase 2 — Close #50

An allowlist projection over the six certificate and licence readers only, built
from Phase 1's observed fields. Unknown fields are excluded by default, so an
upstream addition cannot leak by omission. Every other reader stays on `Value`
passthrough as an explicit recorded decision rather than by silence.

Test: a fixture carrying an injected `private_key` asserts the field is dropped.

### Phase 3 — Documentation and hygiene

Independent; can run at any point.

- Untrack `clippy.log`, `clippy-final.log`, `test-final.log`, `doc-final.log`;
  extend `.gitignore`. (#41 removed `test.log`; these four survived.)
- Rewrite `README.md`'s "Relationship to `mecmcp`": six crates, `v0.8.0`,
  blocker cleared in #36 / `369f9bb`, with the gates that actually remain named.
- Fix roadmap item 2, which restates the cleared blocker.
- Repair the dead ledger links in `docs/lab-deployment-606.md:17,72` and
  `docs/operations.md:25`.
- Rewrite the CHANGELOG header; add the missing `lab.3` and `lab.4` sections and
  log #35–#53.
- Delete the two dead branches `feature/24-firewall-policy-writes` and
  `issue-30-nat-pools` (superseded by their `-v2` branches, PRs #46 and #43
  closed).

### Phase 4 — Lab mode and container 612

**Lab mode, via the CLI standard (rustsdcmcp#54).** Own PR, own review.

1. Flatten `mecmcp_runtime::cli::Cli` into a local `ServerCli` and declare
   `--lab-mode`, `--state-file`, and `--approval-timeout-secs` there.
2. Parse with `parse_with_provenance::<ServerCli>(env!("CARGO_PKG_NAME"),
   env!("CARGO_PKG_VERSION"))`, which also repairs `--version`.
3. Apply the documented precedence with `was_supplied` — explicit CLI, then
   `sdc.json`, then the default. Never compare against the parser default;
   PACKAGING.md calls that the trap, and it fails in both directions.
4. Thread `lab_mode` into `ChangeManager::load`, replacing the hardcoded `false`
   at `change.rs:277`.
5. Warn loudly at startup when enabled.
6. No waive tool. The waiver applies automatically at creation.
7. Document `--lab-mode` in `README.md` and `docs/operations.md`: what it
   weakens, that it is off by default, and how a waived change set stays
   distinguishable in the audit trail.

Tests cover omitted flags, explicit flags, existing product configuration,
conflicting values, the waived approval path, and the `approver: null` plus
`approval_waiver: "lab-mode"` record shape.

Existing lab containers already carry `changeset_state_file` and
`approval_ttl_secs` in their deployed `sdc.json`. Adoption must not silently
move a durable state file or change an approval lifetime — the precedence rule
handles this only if step 3 is implemented correctly.

**Container 612.** Mirrors 606's hardened unit, with the exposure differences
that make it usable as a client endpoint.

| Property | Value |
|---|---|
| VMID / host | 612 on pve2 |
| Hostname | `rustsdcmcp-612` |
| Template | `debian-13-standard_13.1-2_amd64` |
| Resources | 1 core, 512 MB RAM, 512 MB swap, 4 GB rootfs, unprivileged, `nesting=1` |
| Address | `192.168.1.213/24`, gw `192.168.1.1`, `searchdomain mechub.org` |
| DNS | new record `rustsdcmcp-612.mechub.org` |
| Listener | streamable-HTTP over **TLS**, bound to its own address |
| Auth | bearer token; `--allowed-host` set to the dialled name |
| Credential | its own SDC API key, minted in the portal |
| Lab mode | `--lab-mode` in the unit's `ExecStart` |
| Tag | `protected` — **applied only after validation** |

Two departures from 606 are deliberate and worth stating. 606 binds
`127.0.0.1:30032`, which is why it cannot serve a client; 612 binds its LAN
address. And 606's unit sets `IPAddressAllow=localhost`, which would drop LAN
traffic, so 612 needs a systemd drop-in widening it — the same override pattern
609 uses.

The container is built **untagged**, validated end to end, and tagged
`protected` only once confirmed working. Tagging first would invoke the
guardrail against touching protected guests and prevent repair of a botched
build.

The binary is installed from the **CI artifact, never a local build** — a local
build links against the wrong glibc.

### Phase 5 — Release

Tag `v0.1.0-lab.5`. Deploy to 606 and 612 from the CI artifact. Then the
follow-up documentation commit repointing `README.md`'s install block at the new
tag and its digest — the ordering wrinkle that appears in this repository's
history as a separate "point the release documentation at…" pull request each
time, and which #15 partially addressed by generating the package README.

## Risks

| Risk | Mitigation |
|---|---|
| Junos commit breaks `vsrx-ci` | Snapshot VM 114; `commit confirmed`; `.162` untouched |
| `BulkSyncDevices` overwrites the device | Snapshot; single-device scope; config diff before and after. If it pushes, stop and leave #21 open with the direction documented — that is still a win |
| Protected guests | 103 `vsrx-prod` and 301 are never touched. 103 also carries `hhome` and serves the real network |
| 612 tagged protected before it works | Tag last, after validation |
| Lab mode weakens change control | Per-deployment opt-in, default off, tamper-evident waiver digest, startup warning, documented in README, own PR |
| CLI adoption silently moves 606's durable state or approval TTL | Precedence implemented with `was_supplied`, not a default comparison; tests cover the existing-config case; verify 606 after upgrade |
| Projection hides fields callers rely on | Scoped to certificate and licence readers only; documented |

## Out of scope

- #31 (~110 operations), #33 implementation, and #34's remaining groups. #33's
  Phase 1 question is answered; the implementation is not attempted.
- #21's implementation. The sync tools need the changeset binding extended
  beyond policy deploy and job polling shared with the deploy-status tools. Only
  the blocking direction question is resolved today.
- Onboarding additional devices.
- mecmcp#267, the upstream documentation ambiguity. It does not block adoption.

## Verification

`cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D
warnings`, and `cargo test --workspace` pass at every commit. New tests
accompany the projection and lab mode. The tool contract test is updated if the
surface changes.

No phase is reported complete on inference. Live findings are recorded with the
call that produced them.
