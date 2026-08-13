# Changelog

All entries remain unreleased publicly. The `v0.1.0-lab.N` tags are private lab
prereleases, not public releases.

The upstream blocker that previously appeared here — 59 compatibility ledger
entries awaiting one coherent `mecmcp` release — **is cleared**. The `compat/`
layer was deleted in #36 on the move to mecmcp 0.7.2, and the ledger itself in
`369f9bb` on the move to 0.8.0. What still gates a public `v0.1.0` is
operational: container image support, remote audit-journal forwarding, broader
live validation, and a tool surface that covers a minority of the SDC API.

## Unreleased

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

## `v0.1.0-lab.7` — 2026-08-13

Phase A of the completion plan: the four change-control defects.

### Changed

- **Previews are now requested as XML, and this changes what a reviewer
  reads.** `GET /api/v1/policies/preview/{id}/devices/{id}` accepts a `format`
  parameter — `CLI` (the default) or `XML` — and this client never passed it.
  The CLI rendering omits parent objects that XML names: the same preview
  rendered 273 bytes naming one deletion in CLI and 570 bytes naming two in
  XML, the second being a `<feed-server operation="delete">`. Since the preview
  digest is computed over that artifact, an approver could be shown less than
  the change (#66).

  SDC was never concealing anything — its XML answer was always complete. This
  client digested the lossy rendering of it. Verified live: the parent object
  now appears in the digest-bound artifact.

### Added

- `discard_sdc_operation`, which clears a terminal-but-unreconciled operation
  (#63). A failed deploy previously refused **every later apply on the tenant**,
  and the only remedy was editing `changeset-state.json` on a running
  deployment. Owner-only, fingerprint-bound, and in `WRITE_TOOLS` so a wildcard
  token scope cannot reach it. The failed operation stays visible: this
  unblocks applies, it does not erase the failure.

  Exposing the upstream call alone would not have worked, and would have made
  things worse. It invokes `transaction.rollback`, which returned an error that
  the caller converts to `Indeterminate` — a state that can never be discarded.
  `SdcTransaction::rollback` now reports truthfully first, since SDC reverts the
  device itself on a failed deploy.

  **The tool surface is now 51.** A token minted against the previous 50 will
  not see this tool until re-minted; tool scopes are explicit allowlists.

### Fixed

- Refuse a `DEVICE_GROUP` deploy target locally instead of sending a request
  SDC rejects (#61). The pinned spec marks the target type "Not supported,
  future support", so the refusal happens before a preview job is spent and
  names the limitation. One guard and one call site, deletable when SDC
  supports it.

## `v0.1.0-lab.6` — 2026-08-12

### Added

- Device group read tools: `list_sdc_device_groups` and `get_sdc_device_group`
  (#34). The tool surface is now 50: 39 reads and 11 change-control tools.

  **Anyone holding a token minted against the previous 48 must re-mint it.** A
  token's tool scope is an explicit allowlist of names, so an upgrade that adds
  tools leaves existing tokens seeing exactly what they saw before. The new
  tools simply do not appear, which looks like a failed deployment and is not.

### Documentation

- Show how to enable `--lab-mode`, which the previous release documented the
  meaning of without ever showing the invocation. `--lab-mode` is CLI-only:
  unlike `--state-file` and `--approval-timeout-secs` it has no `sdc.json`
  fallback, deliberately.
- Record that a policy deploy **deletes template-placed configuration** that no
  imported policy references, confirmed by a committed apply (#33). Template
  origin confers no protection, so the co-management boundary in #23 stands and
  templates are not a remedy for it.
- Record that **a deploy can commit more than its preview disclosed** (#66). In
  the observed case the preview named one object and the commit removed two,
  with the omitted object absent from the digest-bound artifact entirely. The
  change-set binding behaved correctly; what it bound did not describe the whole
  change. Treat a preview as a lower bound until the conditions are understood.
- Record the undocumented custom-template upload schema, and an edge WAF that
  rejects a template body containing `http://` plus an RFC1918 address.
- Record that `DEVICE_GROUP` is not a supported deploy target — the pinned spec
  marks it "not supported, future support" — correcting a claim in #34 (#61).

## `v0.1.0-lab.5` — 2026-08-12

### Added since `v0.1.0-lab.4`

- Certificate and licence tools: six read operations and eight write operations
  under change control (#32).
- IPsec profile and tunnel read tools (#28).
- Firewall and NAT policy rule read tools (#25), NAT pool read tools (#30), and
  NAT policy authoring under change control (#27).
- Firewall policy write tools under change control (#24, partial).
- Object authoring for address, application, service, and scheduler objects
  under change control (#29).
- `get_sdc_change_set_details`, which recovers a preview digest that is
  otherwise returned only once by prepare and cannot be recomputed (#22).
- An allowlist projection over the certificate and licence read tools, applied
  at the MCP boundary so change-control drift detection keeps full-fidelity
  state (#50).

### Changed since `v0.1.0-lab.4`

- Adopt the shared `mecmcp` change-set CLI standard: `--lab-mode`,
  `--state-file`, and `--approval-timeout-secs`, with explicit CLI beating
  product configuration and neither silently relocating an existing
  deployment's state file (#54). Parsing through `parse_with_provenance` also
  repairs `--version`, which previously failed as an unknown argument and is
  how a deployment identifies the build it is running.
- Wire `--lab-mode` through to the change-set coordinator. Setting the flag
  alone was not enough: nothing called the waiver, so a single operator still
  could not move a plan past `Planned`. The waiver is now applied at change-set
  creation, records `approver: null` with `approval_waiver: "lab-mode"`, and
  never fabricates an approver.
- Refuse `--approval-timeout-secs 0`, which expired every change set at
  creation and disabled the entire write surface.

- Adopt mecmcp 0.8.0 and its generic scope preflight; adopt 0.7.2 and delete the
  local compatibility transport copies (#36). This removed the last temporary
  compatibility symbols and the ledger tracking them.

### Fixed since `v0.1.0-lab.4`

- Attribute an `expected_preview_digest` mismatch to that argument by name. The
  error previously blamed the wrong input, sending an operator to inspect a
  value that was correct.

### Documentation since `v0.1.0-lab.4`

- Record live-observed SDC API behaviour verified against a real tenant: the
  certificate and licence field sets and their date-format and sentinel traps,
  device sync direction, and what a template is and can express. Device sync
  **imports** rather than pushes, but reconciles inventory only and does not
  clear `OUT_OF_BAND_CHANGED` (#21, #33, #50).
- Document SDC co-management and destructive deploy behaviour: a policy deploy
  removes device configuration SDC does not model (#23).
- Document response-shape mismatches observed live (#26).
- Correct release claims across README, CHANGELOG, and the operations guide.
  Five places asserted a compatibility blocker that cleared in #36/`369f9bb`,
  and the README denied a live policy deploy that had in fact happened and is
  the reason #23 exists.
- Document `--lab-mode`, what it weakens, and why two tokens are preferable
  where the ceremony has value.

## `v0.1.0-lab.4` — 2026-08-05

- Generate the package README instead of copying the repository one. Every
  archive previously shipped download instructions for the *previous* release,
  because a release is built from a commit predating the docs describing it
  (#15).
- Point the release documentation at `v0.1.0-lab.3` (#14).

## `v0.1.0-lab.3` — 2026-08-05

Released the work recorded below under "Fixed since `v0.1.0-lab.2`" and
"Added".

### Fixed since `v0.1.0-lab.2`

- Refuse `--tokens-file` together with `--allow-no-auth`. The pair previously
  fell through to a catch-all arm that dropped the token store, producing an
  unauthenticated listener on any bind address with no diagnostic.
- Bind tool calls to the per-request cancellation token. Every tool previously
  built a fresh token, so the cancellation plumbing threaded through the client
  was connected to nothing and no client cancellation or shutdown could
  interrupt an SDC call or job poll.
- Abort in-flight SDC work on SIGTERM/SIGINT, and drain both listeners behind a
  single forced deadline. Streamable HTTP sessions end on the process token and
  stdio uses `serve_with_ct`, so a signal during the handshake exits cleanly
  instead of reporting a startup failure.
- Preserve SDC job statuses this build does not recognize instead of failing the
  whole read, keeping the vendor's own string in the audit and preview
  artifacts. Unrecognized states are never terminal and never successful.
- Digest the prepared-change envelope once per apply rather than four times.
- Exclude nested checkouts from the SBOM scan; a git worktree under the repo
  root made local package builds impossible.
- Scope workflow `push` triggers to `main`, halving Actions minutes for
  identical checks.

### Added

- systemd egress policy denying the cloud metadata endpoints, with
  `IPAccounting=yes` and an installer probe reporting whether the filters are
  actually enforced. These directives are defence in depth only: systemd
  implements them with cgroup eBPF and fails open where it cannot attach, which
  includes the recommended unprivileged LXC.
- Per-runtime guidance for enforcing egress where systemd cannot, plus a
  verification command that distinguishes a blocked route from an unprobed one.
- Assertions that the tool registry matches the registered router, that a
  tampered prepared-change envelope is refused at the trust boundary, and that
  an injected credential field is rejected.


- Add the Rust workspace and Security Director Cloud MCP binary.
- Add bounded device, policy, shared-object, and asynchronous-job read tools.
- Add preview-bound two-person policy deployment through `mecmcp-changeset`.
- Add shared `mecmcp` auth, audit, server, transport, runtime, and TLS
  composition.
- Add fixture tests, configuration example, operations guide, and security
  policy.
- Add Rust 1.97/MSRV 1.88, packaging, and security CI gates for the lab-only
  package.
- Document the lab artifact workflow, loopback-only listener, token ownership,
  journald forwarding exception, and the public-release compatibility blocker.
- Bind each lab package, checksum, and CI upload to its exact full source
  commit directory; require a Cargo-derived CycloneDX SBOM.
- Fail closed for staged live-installer tests and harden commit artifact output
  directories, SBOM metadata, and upload allowlists.
