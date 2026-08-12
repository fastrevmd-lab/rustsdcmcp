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
