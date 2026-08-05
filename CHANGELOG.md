# Changelog

All entries remain unreleased publicly: `v0.1.0` is blocked until one coherent
upstream `mecmcp` release replaces all 59 compatibility ledger entries. The
`v0.1.0-lab.N` tags are private lab prereleases, not public releases.

## Unreleased

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
