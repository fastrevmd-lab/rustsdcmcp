# rustsdcmcp Lab Packaging and Deployment Design

Date: 2026-07-29

## Decision

Prepare and deploy a traceable, non-release `rustsdcmcp` lab build while the
required shared mecmcp APIs are unavailable in a valid release. The build will
use a temporary local compatibility layer, but every reusable compatibility
symbol will have a dedicated mecmcp issue and an in-source issue reference.

This work must not change mecmcp code, create mecmcp branches, or open mecmcp
pull requests. It may only open issues in mecmcp.

No public `rustsdcmcp` tag or GitHub release will be created while temporary
compatibility code remains.

## Current Upstream State

The current `rustsdcmcp` dependency revision,
`75a1e9db10a21a85876f337313ba47bc0329d74d`, belongs to closed, unmerged mecmcp
PR #89. The branch was deleted, and the PR was explicitly closed because it was
created in error. It is not a valid release dependency.

The latest coherent mecmcp release ref that contains the shared crates needed
by `rustsdcmcp` is `changeset-v0.3.6`. `RustJunosMCP` and `rust-panosmcp` also
use that single ref. All mecmcp crates must resolve from the same immutable ref
because mixing refs creates different `CallerCtx` type identities and can
silently break request-extension authorization.

The released transport provides limits, concurrency, identity, metrics,
preflight primitives, session and rate controls, and TLS loading. It does not
provide the complete authenticated Streamable HTTP composition or the shared
rmcp handler helpers currently consumed by `rustsdcmcp`.

## Goals

- Replace the invalid mecmcp dependency revision with one coherent, valid tag.
- Preserve the current SDC MCP behavior through a temporary, auditable local
  compatibility layer.
- Track every reusable compatibility function, method, and type in mecmcp.
- Produce an amd64 Debian 13 lab package following mecmcp packaging standards.
- Deploy the exact package to VMID 606 on `pve2`.
- Validate authentication, authorization, audit behavior, and read-only SDC API
  access without making an SDC policy change.

## Non-goals

- No code, documentation, branches, or pull requests will be created in mecmcp.
- No public `rustsdcmcp` release will be published from the compatibility build.
- No live SDC preview, approval, apply, or deployment action will be tested.
- No LAN-exposed MCP listener will be created.
- Remote journal forwarding will not be configured until a destination is
  selected; this limitation will be documented for the lab instance.

## Ownership Boundary

The following behavior is Security Director Cloud-specific and remains in this
repository:

- SDC API paths, request and response models, and documented status values.
- The `x-api-key` and `x-oauth2-token` authentication headers.
- Tenant-ID discovery and configured-tenant validation.
- SDC pagination, resource catalogs, path encoding, and HTTP 429 behavior.
- SDC preview, deploy, polling, and device-result semantics.
- The prepared change-set payload and the SDC deployment request.
- SDC-specific tool names, write-tool registry, and sanitized SDC errors.

Reusable Rust behavior belongs in mecmcp:

- Extracting `CallerCtx` from rmcp request extensions.
- Tool and target scope authorization.
- Scope-filtered `tools/list`.
- Bounded MCP tool results and stable tool errors.
- Audit-scope construction.
- Bearer authentication and response profiles.
- Request-body limits and tool-scope preflight.
- Host and Origin policy.
- Streamable HTTP router composition and listener bootstrap.

Existing mecmcp issues #90 and #91 remain the upstream trackers for generic
cloud-client behavior and neutral target vocabulary. New issues must not
duplicate those scopes.

## Temporary Compatibility Contract

Temporary compatibility code will live under clearly named internal modules
such as `compat::server` and `compat::http`. Production SDC modules may call
these modules but may not duplicate their generic behavior.

The current compatibility entry-point inventory contains these 20 functions and
methods:

1. `audit_scope`
2. `authorize_call`
3. `caller_from_extensions`
4. `filter_tools_for_scope`
5. `bounded_text`
6. `tool_error`
7. `tool_result`
8. `BearerAuthenticator::new`
9. `BearerResponseProfile::detailed`
10. `BearerBoundary::new`
11. `BearerBoundary::with_preflight`
12. `HostOriginPolicy::enforced`
13. `HttpTransportConfig::new`
14. `HttpTransportConfig::with_bearer`
15. `HttpTransportConfig::with_metrics`
16. `TargetField::scalar`
17. `ToolScopePreflight::new`
18. `build_streamable_http_router`
19. `serve_router`
20. `parse_bearer_header`

The currently known reusable supporting-type inventory is:

1. `AuthorizationError`
2. `ResultFormat`
3. `ResultLimits`
4. `BoundedText`
5. `BearerAuthenticator`
6. `BearerResponseProfile`
7. `BearerBoundary`
8. `HostOriginPolicy`
9. `HttpTransportConfig`
10. `MalformedArgumentsPolicy`
11. `TargetField`
12. `ToolScopePreflight`
13. `HttpTransportBuildError`
14. `HttpServeError`
15. `BearerSyntax`
16. `BearerHeaderError`

Implementation-plan analysis expanded the complete production compatibility
surface to 59 symbols: 37 functions or methods and 22 types. That exhaustive
classification, including private helpers and the four released preflight
symbols that must be reused instead of copied, is recorded in
`docs/superpowers/plans/2026-07-29-rustsdcmcp-lab-package-deployment.md`.
The one-to-one issue contract applies to all 59 temporary symbols.

Before any compatibility implementation is written:

1. Each function or method above receives a dedicated mecmcp issue.
2. Each reusable supporting type receives a dedicated mecmcp issue.
3. Each additional private compatibility helper receives its own mecmcp issue
   before that helper is added.
4. Test-only helpers and permanently SDC-specific functions are excluded.

“Dedicated” is one-to-one: two compatibility symbols may not share the same
mecmcp issue. If implementation reveals another reusable symbol, its issue must
exist before its declaration is added to the repository.

Each temporary implementation will include a doc comment in this form:

```rust
/// Temporary mecmcp compatibility implementation.
///
/// Upstream: the full URL of this symbol's dedicated mecmcp issue
/// Replace with: `mecmcp_crate::symbol`
/// Remove after: first coherent mecmcp release containing the upstream issue
```

The repository will contain a compatibility ledger mapping:

| Local symbol | Dedicated issue | Target crate and symbol | Removal condition |
| --- | --- | --- | --- |
| Every compatibility function, method, and type | Full mecmcp issue URL | Expected upstream API | First coherent release containing it |

An automated contract test will scan the non-test compatibility surface and
fail when a function, method, or reusable type lacks a full mecmcp issue URL.
The ledger and source references must agree.

The compatibility layer is removed only when every linked issue is present in
one coherent mecmcp release. At that point all mecmcp crates are re-pinned to
that single release, imports are switched to upstream symbols, compatibility
tests and the ledger are deleted, and the full release gates are rerun.

## Dependency Migration

All valid mecmcp dependencies will be pinned to `changeset-v0.3.6`. The invalid
revision will be removed, and `mecmcp-server` will be removed because it does
not exist in that release.

The compatibility implementation will use released mecmcp primitives where
available. It will not vendor or modify the mecmcp repository.

## Package Design

The lab artifact name will identify its status, date, and exact source commit:

```text
rustsdcmcp_0.1.0-lab.20260729.${GIT_SHA12}_amd64.tar.gz
```

The package will contain:

- The release binary.
- An idempotent LXC installer.
- A hardened systemd service unit.
- A non-secret configuration example.
- A persistent journald configuration.
- sysusers and tmpfiles declarations.
- A SHA-256 checksum.
- An SBOM.
- Source commit and mecmcp dependency metadata.

The package will not contain:

- SDC API credentials.
- MCP bearer tokens.
- Audit HMAC keys.
- Tenant-specific runtime configuration.
- Change-set state or other runtime state.

Runtime dependencies will explicitly include `curl` and `ca-certificates` to
match the mecmcp Debian 13 LXC standard. The package will be checked for
installer idempotency, non-overwriting state behavior, binary linkage, and its
minimum glibc requirement.

The implementation branch will be pushed as a draft pull request so the exact
deployed commit is reviewable. The lab archive is not a GitHub release asset,
and no release tag is created.

## LXC Design

VMID 602 is already assigned cluster-wide to the running `journal-collector`
LXC on `pve3`. It must not be modified. The user selected VMID 606 on `pve2`
instead.

The deployment target is:

| Setting | Value |
| --- | --- |
| Proxmox node | `pve2` |
| VMID | `606` |
| Hostname | `rustsdcmcp-606` |
| DNS name | `rustsdcmcp.mechub.org` |
| Address | `192.168.1.211/24` |
| Gateway | `192.168.1.1` |
| Bridge | `vmbr0` |
| OS | Debian 13 |
| Root filesystem | 4 GiB on `local-lvm` |
| CPU | 1 core |
| Memory | 512 MiB |
| Swap | 512 MiB |
| Privilege | Unprivileged |
| Features | `nesting=1` |
| Proxmox firewall | Enabled |
| Start on boot | Enabled |

VMID 606, the address, and the DNS name will be checked again immediately
before creation. The static address is outside the DHCP pool. After the LXC MAC
is known, UniFi will receive the reservation and exact DNS record
`rustsdcmcp.mechub.org`.

The service will run as a dedicated, non-root `rustsdcmcp` user. MCP will bind
only to `127.0.0.1:30032`; testing will use an SSH tunnel or `pct exec`.

Persistent paths are:

- `/etc/rustsdcmcp` for configuration, token metadata, and the audit HMAC key.
- `/var/lib/rustsdcmcp` for change-set state.
- `/usr/local/bin/rustsdcmcp` for the binary.

Persistent journald will use a 512 MiB cap. Audit output will use JSON and
journald, with tenant targets HMAC-redacted. Unprivileged LXC journal FSS is
not available. Remote forwarding remains a documented lab limitation.

## Secret Handling

The source SDC credential is
`/home/mharman/.config/rustsdcmcp/credentials.env`. Its directory is mode
`0700`, and the file is mode `0600`.

The credential will be transferred without printing its value and installed as
`/etc/rustsdcmcp/credentials.env`, owned by root and mode `0600`. It must never
appear in Git, package contents, command output, shell history, logs, or chat.
The systemd manager reads the environment file before dropping privileges to
the service user.

The audit HMAC key and token store will be created in the LXC with mode `0600`.
The initial MCP token will be read-only, stored locally outside the repository,
and never printed in the handoff.

## Runtime Data Flow

1. systemd loads the external credential and starts `rustsdcmcp` as the
   dedicated service user.
2. `rustsdcmcp` binds its authenticated MCP endpoint to loopback.
3. A read-only tenant-ID request confirms that the credential matches the
   configured tenant scope.
4. An MCP client connects through a protected local path or SSH tunnel.
5. The bearer boundary authenticates the MCP token.
6. Preflight and handler authorization constrain the tool and tenant scope.
7. The SDC client sends bounded HTTPS requests to the allowlisted SDC API.
8. Results are bounded and serialized as MCP tool results.
9. Audit events record attribution, action, outcome, and HMAC-redacted targets.

## Error Handling

- Dependency or compatibility-ledger drift fails the build before packaging.
- Package verification failure prevents deployment.
- A no-longer-free VMID, address, or DNS name stops deployment before mutation.
- SDC authentication failures expose only sanitized status and error
  information.
- Missing or invalid MCP bearer tokens are rejected at the HTTP boundary.
- Requests beyond token scope are denied before reaching an SDC operation.
- Oversized HTTP requests, SDC responses, or MCP results fail with bounded,
  credential-free errors.
- Deployment failure preserves the LXC and diagnostics for investigation
  instead of deleting it automatically.
- DNS, service, security, audit, or smoke-test failure prevents the lab
  deployment from being reported as accepted.

## Verification and Acceptance

Pre-deployment verification includes:

- `cargo fmt --check`
- Clippy across the workspace and all targets
- All unit, integration, contract, and documentation tests
- Compatibility issue-reference and ledger tests
- Dependency policy and vulnerability checks
- Trivy scan
- SBOM generation and inspection
- Package content and checksum verification
- Installer idempotency
- Binary linkage and glibc-floor inspection

Post-deployment verification includes:

- LXC configuration, address, gateway, firewall, DNS, and outbound HTTPS
- File ownership and secret permissions
- systemd enablement, hardening, health, restart, and boot persistence
- Persistent journald
- Loopback-only port `30032`
- Rejection of missing and invalid MCP bearer tokens
- MCP initialization with the protected read-only token
- Scope-filtered `tools/list` with no write tools exposed
- Read-only tenant-scope lookup
- Small, bounded device and policy list operations
- Audit attribution, outcomes, and HMAC target redaction

No preview, approval, apply, or deployment mutation is part of acceptance.

The handoff record will include the source commit, artifact checksum, mecmcp
tag, VMID, IP address, DNS name, and sanitized test results.

The lab deployment is accepted only when every applicable verification passes.
Public `v0.1.0` remains blocked until every temporary compatibility issue ships
in one coherent mecmcp release and the compatibility layer is removed.
