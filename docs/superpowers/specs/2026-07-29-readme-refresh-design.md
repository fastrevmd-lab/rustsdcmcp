# README Refresh Design

Date: 2026-07-29

## Goal

Rewrite the project README so a collaborator can understand the current
Security Director Cloud MCP server, verify the private lab prerelease, build it
from source, and deploy it safely to a Debian 13 LXC. The README must accurately
reflect completed work and the remaining roadmap.

This phase changes documentation only. First-class Docker support is a separate
follow-up phase and must not be presented as available yet.

## Audience and reading order

The primary audience is a repository collaborator evaluating or operating the
current lab release. The README should lead with the project's purpose and
current maturity, then progress from release verification to deployment and
security details:

1. Project overview and lab-release notice.
2. Current capabilities and qualified live-validation status.
3. Private prerelease download and checksum verification.
4. Source build and configuration.
5. Reusable Debian 13 LXC quick start.
6. Security and change-control model.
7. Completed work and current lab deployment.
8. Near-term roadmap.
9. Related projects, detailed documentation, and license.

## Source-of-truth facts

The refreshed README must preserve these verified project facts:

- The MCP surface has 17 tools: 14 read-only tools plus the
  `prepare_sdc_policy_deploy`, `approve_sdc_change_set`, and
  `apply_sdc_change_set` workflow.
- Live SDC testing has verified credential-based startup tenant validation,
  `get_sdc_tenant_scope`, and a bounded `list_sdc_devices` call returning one
  device. Those read-only checks succeeded before and after a service restart.
  No mutating SDC operation was invoked.
- The collaborator release is the private prerelease
  `v0.1.0-lab.1`, targeting source commit
  `65135e29484be4487f5ba58bdf70ec0ef7518288`.
- Its archive is
  `rustsdcmcp_0.1.0-lab.20260729.65135e29484b_amd64.tar.gz`, with SHA-256
  `f3497192cb6fe8c83cfad8014fadc787ff16de7bca89a2302b565331e4f21848`.
- The archive targets Debian 13 AMD64, includes an SBOM, installs a loopback-only
  Streamable HTTP service on port `30032`, and follows the file ownership and
  mode requirements in `docs/operations.md`.
- The deployed lab instance is VMID 606 on `pve2`, reachable for operators as
  `rustsdcmcp.mechub.org` and serving MCP only on `127.0.0.1:30032`.
- The package pins the `mecmcp` `changeset-v0.3.6` release. All 59 temporary
  compatibility declarations remain tied to upstream mecmcp issues through the
  compatibility ledger.
- This remains a lab prerelease. A stable release is blocked until the
  compatibility ledger can be replaced by one coherent upstream mecmcp release.

## README content

### Overview and status

Keep the existing independent-community-project notice and management-plane
risk explanation. Consolidate the API and mecmcp relationship material so it
supports the operational path without overwhelming it.

Replace the stale statement that the implementation has not been exercised
against a live tenant. The replacement must say exactly which read-only paths
were tested and explicitly state that no write workflow was exercised. It must
not imply that every read endpoint has been live-tested.

### Release verification

Document how a GitHub collaborator retrieves the private prerelease archive and
checksum, checks the SHA-256 file, and confirms the expected digest. Keep the
source-commit artifact rules for operators building an archive locally. Do not
describe `v0.1.0-lab.1` as public or stable.

No configuration dump is required or recommended. Runtime state, credentials,
tokens, audit keys, and tenant-specific configuration must not be packaged with
the release.

### Source build

Retain the Rust 1.88 build and workspace-test commands. Show configuration using
the checked-in example while keeping the actual credential in an external
environment file or process environment. Link to deeper configuration and API
documentation rather than reproducing it in full.

### Debian 13 LXC quick start

Provide a reusable operator flow rather than instructions hard-coded only to
the current lab container. State these prerequisites:

- Debian 13 AMD64, with an unprivileged LXC recommended.
- At least 1 vCPU, 512 MiB RAM, 512 MiB swap, and 4 GiB disk for the lab profile.
- Working DNS, time synchronization, and outbound HTTPS to the SDC API.
- Root or equivalent operator access for installation and service management.

The flow should cover:

1. Downloading the release assets as an authenticated repository collaborator,
   or building the package from the approved source commit.
2. Verifying the archive checksum before transfer or extraction.
3. Transferring, extracting, and running the packaged installer.
4. Creating `/etc/rustsdcmcp/credentials.env` as `0600 root:root` without
   displaying or committing the credential.
5. Creating `/etc/rustsdcmcp/sdc.json` from the example with an operator-obtained
   expected tenant ID; examples must not include the real lab tenant ID.
6. Minting an initial token with the exact 14 read-only tool names.
7. Enabling and starting the service only after configuration is complete.
8. Verifying systemd status and the loopback-only listener.
9. Accessing the MCP endpoint through an SSH tunnel.

Detailed file modes, startup behavior, recovery, audit retention, and token
reload remain authoritative in `docs/operations.md`.

### Security, completed work, and roadmap

Keep the core commitments: external secrets, exact tool and tenant scopes,
bounded I/O, audit redaction, startup tenant verification, and two-principal
prepare/approve/apply change control.

Summarize completed work, including the private prerelease, Debian package,
systemd deployment, VMID 606 lab instance, DNS name, and qualified live
read-only validation.

The roadmap should be short and ordered:

1. Add first-class Docker image, Compose, secret injection, health checks, and
   release documentation.
2. Replace the 59 compatibility declarations as their tracked mecmcp APIs ship
   together.
3. Add remote audit-journal forwarding for non-lab operation.
4. Expand live, bounded validation across the remaining read endpoints and then
   exercise write workflows under approved change control.
5. Publish a stable release only after the upstream and operational blockers
   are cleared.

## Security and privacy constraints

The README and its examples must not contain:

- the real SDC API key or OAuth token;
- the real tenant ID;
- a bearer token, token digest, or audit HMAC key;
- live tenant configuration or runtime-state dumps.

Use placeholders that cannot be mistaken for working credentials. Commands
must avoid printing secrets and should direct operators to local files with
restrictive modes.

## Validation

Before merging the README change:

- verify every local README link resolves;
- verify the stale live-testing claim is absent;
- verify no Docker instructions claim unsupported functionality;
- inspect shell snippets for syntax and safe secret handling;
- run `git diff --check`;
- run the workspace test suite as a final regression check.

## Non-goals

This phase does not add Docker files, container images, Compose configuration,
application code, packaging code, release assets, release tags, or mutations to
the live LXC. Those changes require a separate first-class Docker design and
implementation.
