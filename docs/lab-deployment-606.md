# VMID 606 Lab Deployment

## Deployment identity

- Date: 2026-07-29
- Operator: `mharman`, assisted by Codex
- Draft pull request: https://github.com/fastrevmd-lab/rustsdcmcp/pull/1
- Release status: lab-only; no Git tag or GitHub release was created
- Source commit from `BUILD-INFO`:
  `44a28f55598ad038389d9f734e11e0f520b82837`
- Archive:
  `rustsdcmcp_0.1.0-lab.20260729.44a28f55598a_amd64.tar.gz`
- SHA-256:
  `74723b532f81967bf34dbfc87ce7cb7464fe997d342186fb4062e7891e14779d`
- mecmcp reference: `changeset-v0.3.6`
- Compatibility boundary: 59 temporary, issue-linked Rust symbols are recorded
  one-to-one in [the compatibility ledger](mecmcp-compatibility.md). Their
  upstream issues are `fastrevmd-lab/mecmcp` issues 96 through 154.

## Infrastructure

- Proxmox node: `pve2`
- LXC VMID: `606`
- Hostname: `rustsdcmcp-606`
- Operating system: Debian GNU/Linux 13
- Address: `192.168.1.211/24`
- Gateway: `192.168.1.1`
- DNS: `rustsdcmcp.mechub.org`
- Resources: 1 CPU core, 512 MiB memory, 512 MiB swap, 4 GiB
  `local-lvm` root disk
- Isolation: unprivileged LXC with `nesting=1`, Proxmox interface firewall
  enabled, and start-on-boot enabled

VMID 602 was not modified. It remained the running `journal-collector`
container on `pve3` throughout this deployment.

## Service and security acceptance

- `rustsdcmcp.service` is enabled and active as the non-root
  `rustsdcmcp:rustsdcmcp` account.
- The only MCP listener is `127.0.0.1:30032`; a connection to port 30032 from
  the LAN was rejected.
- `systemd-analyze security` reported an overall exposure level of `1.5 OK`.
- Missing and fixed-invalid bearer tokens returned HTTP 401 with a Bearer
  challenge and credential-free JSON.
- Authenticated MCP initialization succeeded through an SSH tunnel.
- `tools/list` returned exactly the 14 explicitly granted read tools.
  `prepare_sdc_policy_deploy`, `approve_sdc_change_set`, and
  `apply_sdc_change_set` were absent.
- The bounded `get_sdc_tenant_scope` call succeeded.
- The bounded `list_sdc_devices` call with `from=0,size=1` succeeded.
- JSON audit records attributed both calls to the human `lab-read` token,
  recorded an allowed/successful outcome, and HMAC-redacted the tenant target.
  The cleartext target alias was absent from the audit target field.
- After a service restart, authenticated initialization and the bounded tenant
  scope call succeeded again.

No SDC preview submission, approval, apply, deployment submission, or other SDC
mutation was attempted.

## Audit retention exception

Persistent journald is enabled with the packaged 512 MiB cap. Remote journal
forwarding is not configured because no destination has been selected. This is
an explicit temporary lab exception and must be reviewed before any promotion
or production traffic. Unprivileged LXC journal forward-secure sealing is not
available.

## 2026-07-30 lab.2 upgrade

The sections above are the immutable record of VMID 606's original deployment.
On 2026-07-30, the same container was upgraded in place to the private
[`v0.1.0-lab.2` prerelease](https://github.com/fastrevmd-lab/rustsdcmcp/releases/tag/v0.1.0-lab.2):

- Source commit:
  `190dab9a4e8ff546b06403999afbaaacfe96633c`
- Archive:
  `rustsdcmcp_0.1.0-lab.20260730.190dab9a4e8f_amd64.tar.gz`
- Archive SHA-256:
  `7ce2b10c27d422aebb18488f08b7a12419e543ad33ff95b1ec16e2cf014a06d5`
- Installed binary SHA-256:
  `dc839d43cff890d69a9fe572518c4981a4f23a5db7fada3d8cdbf4d46746ccf0`
- mecmcp reference: `changeset-v0.3.7`
- CI source: successful `main` run `30506333708`

Before the upgrade, Proxmox snapshot `pre-lab2-20260730` was created on
`pve2`. It records the transition from source
`44a28f55598ad038389d9f734e11e0f520b82837` and mecmcp `0.3.6`; the snapshot
was retained after acceptance.

The release assets were downloaded independently after publication and passed
their checksum, package smoke, `BUILD-INFO`, SBOM, and packaged-binary digest
checks. The installer then preserved the content of the live SDC
configuration, external credential file, bearer-token store, and audit HMAC
key. The optional change-set state file was absent before the upgrade and
remained absent, so no live planned or approved operation required migration.

After the upgrade:

- `rustsdcmcp.service` remained enabled and active as
  `rustsdcmcp:rustsdcmcp`.
- The installed binary exactly matched the published package.
- The sole listener was `127.0.0.1:30032`; LAN access to port 30032 was
  rejected.
- `systemd-analyze security` again reported an overall exposure level of
  `1.5 OK`.
- Missing and fixed-invalid bearer tokens returned HTTP 401 with a Bearer
  challenge and no credential echo.
- Credential-based startup tenant validation succeeded through the normal
  service startup path.
- A one-shot listener assertion initially raced the `Type=simple` service
  startup. A bounded readiness check against the actual listener condition
  then passed; the service itself had started successfully.
- The Proxmox description was updated with the lab.2 source and mecmcp
  provenance, and the root-only deployment staging directory was removed.

The protected one-time MCP bearer value was not read or reconstructed during
this upgrade, so authenticated `tools/list` and SDC read calls were not
replayed. Their original qualified results remain recorded above. No SDC
preview submission, approval, apply, deployment submission, or other SDC
mutation was attempted during the upgrade.

## Public release blocker

This build must not receive a stable public tag or promoted production image
while any of the 59 compatibility symbols remain implemented locally. Private
collaborator lab prereleases are explicitly non-production. All 59 symbols
must first ship together in one coherent mecmcp release, after which
rustsdcmcp must replace the temporary implementation with the standardized
library API and pass the complete test, package, security, and live read-only
acceptance suite again.
