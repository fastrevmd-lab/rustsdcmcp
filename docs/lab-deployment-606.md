# VMID 606 Lab Deployment

> **Historical record — this deployment no longer exists.** LXC 606 was
> destroyed during the 2026-08-12 VMID renumber, and the DNS name recorded
> below stopped resolving with it. Nothing here describes current state; it is
> kept as the record of what was deployed on 2026-07-29. For how to reach a
> running deployment, see [`operations.md`](operations.md).

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
- Compatibility boundary: 59 temporary, issue-linked Rust symbols were recorded
  one-to-one in a compatibility ledger. Their upstream issues were
  `fastrevmd-lab/mecmcp` issues 96 through 154.

> **Superseded 2026-08-12.** This file is the immutable acceptance record for
> the 2026-07-29 deployment and the statements above were true then. They no
> longer describe the repository. The `compat/` layer was deleted in #36 on the
> move to mecmcp 0.7.2, and `docs/mecmcp-compatibility.{md,tsv}` were removed in
> `369f9bb` on the move to 0.8.0 — which is why the ledger is named here but no
> longer linked. Current state is in [`../README.md`](../README.md) and
> [`operations.md`](operations.md).

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

## Public release blocker

This build must not receive a public tag, GitHub release, or promoted release
image while any of the 59 compatibility symbols remain implemented locally.
All 59 symbols must first ship together in one coherent mecmcp release, after
which rustsdcmcp must replace the temporary implementation with the
standardized library API and pass the complete test, package, security, and
live read-only acceptance suite again.

> **Superseded 2026-08-12.** The condition above was met. mecmcp 0.8.0 replaced
> the temporary implementation, the `compat/` layer is gone, and this specific
> blocker no longer applies. Remaining blockers to a public release are
> operational and are tracked in [`../README.md`](../README.md) under Roadmap.
> This paragraph is retained because it records what gated *this* build.
