# Operations

## Lab deployment boundary

This package is for a controlled lab deployment only. Its archive is named
`rustsdcmcp_0.1.0-lab.YYYYMMDD.<source-commit-12>_amd64.tar.gz` and is paired
with a sibling `.sha256` file under `dist/<full-source-commit>/`. Select the
approved full source commit explicitly; never glob across `dist/`. The checksum
contains the archive basename, so verify it from that commit directory:

```console
source_commit="$(git rev-parse HEAD)"
artifact_dir="dist/$source_commit"
mapfile -t archives < <(find "$artifact_dir" -maxdepth 1 -type f -name 'rustsdcmcp_*_amd64.tar.gz' -print)
test "${#archives[@]}" -eq 1
(cd "$artifact_dir" && sha256sum -c "$(basename "${archives[0]}").sha256")
```

Current source and future lab packages pin all five shared `mecmcp` crates to
`changeset-v0.3.7`. The existing private `v0.1.0-lab.1` prerelease and VMID
606 remain `changeset-v0.3.6` artifacts; their immutable acceptance record is
[`lab-deployment-606.md`](lab-deployment-606.md). This repository still has 59
temporary compatibility symbols, each tracked in
[`mecmcp-compatibility.tsv`](mecmcp-compatibility.tsv). There is no public
`v0.1.0` release: do not publish, tag, or promote a lab archive until one
coherent upstream `mecmcp` release replaces every ledger entry.

## Installed layout and configuration

The installer creates the service account and these paths:

| Path | Required purpose and final mode/owner |
|---|---|
| `/etc/rustsdcmcp/sdc.json` | Live SDC configuration; `0640 root:rustsdcmcp` |
| `/etc/rustsdcmcp/credentials.env` | SDC credential environment; `0600 root:root` |
| `/etc/rustsdcmcp/tokens.json` | Digest-only bearer-token store; `0600 rustsdcmcp:rustsdcmcp` |
| `/etc/rustsdcmcp/audit-hmac.key` | Audit redaction key; `0600 rustsdcmcp:rustsdcmcp` |
| `/var/lib/rustsdcmcp/changeset-state.json` | Durable change-set state under the `0700 rustsdcmcp:rustsdcmcp` state directory |

The package supplies only `sdc.json.example`; an operator must create the live
configuration and credentials before manually starting the service. Never put
the credential into JSON or record it in command history.

## Listener and lab access

The systemd unit binds the Streamable HTTP endpoint only to
`http://127.0.0.1:30032/mcp`. Do not expose this listener directly. The lab DNS
name is exactly `rustsdcmcp.mechub.org`; access it through an authenticated SSH
tunnel from an authorized workstation:

```console
ssh -N -L 30032:127.0.0.1:30032 root@rustsdcmcp.mechub.org
```

Point the local MCP client at `http://127.0.0.1:30032/mcp` while the tunnel is
open.

## Egress policy

> **The systemd egress directives are probably inert on the recommended
> deployment.** Read this section before treating them as a control.

Inbound is loopback-only, but the service holds a tenant-wide SDC credential,
so its *outbound* reach matters. The unit declares:

```
IPAddressAllow=localhost
IPAddressDeny=169.254.0.0/16 fe80::/10
IPAccounting=yes
```

### Whether it enforces at all

systemd implements `IPAddress*` with cgroup eBPF. An **unprivileged LXC — the
container type this project recommends — usually cannot attach those programs
without host delegation, and systemd fails open**: it logs a warning and runs
the unit with no filter whatsoever. Nothing about the service's behaviour
reveals this, and `systemd-analyze security` cannot either — it scores the
*declaration*, so the unit looks hardened whether or not a single packet is
filtered.

The installer therefore probes actual enforcement and prints one of:

- `egress filter: ENFORCED`
- `egress filter: NOT ENFORCED` — with guidance to enforce at the hypervisor
- `egress filter: UNKNOWN` — the probe could not run; nothing is claimed

It uses IP accounting, which rides the same BPF attachment, so a populated
counter proves the filter attached. Check it any time:

```console
systemctl show rustsdcmcp.service -p IPEgressBytes --value
```

`[no data]` means the egress directives are doing nothing. Set
`SDCMCP_REQUIRE_EGRESS_FILTER=1` to make the installer refuse a host that
cannot enforce.

**When it is not enforced, put the control at the hypervisor.** On Proxmox,
that is the container's interface firewall: deny `169.254.0.0/16`, deny the
local subnet except your resolver, allow 443 outbound. That layer actually
holds for an unprivileged container; the unit directives are defence in depth
for hosts where they attach (VMs, bare metal, privileged containers).

### What is denied, and what is not

`169.254.0.0/16` covers the cloud metadata endpoint — the standard route from a
compromised HTTP client to stolen credentials — and no legitimate resolver
lives there, so it is safe to deny on any install. `fe80::/10` is the IPv6
equivalent.

**RFC1918 ranges are deliberately not denied by default.** This package
installs on networks whose resolver may sit in any of `10.0.0.0/8`,
`172.16.0.0/12`, or `192.168.0.0/16`; denying the resolver stops the service
resolving the SDC endpoint at all — a hard outage, not a hardening. Add them
per-site, together with an explicit allow for the resolver you actually use.

A denylist rather than an allowlist is deliberate regardless: the SDC API is a
cloud address whose IPs rotate, so `IPAddressDeny=any` plus an allowlist would
fail on the first rotation. `systemd-analyze security` reports "Service does
not define an IP address allow list" for this reason — expected, not an
oversight.

### Tightening per site

Use a drop-in rather than editing the shipped unit — the installer replaces it:

```console
sudo systemctl edit rustsdcmcp.service
```

```ini
[Service]
IPAddressAllow=192.168.1.1
IPAddressDeny=10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 fc00::/7
```

Substitute your own resolver address. This only has effect on a host where the
probe above reports `ENFORCED`.

systemd checks `IPAddressAllow=` **first** and grants on any match, then checks
`IPAddressDeny=`, then defaults to granting. It is allow-before-deny, *not*
longest-prefix — so the `/32` above works because it is an allow, not because
it is narrower. The practical consequence when adapting this: a broad
`IPAddressAllow=` silently defeats every narrower deny, so keep allow entries
as tight as possible.

Confirm DNS still resolves before considering the change good:

```console
sudo systemctl restart rustsdcmcp.service
sudo journalctl -u rustsdcmcp.service -n 20 --no-pager
```

A startup that fails at `verifying SDC credential tenant scope` is the symptom
of a denied resolver.

## Initial read-only token

Create the initial token as root, and redirect the one-time token value to a
mode-`0600` local file without displaying it. Do **not** use `runuser`: mecmcp
atomically writes in `/etc/rustsdcmcp`, preserving the existing
`rustsdcmcp`-owned `0600` destination while root has the authority needed to
perform the same-directory replacement.

```console
sudo /usr/local/bin/rustsdcmcp token add \
  --tokens-file /etc/rustsdcmcp/tokens.json \
  --device-mapping /etc/rustsdcmcp/sdc.json \
  --name lab-read \
  --devices production \
  --tools get_sdc_tenant_scope,list_sdc_devices,get_sdc_device,list_sdc_firewall_policies,get_sdc_firewall_policy,list_sdc_nat_policies,get_sdc_nat_policy,list_sdc_resources,get_sdc_resource,get_sdc_preview_status,get_sdc_deploy_status,get_sdc_preview_device_result,get_sdc_deploy_device_result,get_sdc_change_set \
  --actor-type human > /secure/local/path/rustsdcmcp-lab-read-token
```

This is an explicit 14-tool read-only grant; do not use wildcard tool scopes
and do not add a write tool to the initial lab token. Confirm afterward that
`/etc/rustsdcmcp/tokens.json` remains `0600 rustsdcmcp:rustsdcmcp`.

## Audit retention and forwarding

The package installs persistent journald storage with a 512 MiB cap and emits
redacted JSON audit events to journald. Remote journal forwarding is required
before production traffic. The approved lab deployment has a temporary
exception: it may retain the persistent local journal without remote forwarding
while it remains lab-only; review that exception before any promotion.

## Startup

`rustsdcmcp` loads one JSON tenant configuration through the shared runtime's
`-f` option. It then:

1. installs the `ring` rustls provider;
2. resolves the SDC credential from `credential_env`;
3. builds an HTTPS-only client with redirects and environment proxies disabled;
4. calls `GET /api/v2/tenant/tenant-id`;
5. refuses startup unless the response matches `expected_tenant_id`;
6. loads `mecmcp-changeset` state and the optional bearer-token store;
7. starts stdio or the shared hardened Streamable HTTP listener.

No API endpoint, token, or secret is accepted from MCP tool arguments.

## Read tools

Every list tool requires an explicit positive `size` no larger than
`max_page_size`. SDC interprets `size=0` as unbounded, so the server rejects it.
Responses are streamed under `max_response_bytes`; oversized bodies fail
without returning partial JSON.

SDC HTTP 429 is surfaced as resource exhaustion. It is not automatically
retried because the API uses the same status for rate limiting and responses
that exceed service limits.

## Policy deployment

There is no directly callable deploy tool.

1. `prepare_sdc_policy_deploy` submits the exact preview request, polls its
   documented status to a terminal state, fetches each per-device CLI result,
   and creates a change set binding the deploy request and preview digest.
2. A different authenticated principal calls `approve_sdc_change_set` with the
   exact plan digest before its TTL expires.
3. The original owner calls `apply_sdc_change_set` with both digests.
4. `mecmcp-changeset` revalidates ownership, approval, fingerprints, and policy
   signature before the SDC deploy request is submitted.
5. The server polls the deploy job. `COMPLETED` is success;
   `PARTIAL_SUCCESS`/`FAILED` are reconciled failures. Cancellation or deadline
   after submission is persisted as indeterminate.

Write tools require an authenticated bearer token and exact tool grants.
Wildcard tool scope deliberately excludes them. Stdio and `--allow-no-auth`
are read-only.

## Persistence and recovery

Set `changeset_state_file` to an absolute path on durable storage. If omitted,
state is in memory and planned/approved operations do not survive restart.

An indeterminate deployment means the request may have reached SDC but this
process did not observe a terminal state. Reconcile it using
`get_sdc_deploy_status`, the per-device result tool, and the SDC portal before
planning another deployment.

The SDC API does not expose a candidate rollback primitive for this workflow.
Rollback is therefore reported as unsupported rather than guessed.

## Token reload

On Unix, SIGHUP reloads the digest-only bearer-token file atomically. A failed
reload keeps the previous verified snapshot.
