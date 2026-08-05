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

Inbound is loopback-only, but the service also holds a tenant-wide SDC
credential, so its *outbound* reach matters. The unit denies the ranges it
provably never needs:

```
IPAddressAllow=localhost
IPAddressDeny=169.254.0.0/16 fe80::/10 fc00::/7 10.0.0.0/8 172.16.0.0/12
```

`169.254.0.0/16` is the one that matters most: it covers the cloud metadata
endpoint, the standard target for turning a compromised HTTP client into
credential theft. The RFC1918 ranges blunt lateral movement from this container
into the rest of a network.

This is a denylist, not an allowlist, and that is deliberate. The SDC API is a
cloud address whose IPs rotate, so `IPAddressDeny=any` plus an allowlist would
fail on the first rotation. `systemd-analyze security` will report
"Service does not define an IP address allow list" for this reason — expected,
not an oversight.

**`192.168.0.0/16` is deliberately not denied.** The packaged deployment
resolves DNS through its LAN gateway (`192.168.1.1` for VMID 606), and denying
that range stops the service resolving the SDC endpoint at all — a hard outage,
not a hardening. The consequence is that the local `/24` stays reachable from
this container.

If your resolver is external, or you know its address, tighten this with a
drop-in rather than editing the shipped unit — the installer replaces it:

```console
sudo systemctl edit rustsdcmcp.service
```

```ini
[Service]
IPAddressAllow=192.168.1.1
IPAddressDeny=192.168.0.0/16
```

More specific rules win, so the resolver stays reachable while the rest of the
LAN is refused. Confirm DNS still resolves before considering the change good:

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
