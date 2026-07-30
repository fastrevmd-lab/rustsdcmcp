# VMID 606 Direct-LAN MCP Access Design

## Context

VMID 606 runs the private `v0.1.0-lab.2` prerelease on `pve2` at
`192.168.1.211`, with DNS `rustsdcmcp.mechub.org`. The packaged systemd unit
binds the authenticated Streamable HTTP service to `127.0.0.1:30032`.
Codex and Claude currently reach it through a workstation user service that
forwards `127.0.0.1:39032` over SSH.

The internal lab does not require the SSH-tunnel layer. Plain HTTP on the
trusted LAN is explicitly accepted for this deployment. Bearer authentication,
per-client attribution, and exact read-only tool scopes remain required.

## Goals

- Expose the MCP service directly at
  `http://rustsdcmcp.mechub.org:30032/mcp`.
- Bind only the LXC address `192.168.1.211`, not every interface.
- Keep the existing Codex and Claude tokens separate and limited to the exact
  14 read tools.
- Preserve the packaged systemd hardening and the live SDC credential,
  configuration, token store, HMAC key, and change-set state.
- Remove the workstation SSH tunnel only after both clients pass direct-LAN
  acceptance.
- Record the exposure-boundary change without rewriting the immutable original
  deployment and lab.2 upgrade history.

## Non-goals

- TLS or a reverse proxy for this temporary internal-lab endpoint.
- Binding to `0.0.0.0`.
- Adding an unauthenticated HTTP path.
- Granting any write tool to Codex or Claude.
- Calling an SDC preview, approval, apply, deploy, or other mutation.
- Changing the packaged default, which remains loopback-only.
- Resolving the separately observed stdio behavior that advertises all 17
  tools; stdio is not used for either client.

## Approaches considered

### Selected: exact-address HTTP bind

Bind the service to `192.168.1.211:30032`, retain bearer authentication, and
explicitly allow the DNS authority `rustsdcmcp.mechub.org:30032`. This removes
the tunnel while limiting exposure to the one intended LXC interface.

### Rejected: all-interface HTTP bind

Binding `0.0.0.0:30032` is simpler but would expose the service on any future
interface added to the container. The exact-address bind has no meaningful
operational cost.

### Deferred: TLS or reverse proxy

TLS would protect bearer tokens from LAN observation, but it adds certificate
and proxy lifecycle work that is not required for today's internal-lab use.
It remains the appropriate next step before any less-trusted network exposure.

## Service configuration

Create a deployment-specific systemd drop-in at:

```text
/etc/systemd/system/rustsdcmcp.service.d/lan.conf
```

The drop-in clears and replaces `ExecStart` with the packaged command plus:

```text
--host 192.168.1.211
--port 30032
--allow-insecure-bind
--allowed-host rustsdcmcp.mechub.org:30032
```

All existing authentication, audit, HMAC-redaction, token-store, and device
mapping arguments remain unchanged. The explicit `--allow-insecure-bind`
records the accepted plain-HTTP lab exception in executable configuration.
The drop-in keeps the package-owned unit unchanged and can be removed cleanly
to restore the default.

No Proxmox or guest firewall rule is broadened in advance. If the existing
policy blocks the exact LAN listener after a successful bind, implementation
stops and reports that boundary rather than opening a wider rule
automatically.

## Client routing and credentials

Codex and Claude will both use:

```text
http://rustsdcmcp.mechub.org:30032/mcp
```

The existing credentials remain unchanged:

- `codex-lab-read`: provider `openai`, tier `public`, actor type `agent`,
  on behalf of `mharman`.
- `claude-lab-read`: provider `anthropic`, tier `public`, actor type `agent`,
  on behalf of `mharman`.

Each token retains the exact 14 read tools. The three write tools
`prepare_sdc_policy_deploy`, `approve_sdc_change_set`, and
`apply_sdc_change_set` must be absent from each client's `tools/list`.
No token or SDC credential is written into this repository or displayed in
diagnostics.

The final data path is:

```text
Codex or Claude
  -> internal LAN HTTP with bearer authentication
  -> rustsdcmcp.mechub.org / 192.168.1.211:30032
  -> rustsdcmcp.service
  -> bounded SDC read API
```

## Migration sequence

1. Verify DNS, VMID 606 placement, current service health, protected-file
   metadata, and the existing client token scopes.
2. Create Proxmox snapshot `pre-lan-bind-20260730`.
3. Stage and validate the systemd drop-in without reading secret contents.
4. Reload systemd, restart the service, and wait for the exact LAN listener.
5. Verify missing and fixed-invalid bearer requests return credential-free
   HTTP 401 responses.
6. Verify each existing token directly over the LAN with initialize,
   `tools/list`, and one bounded `get_sdc_tenant_scope` call.
7. Change Codex and Claude from the local tunnel URL to the DNS URL.
8. Re-run both client acceptance paths from their stored configurations.
9. Disable and remove `rustsdcmcp-tunnel.service`, then confirm local port
   `39032` is closed.
10. Append the direct-LAN change to the deployment record and update current
    README and operations guidance in pull request 4.

The old tunnel remains active until step 8 succeeds, so client routing has a
known-good fallback throughout the migration.

## Acceptance criteria

- DNS resolves `rustsdcmcp.mechub.org` to only `192.168.1.211`.
- `rustsdcmcp.service` is enabled and active as
  `rustsdcmcp:rustsdcmcp`.
- Exactly one port-30032 listener exists, at `192.168.1.211:30032`.
- The installed binary still matches the published lab.2 digest.
- Protected configuration, credential, token, HMAC, and optional state
  contents are unchanged by the service configuration update.
- Missing and invalid bearer requests return HTTP 401 with a Bearer challenge
  and no credential echo.
- Codex and Claude each see exactly the 14 approved read tools.
- Both clients complete `get_sdc_tenant_scope`; audit records retain their
  distinct provider and actor attribution.
- No SDC mutation is attempted.
- `rustsdcmcp-tunnel.service` is disabled and absent, and nothing listens on
  workstation port `39032`.
- The pre-change snapshot remains available after acceptance.

## Failure handling and rollback

If the new process fails before direct client acceptance, remove the drop-in,
reload systemd, and restart the original loopback service. The still-active
SSH tunnel then restores the prior client path.

If the service succeeds but either client configuration fails, restore that
client's URL to `http://127.0.0.1:39032/mcp`; do not remove the tunnel.

The Proxmox snapshot is retained as a last-resort rollback point. Snapshot
rollback is not automatic because it would also revert later token and
deployment state; the systemd drop-in is the preferred recovery boundary.

## Documentation

The original 2026-07-29 deployment and the 2026-07-30 lab.2 upgrade remain
historically accurate. A new dated section records the later LAN exposure
change. Current README and operations text will describe the direct internal
lab endpoint while keeping loopback binding as the packaged default and plain
HTTP as an explicit lab-only exception.
