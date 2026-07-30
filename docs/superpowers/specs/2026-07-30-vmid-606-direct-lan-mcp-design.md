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

Bind the final service to `192.168.1.211:30032`, retain bearer authentication,
and explicitly allow the DNS authority `rustsdcmcp.mechub.org:30032`. During
migration, retain a working rollback path by temporarily allowing both that
authority and `127.0.0.1:39032`, and by retargeting the existing tunnel to the
exact LAN listener before client routing changes. This removes the tunnel only
after final direct-client acceptance while limiting final exposure to the one
intended LXC interface.

### Rejected: all-interface HTTP bind

Binding `0.0.0.0:30032` is simpler but would expose the service on any future
interface added to the container. The exact-address bind has no meaningful
operational cost.

### Deferred: TLS or reverse proxy

TLS would protect bearer tokens from LAN observation, but it adds certificate
and proxy lifecycle work that is not required for today's internal-lab use.
It remains the appropriate next step before any less-trusted network exposure.

## Service configuration

Create separately named, deployment-specific staging drop-ins:

```text
/tmp/rustsdcmcp-lan-bind-20260730/transition-lan.conf
/tmp/rustsdcmcp-lan-bind-20260730/final-lan.conf
```

The transition drop-in clears and replaces `ExecStart` with the packaged
command plus:

```text
--host 192.168.1.211
--port 30032
--allow-insecure-bind
--allowed-host rustsdcmcp.mechub.org:30032
--allowed-host 127.0.0.1:39032
```

All existing authentication, audit, HMAC-redaction, token-store, and device
mapping arguments remain unchanged. The explicit `--allow-insecure-bind`
records the accepted plain-HTTP lab exception in executable configuration.
After both clients pass on the direct DNS URL, replace the transition drop-in
with the separately staged final drop-in. The final drop-in has the same
command but only this authority flag:

```text
--allowed-host rustsdcmcp.mechub.org:30032
```

Install each selected staging file as
`/etc/systemd/system/rustsdcmcp.service.d/lan.conf`. The package-owned unit
remains unchanged and removing the deployment drop-in cleanly restores the
packaged loopback behavior.

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
3. Stage and validate the separate transition and final systemd drop-ins and
   the edited tunnel unit without reading secret contents. The staged tunnel
   retains local `127.0.0.1:39032` but changes its remote target from
   `127.0.0.1:30032` to `192.168.1.211:30032`; do not restart it yet.
4. Install the transition dual-Host drop-in, reload systemd, restart the
   server, and wait for the exact LAN listener.
5. Reload and restart the user tunnel from its staged unit, then prove its
   `127.0.0.1:39032` path still provides authenticated access. It is the
   working fallback before direct endpoint qualification or client migration.
6. Verify missing and fixed-invalid bearer requests return credential-free
   HTTP 401 responses.
7. Verify each existing token directly over the LAN with initialize,
   `tools/list`, and one bounded `get_sdc_tenant_scope` call.
8. Change Codex and Claude from the local tunnel URL to the DNS URL, retaining
   the active, proven fallback.
9. Re-run both client acceptance paths from their stored configurations.
10. Replace the transition drop-in with the staged final DNS-only drop-in and
    restart the server. Verify direct Codex and Claude access again. If this
    finalization fails, restore the dual-Host transition drop-in and retain
    the running tunnel.
11. Disable and remove `rustsdcmcp-tunnel.service`, then confirm local port
    `39032` is closed, only after final DNS-only service and both direct
    clients pass.
12. Append the direct-LAN change to the deployment record and update current
    README and operations guidance in pull request 4.

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
- Before direct endpoint qualification, the retargeted local tunnel completes
  authenticated access through `127.0.0.1:39032`.
- Final `lan.conf` accepts only Host authority
  `rustsdcmcp.mechub.org:30032`; the transition-only `127.0.0.1:39032`
  authority is absent.
- No SDC mutation is attempted.
- `rustsdcmcp-tunnel.service` is disabled and absent, and nothing listens on
  workstation port `39032`.
- The pre-change snapshot remains available after acceptance.

## Failure handling and rollback

If server rebinding or tunnel retargeting fails, remove the deployment
drop-in, reload systemd, and restart the packaged loopback service. Restore
the original tunnel target `127.0.0.1:30032`, ensure its active and enabled
state, and restore both clients' original
`http://127.0.0.1:39032/mcp` URLs. The separately staged transition and final
drop-ins make this rollback independent of reconstructing prior content.

If the service succeeds but either client configuration fails, restore that
client's URL to `http://127.0.0.1:39032/mcp`; do not remove the proven,
retargeted tunnel. If final DNS-only configuration fails, restore the
dual-Host transition drop-in and retain the running tunnel.

The Proxmox snapshot is retained as a last-resort rollback point. Snapshot
rollback is not automatic because it would also revert later token and
deployment state; the systemd drop-in is the preferred recovery boundary.

## Documentation

The original 2026-07-29 deployment and the 2026-07-30 lab.2 upgrade remain
historically accurate. A new dated section records the later LAN exposure
change. Current README and operations text will describe the direct internal
lab endpoint while keeping loopback binding as the packaged default and plain
HTTP as an explicit lab-only exception.
