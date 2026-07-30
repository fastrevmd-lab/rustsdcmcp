# VMID 606 Direct-LAN MCP Access Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the workstation SSH tunnel with direct authenticated internal-LAN access to VMID 606 while preserving exact read-only client scopes and a clean rollback path.

**Architecture:** Stage separate transition and final deployment-only systemd drop-ins that bind `rustsdcmcp` to the LXC's exact address, retain bearer authentication, and explicitly record the accepted plain-HTTP lab exception. Before rebinding, stage an edit that retargets the existing local tunnel at the exact LAN listener without restarting it. After the LAN listener is healthy, restart and prove that tunnel fallback, then qualify the direct route and migrate clients. Finalize DNS-only Host acceptance and re-verify both clients before removing the tunnel.

**Tech Stack:** Proxmox VE LXC snapshots, systemd, OpenSSH, Streamable HTTP MCP, mecmcp bearer-token scopes and attribution, Codex CLI, Claude Code CLI, Bash, `curl`, `jq`, GitHub Actions.

## Global Constraints

- Work only in `/home/mharman/Projects/rustsdcmcp/.worktrees/lab2-606-upgrade` for repository changes.
- Do not change, branch, or commit anything in the `mecmcp` repository.
- VMID 606 remains on `pve2` at `192.168.1.211`; DNS remains exactly `rustsdcmcp.mechub.org`.
- Bind only `192.168.1.211:30032`, never `0.0.0.0`.
- Plain HTTP is accepted only for this internal-lab deployment and requires `--allow-insecure-bind`.
- Bearer authentication remains mandatory.
- Codex and Claude retain separate tokens with exactly 14 read tools; never print, log, or commit token values.
- Never read or display the SDC API credential, token digests, HMAC key, tenant ID, or change-set contents.
- Never call `prepare_sdc_policy_deploy`, `approve_sdc_change_set`, `apply_sdc_change_set`, or another SDC mutation.
- During migration, the server accepts both Host authorities
  `rustsdcmcp.mechub.org:30032` and `127.0.0.1:39032`; final state accepts
  only `rustsdcmcp.mechub.org:30032`.
- Stage the tunnel-unit retarget from remote `127.0.0.1:30032` to remote
  `192.168.1.211:30032`, retaining local `127.0.0.1:39032`, before server
  rebind and without restarting it.
- Do not qualify the direct endpoint or migrate either client until the
  retargeted tunnel provides authenticated access.
- Keep the proven SSH tunnel active through final DNS-only server and direct
  client verification; remove it only afterwards.
- Keep the pre-change Proxmox snapshot after acceptance; do not create an LXC dump.
- Preserve the original deployment and lab.2 upgrade history in documentation.

---

### Task 1: Preflight the live deployment and create the rollback snapshot

**Files:**
- Read: `/etc/systemd/system/rustsdcmcp.service` on VMID 606
- Read: `/home/mharman/.codex/config.toml`
- Read: `/home/mharman/.claude.json`
- Read: `/home/mharman/.config/systemd/user/rustsdcmcp-tunnel.service`
- Read: `docs/superpowers/specs/2026-07-30-vmid-606-direct-lan-mcp-design.md`

**Interfaces:**
- Consumes: the running lab.2 deployment, direct-LAN design, current client registrations, and Proxmox snapshot API.
- Produces: a verified baseline and snapshot `pre-lan-bind-20260730`.

- [ ] **Step 1: Confirm the isolated worktree and clean branch**

Run:

```bash
worktree=/home/mharman/Projects/rustsdcmcp/.worktrees/lab2-606-upgrade
git -C "$worktree" status --short --branch
git -C "$worktree" rev-parse --show-toplevel
git -C "$worktree" branch --show-current
```

Expected: branch `docs/lab2-606-upgrade`, no uncommitted files, and the exact
worktree path.

- [ ] **Step 2: Verify DNS is singular and exact**

Run:

```bash
mapfile -t sdc_addresses < <(
  getent ahostsv4 rustsdcmcp.mechub.org |
    awk '{print $1}' |
    sort -u
)
test "${#sdc_addresses[@]}" -eq 1
test "${sdc_addresses[0]}" = 192.168.1.211
```

Expected: only `192.168.1.211`.

- [ ] **Step 3: Verify VMID 606 and snapshot-name availability**

Use the Proxmox connector:

```text
get_container_config(node="pve2", vmid="606")
get_container_ip(node="pve2", vmid="606")
list_snapshots(node="pve2", vmid="606", vm_type="lxc")
```

Require hostname `rustsdcmcp-606`, address `192.168.1.211`, Debian AMD64,
unprivileged LXC, and no existing snapshot named `pre-lan-bind-20260730`.

- [ ] **Step 4: Verify the current service and protected-file metadata**

Run:

```bash
ssh -T -o BatchMode=yes root@rustsdcmcp.mechub.org 'set -euo pipefail
test "$(systemctl is-enabled rustsdcmcp.service)" = enabled
test "$(systemctl is-active rustsdcmcp.service)" = active
test ! -e /etc/systemd/system/rustsdcmcp.service.d/lan.conf
test "$(sha256sum /usr/local/bin/rustsdcmcp | awk '"'"'{print $1}'"'"')" = \
  dc839d43cff890d69a9fe572518c4981a4f23a5db7fada3d8cdbf4d46746ccf0
ss -lnt | awk '"'"'$4 == "127.0.0.1:30032" {found=1} END {exit !found}'"'"'
for path in \
  /etc/rustsdcmcp/sdc.json \
  /etc/rustsdcmcp/credentials.env \
  /etc/rustsdcmcp/tokens.json \
  /etc/rustsdcmcp/audit-hmac.key \
  /var/lib/rustsdcmcp/changeset-state.json
do
  if test -e "$path"; then
    stat -c "protected=%n owner=%U:%G mode=%a bytes=%s" "$path"
  else
    printf "protected=%s absent\n" "$path"
  fi
done'
```

Expected: enabled/active, exact lab.2 binary, only the loopback listener,
restrictive metadata, and no LAN drop-in.

- [ ] **Step 5: Verify the existing read-only client identities without secrets**

Run:

```bash
fish -c 'codex mcp get rustsdcmcp --json' |
  jq -e '
    .transport.url == "http://127.0.0.1:39032/mcp"
    and .transport.bearer_token_env_var == "RUSTSDCMCP_CODEX_TOKEN"
  ' >/dev/null

jq -e '
  .mcpServers.rustsdcmcp.url == "http://127.0.0.1:39032/mcp"
  and (.mcpServers.rustsdcmcp.headers.Authorization | startswith("Bearer "))
' /home/mharman/.claude.json >/dev/null

ssh -T -o BatchMode=yes root@rustsdcmcp.mechub.org \
  '/usr/local/bin/rustsdcmcp token list \
    --tokens-file /etc/rustsdcmcp/tokens.json \
    --device-mapping /etc/rustsdcmcp/sdc.json' |
  awk '
    $1 == "codex-lab-read" && $2 == "production" {codex=1}
    $1 == "claude-lab-read" && $2 == "production" {claude=1}
    END {exit !(codex && claude)}
  '
```

Expected: both clients use the tunnel and both read-only token names exist.

- [ ] **Step 6: Create and verify the Proxmox snapshot**

Use the Proxmox connector:

```text
create_snapshot(
  node="pve2",
  vmid="606",
  vm_type="lxc",
  snapname="pre-lan-bind-20260730",
  description="Before rustsdcmcp VMID 606 direct-LAN bind: lab.2 190dab9a4e8ff546b06403999afbaaacfe96633c, mecmcp 0.3.7, loopback to 192.168.1.211:30032",
  vmstate=false
)
list_snapshots(node="pve2", vmid="606", vm_type="lxc")
```

Expected: `pre-lan-bind-20260730` exists. Do not delete it later in this plan.

---

### Task 2: Stage the transition and final server configurations, then rebind

**Files:**
- Create temporarily: `/tmp/rustsdcmcp-lan-bind-20260730/transition-lan.conf`
- Create temporarily: `/tmp/rustsdcmcp-lan-bind-20260730/final-lan.conf`
- Create on VMID 606: `/etc/systemd/system/rustsdcmcp.service.d/lan.conf`
- Preserve on VMID 606: `/etc/systemd/system/rustsdcmcp.service`

**Interfaces:**
- Consumes: the verified loopback service and pre-change snapshot.
- Produces: an enabled, active service listening only on
  `192.168.1.211:30032`.

- [ ] **Step 1: Create the drop-in locally with `apply_patch`**

First create the explicit staging directory:

```bash
test ! -e /tmp/rustsdcmcp-lan-bind-20260730
install -d -m 0700 /tmp/rustsdcmcp-lan-bind-20260730
```

Then use `apply_patch` to create
`/tmp/rustsdcmcp-lan-bind-20260730/transition-lan.conf` with exactly:

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/rustsdcmcp --device-mapping /etc/rustsdcmcp/sdc.json --transport streamable-http --host 192.168.1.211 --port 30032 --tokens-file /etc/rustsdcmcp/tokens.json --allow-insecure-bind --allowed-host rustsdcmcp.mechub.org:30032 --allowed-host 127.0.0.1:39032 --audit-format json --audit-journald --audit-redact devices=hmac --audit-hmac-key-file /etc/rustsdcmcp/audit-hmac.key
```

Also create `/tmp/rustsdcmcp-lan-bind-20260730/final-lan.conf` with exactly:

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/rustsdcmcp --device-mapping /etc/rustsdcmcp/sdc.json --transport streamable-http --host 192.168.1.211 --port 30032 --tokens-file /etc/rustsdcmcp/tokens.json --allow-insecure-bind --allowed-host rustsdcmcp.mechub.org:30032 --audit-format json --audit-journald --audit-redact devices=hmac --audit-hmac-key-file /etc/rustsdcmcp/audit-hmac.key
```

- [ ] **Step 2: Validate the local drop-in**

Run:

```bash
grep -Fqx '[Service]' /tmp/rustsdcmcp-lan-bind-20260730/transition-lan.conf
grep -Fqx 'ExecStart=' /tmp/rustsdcmcp-lan-bind-20260730/transition-lan.conf
grep -Fqx \
  'ExecStart=/usr/local/bin/rustsdcmcp --device-mapping /etc/rustsdcmcp/sdc.json --transport streamable-http --host 192.168.1.211 --port 30032 --tokens-file /etc/rustsdcmcp/tokens.json --allow-insecure-bind --allowed-host rustsdcmcp.mechub.org:30032 --allowed-host 127.0.0.1:39032 --audit-format json --audit-journald --audit-redact devices=hmac --audit-hmac-key-file /etc/rustsdcmcp/audit-hmac.key' \
  /tmp/rustsdcmcp-lan-bind-20260730/transition-lan.conf
grep -Fqx '[Service]' /tmp/rustsdcmcp-lan-bind-20260730/final-lan.conf
grep -Fqx 'ExecStart=' /tmp/rustsdcmcp-lan-bind-20260730/final-lan.conf
grep -Fqx \
  'ExecStart=/usr/local/bin/rustsdcmcp --device-mapping /etc/rustsdcmcp/sdc.json --transport streamable-http --host 192.168.1.211 --port 30032 --tokens-file /etc/rustsdcmcp/tokens.json --allow-insecure-bind --allowed-host rustsdcmcp.mechub.org:30032 --audit-format json --audit-journald --audit-redact devices=hmac --audit-hmac-key-file /etc/rustsdcmcp/audit-hmac.key' \
  /tmp/rustsdcmcp-lan-bind-20260730/final-lan.conf
```

The exact-line checks are the local validation. A drop-in is not a
standalone unit, so validate the composed service with `systemd-analyze
verify rustsdcmcp.service` only after staging it in Step 4.

- [ ] **Step 3: Stage the validated drop-in on VMID 606**

Before continuing to Step 4, complete Task 3 Step 1 to stage the edited tunnel
unit without restarting it. This is deliberately before server rebinding.

Run:

```bash
ssh -T -o BatchMode=yes root@rustsdcmcp.mechub.org \
  'test ! -e /root/rustsdcmcp-lan-bind-20260730 &&
   install -d -m 0700 /root/rustsdcmcp-lan-bind-20260730'
scp -p /tmp/rustsdcmcp-lan-bind-20260730/transition-lan.conf \
  /tmp/rustsdcmcp-lan-bind-20260730/final-lan.conf \
  root@rustsdcmcp.mechub.org:/root/rustsdcmcp-lan-bind-20260730/
```

Expected: two root-owned regular staging files and no secret material. Never
reconstruct either configuration during rollback; select the named staged file.

- [ ] **Step 4: Install, restart, and compare protected content in one remote transaction**

Run the following quoted remote script:

```bash
ssh -T -o BatchMode=yes root@rustsdcmcp.mechub.org 'bash -s' <<'REMOTE'
set -euo pipefail
stage=/root/rustsdcmcp-lan-bind-20260730/transition-lan.conf
dropin_dir=/etc/systemd/system/rustsdcmcp.service.d
dropin="$dropin_dir/lan.conf"
protected_paths=(
  /etc/rustsdcmcp/sdc.json
  /etc/rustsdcmcp/credentials.env
  /etc/rustsdcmcp/tokens.json
  /etc/rustsdcmcp/audit-hmac.key
  /var/lib/rustsdcmcp/changeset-state.json
)
declare -A before=()
for path in "${protected_paths[@]}"; do
  if [[ -e "$path" ]]; then
    [[ -f "$path" && ! -L "$path" ]]
    before["$path"]="sha256:$(sha256sum "$path" | awk '{print $1}')"
  else
    before["$path"]=absent
  fi
done

[[ -f "$stage" && ! -L "$stage" ]]
[[ ! -e "$dropin" ]]
install -d -m 0755 "$dropin_dir"
install -o root -g root -m 0644 "$stage" "$dropin"
rollback_needed=1
rollback() {
  rc=$?
  if [[ $rollback_needed -eq 1 && -e "$dropin" ]]; then
    rm -- "$dropin"
    systemctl daemon-reload
    systemctl restart rustsdcmcp.service
  fi
  exit "$rc"
}
trap rollback ERR

systemctl daemon-reload
systemd-analyze verify rustsdcmcp.service
systemctl restart rustsdcmcp.service

ready=0
for _attempt in $(seq 1 50); do
  listener_count=$(ss -lnt | awk '$4 ~ /:30032$/ {count++} END {print count+0}')
  exact_count=$(ss -lnt | awk '$4 == "192.168.1.211:30032" {count++} END {print count+0}')
  if [[ $(systemctl is-active rustsdcmcp.service) == active &&
        $listener_count -eq 1 &&
        $exact_count -eq 1 ]]; then
    ready=1
    break
  fi
  sleep 0.1
done
[[ $ready -eq 1 ]]
[[ $(systemctl is-enabled rustsdcmcp.service) == enabled ]]
[[ $(sha256sum /usr/local/bin/rustsdcmcp | awk '{print $1}') == \
  dc839d43cff890d69a9fe572518c4981a4f23a5db7fada3d8cdbf4d46746ccf0 ]]

for path in "${protected_paths[@]}"; do
  if [[ ${before[$path]} == absent ]]; then
    [[ ! -e "$path" ]]
  else
    [[ -f "$path" && ! -L "$path" ]]
    after="sha256:$(sha256sum "$path" | awk '{print $1}')"
    [[ $after == "${before[$path]}" ]]
  fi
done

rollback_needed=0
trap - ERR
printf '%s\n' 'lan_bind=active exact_listener=yes protected_content=preserved'
REMOTE
```

Expected: exact LAN listener, exact lab.2 binary, and no protected-content
change. On failure, the script removes only the new drop-in and restores the
loopback service.

- [ ] **Step 5: Verify the effective unit without displaying secrets**

Run:

```bash
ssh -T -o BatchMode=yes root@rustsdcmcp.mechub.org \
  'systemctl show rustsdcmcp.service \
    -p User -p Group -p MainPID -p ExecMainStatus -p ActiveState -p SubState \
    --no-pager;
   systemctl cat rustsdcmcp.service;
   ss -lntp "sport = :30032"'
```

Expected: `rustsdcmcp:rustsdcmcp`, status zero, active/running, the explicit
drop-in, and only `192.168.1.211:30032`.

---

### Task 3: Retarget and prove the SSH tunnel fallback

**Files:**
- Stage locally: `/tmp/rustsdcmcp-lan-bind-20260730/rustsdcmcp-tunnel-transition.service`
- Modify after LAN listener health: `/home/mharman/.config/systemd/user/rustsdcmcp-tunnel.service`
- Preserve as rollback source: an exact staged copy of the original tunnel unit

**Interfaces:**
- Consumes: a healthy transition dual-Host listener and the existing enabled,
  active local tunnel.
- Produces: a proven authenticated fallback at local `127.0.0.1:39032` that
  forwards to remote `192.168.1.211:30032`.

- [ ] **Step 1: Stage the tunnel-unit edit before the server rebind**

Before Task 2 Step 4, copy the existing user unit to the named staging file
with mode `0600`, and use `apply_patch` to change only its remote forwarding
target from `127.0.0.1:30032` to `192.168.1.211:30032`. Retain the local
`127.0.0.1:39032` endpoint, all existing SSH identity and hardening options,
and the original unit as a separately named rollback copy. Validate that the
staged unit contains the new remote target and no old remote target. Do not
reload or restart the user tunnel in this step.

- [ ] **Step 2: Activate the staged retarget only after LAN listener health**

After Task 2 confirms the exact LAN listener, install the staged tunnel unit,
then run `systemctl --user daemon-reload` and
`systemctl --user restart rustsdcmcp-tunnel.service`. Require the unit to be
enabled and active and exactly one listener at `127.0.0.1:39032`. If this
fails, restore the original staged tunnel unit, reload and restart it, and
then restore packaged loopback server behavior by removing `lan.conf`, running
`systemctl daemon-reload`, and restarting `rustsdcmcp.service`.

- [ ] **Step 3: Prove authenticated fallback before direct qualification**

Reload each existing token without printing it, and run initialize,
`tools/list`, and bounded `get_sdc_tenant_scope` through
`http://127.0.0.1:39032/mcp` for each client. Require authenticated success,
the exact 14 read tools, and absent write tools. Clear in-memory tokens. Do
not proceed to direct endpoint qualification or change either client URL until
this proof succeeds.

- [ ] **Step 4: Complete rollback if either rebinding or retargeting failed**

Restore all four original states: remove the server deployment drop-in and
restart the packaged loopback service; install the original tunnel unit with
remote `127.0.0.1:30032`; ensure the tunnel is active and enabled; and restore
both client URLs to `http://127.0.0.1:39032/mcp`. Do not disable or delete the
tunnel during this rollback.

---

### Task 4: Qualify the direct authenticated LAN endpoint

**Files:**
- Create temporarily: `/tmp/rustsdcmcp-direct-lan-acceptance/`
- Read without displaying: Codex and Claude stored bearer values

**Interfaces:**
- Consumes: the exact-address listener and existing read-only credentials.
- Produces: credential-bound direct-LAN acceptance before any client routing
  change.

- [ ] **Step 1: Verify unauthenticated and fixed-invalid rejection**

Create an explicit mode-`0700` temporary directory, then send MCP initialize
requests to `http://rustsdcmcp.mechub.org:30032/mcp` without Authorization and
with `Authorization: Bearer rustsdcmcp-fixed-invalid`.

Require for both requests:

```text
HTTP status: 401
WWW-Authenticate: Bearer ...
Body: valid JSON object
Credential echo: absent
```

Use `curl --connect-timeout 5 --max-time 20`, and never print response bodies.

- [ ] **Step 2: Load the existing client tokens into shell variables without output**

Run:

```bash
codex_token=$(fish -c 'printf %s $RUSTSDCMCP_CODEX_TOKEN')
claude_token=$(
  jq -r '
    .mcpServers.rustsdcmcp.headers.Authorization |
    sub("^Bearer "; "")
  ' /home/mharman/.claude.json
)
[[ "$codex_token" =~ ^[A-Za-z0-9_-]{32,}$ ]]
[[ "$claude_token" =~ ^[A-Za-z0-9_-]{32,}$ ]]
[[ "$codex_token" != "$claude_token" ]]
```

Do not print either variable.

- [ ] **Step 3: Verify initialize and the exact 14-tool surface for each token**

For each token:

1. POST MCP initialize with protocol `2025-03-26`.
2. Capture the `Mcp-Session-Id` without printing it.
3. POST `notifications/initialized`.
4. POST `tools/list`.
5. Compare the sorted tool names to exactly:

```text
get_sdc_change_set
get_sdc_deploy_device_result
get_sdc_deploy_status
get_sdc_device
get_sdc_firewall_policy
get_sdc_nat_policy
get_sdc_preview_device_result
get_sdc_preview_status
get_sdc_resource
get_sdc_tenant_scope
list_sdc_devices
list_sdc_firewall_policies
list_sdc_nat_policies
list_sdc_resources
```

Explicitly assert these names are absent:

```text
prepare_sdc_policy_deploy
approve_sdc_change_set
apply_sdc_change_set
```

- [ ] **Step 4: Call one bounded read for each client**

Within each initialized session, send:

```json
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_sdc_tenant_scope","arguments":{"tenant":"production"}}}
```

Require HTTP 200, no JSON-RPC error, and MCP `isError == false`. Do not print
the tenant response.

- [ ] **Step 5: Verify distinct audit attribution**

Run a remote journal query that parses only JSON audit rows and assert:

```text
caller=codex-lab-read
actor_type=agent
provider=openai
provider_tier=public
tool=get_sdc_tenant_scope
authorization=allowed
result=ok
```

and:

```text
caller=claude-lab-read
actor_type=agent
provider=anthropic
provider_tier=public
tool=get_sdc_tenant_scope
authorization=allowed
result=ok
```

Print only a safe summary such as
`direct_lan_audit=verified separate_provenance=yes`.

- [ ] **Step 6: Remove acceptance material and clear in-memory tokens**

Delete each exact non-secret response and header file in
`/tmp/rustsdcmcp-direct-lan-acceptance/` with `apply_patch`, remove the empty
directory with `rmdir`, then run:

```bash
unset codex_token claude_token
test ! -e /tmp/rustsdcmcp-direct-lan-acceptance
```

Task 5 must reload both tokens from their protected stores; it must not depend
on shell state or temporary sessions from this task.

---

### Task 5: Point Codex and Claude directly at VMID 606

**Files:**
- Modify through Codex CLI: `/home/mharman/.codex/config.toml`
- Modify through Claude CLI: `/home/mharman/.claude.json`

**Interfaces:**
- Consumes: direct-LAN acceptance, existing bearer values, and the still-active
  tunnel fallback.
- Produces: two direct client registrations at the DNS endpoint.

- [ ] **Step 1: Reload both tokens and install the complete rollback trap**

Start a fresh Bash process and execute all of Task 5 Steps 1 through 5 in that
one process. Reload both protected values without printing or exporting them,
then install the complete rollback before changing either client:

```bash
set -euo pipefail
codex_token=$(fish -c 'printf %s $RUSTSDCMCP_CODEX_TOKEN')
claude_token=$(
  jq -r '
    .mcpServers.rustsdcmcp.headers.Authorization |
    sub("^Bearer "; "")
  ' /home/mharman/.claude.json
)
[[ "$codex_token" =~ ^[A-Za-z0-9_-]{32,}$ ]]
[[ "$claude_token" =~ ^[A-Za-z0-9_-]{32,}$ ]]
[[ "$codex_token" != "$claude_token" ]]

codex_changed=0
claude_changed=0
rollback_clients() {
  rc=$?
  set +e
  trap - ERR
  if [[ $claude_changed -eq 1 ]]; then
    claude mcp remove --scope user rustsdcmcp >/dev/null 2>&1
    claude mcp add \
      --scope user \
      --transport http \
      rustsdcmcp \
      http://127.0.0.1:39032/mcp \
      --header "Authorization: Bearer $claude_token" >/dev/null 2>&1
  fi
  if [[ $codex_changed -eq 1 ]]; then
    codex mcp remove rustsdcmcp >/dev/null 2>&1 || true
    codex mcp add rustsdcmcp \
      --url http://127.0.0.1:39032/mcp \
      --bearer-token-env-var RUSTSDCMCP_CODEX_TOKEN >/dev/null 2>&1 || true
  fi
  unset codex_token claude_token
  exit "$rc"
}
trap rollback_clients ERR
```

- [ ] **Step 2: Change both URLs while preserving separate credentials**

Run:

```bash
codex_changed=1
codex mcp remove rustsdcmcp >/dev/null
codex mcp add rustsdcmcp \
  --url http://rustsdcmcp.mechub.org:30032/mcp \
  --bearer-token-env-var RUSTSDCMCP_CODEX_TOKEN >/dev/null

claude_changed=1
claude mcp remove --scope user rustsdcmcp >/dev/null
claude mcp add \
  --scope user \
  --transport http \
  rustsdcmcp \
  http://rustsdcmcp.mechub.org:30032/mcp \
  --header "Authorization: Bearer $claude_token" >/dev/null
```

The change flags are set before each removal so even a failed remove/add pair
restores that client to `http://127.0.0.1:39032/mcp`. Never enable shell
tracing or print either bearer.

- [ ] **Step 3: Verify the redacted client configuration**

Run:

```bash
fish -c 'codex mcp get rustsdcmcp --json' |
  jq -e '
    .enabled == true
    and .transport.url ==
      "http://rustsdcmcp.mechub.org:30032/mcp"
    and .transport.bearer_token_env_var ==
      "RUSTSDCMCP_CODEX_TOKEN"
  ' >/dev/null

jq -e '
  .mcpServers.rustsdcmcp.type == "http"
  and .mcpServers.rustsdcmcp.url ==
    "http://rustsdcmcp.mechub.org:30032/mcp"
  and (.mcpServers.rustsdcmcp.headers.Authorization |
    startswith("Bearer "))
' /home/mharman/.claude.json >/dev/null

test "$(stat -c %a /home/mharman/.codex/config.toml)" = 600
test "$(stat -c %a /home/mharman/.claude.json)" = 600
```

- [ ] **Step 4: Re-run exact direct-LAN acceptance from stored client configuration**

Reload the Codex bearer from the Fish universal variable and the Claude bearer
from its user configuration. Repeat initialize, `tools/list`, and
`get_sdc_tenant_scope` against the URL read from each configuration rather
than a hard-coded URL.

Expected for each client:

```text
connected=yes
tools=14
write_tools=absent
tenant_scope=passed
```

- [ ] **Step 5: Clear rollback traps only after both client checks pass**

Run:

```bash
trap - ERR
unset codex_token claude_token
printf '%s\n' 'client_migration=accepted rollback_fallback=still_available'
```

Keep the proven SSH tunnel active until final DNS-only server configuration and
both direct clients pass in Task 6.

---

### Task 6: Finalize DNS-only Host acceptance, then remove the SSH tunnel

**Files:**
- Delete: `/home/mharman/.config/systemd/user/rustsdcmcp-tunnel.service`
- Delete temporarily: `/tmp/rustsdcmcp-lan-bind-20260730/`
- Delete temporarily on VMID 606: `/root/rustsdcmcp-lan-bind-20260730/`
- Preserve: `/etc/systemd/system/rustsdcmcp.service.d/lan.conf`

**Interfaces:**
- Consumes: two accepted direct client configurations.
- Produces: a final DNS-only service configuration, no workstation tunnel, no
  staging material, and a retained direct service configuration.

- [ ] **Step 1: Replace the transition configuration with final DNS-only configuration**

Before disabling the tunnel, install the separately staged
`/root/rustsdcmcp-lan-bind-20260730/final-lan.conf` as
`/etc/systemd/system/rustsdcmcp.service.d/lan.conf`, reload systemd, and
restart `rustsdcmcp.service`. Require enabled/active state, exactly one
`192.168.1.211:30032` listener, and an effective `ExecStart` containing
`--allowed-host rustsdcmcp.mechub.org:30032` but not
`--allowed-host 127.0.0.1:39032`. Re-run direct initialize and exact 14-tool
`tools/list` acceptance for Codex and Claude. If server finalization or either
client check fails, restore the separately staged
`transition-lan.conf`, reload and restart the server, and retain the running
tunnel. Do not remove the tunnel in that case.

- [ ] **Step 2: Disable and stop the user tunnel**

Run:

```bash
systemctl --user disable --now rustsdcmcp-tunnel.service
test "$(systemctl --user is-active rustsdcmcp-tunnel.service || true)" = inactive
```

Expected: the enablement symlink is removed and the SSH process exits.

- [ ] **Step 3: Delete only the exact user unit with `apply_patch`**

Use `apply_patch`:

```diff
*** Begin Patch
*** Delete File: /home/mharman/.config/systemd/user/rustsdcmcp-tunnel.service
*** End Patch
```

Then run:

```bash
systemctl --user daemon-reload
systemctl --user reset-failed rustsdcmcp-tunnel.service || true
test ! -e /home/mharman/.config/systemd/user/rustsdcmcp-tunnel.service
test "$(
  ss -lnt |
    awk '$4 == "127.0.0.1:39032" {count++} END {print count+0}'
)" -eq 0
```

Expected: no unit file and no port-39032 listener.

- [ ] **Step 4: Reconfirm direct access after tunnel removal**

Using the stored client configuration, repeat initialize and `tools/list` for
Codex and Claude.

Expected: both still connect directly and see exactly 14 read tools. This
proves no hidden dependency on local port `39032` remains.

- [ ] **Step 5: Remove only the explicit staging directories**

Run:

```bash
ssh -T -o BatchMode=yes root@rustsdcmcp.mechub.org 'set -euo pipefail
test -d /root/rustsdcmcp-lan-bind-20260730
rm -r -- /root/rustsdcmcp-lan-bind-20260730
test ! -e /root/rustsdcmcp-lan-bind-20260730'
```

Delete `/tmp/rustsdcmcp-lan-bind-20260730/transition-lan.conf`,
`/tmp/rustsdcmcp-lan-bind-20260730/final-lan.conf`, and the named staged tunnel
unit (but never the active unit before Step 3) with `apply_patch`, then:

```bash
rmdir /tmp/rustsdcmcp-lan-bind-20260730
```

Report that both staging directories were removed and the Proxmox snapshot
remains the recovery point.

- [ ] **Step 6: Verify the final live state**

Run:

```bash
ssh -T -o BatchMode=yes root@rustsdcmcp.mechub.org 'set -euo pipefail
test "$(systemctl is-enabled rustsdcmcp.service)" = enabled
test "$(systemctl is-active rustsdcmcp.service)" = active
test "$(sha256sum /usr/local/bin/rustsdcmcp | awk '"'"'{print $1}'"'"')" = \
  dc839d43cff890d69a9fe572518c4981a4f23a5db7fada3d8cdbf4d46746ccf0
test -f /etc/systemd/system/rustsdcmcp.service.d/lan.conf
listener_count=$(ss -lnt | awk '"'"'$4 ~ /:30032$/ {count++} END {print count+0}'"'"')
exact_count=$(ss -lnt | awk '"'"'$4 == "192.168.1.211:30032" {count++} END {print count+0}'"'"')
test "$listener_count" -eq 1
test "$exact_count" -eq 1
systemctl cat rustsdcmcp.service | \
  grep -F -- '--allowed-host rustsdcmcp.mechub.org:30032'
! systemctl cat rustsdcmcp.service | \
  grep -F -- '--allowed-host 127.0.0.1:39032'
systemd-analyze security --no-pager rustsdcmcp.service |
  grep -F "Overall exposure level"'
```

Use the Proxmox connector to list snapshots again and require
`pre-lan-bind-20260730`.

---

### Task 7: Update current documentation without rewriting history

**Files:**
- Modify: `README.md`
- Modify: `docs/operations.md`
- Modify: `docs/lab-deployment-606.md`
- Preserve: `docs/superpowers/specs/2026-07-30-vmid-606-direct-lan-mcp-design.md`
- Preserve: `docs/superpowers/plans/2026-07-30-vmid-606-direct-lan-mcp.md`

**Interfaces:**
- Consumes: the accepted final live state and exact test evidence.
- Produces: current operational guidance and an immutable dated deployment
  addendum in pull request 4.

- [ ] **Step 1: Update README current access guidance with `apply_patch`**

Replace the current tunnel instructions with:

```text
http://rustsdcmcp.mechub.org:30032/mcp
```

State precisely:

- the packaged default remains `127.0.0.1:30032`;
- VMID 606 has a deployment-only exact-address override;
- plain HTTP is accepted only for the internal lab;
- bearer authentication remains mandatory;
- Codex and Claude tokens expose exactly 14 read tools;
- no stable/public-production promotion is implied.

- [ ] **Step 2: Update operations guidance with `apply_patch`**

Document the drop-in path and exact service flags:

```text
/etc/systemd/system/rustsdcmcp.service.d/lan.conf
--host 192.168.1.211
--allow-insecure-bind
--allowed-host rustsdcmcp.mechub.org:30032
```

Include rollback instructions that remove the drop-in, reload systemd, and
restart the packaged loopback unit. Do not place bearer values in the guide.

- [ ] **Step 3: Append a dated direct-LAN section to the deployment record**

Keep the original statements that LAN access was rejected during the initial
and lab.2 acceptance; they were true at those times. Append a new
`2026-07-30 direct-LAN access change` section recording:

- snapshot `pre-lan-bind-20260730`;
- exact listener `192.168.1.211:30032`;
- DNS URL;
- plain-HTTP lab exception;
- separate 14-tool Codex and Claude identities;
- direct tenant-scope acceptance and audit attribution;
- protected-content preservation;
- tunnel removal and closed local port `39032`;
- no SDC mutation;
- retained snapshot and drop-in rollback.

- [ ] **Step 4: Review the documentation diff**

Run:

```bash
git diff --check
git diff -- README.md docs/operations.md docs/lab-deployment-606.md
rg -n \
  'SSH tunnel|127\.0\.0\.1:39032|loopback-only|LAN was rejected|192\.168\.1\.211:30032|rustsdcmcp\.mechub\.org:30032' \
  README.md docs/operations.md docs/lab-deployment-606.md
```

Require historical statements to remain under dated historical sections and
current instructions to use the direct DNS URL.

---

### Task 8: Run repository verification and update pull request 4

**Files:**
- Verify: all files changed on branch `docs/lab2-606-upgrade`
- Commit: documentation-only direct-LAN changes

**Interfaces:**
- Consumes: completed live migration and updated documentation.
- Produces: a pushed, verified draft PR update; it does not merge the PR.

- [ ] **Step 1: Run the complete local CI-equivalent checks**

Run:

```bash
git diff --check
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps --locked
scripts/verify-packaging.sh
```

Expected: all commands exit zero; 37 tests pass.

- [ ] **Step 2: Verify no secret or runtime material entered the diff**

Run:

```bash
git status --short
git diff --name-only
git diff --cached --name-only
```

Require repository changes only under:

```text
README.md
docs/operations.md
docs/lab-deployment-606.md
docs/superpowers/specs/2026-07-30-vmid-606-direct-lan-mcp-design.md
docs/superpowers/plans/2026-07-30-vmid-606-direct-lan-mcp.md
```

The spec may already be committed and therefore absent from the current diff.

- [ ] **Step 3: Commit only the intended documentation**

Run:

```bash
git add \
  README.md \
  docs/operations.md \
  docs/lab-deployment-606.md \
  docs/superpowers/plans/2026-07-30-vmid-606-direct-lan-mcp.md
git diff --cached --check
git commit -m 'Document direct LAN access for VMID 606'
```

Do not amend the already-pushed design commit.

- [ ] **Step 4: Push and verify pull request 4**

Run:

```bash
git push
gh pr view 4 \
  --repo fastrevmd-lab/rustsdcmcp \
  --json number,state,isDraft,headRefName,headRefOid,url,statusCheckRollup
```

Expected: open draft PR 4 with head branch `docs/lab2-606-upgrade`.

- [ ] **Step 5: Wait for the updated CI and security checks**

Poll conditionally:

```bash
gh pr checks 4 \
  --repo fastrevmd-lab/rustsdcmcp \
  --json name,state,bucket,workflow
```

Require every check to have bucket `pass`; report any failure with its exact
job URL and do not merge.

- [ ] **Step 6: Perform the final cross-system verification**

Re-run, freshly:

- direct Codex initialize and exact 14-tool `tools/list`;
- direct Claude initialize and exact 14-tool `tools/list`;
- VMID 606 enabled/active state and exact listener;
- absence of workstation port `39032`;
- presence of snapshot `pre-lan-bind-20260730`;
- clean worktree status.

Report the direct endpoint, retained authentication boundary, snapshot,
rollback drop-in, checks, and the fact that no SDC mutation occurred.
