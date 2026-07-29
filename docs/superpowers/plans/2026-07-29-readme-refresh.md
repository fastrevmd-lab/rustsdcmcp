# README Refresh Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the stale project README with an accurate collaborator guide for the current private lab prerelease, source builds, and Debian 13 LXC deployment.

**Architecture:** Keep `README.md` as the concise entry point and link to the existing detailed operational, API, compatibility, and deployment records. The README will state verified release and live-test facts exactly, provide a reusable LXC path, and leave Docker support explicitly on the roadmap instead of claiming it exists.

**Tech Stack:** GitHub Markdown, Bash/console command examples, Cargo, Debian 13 systemd/LXC packaging, GitHub CLI.

## Global Constraints

- Modify project documentation only; do not change application, packaging, release, or live-LXC state.
- Do not add Docker instructions or imply that Docker support exists in this phase.
- Describe the surface as exactly 17 tools: 14 read-only tools plus `prepare_sdc_policy_deploy`, `approve_sdc_change_set`, and `apply_sdc_change_set`.
- State that live testing verified startup tenant validation, `get_sdc_tenant_scope`, and bounded `list_sdc_devices` before and after restart; no SDC mutation was invoked.
- Describe `v0.1.0-lab.1` as a private collaborator prerelease targeting `65135e29484be4487f5ba58bdf70ec0ef7518288`.
- Use archive `rustsdcmcp_0.1.0-lab.20260729.65135e29484b_amd64.tar.gz` and SHA-256 `f3497192cb6fe8c83cfad8014fadc787ff16de7bca89a2302b565331e4f21848`.
- Keep the real SDC credential, tenant ID, bearer tokens, token digests, HMAC key, live configuration, and runtime-state dumps out of the README.
- Preserve the lab-only boundary: stable promotion remains blocked by the 59 temporary, issue-linked mecmcp compatibility declarations.

---

### Task 1: Rewrite the collaborator-facing README

**Files:**
- Modify: `README.md`
- Reference: `docs/operations.md`
- Reference: `docs/lab-deployment-606.md`
- Reference: `docs/mecmcp-compatibility.md`
- Reference: `examples/sdc.example.json`

**Interfaces:**
- Consumes: the package installer at `packaging/lxc/install.sh`, systemd unit at `packaging/systemd/rustsdcmcp.service`, private GitHub prerelease `v0.1.0-lab.1`, and the exact 14-tool token scope already documented in `docs/operations.md`.
- Produces: one self-contained repository entry point that routes collaborators to the authoritative detailed documents.

- [ ] **Step 1: Capture the stale-claim and Docker-negative baseline**

Run:

```bash
rg -n 'not yet been exercised against a live SDC tenant' README.md
if rg -ni 'docker|compose|container image' README.md; then
    exit 1
fi
```

Expected: the first command reports the stale claim in the Status section; the Docker scan produces no matches.

- [ ] **Step 2: Replace the overview, status, release, and source-build sections**

Edit `README.md` with these sections and facts:

```markdown
## Current status

`rustsdcmcp` is available to repository collaborators as the private
`v0.1.0-lab.1` prerelease. It exposes 17 MCP tools: 14 bounded read tools and
three write tools that can be used only through prepare → independent approval
→ apply.

Live, read-only validation against SDC has verified credential-based startup
tenant validation, `get_sdc_tenant_scope`, and `list_sdc_devices` with
`from=0,size=1`. Authentication and the tenant-scope check also succeeded
after a service restart. No preview, approval, apply, deployment, or other SDC
mutation was attempted; the remaining endpoint questions are tracked in
[`docs/sdc-api/README.md`](docs/sdc-api/README.md#still-unverified).
```

Add a private-release section that includes:

```console
gh release download v0.1.0-lab.1 \
  --repo fastrevmd-lab/rustsdcmcp \
  --pattern 'rustsdcmcp_0.1.0-lab.20260729.65135e29484b_amd64.tar.gz*'
sha256sum -c rustsdcmcp_0.1.0-lab.20260729.65135e29484b_amd64.tar.gz.sha256
sha256sum rustsdcmcp_0.1.0-lab.20260729.65135e29484b_amd64.tar.gz
```

Immediately below it, state that the final command must print:

```text
f3497192cb6fe8c83cfad8014fadc787ff16de7bca89a2302b565331e4f21848  rustsdcmcp_0.1.0-lab.20260729.65135e29484b_amd64.tar.gz
```

Link the release name to:

```text
https://github.com/fastrevmd-lab/rustsdcmcp/releases/tag/v0.1.0-lab.1
```

Retain a source-build section with:

```console
cargo build --release --locked
cargo test --workspace --locked
cp examples/sdc.example.json /secure/operator/path/sdc.json
```

Explain that `credential_env` names the external process variable and the
credential never belongs in JSON. Preserve the local commit-addressed package
verification guidance, but position it as the path for operators building from
approved source rather than as the only available artifact.

- [ ] **Step 3: Add the reusable Debian 13 LXC quick start**

Add an `## Debian 13 LXC quick start` section with these prerequisites:

```markdown
- Debian 13 AMD64; an unprivileged LXC is recommended.
- 1 vCPU, 512 MiB RAM, 512 MiB swap, and 4 GiB disk for the lab profile.
- Working DNS and time synchronization, plus outbound HTTPS to
  `api.sdcloud.juniperclouds.net`.
- Root or equivalent operator access inside the LXC.
```

Use variables rather than embedding tenant or secret values. The installation
block must be directly usable after the release assets have been downloaded:

```bash
set -euo pipefail
archive=rustsdcmcp_0.1.0-lab.20260729.65135e29484b_amd64.tar.gz
sha256sum -c "$archive.sha256"
package_root=$(tar -tzf "$archive" | sed -n '1s#/.*##p')
test -n "$package_root"
tar -xzf "$archive"
sudo "$package_root/packaging/lxc/install.sh"
```

Document configuration without exposing a credential:

```bash
sudo install -o root -g rustsdcmcp -m 0640 \
  /etc/rustsdcmcp/sdc.json.example /etc/rustsdcmcp/sdc.json
sudoedit /etc/rustsdcmcp/sdc.json
sudo install -o root -g root -m 0600 /dev/null \
  /etc/rustsdcmcp/credentials.env
sudoedit /etc/rustsdcmcp/credentials.env
```

Explain that `sdc.json` must retain the HTTPS SDC endpoint, use the desired
local tenant alias, and set `expected_tenant_id` to the operator-obtained SDC
tenant ID. The credentials file contains one shell-compatible assignment using
the name from `credential_env`, for example `SDC_API_TOKEN=...`; the README must
not include a real value.

Use the existing exact read-only grant:

```console
sudo /usr/local/bin/rustsdcmcp token add \
  --tokens-file /etc/rustsdcmcp/tokens.json \
  --device-mapping /etc/rustsdcmcp/sdc.json \
  --name lab-read \
  --devices production \
  --tools get_sdc_tenant_scope,list_sdc_devices,get_sdc_device,list_sdc_firewall_policies,get_sdc_firewall_policy,list_sdc_nat_policies,get_sdc_nat_policy,list_sdc_resources,get_sdc_resource,get_sdc_preview_status,get_sdc_deploy_status,get_sdc_preview_device_result,get_sdc_deploy_device_result,get_sdc_change_set \
  --actor-type human > /secure/local/path/rustsdcmcp-lab-read-token
```

State that the output is a one-time bearer token and its destination must be
mode `0600`. Complete the service and access flow:

```console
sudo systemctl enable --now rustsdcmcp.service
sudo systemctl --no-pager --full status rustsdcmcp.service
sudo ss -ltnp 'sport = :30032'
ssh -N -L 30032:127.0.0.1:30032 root@rustsdcmcp.mechub.org
```

State that the expected listener is only `127.0.0.1:30032`, and the local MCP
client uses `http://127.0.0.1:30032/mcp` while the SSH tunnel is active. Make
clear that `rustsdcmcp.mechub.org` is the current lab deployment; other
installations use their own SSH host.

- [ ] **Step 4: Consolidate security, completed work, and roadmap**

Retain or rewrite the security commitments so the README explicitly covers:

```markdown
- external credentials and restrictive file modes;
- startup verification against `expected_tenant_id`;
- exact tool and tenant scopes;
- bounded request, response, and page sizes;
- credential-safe audit attribution and HMAC target redaction;
- two-principal prepare → approve → apply change control;
- no direct deploy tool and no unauthenticated writes.
```

Add a completed-work summary with VMID 606 on `pve2`, Debian 13, DNS
`rustsdcmcp.mechub.org`, the loopback-only endpoint, the private prerelease and
SBOM, and the qualified live read-only results. Link the detailed acceptance
record at `docs/lab-deployment-606.md`. Do not copy the tenant ID, API key,
bearer token, HMAC key, or runtime state.

Add this ordered roadmap:

```markdown
1. First-class Docker image and Compose support with secret injection, health
   checks, and release documentation.
2. Replace all 59 temporary compatibility declarations when their tracked
   mecmcp APIs ship together in one coherent release.
3. Add remote audit-journal forwarding for non-lab operation.
4. Expand bounded live validation across the remaining read endpoints, then
   exercise write workflows only through approved change control.
5. Publish a stable release after the upstream and operational blockers clear.
```

Keep the existing independent-project notice, related links to `mecmcp`,
`rustjunosmcp`, and `rustpanosmcp`, the API provenance, and the MIT license.

- [ ] **Step 5: Verify local links and stale-content removal**

Run:

```bash
set -euo pipefail
while IFS= read -r link; do
    target=${link#](}
    target=${target%)}
    target=${target%%#*}
    case "$target" in
        ''|http://*|https://*|mailto:*) continue ;;
    esac
    test -e "$target" || {
        printf 'missing README target: %s\n' "$target" >&2
        exit 1
    }
done < <(rg -o '\]\([^)]+\)' README.md)
! rg -n 'not yet been exercised against a live SDC tenant' README.md
! rg -ni 'docker (is|now)|docker quick start|docker installation' README.md
```

Expected: no output and exit status 0.

- [ ] **Step 6: Verify exact facts, tool scope, and secret hygiene**

Run:

```bash
set -euo pipefail
rg -q 'v0\\.1\\.0-lab\\.1' README.md
rg -q '65135e29484be4487f5ba58bdf70ec0ef7518288' README.md
rg -q 'f3497192cb6fe8c83cfad8014fadc787ff16de7bca89a2302b565331e4f21848' README.md
rg -q '59 temporary' README.md
rg -q 'No .*mutation was attempted|No SDC mutation was attempted' README.md
tools=$(sed -n '/--tools /{s/.*--tools //;s/ *\\$//;p;}' README.md)
test "$(tr ',' '\n' <<<"$tools" | sed '/^$/d' | wc -l)" -eq 14
! rg -ni '(api[_ -]?key|oauth[_ -]?token|bearer token|hmac key)[[:space:]]*[:=][[:space:]]*[A-Za-z0-9+/]{16,}' README.md
```

Expected: all assertions pass with no credential-like literal.

- [ ] **Step 7: Run documentation and workspace regression checks**

Run:

```bash
git diff --check
bash -n packaging/lxc/install.sh
scripts/verify-packaging.sh
cargo test --workspace --locked
```

Expected: no whitespace errors; installer syntax succeeds; packaging policy
verification passes; all 32 workspace tests pass.

- [ ] **Step 8: Review and commit the README**

Run:

```bash
git diff --stat
git diff -- README.md
git status --short
git add README.md
git commit -m "docs: add LXC deployment guide"
git status --short --branch
```

Expected: the diff contains only the approved README rewrite, the commit
succeeds, and the worktree is clean.
