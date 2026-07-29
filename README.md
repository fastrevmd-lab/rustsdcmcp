<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/mechub-mark.svg">
    <img src="docs/assets/mechub-mark-light.svg" width="72" alt="mechub mark">
  </picture>
</p>

<h1 align="center">rustsdcmcp</h1>

<p align="center"><strong>Async Rust Model Context Protocol server for HPE Juniper Security Director Cloud</strong><br>
<em>a mechub project — sovereign network-security automation</em></p>

> **Unofficial / community project.** This is an independent community project
> and does not claim affiliation with or endorsement by Hewlett Packard
> Enterprise or Juniper Networks. Product names and trademarks are used only to
> identify the systems with which the software interoperates.

---

`rustsdcmcp` exposes HPE Juniper **Security Director Cloud** (SDC) to MCP
clients as a bounded, auditable tool surface. Where
[`rustjunosmcp`](https://github.com/fastrevmd-lab/rustjunosmcp) talks NETCONF to
individual SRX devices and
[`rustpanosmcp`](https://github.com/fastrevmd-lab/rustpanosmcp) talks XML-API to
individual PAN-OS firewalls, this server talks to the management plane.

That distinction has a large blast radius: one SDC action can affect many
managed devices. Strict approval, credential-safe attribution, and bounded I/O
therefore protect the management plane rather than merely decorate it.

## Current status

`rustsdcmcp` is available to repository collaborators as the private
[`v0.1.0-lab.1` prerelease](https://github.com/fastrevmd-lab/rustsdcmcp/releases/tag/v0.1.0-lab.1),
which targets `65135e29484be4487f5ba58bdf70ec0ef7518288`. It exposes 17 MCP
tools: 14 bounded read tools and three write tools—`prepare_sdc_policy_deploy`,
`approve_sdc_change_set`, and `apply_sdc_change_set`—that can be used only
through prepare → independent approval → apply.

Live, read-only validation against SDC has verified credential-based startup
tenant validation, `get_sdc_tenant_scope`, and `list_sdc_devices` with
`from=0,size=1`. Authentication and the tenant-scope check also succeeded
after a service restart. No preview, approval, apply, deployment, or other SDC
mutation was attempted; the remaining endpoint questions are tracked in
[`docs/sdc-api/README.md`](docs/sdc-api/README.md#still-unverified).

## Private prerelease

Repository collaborators can download the private
[`v0.1.0-lab.1` prerelease](https://github.com/fastrevmd-lab/rustsdcmcp/releases/tag/v0.1.0-lab.1)
and verify its archive:

```console
gh release download v0.1.0-lab.1 \
  --repo fastrevmd-lab/rustsdcmcp \
  --pattern 'rustsdcmcp_0.1.0-lab.20260729.65135e29484b_amd64.tar.gz*'
sha256sum -c rustsdcmcp_0.1.0-lab.20260729.65135e29484b_amd64.tar.gz.sha256
sha256sum rustsdcmcp_0.1.0-lab.20260729.65135e29484b_amd64.tar.gz
```

The final command must print:

```text
f3497192cb6fe8c83cfad8014fadc787ff16de7bca89a2302b565331e4f21848  rustsdcmcp_0.1.0-lab.20260729.65135e29484b_amd64.tar.gz
```

## Build from approved source

Rust 1.88 is pinned by `rust-toolchain.toml`. In an approved clone containing
the authorized commit, operators must first bind their detached checkout to
that commit before building, testing, or packaging:

```console
approved_commit=65135e29484be4487f5ba58bdf70ec0ef7518288
git checkout --detach "$approved_commit"
test "$(git rev-parse HEAD)" = "$approved_commit"
cargo build --release --locked
cargo test --workspace --locked
scripts/build-lab-package.sh
cp examples/sdc.example.json /secure/operator/path/sdc.json
```

In that configuration, `credential_env` names the external process variable;
the credential itself never belongs in JSON. For a local commit-addressed
package, verify the newly built archive and its embedded `BUILD-INFO` from the
approved commit directory—never glob across `dist/` because the checksum
records only the archive basename:

```console
artifact_dir="dist/$approved_commit"
archive="$artifact_dir/rustsdcmcp_0.1.0-lab.20260729.65135e29484b_amd64.tar.gz"
(cd "$artifact_dir" && sha256sum -c "$(basename "$archive").sha256")
package_root=$(tar -tzf "$archive" | sed -n '1s#/.*##p')
test -n "$package_root"
tar -xOf "$archive" "$package_root/BUILD-INFO" | grep -Fx "git_commit=$approved_commit"
```

## Debian 13 LXC quick start

Prerequisites:

- Debian 13 AMD64; an unprivileged LXC is recommended.
- 1 vCPU, 512 MiB RAM, 512 MiB swap, and 4 GiB disk for the lab profile.
- Working DNS and time synchronization, plus outbound HTTPS to
  `api.sdcloud.juniperclouds.net`.
- Root or equivalent operator access inside the LXC.

After downloading the release assets, install the verified package:

```bash
set -euo pipefail
archive=rustsdcmcp_0.1.0-lab.20260729.65135e29484b_amd64.tar.gz
sha256sum -c "$archive.sha256"
package_root=$(tar -tzf "$archive" | sed -n '1s#/.*##p')
test -n "$package_root"
tar -xzf "$archive"
sudo "$package_root/packaging/lxc/install.sh"
```

Create the configuration and credential file without exposing a credential:

```bash
sudo install -o root -g rustsdcmcp -m 0640 \
  /etc/rustsdcmcp/sdc.json.example /etc/rustsdcmcp/sdc.json
sudoedit /etc/rustsdcmcp/sdc.json
sudo install -o root -g root -m 0600 /dev/null \
  /etc/rustsdcmcp/credentials.env
sudoedit /etc/rustsdcmcp/credentials.env
```

`sdc.json` must retain the HTTPS SDC endpoint, use the desired local tenant
alias, and set `expected_tenant_id` to the operator-obtained SDC tenant ID. The
credentials file contains one shell-compatible assignment using the name from
`credential_env`, for example `SDC_API_TOKEN=...`; never put a real value in
the README or JSON.

Create the initial exact 14-tool read-only grant. The redirect destination must
already be mode `0600`; the output is a one-time bearer token.

```console
sudo /usr/local/bin/rustsdcmcp token add \
  --tokens-file /etc/rustsdcmcp/tokens.json \
  --device-mapping /etc/rustsdcmcp/sdc.json \
  --name lab-read \
  --devices production \
  --tools get_sdc_tenant_scope,list_sdc_devices,get_sdc_device,list_sdc_firewall_policies,get_sdc_firewall_policy,list_sdc_nat_policies,get_sdc_nat_policy,list_sdc_resources,get_sdc_resource,get_sdc_preview_status,get_sdc_deploy_status,get_sdc_preview_device_result,get_sdc_deploy_device_result,get_sdc_change_set \
  --actor-type human > /secure/local/path/rustsdcmcp-lab-read-token
```

Start the service and access it through an authenticated SSH tunnel:

```console
sudo systemctl enable --now rustsdcmcp.service
sudo systemctl --no-pager --full status rustsdcmcp.service
sudo ss -ltnp 'sport = :30032'
ssh -N -L 30032:127.0.0.1:30032 root@rustsdcmcp.mechub.org
```

The expected listener is only `127.0.0.1:30032`. While the tunnel is active,
the local MCP client uses `http://127.0.0.1:30032/mcp`.
`rustsdcmcp.mechub.org` is the current lab deployment; other installations use
their own SSH host.

## Security commitments

- External credentials use restrictive file modes and never belong in JSON.
- Startup verifies the configured identity against `expected_tenant_id`.
- Bearer tokens carry exact tool and tenant scopes.
- Request, response, and page sizes are bounded.
- Audit attribution is credential-safe and target values receive HMAC redaction.
- Mutations require two-principal prepare → approve → apply change control.
- There is no direct deploy tool and no unauthenticated write path.

Detailed deployment, recovery, audit-retention, and write-workflow guidance is
in [`docs/operations.md`](docs/operations.md).

## Completed lab work

The qualified Debian lab package deployment runs on VMID 606 on `pve2`, with
Debian 13 and DNS `rustsdcmcp.mechub.org`; VMID 606 runs under the packaged
`rustsdcmcp.service` systemd unit. It uses a loopback-only endpoint, the private
prerelease and SBOM, and the qualified live read-only results described above.
The detailed acceptance record is
[`docs/lab-deployment-606.md`](docs/lab-deployment-606.md). It intentionally
does not reproduce tenant identifiers, credentials, bearer tokens, HMAC keys,
or runtime state.

## Roadmap

1. First-class Docker image and Compose support with secret injection, health
   checks, and release documentation.
2. Replace all 59 temporary compatibility declarations when their tracked
   mecmcp APIs ship together in one coherent release.
3. Add remote audit-journal forwarding for non-lab operation.
4. Expand bounded live validation across the remaining read endpoints, then
   exercise write workflows only through approved change control.
5. Publish a stable release after the upstream and operational blockers clear.

## Relationship to `mecmcp`

[`mecmcp`](https://github.com/fastrevmd-lab/mecmcp) is the vendor-neutral Rust
foundation shared by the mechub MCP server family. This repository consumes it,
rather than forking it. Current source and the next lab-package build pin all
five shared crates to `changeset-v0.3.7`. The existing private
`v0.1.0-lab.1` prerelease and VMID 606 were built with `changeset-v0.3.6`, as
recorded in [`docs/lab-deployment-606.md`](docs/lab-deployment-606.md).
The 59 temporary compatibility declarations remain tracked in the
[`mecmcp compatibility ledger`](docs/mecmcp-compatibility.md); public `v0.1.0`
remains blocked until all 59 are replaced by one coherent upstream release.

## API provenance

The API surface is pinned from Juniper's OpenAPI 3 export, vendored in
[`docs/sdc-api/`](docs/sdc-api/README.md). It is the authoritative inventory of
the supported SDC API surface and its remaining open questions.

Primary references:

- [Security Director Cloud API Reference](https://www.juniper.net/documentation/us/en/software/sd-cloud/api/http/getting-started/how-to-get-started)
- [API Security Overview](https://www.juniper.net/documentation/us/en/software/sd-cloud/sd-cloud-user-guide/user-guide/topics/concept/about-api-access.html)
- [Security Director Cloud documentation portal](https://www.juniper.net/documentation/product/us/en/juniper-security-director-cloud/)

## License

Licensed under [MIT](LICENSE).
