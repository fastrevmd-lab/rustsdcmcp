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
individual PAN-OS firewalls, this server talks to the **management plane** — the
SASE portal that fronts an entire estate of on-premises, cloud-based, and
cloud-delivered security.

That difference matters. A single SDC call can move policy across thousands of
managed devices at once, so the change-control and attribution machinery is not
optional garnish here; it is the point.

## Relationship to `mecmcp`

[`mecmcp`](https://github.com/fastrevmd-lab/mecmcp) is the vendor-neutral Rust
foundation shared by the mechub MCP server family. This repository is a
**consumer** of that foundation, not a fork of it:

| Concern | Where it lives |
|---|---|
| Token mint/digest/verify, `tokens.json`, scopes, grants, caller context | `mecmcp-auth` |
| Attribution, audit events, redaction, sinks | `mecmcp-audit` |
| Streamable-HTTP transport, host/Origin checks, rate + concurrency limits | `mecmcp-transport` |
| CLI skeleton, listener validation, token commands, signals | `mecmcp-runtime` |
| Listener TLS loading and crypto-provider boundary | `mecmcp-transport` |
| Plan → digest → approve → apply → verify change control | `mecmcp-changeset` |
| Bounded MCP result conversion and handler authorization adapters | `mecmcp-server` |
| **SDC REST client, opaque OAuth-token/API-key headers, response models, endpoint catalog, tool surface** | **this repo** |

Two proposed shared abstractions are deliberately tracked as issues rather than
unpublished cross-repository code: [mecmcp#90](https://github.com/fastrevmd-lab/mecmcp/issues/90)
for cloud-client foundations and
[mecmcp#91](https://github.com/fastrevmd-lab/mecmcp/issues/91) for
target-neutral token vocabulary. Until those land, the corresponding local
code is isolated and SDC-specific; it is not treated as a new family standard.

## The API

The API surface is **pinned from Juniper's own OpenAPI 3 export**, vendored in
[`docs/sdc-api/`](docs/sdc-api/README.md) — 227 paths, 368 operations, 61 groups,
804 schemas, against `https://api.sdcloud.juniperclouds.net/`.

Authentication is a header, one of two schemes, applied to every operation
(no operation overrides it): `x-api-key`, or `x-oauth2-token` for the OAuth 2.0
path that federates to a customer IdP. Path versioning is mixed — `/api/v1/…`
for policies, devices, and templates; `/api/v2/…` for IAM, sites, and tunnels.

Three facts shape everything this server does:

- **Bulk mutations are asynchronous.** `POST` returns a job id; status and
  per-device results are separate `GET`s. Treating them as synchronous reports
  success for work that has not happened.
- **Preview and deploy are already separate endpoints.** The API hands us a
  native change-control boundary; `mecmcp-changeset` binds to it directly.
- **`429` means two different things** — rate limited *or* response payload too
  large — so it is not unconditionally retry-after-sleep.

Details, the full endpoint inventory, and an explicit list of what the spec does
**not** answer: [`docs/sdc-api/README.md`](docs/sdc-api/README.md).

Primary references:

- [Security Director Cloud API Reference](https://www.juniper.net/documentation/us/en/software/sd-cloud/api/http/getting-started/how-to-get-started)
- [API Security Overview](https://www.juniper.net/documentation/us/en/software/sd-cloud/sd-cloud-user-guide/user-guide/topics/concept/about-api-access.html)
- [Security Director Cloud documentation portal](https://www.juniper.net/documentation/product/us/en/juniper-security-director-cloud/)

## Status

The workspace now builds an MCP server with 17 tools:

- bounded tenant, device, firewall-policy, NAT-policy, and shared-object reads;
- explicit preview/deploy job and per-device result reads;
- policy deployment only through `prepare_sdc_policy_deploy` →
  `approve_sdc_change_set` → `apply_sdc_change_set`;
- startup verification that the configured credential resolves to the expected
  tenant ID;
- stdio and hardened Streamable HTTP composition from `mecmcp`.

The implementation is fixture-tested against the pinned OpenAPI shapes. It has
not yet been exercised against a live SDC tenant, so the API questions listed
in [`docs/sdc-api/README.md`](docs/sdc-api/README.md#still-unverified) remain
open.

## Build and configure

Rust 1.88 is pinned by `rust-toolchain.toml`.

```console
cargo build --release
cargo test --workspace
```

Copy [`examples/sdc.example.json`](examples/sdc.example.json), set the named
credential environment variable in the server process, and keep the secret
itself out of JSON:

```console
export SDC_API_TOKEN='...'
cargo run -p rustsdcmcp -- -f /absolute/path/to/sdc.json
```

The shared runtime currently names `-f`/`--device-mapping`; in this
management-plane consumer it selects the SDC configuration file. A neutral
spelling is tracked by mecmcp#91.

Streamable HTTP requires an absolute token-store path unless explicit
loopback-only no-auth mode is selected:

```console
cargo run -p rustsdcmcp -- \
  -f /etc/rustsdcmcp/sdc.json \
  --transport streamable-http \
  --tokens-file /etc/rustsdcmcp/tokens.json
```

Use the shared `token` subcommand to mint scoped credentials. Until
mecmcp#91 lands, the tenant allowlist is passed through the historical
`--devices` flag. Wildcard tool scopes exclude the three write tools; grant
them by exact name.

See [`docs/operations.md`](docs/operations.md) for deployment and recovery
details.

## Lab package status

The package is a **lab-only** archive, not a public release. Its name is
`rustsdcmcp_0.1.0-lab.YYYYMMDD.<source-commit-12>_amd64.tar.gz`; its sibling
checksum binds that exact archive. Each build is isolated under
`dist/<full-source-commit>/`; select that exact directory, never a glob across
`dist/`, and verify from it because the checksum records only the basename:

```console
source_commit="$(git rev-parse HEAD)"
artifact_dir="dist/$source_commit"
mapfile -t archives < <(find "$artifact_dir" -maxdepth 1 -type f -name 'rustsdcmcp_*_amd64.tar.gz' -print)
test "${#archives[@]}" -eq 1
(cd "$artifact_dir" && sha256sum -c "$(basename "${archives[0]}").sha256")
```

The package pins `mecmcp` to `changeset-v0.3.6`. Public `v0.1.0` is blocked
until all 59 temporary compatibility symbols in the
[`mecmcp compatibility ledger`](docs/mecmcp-compatibility.md) are replaced by
one coherent upstream `mecmcp` release. The lab artifact must not be promoted,
tagged, or presented as a public release while that blocker remains.

## Design commitments

- **Read before write.** Every mutating tool is reachable only through a
  plan → digest → approve → apply lifecycle. No tool writes to a tenant on a
  single unattested call.
- **Scoped tokens.** HTTP bearer tokens carry explicit tool and tenant scopes.
  Write tools require authentication and exact tool grants; unauthenticated
  stdio/loopback modes are read-only.
- **Bounded I/O.** Request and response sizes are capped. A management-plane
  API will happily hand back an estate-sized payload; the server will not.
- **Auditable by construction.** Attribution and redaction come from
  `mecmcp-audit`, so every call is traceable to a caller without leaking
  credentials into logs.
- **No secrets in the repo.** SDC API keys and opaque OAuth tokens are supplied
  through an operator-named process environment variable and are redacted from
  formatting and audit output.

## License

Licensed under [MIT](LICENSE).
