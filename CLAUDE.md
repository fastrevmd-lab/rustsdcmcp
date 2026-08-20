# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

`rustsdcmcp` is an MCP server for **HPE Juniper Security Director Cloud** (SDC).
The repository is a Rust workspace with `rustsdcmcp-core` (SDC client, models,
and change adapter) and `rustsdcmcp` (rmcp handler and runtime composition).
Use `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D
warnings`, and `cargo fmt --all --check`.

## The one architectural rule

This repo is a **consumer** of [`mecmcp`](https://github.com/fastrevmd-lab/mecmcp)
(local checkout: `~/Projects/mecmcp`), the vendor-neutral Rust foundation shared
across the mechub MCP server family. The split is not negotiable:

- **Consumed from `mecmcp`:** token auth/scopes/grants (`mecmcp-auth`), audit and
  redaction (`mecmcp-audit`), streamable-HTTP transport and limits
  (`mecmcp-transport`), CLI/TLS/shutdown (`mecmcp-runtime`), change-control
  state machine (`mecmcp-changeset`), inventory (`mecmcp-inventory`).
- **Here:** the SDC REST client, exact opaque OAuth-token/API-key headers,
  response models, endpoint allowlist, and MCP tool surface.

Do not modify `mecmcp` from this repository task. Missing shared cloud-client
foundations are tracked in mecmcp#90, and target-neutral auth vocabulary in
mecmcp#91. Keep temporary compatibility code product-specific and isolated;
do not expand it into a competing shared framework.

Sibling reference implementations for the *shape* of a mechub MCP server:
`~/Projects/RustJunosMCP` (NETCONF/SSH, runtime hardening) and
`~/Projects/rust-panosmcp` (HTTPS XML-API, change-control lifecycle). SDC is
closest to the PAN-OS repo — HTTPS REST against a remote management plane — so
prefer its structure when adding the client and tool layers.

## Management plane, not device plane

SDC is a SASE portal fronting an entire estate. One API call can move policy
across thousands of managed devices. Consequences that must hold in any code
added here:

- Mutating tools are reachable **only** through `mecmcp-changeset`'s
  plan → digest → approve → apply → verify lifecycle. Never a direct write.
- Read-only tools land first and stay the majority of the surface.
- Response sizes are bounded — an estate-wide query will return far more than a
  single-device one.
- HTTP bearer tokens carry explicit tool **and tenant** scopes. Write tools
  reject unauthenticated stdio/loopback callers.

## What this server is not for

Decided 2026-08-20 (#34). SDC's API spans the whole product; this server covers
the part of it that manages SRX devices and their policy. The rest is recorded
here so an absence reads as a decision rather than as work nobody got to.

**Out of scope — do not implement.**

- **IAM** (user and role administration, 9 operations beyond the `GetTokenScope`
  used for startup tenant validation)
- **Subscriptions** (tenant entitlement, 3 operations)

These are tenant administration, not network management. An MCP client that can
create users, alter roles or change entitlements holds a surface with no
networking value and a large blast radius — the same reasoning that puts Mist's
portal identity flows in `ExecuteClass::Excluded` over in rustmistmcp. If a
future need appears, it needs its own decision recorded here, not a quiet
addition.

**Deferred with SASE**, if this repo ever grows a SASE remit: PAC Manager (2),
Service Location Management (1).

**In scope, simply unbuilt.** Fair game whenever there is a reason:

- **Device Resources** (7) — interfaces and zones as SDC sees them. The most
  useful of these, because it is how SDC's view could be reconciled against
  `rustjunosmcp`'s.
- **Device Image Definitions** (8) and **RMA** (6) — pair with lifecycle
  workflows this server does not have yet.
- **MNHA Clusters** (2) — untested territory; the lab device is standalone.

## The API surface is pinned — read it, don't re-derive it

**`docs/sdc-api/README.md` is the authority.** It is written entirely from
Juniper's OpenAPI 3 export, which is vendored alongside it. Read it before
writing any client code, and never restate an endpoint, header, or parameter
from memory.

Do not try to scrape the HTML reference — the portal is client-rendered
(APIMatic) and fetching pages returns only the shell. That is a dead end
someone will otherwise rediscover. The spec comes from the portal's export
route; `docs/sdc-api/fetch-spec.sh` refreshes it and
`scripts/gen-endpoint-inventory.py` regenerates `docs/sdc-api/endpoints.md`.
`endpoints.md` is generated — never hand-edit it.

Load-bearing facts, all verified in the spec:

- Base URL `https://api.sdcloud.juniperclouds.net/`, single server.
- Auth is a header — `x-api-key` or `x-oauth2-token` — declared at the document
  root, and **no operation overrides it** (0 of 368).
- Path versioning is **mixed**: `/api/v1/` for policies/devices/templates,
  `/api/v2/` for IAM/site/tunnels. Never assume one version.
- Bulk mutations are **async**: `POST` → job id, then status and per-device
  result `GET`s. Same shape for `preview`/`deploy`/`selective_deploy`/`cleanup`
  and for device `sync`/`reboot`/`rollback`.
- Preview and deploy are separate endpoints — bind `mecmcp-changeset` to that
  boundary and digest the *preview output*, never a re-render at apply time.
- `size=0` on a list call means "return as many as possible". Never emit it.
- `429` means rate-limited **or** payload-too-large; the remedies differ.

`docs/sdc-api/README.md` ends with a **Still unverified** list (rate-limit
numbers, retry headers, OAuth token format, polling intervals, `409`
retryability, regional hosts). Treat those as open questions requiring a live
tenant — do not close them by inference.

## Conventions inherited from the family

- Rust edition 2024, MSRV 1.88, build toolchain pinned in `rust-toolchain.toml`.
- Workspace lints: `missing_docs = "warn"`, `unsafe_code = "forbid"`,
  `clippy::all` warn, `dbg_macro`/`todo` deny, `unwrap_used` warn.
- Single MIT license (not dual). Repo name is lowercase, no dashes — mechub
  brand rule.
- `.gitignore` deliberately blocks `tokens.json`, `*.tokens.json`, `.env`,
  `*.pem`, `*.key`. Test fixtures under `crates/*/tests/fixtures/` are the only
  exception.
