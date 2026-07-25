# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

`rustsdcmcp` is an MCP server for **HPE Juniper Security Director Cloud** (SDC).
The repository is currently a **scaffold** — README, LICENSE, branding, and
toolchain pin only. There is no Cargo workspace, no crates, and no build/test
commands yet. Do not invent build instructions; add them here when the
workspace actually lands.

## The one architectural rule

This repo is a **consumer** of [`mecmcp`](https://github.com/fastrevmd-lab/mecmcp)
(local checkout: `~/Projects/mecmcp`), the vendor-neutral Rust foundation shared
across the mechub MCP server family. The split is not negotiable:

- **Upstream in `mecmcp`:** token auth/scopes/grants (`mecmcp-auth`), audit and
  redaction (`mecmcp-audit`), streamable-HTTP transport and limits
  (`mecmcp-transport`), CLI/TLS/shutdown (`mecmcp-runtime`), change-control
  state machine (`mecmcp-changeset`), inventory (`mecmcp-inventory`).
- **Here:** the SDC REST client, its OAuth 2.0 / API-key auth flow, response
  models, and the MCP tool surface built on them.

If you are about to write generic auth, transport, rate-limiting, or
change-control code in this repo, stop — it belongs in `mecmcp`. `mecmcp` is
itself mid-extraction (only `mecmcp-auth` exists so far); its `PLAN.md` and
`ANALYSIS.md` describe what lands when.

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
- Bearer tokens carry explicit tool **and tenant** scopes.

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
