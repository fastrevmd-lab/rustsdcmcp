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

## API research discipline

The SDC API reference is thin on public detail; several pages return
navigation-only content to fetchers. Do not write endpoint paths, header names,
or pagination behavior from memory or inference. Verify against:

- https://www.juniper.net/documentation/us/en/software/sd-cloud/api/http/getting-started/how-to-get-started
- https://www.juniper.net/documentation/us/en/software/sd-cloud/sd-cloud-user-guide/user-guide/topics/concept/about-api-access.html

Verified so far: API-key auth (per user or service account, portal-minted,
default one-year expiry, per-key roles/privileges) and OAuth 2.0 via customer
IdP (Okta, Entra ID). Everything else — base URLs, versioning, resource groups
— is unverified. Record findings in `docs/` as they are confirmed.

## Conventions inherited from the family

- Rust edition 2024, MSRV 1.88, build toolchain pinned in `rust-toolchain.toml`.
- Workspace lints: `missing_docs = "warn"`, `unsafe_code = "forbid"`,
  `clippy::all` warn, `dbg_macro`/`todo` deny, `unwrap_used` warn.
- Single MIT license (not dual). Repo name is lowercase, no dashes — mechub
  brand rule.
- `.gitignore` deliberately blocks `tokens.json`, `*.tokens.json`, `.env`,
  `*.pem`, `*.key`. Test fixtures under `crates/*/tests/fixtures/` are the only
  exception.
