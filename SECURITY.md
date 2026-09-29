# Security policy

## Reporting a vulnerability

Please **do not** open a public GitHub issue for a security vulnerability.

Instead, use GitHub's private vulnerability reporting for this repository
(Security tab → Report a vulnerability, or the link below):

https://github.com/mechubsec/rustsdcmcp/security/advisories/new

Include what you'd include in a bug report — affected version or commit,
reproduction steps, and impact — but keep it in the private report, not a
public issue, PR, or discussion. Do not include live SDC credentials, tenant
identifiers, policy payloads, or device configuration anywhere, including in
a private report — sanitize or describe them instead.

## Scope

This server exposes HPE Juniper Security Director Cloud (SDC) — a management
plane that can affect many SRX devices at once — as a bounded MCP tool
surface. Vulnerability classes we especially want to hear about: anything
that lets a caller bypass token/tenant scope checks, anything that lets a
write tool fire without going through prepare → independent approval →
apply, credential handling issues, and anything that could cause an SDC
mutation to happen without the caller's explicit intent.

## Security boundaries

- SDC credentials are external environment values, never configuration
  fields, MCP arguments, or audit metadata.
- The outbound client is HTTPS-only, refuses redirects and environment
  proxies, caps concurrency, applies whole-request deadlines, and enforces
  response limits while streaming.
- MCP Streamable HTTP uses `mecmcp-transport` Host/Origin checks, body
  limits, bearer token auth, scope preflight, concurrency/session limits, and
  optional TLS.
- Tool handlers repeat authorization after middleware. Every argument
  carries the configured tenant alias and is checked against token target
  scope.
- Write tools require authenticated callers, exact tool scopes,
  preview-bound plans, independent approval, owner-only apply, and terminal
  job resolution.
- HTTP 429 and indeterminate async outcomes are never silently retried or
  reported as success.

This project is not yet validated against a live SDC tenant in every code
path. Treat the unverified API behaviors documented in
`docs/sdc-api/README.md` as operational risks.

## Response

This is a community-maintained project. There's no guaranteed SLA. A human maintainer is responsible for triaging every report and for all disclosure and fix decisions.
