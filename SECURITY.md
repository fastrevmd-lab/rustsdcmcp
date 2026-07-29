# Security policy

Report suspected vulnerabilities privately to the repository maintainers.
Do not include live SDC credentials, tenant identifiers, policy payloads, or
device configuration in a public issue.

## Security boundaries

- SDC credentials are external environment values, never configuration fields,
  MCP arguments, or audit metadata.
- The outbound client is HTTPS-only, refuses redirects and environment proxies,
  caps concurrency, applies whole-request deadlines, and enforces response
  limits while streaming.
- MCP Streamable HTTP uses `mecmcp-transport` Host/Origin checks, body limits,
  bearer authentication, scope preflight, concurrency/session limits, and
  optional TLS.
- Tool handlers repeat authorization after middleware. Every argument carries
  the configured tenant alias and is checked against token target scope.
- Write tools require authenticated callers, exact tool scopes, preview-bound
  plans, independent approval, owner-only apply, and terminal job resolution.
- HTTP 429 and indeterminate async outcomes are never silently retried or
  reported as success.

This project is not yet validated against a live SDC tenant. Treat the
unverified API behaviors in `docs/sdc-api/README.md` as operational risks.
