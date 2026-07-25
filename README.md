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
| CLI skeleton, TLS bootstrap, signals, graceful shutdown | `mecmcp-runtime` |
| Plan → digest → approve → apply → verify change control | `mecmcp-changeset` |
| Device/tenant registry | `mecmcp-inventory` |
| **SDC REST client, OAuth 2.0 / API-key auth, response models, tool surface** | **this repo** |

Everything that is *not* specific to the Security Director Cloud API is
upstream. If you find yourself writing generic auth or transport code here,
it belongs in `mecmcp` instead.

## The API

Security Director Cloud publishes a REST API with API-key and OAuth 2.0
authentication, where API keys are minted per user or service account from the
portal and carry an expiry (one year by default). Roles and access privileges
are configured per key, and OAuth 2.0 allows organizations to authenticate
through an existing IdP (Okta, Entra ID).

Primary references:

- [Security Director Cloud API Reference](https://www.juniper.net/documentation/us/en/software/sd-cloud/api/http/getting-started/how-to-get-started)
- [API Security Overview](https://www.juniper.net/documentation/us/en/software/sd-cloud/sd-cloud-user-guide/user-guide/topics/concept/about-api-access.html)
- [Security Director Cloud documentation portal](https://www.juniper.net/documentation/product/us/en/juniper-security-director-cloud/)

The concrete endpoint map, resource groups, and pagination/versioning semantics
are being vetted directly against the live API reference before any client code
lands — this README will not restate an endpoint surface it has not verified.

## Status

**Scaffold.** Repository, license, and branding only. No crates, no binary, no
tool surface yet. Nothing here is usable against a real tenant.

Next, in order:

1. Pin the verified SDC API surface (auth flow, base URLs, versioning, the
   resource groups worth exposing) into `docs/`.
2. Stand up the Cargo workspace against the `mecmcp` crates as they publish.
3. Read-only tools first — inventory, policy read, device state — under bearer
   auth with per-token scopes.
4. Mutating tools only behind `mecmcp-changeset`, never as direct writes.

## Design commitments

- **Read before write.** Every mutating tool is reachable only through a
  plan → digest → approve → apply lifecycle. No tool writes to a tenant on a
  single unattested call.
- **Scoped tokens.** Bearer tokens carry explicit tool and tenant scopes;
  an unscoped token is a configuration error, not a convenience.
- **Bounded I/O.** Request and response sizes are capped. A management-plane
  API will happily hand back an estate-sized payload; the server will not.
- **Auditable by construction.** Attribution and redaction come from
  `mecmcp-audit`, so every call is traceable to a caller without leaking
  credentials into logs.
- **No secrets in the repo.** SDC API keys and OAuth client secrets live in
  operator-managed files outside version control.

## License

Licensed under [MIT](LICENSE).
