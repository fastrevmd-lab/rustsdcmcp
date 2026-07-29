# The Security Director Cloud API — pinned surface

Everything in this file is taken from the **vendored OpenAPI 3 document**, not
from prose documentation or inference. If a fact is not in the spec, it is
listed under [Still unverified](#still-unverified) rather than guessed.

## Provenance

The public API reference at
<https://www.juniper.net/documentation/us/en/software/sd-cloud/api/> is an
**APIMatic dev portal**. Its pages are client-rendered, so fetching them
returns only the page shell — which is why the endpoint surface could not be
read from the HTML. The portal config at `static/js/portal.js` declares an
export route, and that route serves the complete spec:

```
https://www.juniper.net/documentation/us/en/software/sd-cloud/api/static/exports/security-director-cloud-apis-openapi3json.json
```

| | |
|---|---|
| Vendored as | `security-director-cloud-apis-openapi3.json` |
| Retrieved | 2026-07-25 |
| `info.title` / `info.version` | `Security Director Cloud APIs` v`1.0.0` |
| `openapi` | `3.0.0` |
| sha256 | `099d1f0f5f4ce008e0c927dbc2c948b3bfe57337e15b909733dbea21d347ecc5` |
| Size | 227 paths · 368 operations · 61 tag groups · 804 schemas |

Refresh with [`fetch-spec.sh`](fetch-spec.sh), then regenerate
[`endpoints.md`](endpoints.md) with `scripts/gen-endpoint-inventory.py`. The
fetch script validates the download before overwriting the known-good copy.

> **Redistribution.** The spec is Juniper's published artifact, vendored here
> for offline client generation while this repository is **private**. If the
> repo is ever made public, replace the vendored copy with a fetch step.

## Base URL and versioning

```
https://api.sdcloud.juniperclouds.net/
```

One server, no variables. Versioning is **per-path, not per-host** — and it is
mixed. Do not assume a single API version:

| Prefix | Groups |
|---|---|
| `/api/v1/…` | policies, devices, templates, all shared security objects |
| `/api/v2/…` | IAM (users, roles, tenant), site management, tunnels, ipsec-profile |

## Authentication

Two schemes, declared at the document root, so they apply to **every** operation
(no operation overrides its security). Both are plain headers:

| Scheme | Header | Type |
|---|---|---|
| `ApiKeyAuth` | `x-api-key` | `apiKey` in header |
| `OauthKeyAuth` | `x-oauth2-token` | `apiKey` in header |

They are alternatives — the root `security` is a list of two single-key
requirements, so **one** of them satisfies a call. Note that `x-oauth2-token`
is modeled as an opaque header value, *not* as `Authorization: Bearer …`.

From the portal's user-guide prose (not the spec): API keys are minted per user
or service account, carry per-key roles and privileges, and default to a
one-year expiry; OAuth 2.0 federates to a customer IdP (Okta, Entra ID).

`GET /api/v2/tenant/tenant-id` (`GetTokenScope`) resolves what a credential is
actually scoped to — the natural startup probe for validating configuration.

## The async job pattern

**This is the most important structural fact about the API.** Every
state-changing bulk operation is asynchronous and follows one shape:

```
POST   /api/v1/policies/{action}                        -> { "{action}_id": "..." }
GET    /api/v1/policies/{action}/{id}                   -> overall status
GET    /api/v1/policies/{action}/{id}/devices/{device}  -> per-device result
```

It holds for `preview`, `deploy`, `selective_deploy`, and `cleanup`, and the
same submit-then-poll shape recurs in Device Operations (`sync`, `reboot`,
`config/rollback`). A client that treats these as synchronous will report
success for work that has not happened yet.

## Preview → deploy is a native change-control boundary

The API already separates rendering a change from applying it:

| Stage | Batch | Single policy |
|---|---|---|
| Preview | `POST /api/v1/policies/preview` | `POST /api/v1/policies/firewall/{id}/preview` |
| Deploy | `POST /api/v1/policies/deploy` | `POST /api/v1/policies/firewall/{id}/deploy` |
| Selective deploy | `POST /api/v1/policies/selective_deploy` | `POST /api/v1/policies/firewall/{id}/selective_deploy` |
| Cleanup | `POST /api/v1/policies/cleanup` | `POST /api/v1/policies/firewall/{id}/cleanup` |
| State | — | `GET /api/v1/policies/firewall/{uuid}/state` |

NAT policies expose the identical set under `/api/v1/policies/nat/{id}/…`.

Preview request entries carry both `deploy_targets` and `undeploy_targets`, and
the spec states that for each device **undeploy targets are processed first**,
then deploy targets. A `target_type` of `DEVICE` selects the target. The batch
deploy request is a separate shape containing only `policy_id` and
`policy_type`; the implementation preserves that distinction exactly.

This maps cleanly onto `mecmcp-changeset`: preview produces the artifact to
digest and show a human, deploy is the apply step. Preview output is what the
approval digest should be computed over — **never** re-render at apply time,
or the approved artifact and the applied one can differ.

## Pagination, filtering, and result shaping

List endpoints share a query-parameter vocabulary (occurrence counts across the
spec): `from` (68), `size` (68), `filters` (58), `sortby` (54), `count` (50),
`fields` (41), `obj_uuids` (39).

- `from` — zero-based starting index, default `0`
- `size` — max results per page; **`size=0` asks the server for as many as it
  can return**, which is the single easiest way to trigger a 429 on an
  estate-sized tenant. Always set an explicit bound.
- `count=true` — returns only the total match count, no resource bodies
- `fields` — server-side projection; use it to keep responses small
- `sortby` — e.g. `sortby=(name(descending))`

## Errors

Every operation declares exactly the same response set: `200`, `400`, `401`,
`403`, `404`, `409`, `429`, `500`, and `default`. All non-200 bodies use one
schema (`runtimeError1`):

```json
{ "code": 0, "message": "string", "details": [ {} ] }
```

`message` is the only required field. Two codes deserve first-class handling:

- **`429`** — the spec's description covers *two distinct conditions*: rate
  limiting **and** a response payload exceeding the maximum allowed size. The
  remedy differs (back off vs. paginate/filter), so a client must not treat 429
  as retry-after-sleep unconditionally.
- **`409`** — present on every operation, which is what you would expect from
  an API where concurrent deploys can conflict.

## Surface at a glance

368 operations — 173 `GET`, 96 `POST`, 50 `DELETE`, 49 `PUT`. Largest groups:

| Group | Ops | | Group | Ops |
|---|---:|---|---|---:|
| NAT Policies | 24 | | Device Onboarding | 8 |
| Firewall Policies | 23 | | Device Image Definitions | 8 |
| Site Management | 20 | | EnhancedContentFilteringProfileSet | 8 |
| Templates | 20 | | Device Operations | 7 |
| License and Certificate Management | 14 | | Device Resources | 7 |
| IAM | 10 | | IPSSignature | 7 |

The long tail is ~35 shared-security-object groups (Address, Application,
Services, Scheduler, URLCategoryList, IpsProfile, WebFilteringProfile, …) that
are almost all a uniform 5-op CRUD shape. Full listing:
[`endpoints.md`](endpoints.md).

## What this means for the tool surface

1. **Read-only first.** 173 `GET` operations, and the object-CRUD groups are
   uniform enough that a small number of generic list/get tools can cover most
   of them without 35 bespoke tools.
2. **Mutations go through `mecmcp-changeset`.** The preview → deploy split is
   already the right shape; do not expose `deploy` as a directly callable tool.
3. **Poll, don't fire-and-forget.** Any tool wrapping an async action must
   resolve the job and surface per-device results, or it will lie about outcomes.
4. **Bound every list call.** Never emit `size=0`; always set `size` and prefer
   `fields` projections. The 429-on-payload-size behavior makes this a
   correctness issue, not just an efficiency one.
5. **Tenant scoping is real.** Bearer tokens in this server must carry a tenant
   scope, validated against `GET /api/v2/tenant/tenant-id` at startup.

## Still unverified

Not answered by the spec; do not write code that assumes an answer:

- Rate-limit numbers, window, and whether `Retry-After` or any `X-RateLimit-*`
  response headers are sent. Every operation declares `"headers": {}`.
- Whether `x-oauth2-token` expects a raw JWT or an opaque token, and the token
  endpoint / refresh flow for the OAuth path.
- Concrete polling interval and timeout guidance. The status schema does
  enumerate `PENDING`, `IN_PROGRESS`, `COMPLETED`, `PARTIAL_SUCCESS`, and
  `FAILED`, but does not recommend how often or how long a client should poll.
- Whether `409` is safely retryable per operation.
- Region-specific base URLs. The spec declares exactly one server; whether
  other tenants land on a different host is unconfirmed.
- Real payload examples. Spec examples are placeholder `"string"` values, so
  field semantics for policy/rule bodies need a live tenant to confirm.
