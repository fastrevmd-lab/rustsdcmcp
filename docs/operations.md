# Operations

## Startup

`rustsdcmcp` loads one JSON tenant configuration through the shared runtime's
`-f` option. It then:

1. installs the `ring` rustls provider;
2. resolves the SDC credential from `credential_env`;
3. builds an HTTPS-only client with redirects and environment proxies disabled;
4. calls `GET /api/v2/tenant/tenant-id`;
5. refuses startup unless the response matches `expected_tenant_id`;
6. loads `mecmcp-changeset` state and the optional bearer-token store;
7. starts stdio or the shared hardened Streamable HTTP listener.

No API endpoint, token, or secret is accepted from MCP tool arguments.

## Read tools

Every list tool requires an explicit positive `size` no larger than
`max_page_size`. SDC interprets `size=0` as unbounded, so the server rejects it.
Responses are streamed under `max_response_bytes`; oversized bodies fail
without returning partial JSON.

SDC HTTP 429 is surfaced as resource exhaustion. It is not automatically
retried because the API uses the same status for rate limiting and responses
that exceed service limits.

## Policy deployment

There is no directly callable deploy tool.

1. `prepare_sdc_policy_deploy` submits the exact preview request, polls its
   documented status to a terminal state, fetches each per-device CLI result,
   and creates a change set binding the deploy request and preview digest.
2. A different authenticated principal calls `approve_sdc_change_set` with the
   exact plan digest before its TTL expires.
3. The original owner calls `apply_sdc_change_set` with both digests.
4. `mecmcp-changeset` revalidates ownership, approval, fingerprints, and policy
   signature before the SDC deploy request is submitted.
5. The server polls the deploy job. `COMPLETED` is success;
   `PARTIAL_SUCCESS`/`FAILED` are reconciled failures. Cancellation or deadline
   after submission is persisted as indeterminate.

Write tools require an authenticated bearer token and exact tool grants.
Wildcard tool scope deliberately excludes them. Stdio and `--allow-no-auth`
are read-only.

## Persistence and recovery

Set `changeset_state_file` to an absolute path on durable storage. If omitted,
state is in memory and planned/approved operations do not survive restart.

An indeterminate deployment means the request may have reached SDC but this
process did not observe a terminal state. Reconcile it using
`get_sdc_deploy_status`, the per-device result tool, and the SDC portal before
planning another deployment.

The SDC API does not expose a candidate rollback primitive for this workflow.
Rollback is therefore reported as unsupported rather than guessed.

## Token reload

On Unix, SIGHUP reloads the digest-only bearer-token file atomically. A failed
reload keeps the previous verified snapshot.
