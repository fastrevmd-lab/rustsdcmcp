# How to run rustsdcmcp in Docker

Runs the server as a container in either **lab mode** or **two-person** mode.
Written from a working setup built on 2026-09-07: every command here was run,
and the three failures that occurred are in [Troubleshooting](#troubleshooting)
with their exact error text.

| mode | approvals | use it for |
|---|---|---|
| **lab mode** (`--lab-mode`) | waived on creation, recorded as `approval_waiver=lab-mode` | ordinary tool work, reads, single-operator change sets |
| **two-person** (no flag) | a second principal must approve before apply | anything that must prove the approval gate holds |

The server announces lab mode at startup, as a `WARN`:

```
lab mode enabled: change sets are approved on creation with no second principal.
Records carry approval_waiver=lab-mode. Do not run this against production devices.
```

If you see that line and did not intend it, stop and fix the flag.

## The defining behavior of this server

**rustsdcmcp validates its credential against the live Security Director Cloud
API before it will serve.** With a placeholder credential the container starts,
parses everything, and then exits:

```
INFO rustsdcmcp: change-control configuration resolved lab_mode=false approval_ttl_secs=3600 state_file="/var/lib/sdcmcp/changeset-state.json"
Error: verifying SDC credential tenant scope

Caused by:
    SDC API error 401 (http_401): API key not valid
```

There is **no flag that relaxes this** — `--help` offers no skip/offline option.
Consequences an operator needs to know before they start:

- A valid tenant credential and network egress to the SDC API are
  **prerequisites**, not things you add later.
- This server cannot be brought up offline, air-gapped, or with a placeholder
  for a smoke test.
- Every other server in the family starts without contacting anything and only
  reaches the device when a tool is called.

Failing fast is defensible — a server that starts with a dead credential only
fails later, in front of a user. But it is unique to this repo, so say it
plainly and early rather than letting someone discover it.

Because of that, be honest about what was verified: the image, mounts, config
parsing, CLI wiring and auth all work and the process reaches its outbound
credential check. The steps past that point require a real tenant credential.

## What the image supplies

The image runs as numeric UID/GID `65532:65532` and its `ENTRYPOINT` is
`/usr/local/bin/rustsdcmcp` with no `CMD`. So **you supply every argument** —
nothing is preset and nothing can be silently lost.

## 1. Prepare host paths

```bash
mkdir -p sdc-docker/state-twoperson sdc-docker/state-labmode \
         sdc-docker/audit-twoperson sdc-docker/audit-labmode
cd sdc-docker
```

Two state directories — one per mode — because running both modes against the
same tenant with a shared state file creates uncoordinated writers (see step 4).
Two audit directories keep the audit trails separate. Generate an HMAC key for
redacted device names:

```bash
openssl rand -hex 32 > audit-hmac.key
chmod 0600 audit-hmac.key
```

`sdc.json` — based on `examples/sdc.example.json`. The credential is **not** in
this file — it names an environment variable via `credential_env` (default
`SDC_API_TOKEN`), supplied with `--env-file` or `-e`:

```json
{
  "version": 1,
  "tenant": "production",
  "expected_tenant_id": "replace-with-sdc-tenant-id",
  "credential_env": "SDC_API_TOKEN",
  "auth_scheme": "api_key",
  "endpoint": "https://api.sdcloud.juniperclouds.net/",
  "connect_timeout_ms": 10000,
  "request_timeout_ms": 30000,
  "max_response_bytes": 8388608,
  "max_concurrency": 16,
  "max_page_size": 200,
  "poll_initial_ms": 250,
  "poll_max_ms": 3000,
  "poll_deadline_ms": 120000,
  "changeset_state_file": "/var/lib/sdcmcp/changeset-state.json",
  "approval_ttl_secs": 3600
}
```

Use documentation addresses only — `expected_tenant_id` is replaced with the
real tenant ID from your SDC instance.

`credentials.env` — one shell-compatible assignment using the name from
`credential_env`:

```bash
SDC_API_TOKEN=your-actual-api-token-here
```

Never put a real credential in this README or in the JSON.

Mint a bearer token. If you have the host binary, run `token add` directly.
Otherwise, run it through the container image with a writable bind mount:

```bash
# With host binary (requires rustsdcmcp installed locally):
rustsdcmcp token add --tokens-file ./tokens.json --name my-client \
    --devices '*' --tools '*' -f ./sdc.json

# Or via the container image (no host binary needed):
docker run --rm --user "$(id -u):$(id -g)" \
    -v "$PWD:/workspace" -w /workspace \
    ghcr.io/fastrevmd-lab/rustsdcmcp:0.0.4 \
    token add --tokens-file ./tokens.json --name my-client \
    --devices '*' --tools '*' -f ./sdc.json
```

**The papercut worth documenting**: `token add` defaults `--device-mapping` to
`devices.json`, but this server's inventory is `sdc.json`, so it fails with
`Error: loading devices.json` until you pass `-f`.

The secret prints **once** and is stored hashed. `--tools '*'` resolves to
read-only tools only; write tools must be named explicitly, so a wildcard token
calling a write tool gets `insufficient_scope`. That is deliberate.

Then lock the modes down. File modes differ per file in this repo and matter:

```bash
chmod 0640 sdc.json               # 0640 — holds only tenant alias and endpoint, no secret
chmod 0600 credentials.env tokens.json  # 0600 — these hold secrets
```

## 2. Ownership: two options

The container process is UID 65532 and must read the config and write the state
directory. Choose one of two ownership strategies:

**Option A — For a real deployment**: Run as UID 65532 (the image's default)
and give it file ownership:

```bash
sudo chown -R 65532:65532 sdc.json credentials.env tokens.json state-twoperson state-labmode
sudo chmod 0700 state-twoperson state-labmode
```

Then omit `--user` from `docker run` — the container runs as 65532 and can read
its config and write state.

**Option B — For local testing without root**: Run the container as your own
UID and leave files owned by you:

```bash
# Keep files owned by yourself
# Add --user "$(id -u):$(id -g)" to docker run
```

The examples below show **Option B** (verified setup). For Option A, omit the
`--user` line and chown files to 65532 first.

## 3. Run it — two-person mode

```bash
docker run -d --name sdc-twoperson \
  --user "$(id -u):$(id -g)" \
  -p 127.0.0.1:30032:30032 \
  --env-file ./credentials.env \
  -v "$PWD/sdc.json:/etc/rustsdcmcp/sdc.json:ro" \
  -v "$PWD/tokens.json:/etc/rustsdcmcp/tokens.json:ro" \
  -v "$PWD/state-twoperson:/var/lib/sdcmcp" \
  -v "$PWD/audit-hmac.key:/etc/rustsdcmcp/audit-hmac.key:ro" \
  -v "$PWD/audit-twoperson:/var/lib/rustsdcmcp/audit" \
  ghcr.io/fastrevmd-lab/rustsdcmcp@sha256:c8b463c962bae51530f54694f59bc9cb4fee72ded4e8234bbb4fd3227010f877 `# :0.0.4` \
  --device-mapping /etc/rustsdcmcp/sdc.json \
  --transport streamable-http --host 0.0.0.0 --port 30032 \
  --tokens-file /etc/rustsdcmcp/tokens.json \
  --allow-insecure-bind \
  --allowed-host 127.0.0.1:30032 --allowed-host localhost:30032 \
  --allowed-origin http://console.example.org \
  --audit-format json \
  --audit-log-file /var/lib/rustsdcmcp/audit/audit.jsonl \
  --audit-redact devices=hmac \
  --audit-hmac-key-file /etc/rustsdcmcp/audit-hmac.key
```

**Port binding**: `-p 127.0.0.1:30032:30032` binds the published port to
loopback only. Reaching this server from another host requires TLS (via
`--tls-cert` and `--tls-key`), not a wider publish — Host and Origin are header
checks, not a network boundary.

**Image pinning**: The image is referenced by immutable digest
(`@sha256:c8b4...`). The version tag (`:0.0.4`) is kept as a comment for
readability. Obtain the digest with:

```bash
docker inspect ghcr.io/fastrevmd-lab/rustsdcmcp:0.0.4 \
    --format '{{index .RepoDigests 0}}'
```

Configuration and credentials are mounted read-only; only the state directory is
writable. It holds the change-set lifecycle state — do not delete state files
while a server is running.

## 4. Run it — lab mode

Identical but for `--lab-mode`, a different published port, and **a separate
state directory**:

```bash
docker run -d --name sdc-labmode \
  --user "$(id -u):$(id -g)" \
  -p 127.0.0.1:30042:30032 \
  --env-file ./credentials.env \
  -v "$PWD/sdc.json:/etc/rustsdcmcp/sdc.json:ro" \
  -v "$PWD/tokens.json:/etc/rustsdcmcp/tokens.json:ro" \
  -v "$PWD/state-labmode:/var/lib/sdcmcp" \
  -v "$PWD/audit-hmac.key:/etc/rustsdcmcp/audit-hmac.key:ro" \
  -v "$PWD/audit-labmode:/var/lib/rustsdcmcp/audit" \
  ghcr.io/fastrevmd-lab/rustsdcmcp@sha256:c8b463c962bae51530f54694f59bc9cb4fee72ded4e8234bbb4fd3227010f877 `# :0.0.4` \
  --device-mapping /etc/rustsdcmcp/sdc.json \
  --transport streamable-http --host 0.0.0.0 --port 30032 \
  --tokens-file /etc/rustsdcmcp/tokens.json \
  --allow-insecure-bind \
  --allowed-host 127.0.0.1:30042 --allowed-host localhost:30042 \
  --allowed-origin http://console.example.org \
  --audit-format json \
  --audit-log-file /var/lib/rustsdcmcp/audit/audit.jsonl \
  --audit-redact devices=hmac \
  --audit-hmac-key-file /etc/rustsdcmcp/audit-hmac.key \
  --lab-mode
```

**Note the port asymmetry, because it catches people.** The server always
listens on `30032` *inside* the container; `-p 127.0.0.1:30042:30032` publishes
it as 30042 on the host. But `--allowed-host` are matched against the `Host`
header the **client** sends, and the client is talking to 30042. So that flag
carries the *published* port, not the internal one. Get this wrong and the
server starts cleanly and then refuses every request with `421`.

**Each mode requires its own state directory** (`state-twoperson` vs
`state-labmode` above) and audit directory. **Only ONE writer per tenant may be
active**: separate state directories prevent snapshot clobbering, but each
process has its own coordinator and process-local locks, so neither sees the
other's in-flight mutation and both can submit conflicting SDC policy changes.
Run only one mode at a time against the same tenant, or use distinct tenants
(different `sdc.json` files pointing to different tenant configurations). If you
must run both modes simultaneously, serialize their access externally or use
completely separate tenant credentials.
the change-set lifecycle state is shared, and two servers pointed at one state
directory are two servers that can disagree about who owns a change set.

## 5. Verify

```bash
docker ps --filter name=sdc- --format '{{.Names}} {{.Status}}'

curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:30032/mcp \
     -H 'content-type: application/json' -d '{}'    # 401
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:30042/mcp \
     -H 'content-type: application/json' -d '{}'    # 401
```

**`401` is the success case**: the transport is up and authentication is being
enforced. `000` means nothing is listening — check `docker logs`. A `421` means
the allow-lists do not match the address the client used.

Confirm the mode is what you intended:

```bash
docker logs sdc-labmode 2>&1 | grep -i 'lab mode'
```

## 6. Stop

```bash
docker stop sdc-twoperson sdc-labmode
docker rm sdc-twoperson sdc-labmode
```

`docker stop` sends SIGTERM and waits, which lets the server finish in-flight
work and flush its state. Avoid `docker kill` for anything holding change-set
state: a process killed mid-write leaves an operation non-terminal, and the next
caller finds the tenant blocked.

## Troubleshooting

All three of these were hit while writing this document.

**`Error: verifying SDC credential tenant scope` / `SDC API error 401 (http_401): API key not valid`**
The credential is invalid or expired. Check the value in `credentials.env`, and
verify it against the SDC portal. The server validates the credential at startup
and exits immediately if it does not work. There is no flag to skip this check.

**`Error: non-loopback bind '0.0.0.0' requires at least one --allowed-origin (the accepted browser Origin, e.g. https://server.example.org:8443)`**
Binding anything other than loopback demands an explicit origin allow-list. This
is a guard, not an inconvenience: a container published to a host port is
reachable by any browser page that can resolve it, and the origin list is what
stops one driving your infrastructure. Add `--allowed-origin` for each address a
client will use.

**`Error: loading devices.json` when minting a token**
`token add` defaults `--device-mapping` to `devices.json`, but this server's
inventory is `sdc.json`. Pass `-f ./sdc.json` to fix it.

**`421` when calling the server**
`--allowed-host` and `--allowed-origin` do not match the address the client
used. These are matched against the `Host` and `Origin` headers the client
sends, so they must carry the **published** port when you use `-p` to map it,
not the internal container port.

**Container exits immediately with no log output** — check `docker logs` on the
stopped container: `docker ps -a --filter name=sdc-`. Startup validation
failures print and exit before the transport is up, so the container is gone by
the time you look for it with plain `docker ps`.

**Permission denied reading the inventory or writing state** — the container
process is UID 65532 and does not own your files. Either `chown -R 65532:65532`
them, or run with `--user "$(id -u):$(id -g)"` as shown above.
