# How to set up a rustsdcmcp LXC from scratch

Builds one Proxmox LXC running `rustsdcmcp`, in either **lab mode** or
**two-person** mode. Written from a rebuild performed on 2026-09-07, not from
memory: every command here was run.

Two rigs are normally built as a pair, because they test different things:

| mode | approvals | use it for |
|---|---|---|
| **lab mode** (`--lab-mode`) | waived on creation, recorded as `approval_waiver=lab-mode` | ordinary tool work, reads, single-operator change sets |
| **two-person** (no flag) | a second principal must approve before apply | anything that must prove the approval gate holds |

Never point a lab-mode server at production devices. It says so itself at
startup, in a `WARN`.

## 0. Before you start

You need:

- A Proxmox node, a container template, and a free VMID and IP.
- **The SDC API token and tenant configuration.** Building the container is the
  easy part; these are the part you need first. If you are rebuilding an
  existing rig, back them up first — see [Rebuilding](#rebuilding-an-existing-rig).

Check the template is present:

```bash
pveam list local | grep debian-13
# local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst
```

## 1. Get a binary that will actually run

**Do not `cargo build --release` on your workstation and copy the binary in.**
glibc is forward-incompatible: a binary linked against a newer glibc will not
start on an older one, and it fails at service start with a loader error *after*
the old binary has been replaced — an outage, not a build failure.

Take the binary from the release image, which CI builds against the right glibc:

```bash
docker create --name sx ghcr.io/fastrevmd-lab/rustsdcmcp:0.0.4
docker cp sx:/usr/local/bin/rustsdcmcp target/release/rustsdcmcp
docker rm sx
```

No docker? `skopeo copy docker://ghcr.io/fastrevmd-lab/rustsdcmcp:0.0.4 dir:/tmp/img`
then find the layer containing `usr/local/bin/rustsdcmcp` and untar it.

## 2. Assemble the install package

`scripts/build-package.sh` builds the package. Point it at the binary you just
extracted rather than letting it compile one:

```bash
cd /path/to/rustsdcmcp
mkdir -p target/release
install -m 0755 ./rustsdcmcp target/release/rustsdcmcp
SDCMCP_PACKAGE_SKIP_BUILD=1 scripts/build-package.sh
# >> Wrote dist/<commit>/rustsdcmcp_0.0.4_<date>.<commit>_amd64.tar.gz
```

**This repo has the strictest installer in the family.** `packaging/lxc/install.sh`
validates a complete payload — `bin/rustsdcmcp`, `config/sdc.json.example`, four
`packaging/systemd/*` files, `BUILD-INFO`, `SBOM.cdx.json`, `README.md`,
`LICENSE`, `SECURITY.md`, `docs/operations.md` — and it validates **BUILD-INFO at
install time**, so a stale version or mecmcp_ref fails on the container even
though CI was green. A package assembled from the wrong commit or with stale
embedded files is rejected at install.

## 3. Create the container

`nesting=1` is **required**. systemd 257 degrades badly in an unprivileged LXC
without it.

```bash
pct create 614 local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst \
    --hostname test-twoperson-sdc \
    --cores 1 --memory 512 --swap 512 \
    --rootfs local-lvm:4 \
    --unprivileged 1 --features nesting=1 \
    --net0 name=eth0,bridge=vmbr0,firewall=1,gw=192.0.2.1,ip=192.0.2.10/24,type=veth \
    --onboot 0 --ostype debian \
    --tags "disposable;test;twoperson"

pct start 614
```

512 MB and one core is enough. The tags matter: `disposable` is what marks a
guest as safe to destroy, and the fleet's own safety rules key on it.

For lab mode, use VMID 615 with IP `.235`, hostname `test-labmode-sdc`, and tag
`labmode` instead of `twoperson`.

## 4. Install

```bash
pct push 614 dist/<commit>/rustsdcmcp_0.0.4_*_amd64.tar.gz /tmp/pkg.tar.gz
pct exec 614 -- bash -lc 'cd /tmp && tar xzf pkg.tar.gz && cd rustsdcmcp_*/ && bash ./install.sh'
```

Invoke the installer as `bash ./packaging/lxc/install.sh` — it may not be
executable in the archive.

`install.sh` creates the `rustsdcmcp` service user, installs the binary and the
unit, and stops there. **The service will not start yet** — it has no
configuration, and it says so.

The installer notes `IPAddressDeny` is inert in unprivileged LXC. That is
expected and true — mention it so nobody reads it as a fault.

## 5. Configuration and credentials

Place the configuration and credential files:

```bash
pct push 614 sdc.json         /etc/rustsdcmcp/sdc.json
pct push 614 credentials.env  /etc/rustsdcmcp/credentials.env
```

Then fix ownership and modes. **Do this for every credential file at once.** The
server refuses to start if a credential file is group- or world-readable, and it
checks them one at a time — so getting this wrong costs you one restart per file.
The error names the file and the required mode:

```
mode 0644 is group- or world-accessible (owner uid 999, this process uid 999);
run: chmod 600 /etc/rustsdcmcp/credentials.env
```

Set the correct mode per file:

```bash
pct exec 614 -- bash -lc '
    chown -R rustsdcmcp:rustsdcmcp /etc/rustsdcmcp
    chmod 0640 /etc/rustsdcmcp/sdc.json
    chmod 0600 /etc/rustsdcmcp/credentials.env
    chmod 0600 /etc/rustsdcmcp/tokens.json
    install -d -o rustsdcmcp -g rustsdcmcp -m 0700 /var/lib/rustsdcmcp
'
```

`sdc.json` is 0640 because it contains no secrets — only the tenant alias,
endpoint URL, and expected tenant ID. The credentials live in `credentials.env`.

## 6. The site drop-in

The shipped unit binds `127.0.0.1` and is deliberately conservative. Site
configuration goes in a drop-in, which keeps the shipped unit replaceable.
**The installer does NOT create `/etc/systemd/system/rustsdcmcp.service.d/`**;
`mkdir -p` it first:

```bash
pct exec 614 -- mkdir -p /etc/systemd/system/rustsdcmcp.service.d
```

`/etc/systemd/system/rustsdcmcp.service.d/override.conf`:

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/rustsdcmcp \
    --device-mapping /etc/rustsdcmcp/sdc.json \
    --transport streamable-http \
    --host 0.0.0.0 \
    --port 30032 \
    --tokens-file /var/lib/rustsdcmcp/tokens.json \
    --audit-format json \
    --audit-journald \
    --audit-log-file /var/lib/rustsdcmcp/audit.jsonl \
    --audit-redact devices=hmac \
    --audit-hmac-key-file /etc/rustsdcmcp/audit-hmac.key \
    --allowed-host 192.0.2.10 \
    --allowed-host 192.0.2.10:30032
```

The empty `ExecStart=` is required: it clears the shipped one before setting a
new one. Why site config belongs in a drop-in: the shipped unit carries the
seccomp posture, and replacing it wholesale silently loses that.

**Two-person mode is the same file with no additional flag.** Lab mode adds
`--lab-mode` to the end. That single flag is the whole difference. Point
`--allowed-host` at that rig's own address — it must track whatever clients
actually dial, or requests are refused with 421.

Then:

```bash
pct exec 614 -- systemctl daemon-reload
pct exec 614 -- systemctl enable rustsdcmcp.service
pct exec 614 -- systemctl start rustsdcmcp.service
```

## 7. Mint a token

```bash
pct exec 614 -- runuser -u rustsdcmcp -- /usr/local/bin/rustsdcmcp token add \
    --tokens-file /var/lib/rustsdcmcp/tokens.json \
    --name my-client --devices 'production' --tools '*' \
    --device-mapping /etc/rustsdcmcp/sdc.json
```

The secret is printed **once** and stored hashed. Two things worth knowing:

- A running server holds its token store in memory. A newly minted or revoked
  token does nothing until the server is restarted: `systemctl restart rustsdcmcp.service`.
  The CLI warns you about this.
- `--tools '*'` is a wildcard that resolves to *read-only tools only*. Write
  tools must be named explicitly, so a wildcard token calling
  `create_sdc_change_set` gets `insufficient_scope`. That is deliberate.

## 8. Verify

Check the four things that actually matter:

```bash
# 1. it is running the version you think
pct exec 614 -- /usr/local/bin/rustsdcmcp --version

# 2. the seccomp posture comes from the SHIPPED unit, not a local patch
pct exec 614 -- systemctl show rustsdcmcp.service -p SystemCallErrorNumber --value   # 1 (EPERM)
pct exec 614 -- grep -l SystemCallErrorNumber /etc/systemd/system/rustsdcmcp.service

# 3. the filter is actually installed, read from the kernel rather than systemd
pid=$(pct exec 614 -- systemctl show -p MainPID --value rustsdcmcp.service)
pct exec 614 -- grep -E '^Seccomp' /proc/$pid/status                                 # Seccomp: 2

# 4. it is serving, and refusing unauthenticated callers
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://192.0.2.10:30032/mcp \
     -H 'content-type: application/json' -d '{}'                                     # 401
```

`401` is the success case here: the transport is up and authentication is being
enforced. A `000` means nothing is listening on that address or port.

Checking `SystemCallErrorNumber` matters. Without it a denied syscall raises
SIGSYS and kills the process mid-request instead of returning `EPERM`; that is
mecmcp#351, and reading it back from the unit is how you know the fix is present.

Also verify `Seccomp: 2` in `/proc/<pid>/status` — this proves the filter is
actually installed, not just configured. A directive can be present in the unit
and enforce nothing.

## 9. Final step: stop the rig

Test rigs here are stopped by default; started only when needed, stopped again at
completion.

```bash
pct shutdown 614
```

Use `pct shutdown`, not `pct stop`. `shutdown` asks systemd inside the container
to shut down cleanly so the service can flush its change-set state to disk. `stop`
kills the container immediately, and a process killed mid-write is how an
operation ends up non-terminal and blocks the tenant for the next caller.

## Rebuilding an existing rig

Back the credentials out **before** destroying anything. `pct mount` reads a
stopped container's filesystem without starting it:

```bash
pct mount 614
cp -a /var/lib/lxc/614/rootfs/etc/rustsdcmcp        /root/backup-614/
cp -a /var/lib/lxc/614/rootfs/var/lib/rustsdcmcp    /root/backup-614/
cp -a /var/lib/lxc/614/rootfs/etc/systemd/system/rustsdcmcp.service.d /root/backup-614/
pct config 614 > /root/backup-614/pct-config.txt
pct unmount 614
```

`pct-config.txt` is worth keeping: it is the network, resources and tags you will
want to reproduce.

Restoring `tokens.json` rather than minting fresh tokens keeps existing clients
working — the secrets are hashed and cannot be recovered, so re-minting means
reconfiguring every client that talks to this rig.
