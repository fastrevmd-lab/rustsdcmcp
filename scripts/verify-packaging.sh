#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

fail() {
    printf '%s\n' "packaging verification failed: $*" >&2
    exit 1
}
require() {
    local needle=$1
    local file=$2
    grep -Fqx -- "$needle" "$file" || fail "missing '$needle' in $file"
}
require_contains() {
    local needle=$1
    local file=$2
    grep -Fq -- "$needle" "$file" || fail "missing '$needle' in $file"
}

for script in scripts/build-lab-package.sh scripts/verify-packaging.sh \
    packaging/lxc/install.sh packaging/tests/package-smoke.sh; do
    [[ -x "$script" ]] || fail "$script must be executable"
    bash -n "$script"
done

if rg -n 'Command::new|std::process|tokio::process' crates --glob '*.rs' \
    -g '!tests/**' -g '!**/tests/**' -g '!**/*_test.rs'; then
    fail 'production Rust must not spawn processes'
fi

service=packaging/systemd/rustsdcmcp.service
installer=packaging/lxc/install.sh
tmpfiles=packaging/systemd/rustsdcmcp.tmpfiles
sysusers=packaging/systemd/rustsdcmcp.sysusers
journal=packaging/journald/mecmcp.conf
require 'u rustsdcmcp - "rustsdcmcp service" /var/lib/rustsdcmcp /usr/sbin/nologin' "$sysusers"
require 'd /etc/rustsdcmcp 0750 root rustsdcmcp -' "$tmpfiles"
require 'd /var/lib/rustsdcmcp 0700 rustsdcmcp rustsdcmcp -' "$tmpfiles"
require '[Journal]' "$journal"
require 'Storage=persistent' "$journal"
require 'SystemMaxUse=512M' "$journal"
require_contains '--host 127.0.0.1' "$service"
require_contains '--port 30032' "$service"
require_contains '--audit-format json' "$service"
require_contains '--audit-journald' "$service"
require_contains '--audit-redact devices=hmac' "$service"
require_contains '--audit-hmac-key-file /etc/rustsdcmcp/audit-hmac.key' "$service"

require_contains '/etc/rustsdcmcp/tokens.json' "$service"
require_contains '/etc/rustsdcmcp/tokens.json' "$installer"
require_contains '/var/lib/rustsdcmcp/changeset-state.json' scripts/build-lab-package.sh
require_contains 'config/sdc.json.example' "$installer"
require_contains 'systemd-sysusers' "$installer"
require_contains 'systemd-tmpfiles' "$installer"
require_contains 'curl ca-certificates' "$installer"
require_contains 'systemctl daemon-reload' "$installer"
if rg -n 'systemctl (enable|start|restart|try-restart)' "$installer"; then
    fail 'installer must not enable or start the nonbootable service'
fi

if rg -n 'credentials\.env|config/sdc\.json$|/sdc\.json$' packaging scripts \
    -g '!packaging/lxc/install.sh' -g '!packaging/systemd/rustsdcmcp.service' \
    -g '!packaging/tests/package-smoke.sh' -g '!scripts/verify-packaging.sh'; then
    fail 'packaging inputs must not contain a live config or credentials'
fi

verification_root=$(mktemp -d)
trap 'rm -rf -- "$verification_root"' EXIT
install -d "$verification_root/etc/systemd/system" "$verification_root/usr/local/bin" \
    "$verification_root/usr/lib/systemd/system" "$verification_root/bin"
install -m 0644 "$service" "$verification_root/etc/systemd/system/rustsdcmcp.service"
install -m 0755 /bin/true "$verification_root/usr/local/bin/rustsdcmcp"
install -m 0755 /bin/true "$verification_root/bin/kill"
printf '%s\n' '[Unit]' >"$verification_root/usr/lib/systemd/system/sysinit.target"
systemd-analyze --root="$verification_root" verify /etc/systemd/system/rustsdcmcp.service
printf '%s\n' 'packaging policy verification passed'
