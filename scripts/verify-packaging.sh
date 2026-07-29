#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

fail() {
    printf '%s\n' "packaging verification failed: $*" >&2
    exit 1
}
require() {
    local needle=$1 file=$2
    grep -Fqx -- "$needle" "$file" || fail "missing '$needle' in $file"
}
require_contains() {
    local needle=$1 file=$2
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
expected_exec='/usr/local/bin/rustsdcmcp --device-mapping /etc/rustsdcmcp/sdc.json --transport streamable-http --host 127.0.0.1 --port 30032 --tokens-file /etc/rustsdcmcp/tokens.json --audit-format json --audit-journald --audit-redact devices=hmac --audit-hmac-key-file /etc/rustsdcmcp/audit-hmac.key'

service_directive_values() {
    local key=$1
    awk -v key="$key" '
        /^[[:space:]]*\[Service\][[:space:]]*$/ { in_service = 1; next }
        /^[[:space:]]*\[[^]]+\][[:space:]]*$/ { in_service = 0 }
        in_service {
            line = $0
            sub(/^[[:space:]]+/, "", line)
            if (line ~ ("^" key "[[:space:]]*=")) {
                sub("^" key "[[:space:]]*=[[:space:]]*", "", line)
                sub(/[[:space:]]+$/, "", line)
                print line
            }
        }
    ' "$service"
}

require_service_directive() {
    local key=$1 expected=$2
    local -a values=()
    mapfile -t values < <(service_directive_values "$key")
    [[ ${#values[@]} -eq 1 && ${values[0]} == "$expected" ]] \
        || fail "active $key directives conflict"
}

exec_start=$(awk '
    /^[[:space:]]*\[Service\][[:space:]]*$/ { in_service = 1; next }
    /^[[:space:]]*\[[^]]+\][[:space:]]*$/ { in_service = 0 }
    in_service && $0 ~ /^[[:space:]]*ExecStart[[:space:]]*=/ {
        if (found++) exit 2
        line = $0
        sub(/^[[:space:]]*ExecStart[[:space:]]*=[[:space:]]*/, "", line)
        while (line ~ /\\$/) {
            sub(/\\$/, "", line)
            if (getline continuation <= 0) exit 2
            sub(/^[[:space:]]+/, "", continuation)
            line = line " " continuation
        }
        print line
    }
    END { if (found != 1) exit 2 }
' "$service" | sed 's/[[:space:]]\+/ /g; s/^ //; s/ $//') || fail 'unit must contain one complete ExecStart'
[[ "$exec_start" == "$expected_exec" ]] || fail 'active ExecStart conflicts with loopback/token/audit policy'
require_service_directive EnvironmentFile /etc/rustsdcmcp/credentials.env
require_service_directive ReadOnlyPaths /etc/rustsdcmcp
require_service_directive ReadWritePaths /var/lib/rustsdcmcp
require 'u rustsdcmcp - "rustsdcmcp service" /var/lib/rustsdcmcp /usr/sbin/nologin' "$sysusers"
require 'd /etc/rustsdcmcp 0750 root rustsdcmcp -' "$tmpfiles"
require 'd /var/lib/rustsdcmcp 0700 rustsdcmcp rustsdcmcp -' "$tmpfiles"
require '[Journal]' "$journal"
require 'Storage=persistent' "$journal"
require 'SystemMaxUse=512M' "$journal"
# These assertions intentionally match literal shell source fragments.
# shellcheck disable=SC2016
require_contains 'install -o root -g rustsdcmcp -m 0640 "$package_dir/config/sdc.json.example" "$config_dir/sdc.json.example"' "$installer"
# shellcheck disable=SC2016
require_contains 'install_root=$(realpath -m -- "$install_root")' "$installer"
# shellcheck disable=SC2016
require_contains '[[ "$install_root" != / ]] || die '\''SDCMCP_INSTALL_ROOT must not resolve to /'\''' "$installer"
# shellcheck disable=SC2016
require_contains 'systemd-sysusers "$package_dir/packaging/systemd/rustsdcmcp.sysusers"' "$installer"
# shellcheck disable=SC2016
require_contains 'systemd-tmpfiles --create "$package_dir/packaging/systemd/rustsdcmcp.tmpfiles"' "$installer"
require_contains 'DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends curl ca-certificates' "$installer"
require_contains 'systemctl daemon-reload' "$installer"
if rg -n 'systemctl (enable|start|restart|try-restart)' "$installer"; then
    fail 'installer must not enable or start the nonbootable service'
fi

if find packaging -type f \( -name 'sdc.json' -o -name 'credentials.env' \) -print -quit | grep -q .; then
    fail 'live config or credentials are present in packaging inputs'
fi
if ! grep -Fq 's#/var/lib/sdcmcp/changeset-state.json#/var/lib/rustsdcmcp/changeset-state.json#' scripts/build-lab-package.sh; then
    fail 'builder does not package the canonical state path'
fi

assert_builder_preserves_unsafe_output_entries() {
    local fixture fake_bin commit archive checksum outside extra
    fixture=$(mktemp -d)
    fake_bin="$fixture/fake-bin"
    mkdir -p "$fixture/scripts" "$fake_bin"
    cp scripts/build-lab-package.sh "$fixture/scripts/build-lab-package.sh"
    chmod 0755 "$fixture/scripts/build-lab-package.sh"
    printf '%s\n' 'dist/' 'fake-bin/' 'outside/' >"$fixture/.gitignore"
    git -C "$fixture" init -q
    git -C "$fixture" config user.email packaging-test@example.invalid
    git -C "$fixture" config user.name packaging-test
    git -C "$fixture" add .gitignore scripts/build-lab-package.sh
    git -C "$fixture" commit -qm 'test fixture'
    commit=$(git -C "$fixture" rev-parse HEAD)
    archive="$fixture/dist/$commit/rustsdcmcp_0.1.0-lab.$(date -u -d "@$(git -C "$fixture" show -s --format=%ct HEAD)" +%Y%m%d).${commit:0:12}_amd64.tar.gz"
    checksum="${archive}.sha256"
    cat >"$fake_bin/trivy" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' 'Version: 0.70.0'
EOF
    cat >"$fake_bin/cargo" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
    chmod 0755 "$fake_bin/trivy" "$fake_bin/cargo"

    outside="$fixture/outside"
    mkdir -p "$outside" "$fixture/dist"
    printf '%s\n' sentinel-archive >"$outside/$(basename -- "$archive")"
    printf '%s\n' sentinel-checksum >"$outside/$(basename -- "$checksum")"
    ln -s "$outside" "$fixture/dist/$commit"
    if (cd "$fixture" && PATH="$fake_bin:$PATH" scripts/build-lab-package.sh) >/dev/null 2>&1; then
        fail 'builder accepted a symlinked commit artifact directory'
    fi
    [[ -f "$outside/$(basename -- "$archive")" && -f "$outside/$(basename -- "$checksum")" ]] \
        || fail 'builder removed artifacts through a symlinked commit directory'

    rm "$fixture/dist/$commit"
    mkdir -p "$fixture/dist/$commit"
    printf '%s\n' sentinel-archive >"$archive"
    printf '%s\n' sentinel-checksum >"$checksum"
    extra="$fixture/dist/$commit/unexpected-artifact"
    printf '%s\n' sentinel-extra >"$extra"
    if (cd "$fixture" && PATH="$fake_bin:$PATH" scripts/build-lab-package.sh) >/dev/null 2>&1; then
        fail 'builder accepted an artifact directory with an extra entry'
    fi
    [[ -f "$archive" && -f "$checksum" && -f "$extra" ]] \
        || fail 'builder removed stale artifacts before rejecting an extra entry'
    rm -rf -- "$fixture"
}
assert_builder_preserves_unsafe_output_entries

verification_root=$(mktemp -d)
trap 'rm -rf -- "$verification_root"' EXIT
install -d "$verification_root/etc/systemd/system" "$verification_root/usr/local/bin" \
    "$verification_root/usr/lib/systemd/system" "$verification_root/bin"
install -m 0644 "$service" "$verification_root/etc/systemd/system/rustsdcmcp.service"
install -m 0755 /bin/true "$verification_root/usr/local/bin/rustsdcmcp"
install -m 0755 /bin/true "$verification_root/bin/kill"
printf '%s\n' '[Unit]' >"$verification_root/usr/lib/systemd/system/sysinit.target"
systemd-analyze --root="$verification_root" verify /etc/systemd/system/rustsdcmcp.service

git_commit=$(git rev-parse HEAD)
package_date=$(date -u -d "@$(git show -s --format=%ct HEAD)" +%Y%m%d)
archive="dist/$git_commit/rustsdcmcp_0.1.0-lab.${package_date}.${git_commit:0:12}_amd64.tar.gz"
if [[ -f "$archive" ]]; then
    packaging/tests/package-smoke.sh "$archive"
fi
printf '%s\n' 'packaging policy verification passed'
