#!/usr/bin/env bash
# Install a rustsdcmcp lab package. Run from an extracted package, never from a
# source checkout: the payload is validated before the target is changed.
set -euo pipefail

install_root=${SDCMCP_INSTALL_ROOT:-}
skip_user=${SDCMCP_INSTALL_SKIP_USER:-0}
skip_reload=${SDCMCP_INSTALL_SKIP_SYSTEMD_RELOAD:-0}
skip_runtime_deps=${SDCMCP_INSTALL_SKIP_RUNTIME_DEPS:-0}
force_unit=${SDCMCP_FORCE_UNIT:-0}

for flag in "$skip_user" "$skip_reload" "$skip_runtime_deps" "$force_unit"; do
    [[ "$flag" == 0 || "$flag" == 1 ]] || {
        printf '%s\n' "installer flags must be 0 or 1" >&2
        exit 2
    }
done

if [[ -n "$install_root" ]]; then
    [[ "$install_root" == /* ]] || {
        printf '%s\n' "SDCMCP_INSTALL_ROOT must be absolute" >&2
        exit 2
    }
    install_root=${install_root%/}
fi

package_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
target_path() {
    if [[ -n "$install_root" ]]; then
        printf '%s%s\n' "$install_root" "$1"
    else
        printf '%s\n' "$1"
    fi
}

require_file() {
    [[ -f "$package_dir/$1" ]] || {
        printf '%s\n' "package payload missing: $1" >&2
        exit 1
    }
}

# Validate every required package member before creating a target directory.
for member in \
    bin/rustsdcmcp \
    config/sdc.json.example \
    packaging/lxc/install.sh \
    packaging/systemd/rustsdcmcp.service \
    packaging/systemd/rustsdcmcp.sysusers \
    packaging/systemd/rustsdcmcp.tmpfiles \
    packaging/journald/mecmcp.conf \
    BUILD-INFO SBOM.cdx.json README.md LICENSE SECURITY.md docs/operations.md; do
    require_file "$member"
done
[[ -x "$package_dir/bin/rustsdcmcp" ]] || {
    printf '%s\n' "package binary is not executable" >&2
    exit 1
}

live_install=0
[[ -z "$install_root" ]] && live_install=1

if (( live_install )); then
    if [[ "$skip_runtime_deps" != 1 ]]; then
        [[ -f /etc/debian_version ]] || {
            printf '%s\n' "live installation requires Debian" >&2
            exit 1
        }
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends curl ca-certificates
    fi
    if [[ "$skip_user" != 1 ]]; then
        systemd-sysusers "$package_dir/packaging/systemd/rustsdcmcp.sysusers"
    fi
fi

config_dir=$(target_path /etc/rustsdcmcp)
state_dir=$(target_path /var/lib/rustsdcmcp)
bin_path=$(target_path /usr/local/bin/rustsdcmcp)
sysusers_path=$(target_path /usr/lib/sysusers.d/rustsdcmcp.conf)
tmpfiles_path=$(target_path /usr/lib/tmpfiles.d/rustsdcmcp.conf)
journal_path=$(target_path /etc/systemd/journald.conf.d/mecmcp.conf)
unit_path=$(target_path /etc/systemd/system/rustsdcmcp.service)

install -d -m 0750 "$config_dir"
install -d -m 0700 "$state_dir"
install -d -m 0755 "$(dirname -- "$bin_path")" "$(dirname -- "$sysusers_path")" \
    "$(dirname -- "$tmpfiles_path")" "$(dirname -- "$journal_path")" "$(dirname -- "$unit_path")"
install -m 0755 "$package_dir/bin/rustsdcmcp" "$bin_path"
install -m 0644 "$package_dir/packaging/systemd/rustsdcmcp.sysusers" "$sysusers_path"
install -m 0644 "$package_dir/packaging/systemd/rustsdcmcp.tmpfiles" "$tmpfiles_path"
install -m 0644 "$package_dir/packaging/journald/mecmcp.conf" "$journal_path"
install -m 0640 "$package_dir/config/sdc.json.example" "$config_dir/sdc.json.example"

if (( live_install )) && [[ "$skip_user" != 1 ]]; then
    systemd-tmpfiles --create "$package_dir/packaging/systemd/rustsdcmcp.tmpfiles"
fi

tokens_path=$(target_path /etc/rustsdcmcp/tokens.json)
hmac_path=$(target_path /etc/rustsdcmcp/audit-hmac.key)
if [[ ! -e "$tokens_path" ]]; then
    printf '%s\n' '{"version":1,"tokens":[]}' >"$tokens_path"
fi
if [[ ! -e "$hmac_path" ]]; then
    umask 077
    head -c 32 /dev/urandom >"$hmac_path"
fi
chmod 0600 "$tokens_path" "$hmac_path"

if (( live_install )); then
    chown rustsdcmcp:rustsdcmcp "$tokens_path" "$hmac_path"
fi

if [[ -e "$unit_path" ]] && ! cmp -s "$unit_path" "$package_dir/packaging/systemd/rustsdcmcp.service" && [[ "$force_unit" != 1 ]]; then
    printf '%s\n' "preserving customized unit: $unit_path"
else
    install -m 0644 "$package_dir/packaging/systemd/rustsdcmcp.service" "$unit_path"
fi

if (( live_install )) && [[ "$skip_reload" != 1 ]]; then
    systemctl daemon-reload
fi

printf '%s\n' \
    'Installation complete. Next steps:' \
    '1. Copy and edit /etc/rustsdcmcp/sdc.json.example as /etc/rustsdcmcp/sdc.json.' \
    '2. Install /etc/rustsdcmcp/credentials.env with mode 0600; do not put credentials in JSON.' \
    '3. Mint a least-privilege token, then start rustsdcmcp manually after configuration.' \
    '4. Configure remote journal forwarding before handling production traffic.' \
    'MCP endpoint: http://127.0.0.1:30032/mcp'
