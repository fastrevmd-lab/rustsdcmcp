#!/usr/bin/env bash
set -euo pipefail

archive=${1:-}
if [[ -z "$archive" || ! -f "$archive" ]]; then
    printf '%s\n' "archive not found: ${archive:-<missing>}" >&2
    exit 1
fi

archive=$(CDPATH= cd -- "$(dirname -- "$archive")" && pwd -P)/$(basename -- "$archive")
work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT
members_file="$work_dir/members"
tar -tzf "$archive" >"$members_file"

[[ -s "$members_file" ]] || {
    printf '%s\n' 'archive is empty' >&2
    exit 1
}
if grep -Eq '(^/|(^|/)\.\.(/|$))' "$members_file"; then
    printf '%s\n' 'archive has unsafe member paths' >&2
    exit 1
fi
if grep -Eq '(^|/)\.(/|$)' "$members_file"; then
    printf '%s\n' 'archive has ambiguous member paths' >&2
    exit 1
fi

mapfile -t roots < <(awk -F/ 'NF { print $1 }' "$members_file" | LC_ALL=C sort -u)
[[ ${#roots[@]} -eq 1 && -n ${roots[0]} ]] || {
    printf '%s\n' 'archive must contain exactly one root' >&2
    exit 1
}
package_root=${roots[0]}
case "$package_root" in
    *[!A-Za-z0-9._-]*)
        printf '%s\n' 'archive root has unsafe characters' >&2
        exit 1
        ;;
esac

required=(
    bin/rustsdcmcp
    config/sdc.json.example
    packaging/lxc/install.sh
    packaging/systemd/rustsdcmcp.service
    packaging/systemd/rustsdcmcp.sysusers
    packaging/systemd/rustsdcmcp.tmpfiles
    packaging/journald/mecmcp.conf
    BUILD-INFO
    SBOM.cdx.json
    README.md
    LICENSE
    SECURITY.md
    docs/operations.md
)
for member in "${required[@]}"; do
    grep -Fqx -- "$package_root/$member" "$members_file" || {
        printf '%s\n' "archive payload missing: $member" >&2
        exit 1
    }
done

tar -xzf "$archive" -C "$work_dir" --no-same-owner --no-same-permissions
installer="$work_dir/$package_root/packaging/lxc/install.sh"
[[ -x "$installer" ]] || {
    printf '%s\n' 'packaged installer is not executable' >&2
    exit 1
}

fresh_root="$work_dir/fresh-root"
SDCMCP_INSTALL_ROOT="$fresh_root" \
SDCMCP_INSTALL_SKIP_USER=1 \
SDCMCP_INSTALL_SKIP_SYSTEMD_RELOAD=1 \
SDCMCP_INSTALL_SKIP_RUNTIME_DEPS=1 \
    "$installer" >/dev/null
[[ ! -e "$fresh_root/etc/rustsdcmcp/sdc.json" ]] || {
    printf '%s\n' 'fresh install created live sdc.json' >&2
    exit 1
}
[[ ! -e "$fresh_root/etc/rustsdcmcp/credentials.env" ]] || {
    printf '%s\n' 'fresh install created credentials.env' >&2
    exit 1
}
[[ $(stat -c %a "$fresh_root/etc/rustsdcmcp/tokens.json") == 600 ]] || exit 1
[[ $(stat -c %a "$fresh_root/etc/rustsdcmcp/audit-hmac.key") == 600 ]] || exit 1

stage_root="$work_dir/stage-root"
mkdir -p "$stage_root/etc/rustsdcmcp" "$stage_root/var/lib/rustsdcmcp" \
    "$stage_root/etc/systemd/system"
printf '%s\n' 'existing config' >"$stage_root/etc/rustsdcmcp/sdc.json"
printf '%s\n' 'existing credentials' >"$stage_root/etc/rustsdcmcp/credentials.env"
printf '%s\n' 'existing tokens' >"$stage_root/etc/rustsdcmcp/tokens.json"
printf '%s\n' 'existing audit key' >"$stage_root/etc/rustsdcmcp/audit-hmac.key"
printf '%s\n' 'existing changeset state' >"$stage_root/var/lib/rustsdcmcp/changeset-state.json"
printf '%s\n' 'custom unit' >"$stage_root/etc/systemd/system/rustsdcmcp.service"
preserved=(
    "$stage_root/etc/rustsdcmcp/sdc.json"
    "$stage_root/etc/rustsdcmcp/credentials.env"
    "$stage_root/etc/rustsdcmcp/tokens.json"
    "$stage_root/etc/rustsdcmcp/audit-hmac.key"
    "$stage_root/var/lib/rustsdcmcp/changeset-state.json"
    "$stage_root/etc/systemd/system/rustsdcmcp.service"
)
sha256sum "${preserved[@]}" >"$work_dir/preserved.sha256"

for _ in 1 2; do
    SDCMCP_INSTALL_ROOT="$stage_root" \
    SDCMCP_INSTALL_SKIP_USER=1 \
    SDCMCP_INSTALL_SKIP_SYSTEMD_RELOAD=1 \
    SDCMCP_INSTALL_SKIP_RUNTIME_DEPS=1 \
        "$installer" >/dev/null
done
sha256sum -c "$work_dir/preserved.sha256" >/dev/null
printf '%s\n' 'package smoke passed'
