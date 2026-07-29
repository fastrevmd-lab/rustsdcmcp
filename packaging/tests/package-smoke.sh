#!/usr/bin/env bash
set -euo pipefail

archive=${1:-}
if [[ -z "$archive" || ! -f "$archive" ]]; then
    printf '%s\n' "archive not found: ${archive:-<missing>}" >&2
    exit 1
fi
command -v jq >/dev/null || {
    printf '%s\n' 'jq is required for package smoke SBOM validation' >&2
    exit 1
}

archive=$(CDPATH= cd -- "$(dirname -- "$archive")" && pwd -P)/$(basename -- "$archive")
checksum="${archive}.sha256"
if [[ -f "$checksum" ]]; then
    (
        cd "$(dirname -- "$archive")"
        sha256sum -c "$(basename -- "$checksum")"
    )
fi
work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT
members_file="$work_dir/members"
types_file="$work_dir/types"
tar -tzf "$archive" >"$members_file"
tar -tvz --numeric-owner -f "$archive" >"$types_file"

[[ -s "$members_file" ]] || {
    printf '%s\n' 'archive is empty' >&2
    exit 1
}
if grep -Eq '(^/|(^|/)\.\.?(/|$)|//)' "$members_file"; then
    printf '%s\n' 'archive has unsafe member paths' >&2
    exit 1
fi
if awk 'substr($0, 1, 1) != "-" && substr($0, 1, 1) != "d" { exit 1 }' "$types_file"; then
    :
else
    printf '%s\n' 'archive contains a non-regular member or link' >&2
    exit 1
fi

mapfile -t roots < <(sed 's:/*$::' "$members_file" | awk -F/ 'NF { print $1 }' | LC_ALL=C sort -u)
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

expected=(
    "$package_root"
    "$package_root/bin"
    "$package_root/config"
    "$package_root/packaging"
    "$package_root/packaging/lxc"
    "$package_root/packaging/systemd"
    "$package_root/packaging/journald"
    "$package_root/docs"
    "$package_root/bin/rustsdcmcp"
    "$package_root/config/sdc.json.example"
    "$package_root/packaging/lxc/install.sh"
    "$package_root/packaging/systemd/rustsdcmcp.service"
    "$package_root/packaging/systemd/rustsdcmcp.sysusers"
    "$package_root/packaging/systemd/rustsdcmcp.tmpfiles"
    "$package_root/packaging/journald/mecmcp.conf"
    "$package_root/BUILD-INFO"
    "$package_root/SBOM.cdx.json"
    "$package_root/README.md"
    "$package_root/LICENSE"
    "$package_root/SECURITY.md"
    "$package_root/docs/operations.md"
)
declare -A allowed=()
declare -A seen=()
for member in "${expected[@]}"; do
    allowed["$member"]=1
done
while IFS= read -r member; do
    member=${member%/}
    [[ -n "$member" && ${allowed[$member]+yes} ]] || {
        printf '%s\n' "archive has unexpected member: $member" >&2
        exit 1
    }
    [[ ! ${seen[$member]+yes} ]] || {
        printf '%s\n' "archive has duplicate member: $member" >&2
        exit 1
    }
    seen["$member"]=1
done <"$members_file"
[[ ${#seen[@]} -eq ${#expected[@]} ]] || {
    printf '%s\n' 'archive payload is incomplete' >&2
    exit 1
}

tar -xOf "$archive" "$package_root/SBOM.cdx.json" \
    | jq -e '.bomFormat == "CycloneDX"' >/dev/null || {
        printf '%s\n' 'archive SBOM is not a CycloneDX JSON document' >&2
        exit 1
    }

tar -xzf "$archive" -C "$work_dir" --no-same-owner --no-same-permissions
installer="$work_dir/$package_root/packaging/lxc/install.sh"
[[ -x "$installer" && ! -L "$installer" ]] || {
    printf '%s\n' 'packaged installer is not an executable regular file' >&2
    exit 1
}

fresh_root="$work_dir/fresh-root"
fresh_output="$work_dir/fresh-output"
SDCMCP_INSTALL_ROOT="$fresh_root" \
SDCMCP_INSTALL_SKIP_USER=1 \
SDCMCP_INSTALL_SKIP_SYSTEMD_RELOAD=1 \
SDCMCP_INSTALL_SKIP_RUNTIME_DEPS=1 \
    "$installer" >"$fresh_output"
grep -Fqx '1. Create config: install -o root -g rustsdcmcp -m 0640 /etc/rustsdcmcp/sdc.json.example /etc/rustsdcmcp/sdc.json, then edit /etc/rustsdcmcp/sdc.json.' "$fresh_output"
[[ ! -e "$fresh_root/etc/rustsdcmcp/sdc.json" ]] || {
    printf '%s\n' 'fresh install created live sdc.json' >&2
    exit 1
}
[[ ! -e "$fresh_root/etc/rustsdcmcp/credentials.env" ]] || {
    printf '%s\n' 'fresh install created credentials.env' >&2
    exit 1
}
jq -e '. == {"version": 1, "tokens": []}' "$fresh_root/etc/rustsdcmcp/tokens.json" >/dev/null
[[ $(stat -c %a "$fresh_root/etc/rustsdcmcp/tokens.json") == 600 ]] || exit 1
[[ $(stat -c %a "$fresh_root/etc/rustsdcmcp/audit-hmac.key") == 600 ]] || exit 1
[[ $(wc -c <"$fresh_root/etc/rustsdcmcp/audit-hmac.key") == 32 ]] || exit 1
[[ $(stat -c %a "$fresh_root/etc/rustsdcmcp/sdc.json.example") == 640 ]] || exit 1

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
