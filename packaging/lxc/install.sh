#!/usr/bin/env bash
# Install a validated rustsdcmcp lab package. It deliberately never enables the
# service: an operator must first install real configuration and credentials.
set -euo pipefail

die() {
    printf '%s\n' "installer validation failed: $*" >&2
    exit 1
}

[[ ! -L "$0" ]] || die 'installer must not be invoked through a symlink'
install_root=${SDCMCP_INSTALL_ROOT:-}
skip_user=${SDCMCP_INSTALL_SKIP_USER:-0}
skip_reload=${SDCMCP_INSTALL_SKIP_SYSTEMD_RELOAD:-0}
skip_runtime_deps=${SDCMCP_INSTALL_SKIP_RUNTIME_DEPS:-0}
force_unit=${SDCMCP_FORCE_UNIT:-0}
test_live=${SDCMCP_INSTALL_TEST_LIVE:-0}

for flag in "$skip_user" "$skip_reload" "$skip_runtime_deps" "$force_unit" "$test_live"; do
    [[ "$flag" == 0 || "$flag" == 1 ]] || die 'installer flags must be 0 or 1'
done
if [[ -n "$install_root" ]]; then
    [[ "$install_root" == /* ]] || die 'SDCMCP_INSTALL_ROOT must be absolute'
    command -v realpath >/dev/null || die 'realpath is required to validate SDCMCP_INSTALL_ROOT'
    install_root=$(realpath -m -- "$install_root")
    [[ "$install_root" != / ]] || die 'SDCMCP_INSTALL_ROOT must not resolve to /'
fi
if [[ "$test_live" == 1 ]]; then
    [[ -n "$install_root" ]] || die 'SDCMCP_INSTALL_TEST_LIVE requires a stage root'
    [[ "$skip_user" == 1 ]] || die 'SDCMCP_INSTALL_TEST_LIVE requires SDCMCP_INSTALL_SKIP_USER=1'
    [[ "$skip_runtime_deps" == 1 ]] || die 'SDCMCP_INSTALL_TEST_LIVE requires SDCMCP_INSTALL_SKIP_RUNTIME_DEPS=1'
    [[ "$skip_reload" == 1 ]] || die 'SDCMCP_INSTALL_TEST_LIVE requires SDCMCP_INSTALL_SKIP_SYSTEMD_RELOAD=1'
fi

package_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
target_path() {
    if [[ -n "$install_root" ]]; then
        printf '%s%s\n' "$install_root" "$1"
    else
        printf '%s\n' "$1"
    fi
}

required_files=(
    bin/rustsdcmcp config/sdc.json.example packaging/lxc/install.sh
    packaging/systemd/rustsdcmcp.service packaging/systemd/rustsdcmcp.sysusers
    packaging/systemd/rustsdcmcp.tmpfiles packaging/journald/mecmcp.conf
    BUILD-INFO SBOM.cdx.json README.md LICENSE SECURITY.md docs/operations.md
)
required_dirs=(bin config packaging packaging/lxc packaging/systemd packaging/journald docs)

validate_layout() {
    local entry type file_count=0 dir_count=0
    declare -A files=() dirs=()
    for entry in "${required_files[@]}"; do files["$entry"]=1; done
    for entry in "${required_dirs[@]}"; do dirs["$entry"]=1; done
    [[ -d "$package_dir" && ! -L "$package_dir" ]] || die 'package root is not a real directory'
    while IFS=$'\t' read -r entry type; do
        [[ -n "$entry" ]] || die 'package contains an empty member name'
        case "$type" in
            f)
                [[ ${files[$entry]+yes} ]] || die "unexpected package file: $entry"
                ((file_count += 1))
                ;;
            d)
                [[ ${dirs[$entry]+yes} ]] || die "unexpected package directory: $entry"
                ((dir_count += 1))
                ;;
            *) die "package contains non-regular member: $entry" ;;
        esac
    done < <(find -P "$package_dir" -mindepth 1 -printf '%P\t%y\n')
    [[ $file_count -eq ${#required_files[@]} ]] || die 'package payload files are incomplete'
    [[ $dir_count -eq ${#required_dirs[@]} ]] || die 'package payload directories are incomplete'
    for entry in "${required_files[@]}"; do
        [[ -f "$package_dir/$entry" && ! -L "$package_dir/$entry" ]] || die "missing regular payload file: $entry"
    done
    [[ -x "$package_dir/bin/rustsdcmcp" ]] || die 'package binary is not executable'
}

validate_build_info() {
    local build_info="$package_dir/BUILD-INFO"
    grep -Fqx 'release_status=lab-only' "$build_info" || die 'BUILD-INFO release status is invalid'
    grep -Fqx 'version=0.1.0' "$build_info" || die 'BUILD-INFO version is invalid'
    grep -Eq '^git_commit=[0-9a-f]{40}$' "$build_info" || die 'BUILD-INFO commit is invalid'
    grep -Eq '^source_date_epoch=[0-9]+$' "$build_info" || die 'BUILD-INFO epoch is invalid'
    grep -Fqx 'target=x86_64-unknown-linux-gnu' "$build_info" || die 'BUILD-INFO target is invalid'
    grep -Fqx 'mecmcp_ref=changeset-v0.3.6' "$build_info" || die 'BUILD-INFO mecmcp ref is invalid'
    grep -Eq '^glibc_floor=[0-9]+(\.[0-9]+)+$' "$build_info" || die 'BUILD-INFO GLIBC floor is invalid'
    grep -Eq '^rustc=rustc ' "$build_info" || die 'BUILD-INFO rustc metadata is invalid'
}

validate_sbom() {
    local sbom="$package_dir/SBOM.cdx.json"
    if command -v jq >/dev/null; then
        jq -e '
            .bomFormat == "CycloneDX"
            and (.metadata.component.name == "rustsdcmcp")
            and (.components | type == "array" and length > 0)
            and any(.components[]; .name == "serde")
            and any(.components[]; .name == "mecmcp-auth")
        ' "$sbom" >/dev/null || die 'SBOM lacks required CycloneDX metadata or components'
    else
        grep -Eq '"bomFormat"[[:space:]]*:[[:space:]]*"CycloneDX"' "$sbom" \
            && grep -Fq '"serde"' "$sbom" \
            && grep -Fq '"mecmcp-auth"' "$sbom" \
            && grep -Fq '"name": "rustsdcmcp"' "$sbom" \
            || die 'SBOM does not identify as CycloneDX'
    fi
    ! grep -Eq '"/(home|workspace|workspaces)/' "$sbom" \
        || die 'SBOM contains an absolute repository or worktree path'
}

validate_config() {
    local config="$package_dir/config/sdc.json.example"
    if command -v jq >/dev/null; then
        jq -e '
            .version == 1
            and (.tenant | type == "string" and length > 0)
            and (.credential_env | type == "string" and length > 0)
            and (.endpoint | type == "string" and startswith("https://"))
            and .changeset_state_file == "/var/lib/rustsdcmcp/changeset-state.json"
        ' "$config" >/dev/null || die 'config example is not operationally valid JSON'
    else
        grep -Fq '"version": 1' "$config" \
            && grep -Fq '"changeset_state_file": "/var/lib/rustsdcmcp/changeset-state.json"' "$config" \
            && grep -Fq '"endpoint": "https://' "$config" \
            || die 'config example fails dependency-free validation'
    fi
}

extract_exec_start() {
    awk '
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
    ' "$package_dir/packaging/systemd/rustsdcmcp.service"
}

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
    ' "$package_dir/packaging/systemd/rustsdcmcp.service"
}

require_service_directive() {
    local key=$1 expected=$2
    local -a values=()
    mapfile -t values < <(service_directive_values "$key")
    [[ ${#values[@]} -eq 1 && ${values[0]} == "$expected" ]] \
        || die "unit $key directives are invalid"
}

validate_service() {
    local service="$package_dir/packaging/systemd/rustsdcmcp.service"
    local expected exec_start
    expected='/usr/local/bin/rustsdcmcp --device-mapping /etc/rustsdcmcp/sdc.json --transport streamable-http --host 127.0.0.1 --port 30032 --tokens-file /etc/rustsdcmcp/tokens.json --audit-format json --audit-journald --audit-redact devices=hmac --audit-hmac-key-file /etc/rustsdcmcp/audit-hmac.key'
    exec_start=$(extract_exec_start | sed 's/[[:space:]]\+/ /g; s/^ //; s/ $//') || die 'unit has invalid ExecStart'
    [[ "$exec_start" == "$expected" ]] || die 'unit ExecStart does not match the package policy'
    require_service_directive EnvironmentFile /etc/rustsdcmcp/credentials.env
    require_service_directive ReadOnlyPaths /etc/rustsdcmcp
    require_service_directive ReadWritePaths /var/lib/rustsdcmcp
}

validate_package() {
    validate_layout
    bash -n "$package_dir/packaging/lxc/install.sh"
    validate_build_info
    validate_sbom
    validate_config
    validate_service
    grep -Fqx 'u rustsdcmcp - "rustsdcmcp service" /var/lib/rustsdcmcp /usr/sbin/nologin' "$package_dir/packaging/systemd/rustsdcmcp.sysusers" || die 'sysusers declaration is invalid'
    grep -Fqx 'd /etc/rustsdcmcp 0750 root rustsdcmcp -' "$package_dir/packaging/systemd/rustsdcmcp.tmpfiles" || die 'config tmpfiles declaration is invalid'
    grep -Fqx 'd /var/lib/rustsdcmcp 0700 rustsdcmcp rustsdcmcp -' "$package_dir/packaging/systemd/rustsdcmcp.tmpfiles" || die 'state tmpfiles declaration is invalid'
}

# This is deliberately before apt, sysusers, tmpfiles, or any target mutation.
validate_package

live_install=0
[[ -z "$install_root" || "$test_live" == 1 ]] && live_install=1

config_dir=$(target_path /etc/rustsdcmcp)
state_dir=$(target_path /var/lib/rustsdcmcp)
bin_path=$(target_path /usr/local/bin/rustsdcmcp)
sysusers_path=$(target_path /usr/lib/sysusers.d/rustsdcmcp.conf)
tmpfiles_path=$(target_path /usr/lib/tmpfiles.d/rustsdcmcp.conf)
journal_path=$(target_path /etc/systemd/journald.conf.d/mecmcp.conf)
unit_path=$(target_path /etc/systemd/system/rustsdcmcp.service)
tokens_path=$(target_path /etc/rustsdcmcp/tokens.json)
hmac_path=$(target_path /etc/rustsdcmcp/audit-hmac.key)

reject_unsafe_directory() {
    local path=$1
    if [[ -e "$path" || -L "$path" ]]; then
        [[ -d "$path" && ! -L "$path" ]] || die "unsafe destination directory: $path"
    fi
}

reject_unsafe_file() {
    local path=$1
    if [[ -e "$path" || -L "$path" ]]; then
        [[ -f "$path" && ! -L "$path" ]] || die "unsafe destination file: $path"
        [[ $(stat -c %h -- "$path") == 1 ]] || die "unsafe hard-linked destination file: $path"
    fi
}

reject_unsafe_parent_dirs() {
    local path=$1 parent
    parent=$(dirname -- "$path")
    while [[ "$parent" != / ]]; do
        reject_unsafe_directory "$parent"
        parent=$(dirname -- "$parent")
    done
    reject_unsafe_directory /
}

# Validate destination objects before apt, sysusers, tmpfiles, or any write.
reject_unsafe_directory "$config_dir"
reject_unsafe_directory "$state_dir"
reject_unsafe_parent_dirs "$config_dir/.parent-validation"
reject_unsafe_parent_dirs "$state_dir/.parent-validation"
managed_destinations=(
    "$bin_path" "$config_dir/sdc.json.example" "$sysusers_path" "$tmpfiles_path"
    "$journal_path" "$unit_path" "$tokens_path" "$hmac_path"
)
for destination in "${managed_destinations[@]}"; do
    reject_unsafe_file "$destination"
    reject_unsafe_parent_dirs "$destination"
done

if (( live_install )); then
    if [[ "$skip_user" == 1 ]]; then
        getent passwd rustsdcmcp >/dev/null && getent group rustsdcmcp >/dev/null \
            || die 'SDCMCP_INSTALL_SKIP_USER=1 requires rustsdcmcp user and group'
    fi
    if [[ "$skip_runtime_deps" != 1 ]]; then
        [[ -f /etc/debian_version ]] || die 'live installation requires Debian'
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends curl ca-certificates
    fi
    if [[ "$skip_user" != 1 ]]; then
        systemd-sysusers "$package_dir/packaging/systemd/rustsdcmcp.sysusers"
    fi
fi

install -d -m 0750 "$config_dir"
install -d -m 0700 "$state_dir"
install -d -m 0755 "$(dirname -- "$bin_path")" "$(dirname -- "$sysusers_path")" \
    "$(dirname -- "$tmpfiles_path")" "$(dirname -- "$journal_path")" "$(dirname -- "$unit_path")"
install -m 0755 "$package_dir/bin/rustsdcmcp" "$bin_path"
install -m 0644 "$package_dir/packaging/systemd/rustsdcmcp.sysusers" "$sysusers_path"
install -m 0644 "$package_dir/packaging/systemd/rustsdcmcp.tmpfiles" "$tmpfiles_path"
install -m 0644 "$package_dir/packaging/journald/mecmcp.conf" "$journal_path"
if (( live_install )) && getent group rustsdcmcp >/dev/null; then
    install -o root -g rustsdcmcp -m 0640 "$package_dir/config/sdc.json.example" "$config_dir/sdc.json.example"
else
    install -m 0640 "$package_dir/config/sdc.json.example" "$config_dir/sdc.json.example"
fi

if (( live_install )) && [[ "$skip_user" != 1 ]]; then
    systemd-tmpfiles --create "$package_dir/packaging/systemd/rustsdcmcp.tmpfiles"
fi
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
    '1. Create config: install -o root -g rustsdcmcp -m 0640 /etc/rustsdcmcp/sdc.json.example /etc/rustsdcmcp/sdc.json, then edit /etc/rustsdcmcp/sdc.json.' \
    '2. Install /etc/rustsdcmcp/credentials.env with mode 0600; do not put credentials in JSON.' \
    '3. Mint a least-privilege token as root, then start rustsdcmcp manually after configuration.' \
    '4. Configure remote journal forwarding before handling production traffic.' \
    'MCP endpoint: http://127.0.0.1:30032/mcp'
