#!/usr/bin/env bash
# An upgrade whose live tokens are still at /etc must complete, and must not
# create an empty store at /var/lib.
#
# Two failure modes this covers, both of which shipped at some point:
#
#  1. Creating an empty primary shadows the live legacy store. The runtime
#     prefers an existing primary, so the service starts and rejects every
#     existing bearer token — a silent auth wipe.
#  2. Deliberately leaving the primary absent, then chmod-ing it anyway. That
#     returns ENOENT and `set -e` aborts the installer BEFORE the unit is
#     installed, so the fallback cannot support upgrades at all.
#
# This runs the REAL installer from the built package. An earlier version of
# this file reimplemented the installer's logic and asserted against its own
# copy, so it passed no matter what install.sh did.
set -euo pipefail

ARCHIVE="${1:?usage: test-legacy-store-upgrade.sh <package.tar.gz>}"
[[ -f "$ARCHIVE" ]] || { echo "archive not found: $ARCHIVE" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

tar -xzf "$ARCHIVE" -C "$WORK"
mapfile -t roots < <(find "$WORK" -mindepth 1 -maxdepth 1 -type d -print)
[[ "${#roots[@]}" -eq 1 ]] || { echo "archive must contain one package root" >&2; exit 1; }
INSTALLER="${roots[0]}/packaging/lxc/install.sh"
[[ -x "$INSTALLER" ]] || { echo "installer not executable: $INSTALLER" >&2; exit 1; }

run_installer() {
    SDCMCP_INSTALL_ROOT="$1" \
        SDCMCP_INSTALL_SKIP_USER=1 \
        SDCMCP_INSTALL_SKIP_SYSTEMD_RELOAD=1 \
        SDCMCP_INSTALL_SKIP_RUNTIME_DEPS=1 \
        "$INSTALLER" >"$2" 2>&1
}

# --- Upgrade: only the legacy /etc store exists.
UPGRADE="$WORK/upgrade"
mkdir -p "$UPGRADE/etc/rustsdcmcp"
printf '%s\n' '{"version":1,"tokens":[{"name":"live-token"}]}' \
    >"$UPGRADE/etc/rustsdcmcp/tokens.json"
chmod 0600 "$UPGRADE/etc/rustsdcmcp/tokens.json"

if ! run_installer "$UPGRADE" "$WORK/upgrade.log"; then
    echo "FAIL: installer aborted on a legacy-only upgrade" >&2
    tail -20 "$WORK/upgrade.log" >&2
    exit 1
fi

if [[ -e "$UPGRADE/var/lib/rustsdcmcp/tokens.json" ]]; then
    echo "FAIL: created an empty primary that shadows the live legacy store" >&2
    exit 1
fi

if ! grep -q 'live-token' "$UPGRADE/etc/rustsdcmcp/tokens.json"; then
    echo "FAIL: the legacy token store was modified" >&2
    exit 1
fi

# The installer must have completed far enough to install the unit.
if [[ ! -e "$UPGRADE/etc/systemd/system/rustsdcmcp.service" ]]; then
    echo "FAIL: installer did not reach unit installation" >&2
    tail -20 "$WORK/upgrade.log" >&2
    exit 1
fi

# --- Fresh install: no legacy store, so an empty primary IS correct.
FRESH="$WORK/fresh"
mkdir -p "$FRESH"
if ! run_installer "$FRESH" "$WORK/fresh.log"; then
    echo "FAIL: installer aborted on a fresh install" >&2
    tail -20 "$WORK/fresh.log" >&2
    exit 1
fi

if [[ ! -e "$FRESH/var/lib/rustsdcmcp/tokens.json" ]]; then
    echo "FAIL: fresh install did not create the primary token store" >&2
    exit 1
fi

echo ">> legacy store upgrade test passed"
