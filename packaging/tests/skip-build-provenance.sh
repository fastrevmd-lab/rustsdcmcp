#!/usr/bin/env bash
# Regression guard for mecmcp#355: a hand-written BUILD-INFO was once shipped
# claiming a toolchain that never compiled the binary, to satisfy validation
# with no supported skip-build path. rustsdcmcp has a supported path
# (SDCMCP_PACKAGE_SKIP_BUILD); this proves it stays honest rather than
# reintroducing the same forgery under a different name.
#
# Must run after target/release/rustsdcmcp already exists (a normal build),
# and last among anything that reads dist/<commit>/ in the same job: it
# repackages at the same commit, so it overwrites the tarball built there.
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

[[ -x target/release/rustsdcmcp ]] || {
    printf '%s\n' 'target/release/rustsdcmcp must already be built before this test runs' >&2
    exit 1
}

expected_sha=$(sha256sum target/release/rustsdcmcp | cut -d' ' -f1)
commit=$(git rev-parse HEAD)

cleanup_dir=""
cleanup() {
    [[ -z "$cleanup_dir" ]] || rm -rf -- "$cleanup_dir"
}
trap cleanup EXIT

SDCMCP_ALLOW_DIRTY=1 \
SDCMCP_PACKAGE_SKIP_BUILD=1 \
SDCMCP_BINARY_SOURCE_COMMIT="$commit" \
    scripts/build-package.sh

mapfile -t archives < <(find "dist/$commit" -maxdepth 1 -type f -name 'rustsdcmcp_*_amd64.tar.gz')
[[ ${#archives[@]} -eq 1 ]] || {
    printf '%s\n' "expected exactly one skip-build archive, found ${#archives[@]}" >&2
    exit 1
}
archive=${archives[0]}

cleanup_dir=$(mktemp -d)
tar -xzf "$archive" -C "$cleanup_dir"
build_info=$(find "$cleanup_dir" -maxdepth 2 -name BUILD-INFO)

recorded_rustc=$(sed -n 's/^rustc=//p' "$build_info")
case "$recorded_rustc" in
    unknown\ \(*) ;;
    *)
        printf '%s\n' "skip-build BUILD-INFO must record an honest rustc field starting with 'unknown ('; got: $recorded_rustc" >&2
        exit 1
        ;;
esac
if printf '%s\n' "$recorded_rustc" | grep -Eq 'rustc [0-9]+\.[0-9]+\.[0-9]+'; then
    printf '%s\n' "skip-build BUILD-INFO names a compiler version as if it compiled the binary: $recorded_rustc" >&2
    exit 1
fi

recorded_sha=$(sed -n 's/^binary_sha256=//p' "$build_info")
[[ "$recorded_sha" == "$expected_sha" ]] || {
    printf '%s\n' "skip-build BUILD-INFO binary_sha256 ($recorded_sha) does not match the packaged binary ($expected_sha)" >&2
    exit 1
}

printf '%s\n' 'skip-build provenance is honest'
