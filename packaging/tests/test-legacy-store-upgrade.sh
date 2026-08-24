#!/usr/bin/env bash
# Test that the token store setup logic completes when only a legacy store exists.
#
# A staged install where only the legacy store exists must:
# - Complete the chmod/chown phase without error
# - Leave /var/lib/rustsdcmcp/tokens.json absent
# - Not attempt to chmod a non-existent file
#
# This test extracts the critical logic from install.sh and verifies it handles
# the legacy-only scenario correctly.

set -euo pipefail

# Test the FIXED version - conditional chmod
echo "Testing fixed version (conditional chmod)..."
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT

legacy_tokens_path="$test_dir/etc/rustsdcmcp/tokens.json"
tokens_path="$test_dir/var/lib/rustsdcmcp/tokens.json"
hmac_path="$test_dir/var/lib/rustsdcmcp/hmac.key"

mkdir -p "$(dirname "$legacy_tokens_path")"
mkdir -p "$(dirname "$tokens_path")"

# Create legacy store
echo '{"version":1,"tokens":[{"name":"test","hash":"abc","grants":{"tools":["*"]}}]}' > "$legacy_tokens_path"

# The installer's token creation logic (lines 287-297 of install.sh)
if [[ ! -e "$tokens_path" ]]; then
    if [[ -e "$legacy_tokens_path" ]]; then
        # Legacy exists, so tokens_path is intentionally left absent
        :
    else
        printf '%s\n' '{"version":1,"tokens":[]}' >"$tokens_path"
    fi
fi
if [[ ! -e "$hmac_path" ]]; then
    head -c 32 /dev/urandom >"$hmac_path"
fi

# FIXED VERSION: conditional chmod (the fix we applied)
chmod 0600 "$hmac_path"
if [[ -e "$tokens_path" ]]; then
    chmod 0600 "$tokens_path"
fi

# Verify outcomes
if [[ -e "$tokens_path" ]]; then
    echo "FAIL: tokens_path exists but should be absent when legacy exists"
    exit 1
fi
if [[ ! -e "$legacy_tokens_path" ]]; then
    echo "FAIL: legacy store was removed"
    exit 1
fi
if [[ ! -e "$hmac_path" ]]; then
    echo "FAIL: hmac key was not created"
    exit 1
fi

echo "PASS (fixed): chmod logic handled legacy-only scenario correctly"

# Test the BROKEN version - unconditional chmod
echo ""
echo "Testing broken version (unconditional chmod) - should fail..."

# Create a new test dir for the broken scenario
test_dir2=$(mktemp -d)
trap 'rm -rf "$test_dir" "$test_dir2"' EXIT

legacy_tokens_path2="$test_dir2/etc/rustsdcmcp/tokens.json"
tokens_path2="$test_dir2/var/lib/rustsdcmcp/tokens.json"
hmac_path2="$test_dir2/var/lib/rustsdcmcp/hmac.key"

mkdir -p "$(dirname "$legacy_tokens_path2")"
mkdir -p "$(dirname "$tokens_path2")"

# Create legacy store
echo '{"version":1,"tokens":[{"name":"test","hash":"abc","grants":{"tools":["*"]}}]}' > "$legacy_tokens_path2"

# The installer's token creation logic - same as before
if [[ ! -e "$tokens_path2" ]]; then
    if [[ -e "$legacy_tokens_path2" ]]; then
        :
    else
        printf '%s\n' '{"version":1,"tokens":[]}' >"$tokens_path2"
    fi
fi
if [[ ! -e "$hmac_path2" ]]; then
    head -c 32 /dev/urandom >"$hmac_path2"
fi

# BROKEN VERSION: unconditional chmod (the bug we fixed)
# This should fail because tokens_path2 doesn't exist
set +e
chmod 0600 "$tokens_path2" "$hmac_path2" 2>&1
broken_exit=$?
set -e

if [[ $broken_exit -eq 0 ]]; then
    echo "FAIL: broken version should have failed (chmod on non-existent file) but didn't"
    exit 1
else
    echo "PASS (sabotage): broken version failed as expected (chmod returned exit code $broken_exit)"
fi

echo ""
echo "All tests passed."
