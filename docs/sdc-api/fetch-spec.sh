#!/usr/bin/env bash
# Refresh the vendored Security Director Cloud OpenAPI export.
#
# The public API reference at
#   https://www.juniper.net/documentation/us/en/software/sd-cloud/api/
# is an APIMatic dev portal. Its pages are client-rendered, so fetching them
# yields only the shell — but the portal config (static/js/portal.js) declares
# an export route, and that route serves the full OpenAPI 3 document.
#
# After running this, regenerate the inventory:
#   python3 scripts/gen-endpoint-inventory.py
set -euo pipefail

BASE="https://www.juniper.net/documentation/us/en/software/sd-cloud/api"
SPEC_URL="${BASE}/static/exports/security-director-cloud-apis-openapi3json.json"
DEST="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/security-director-cloud-apis-openapi3.json"

echo "fetching ${SPEC_URL}"
curl -fsSL --max-time 120 "${SPEC_URL}" -o "${DEST}.tmp"

# Refuse to install a truncated or non-JSON download over a known-good spec.
python3 -c "
import json, sys
spec = json.load(open('${DEST}.tmp'))
assert spec.get('openapi', '').startswith('3.'), 'not an OpenAPI 3 document'
assert spec.get('paths'), 'no paths in document'
print('ok:', spec['info']['title'], 'v' + spec['info']['version'],
      '-', len(spec['paths']), 'paths')
"

mv "${DEST}.tmp" "${DEST}"
echo "wrote ${DEST}"
