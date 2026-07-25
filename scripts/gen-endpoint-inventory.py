#!/usr/bin/env python3
"""Regenerate docs/sdc-api/endpoints.md from the vendored SDC OpenAPI export.

Usage:  python3 scripts/gen-endpoint-inventory.py

Reads  docs/sdc-api/security-director-cloud-apis-openapi3.json
Writes docs/sdc-api/endpoints.md

Refresh the spec itself with docs/sdc-api/fetch-spec.sh, then re-run this.
"""

import collections
import json
from pathlib import Path

METHODS = ("get", "post", "put", "delete", "patch")

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "docs" / "sdc-api" / "security-director-cloud-apis-openapi3.json"
DEST = ROOT / "docs" / "sdc-api" / "endpoints.md"


def operations_by_tag(paths):
    """Group every documented operation under each of its OpenAPI tags."""
    grouped = collections.defaultdict(list)
    for path, ops in sorted(paths.items()):
        for method, op in ops.items():
            if method not in METHODS:
                continue
            operation_id = op.get("operationId") or op.get("summary") or ""
            for tag in op.get("tags") or ["(untagged)"]:
                grouped[tag].append((method.upper(), path, operation_id))
    return grouped


def render(spec):
    """Render the inventory markdown for a parsed OpenAPI document."""
    paths = spec["paths"]
    grouped = operations_by_tag(paths)

    order = [t["name"] for t in spec.get("tags", [])]
    order += [t for t in grouped if t not in order]

    total = sum(len(v) for v in grouped.values())
    lines = [
        "# SDC endpoint inventory\n",
        "Generated from the vendored OpenAPI export — see [`README.md`](README.md)\n"
        "for provenance. Do not hand-edit; regenerate with "
        "`scripts/gen-endpoint-inventory.py`.\n",
        f'`{spec["info"]["title"]}` v{spec["info"]["version"]} · '
        f"{len(paths)} paths · {total} operations · {len(order)} groups\n",
        f'Base URL: `{spec["servers"][0]["url"]}`\n',
        "## Groups\n",
        "| Group | Ops |",
        "|---|---:|",
    ]
    for tag in order:
        anchor = tag.lower().replace(" ", "-")
        lines.append(f"| [{tag}](#{anchor}) | {len(grouped[tag])} |")
    lines.append("")

    for tag in order:
        lines += [f"## {tag}\n", "| Method | Path | Operation |", "|---|---|---|"]
        for method, path, operation_id in grouped[tag]:
            lines.append(f"| `{method}` | `{path}` | {operation_id} |")
        lines.append("")

    return "\n".join(lines), total, len(order)


def main():
    spec = json.loads(SPEC.read_text())
    markdown, total, groups = render(spec)
    DEST.write_text(markdown)
    print(f"wrote {DEST.relative_to(ROOT)}: {total} operations across {groups} groups")


if __name__ == "__main__":
    main()
