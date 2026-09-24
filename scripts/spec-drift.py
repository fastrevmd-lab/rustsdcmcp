#!/usr/bin/env python3
"""Detect drift between the vendored SDC OpenAPI export and another copy.

self-check  every API path the Rust source calls must exist in the vendored spec
diff        semantic comparison of two specs; exit 3 when they differ

Paths are extracted from `&["api", "vN", ...]` segment arrays in non-test Rust
source. String literals are fixed segments; a bare identifier (e.g. device_uuid)
becomes PARAM (matches only spec `{x}` segments); a call expression (e.g.
section.segment()) becomes ANY (matches a literal or `{x}`). A template from
catalog.rs also implies its `/{uuid}` item path, which `get_resource` builds at runtime.
"""

import argparse
import hashlib
import json
import pathlib
import re
import sys

VENDORED = pathlib.Path("docs/sdc-api/security-director-cloud-apis-openapi3.json")
METHODS = ("get", "put", "post", "delete", "patch")
PARAM = "{param}"  # matches only {x} segments
ANY = "{any}"      # matches both literals and {x} segments
_ARRAY = re.compile(r'&\[\s*"api"\s*,\s*"v\d+"[^\]]*\]', re.S)
_TEST_MODULE = "\n#[cfg(test)]\nmod tests"


def called_templates(src_root):
    """Return the set of path templates (tuples of segments) the source calls."""
    templates = set()
    for path in pathlib.Path(src_root).rglob("*.rs"):
        text = path.read_text(encoding="utf-8")
        cut = text.find(_TEST_MODULE)
        if cut >= 0:
            text = text[:cut]
        for match in _ARRAY.finditer(text):
            tokens = [token.strip() for token in match.group(0)[2:-1].split(",") if token.strip()]
            template = tuple(
                token[1:-1] if token.startswith('"') and token.endswith('"')
                else ANY if "(" in token else PARAM
                for token in tokens
            )
            templates.add(template)
            if path.name == "catalog.rs":
                templates.add(template + (PARAM,))
    return templates


def _segments(spec_path):
    return tuple(spec_path.strip("/").split("/"))


def _matches(template, spec_path):
    segments = _segments(spec_path)
    if len(template) != len(segments):
        return False
    for want, have in zip(template, segments):
        if want == have:
            continue
        if want == ANY:
            continue
        if want == PARAM and have.startswith("{") and have.endswith("}"):
            continue
        return False
    return True


def unmatched(templates, spec_paths):
    """Templates that match no path in the spec, sorted."""
    return sorted(t for t in templates if not any(_matches(t, p) for p in spec_paths))


def _inline(node, components, stack):
    """Resolve local $refs recursively; a cycle becomes a named marker."""
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/components/"):
            # Parse #/components/<kind>/<name>
            parts = ref.split("/")
            if len(parts) == 4 and parts[1] == "components":
                kind, name = parts[2], parts[3]
                if ref in stack:
                    return {"$cycle": ref}
                resolved = components.get(kind, {}).get(name)
                if resolved:
                    return _inline(resolved, components, stack | {ref})
                return {"$missing": ref}
        return {key: _inline(value, components, stack) for key, value in node.items()}
    if isinstance(node, list):
        return [_inline(value, components, stack) for value in node]
    return node


def _param_identity(param):
    """Return (name, in) for a parameter (already resolved by _inline)."""
    # _inline resolves refs, but unresolvable ones become {"$missing": ref}
    if "$missing" in param:
        ref = param["$missing"]
        return ("$ref", ref)
    if "$ref" in param:
        # Fallback for unresolvable refs that _inline didn't catch
        return ("$ref", param["$ref"])
    return (param.get("name"), param.get("in"))


def _fingerprints(spec):
    components = spec.get("components", {})
    prints = {}

    # Document-level contract
    doc_contract = {
        "servers": spec.get("servers", []),
        "security": spec.get("security", []),
        "securitySchemes": components.get("securitySchemes", {}),
    }
    doc_canonical = json.dumps(doc_contract, sort_keys=True, separators=(",", ":"))
    prints[("DOC", "")] = hashlib.sha256(doc_canonical.encode()).hexdigest()

    for spec_path, operations in spec.get("paths", {}).items():
        # Inline path-level parameters too
        path_params = _inline(operations.get("parameters", []), components, frozenset())
        for method in METHODS:
            if method not in operations:
                continue
            body = _inline(operations[method], components, frozenset())
            # Merge path-level parameters, skipping those overridden by operation-level
            op_params = body.get("parameters", [])
            if path_params or op_params:
                body = dict(body)  # shallow copy to avoid mutation
                op_identities = {_param_identity(p) for p in op_params}
                # Skip path params whose (name, in) the operation already declares
                merged = op_params + [
                    p for p in path_params
                    if _param_identity(p) not in op_identities
                ]
                # Sort by (in, name) so reordering is not drift
                merged.sort(key=lambda p: (_param_identity(p)[1] or "", _param_identity(p)[0] or ""))
                body["parameters"] = merged
            canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
            prints[(method.upper(), spec_path)] = hashlib.sha256(canonical.encode()).hexdigest()
    return prints


def diff(old, new, called):
    """Return (markdown report, drifted) comparing two parsed specs."""
    before, after = _fingerprints(old), _fingerprints(new)
    added = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))
    changed = sorted(key for key in set(before) & set(after) if before[key] != after[key])
    old_version = old.get("info", {}).get("version")
    new_version = new.get("info", {}).get("version")

    # Separate document-level contract from operations
    doc_changed = ("DOC", "") in changed
    op_added = [k for k in added if k[0] != "DOC"]
    op_removed = [k for k in removed if k[0] != "DOC"]
    op_changed = [k for k in changed if k[0] != "DOC"]

    drifted = bool(op_added or op_removed or op_changed or doc_changed or old_version != new_version)

    def is_called(key):
        return any(_matches(template, key[1]) for template in called)

    def section(title, keys):
        lines = [f"### {title}", ""]
        if not keys:
            return lines + ["_None._", ""]
        return lines + [f"- `{method} {path}`" for method, path in keys] + [""]

    lines = ["## SDC OpenAPI drift", ""]
    if not drifted:
        lines += ["No drift."]
        return "\n".join(lines), drifted

    if old_version != new_version:
        lines += [f"`info.version`: {old_version} → {new_version}", ""]
    for label, keys in (("changed", op_changed), ("removed", op_removed), ("added", op_added)):
        lines.append(f"- {len(keys)} {label}")
    lines.append("")

    if doc_changed:
        lines += ["### Document-level contract (affects every call)", ""]
        lines += ["Changed: `servers`, `security`, or `securitySchemes`", ""]

    lines += section("Operations this server calls", [k for k in op_changed + op_removed if is_called(k)])
    lines += section("Other operations", [k for k in op_changed + op_removed if not is_called(k)] + op_added)
    lines += [
        "Refresh with `docs/sdc-api/fetch-spec.sh`, re-run "
        "`scripts/gen-endpoint-inventory.py`, and land it through a normal PR.",
    ]
    return "\n".join(lines), drifted


def _load(path):
    try:
        document = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        print(f"cannot read spec {path}: {error}", file=sys.stderr)
        sys.exit(2)
    if not str(document.get("openapi", "")).startswith("3.") or not document.get("paths"):
        print(f"{path} is not an OpenAPI 3 document with paths", file=sys.stderr)
        sys.exit(2)
    return document


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("self-check")
    check.add_argument("--spec", default=str(VENDORED))
    check.add_argument("--src", default="crates")
    compare = commands.add_parser("diff")
    compare.add_argument("old")
    compare.add_argument("new")
    compare.add_argument("--src", default="crates")
    args = parser.parse_args(argv)

    templates = called_templates(args.src)
    if args.command == "self-check":
        missing = unmatched(templates, _load(args.spec)["paths"])
        if not templates:
            print("no API path templates extracted; the extractor is broken", file=sys.stderr)
            return 1
        for template in missing:
            print("not in spec: /" + "/".join(template), file=sys.stderr)
        print(f"{len(templates)} templates, {len(missing)} unmatched")
        return 1 if missing else 0

    if not templates:
        print("no API path templates extracted; the extractor is broken", file=sys.stderr)
        return 1
    report, drifted = diff(_load(args.old), _load(args.new), templates)
    print(report)
    return 3 if drifted else 0


if __name__ == "__main__":
    sys.exit(main())
