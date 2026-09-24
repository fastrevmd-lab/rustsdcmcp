#!/usr/bin/env python3
"""Detect drift between the vendored SDC OpenAPI export and another copy.

self-check  every API path the Rust source calls must exist in the vendored spec
diff        semantic comparison of two specs; exit 3 when they differ

Paths are extracted from `&["api", "vN", ...]` segment arrays in non-test Rust
source. String literals are fixed segments; anything else (a variable, or a
`.segment()` call) is a one-segment wildcard. A template from catalog.rs also
implies its `/{uuid}` item path, which `get_resource` builds at runtime.
"""

import argparse
import hashlib
import json
import pathlib
import re
import sys

VENDORED = pathlib.Path("docs/sdc-api/security-director-cloud-apis-openapi3.json")
METHODS = ("get", "put", "post", "delete", "patch")
WILDCARD = "{}"
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
                token[1:-1] if token.startswith('"') and token.endswith('"') else WILDCARD
                for token in tokens
            )
            templates.add(template)
            if path.name == "catalog.rs":
                templates.add(template + (WILDCARD,))
    return templates


def _segments(spec_path):
    return tuple(spec_path.strip("/").split("/"))


def _matches(template, spec_path):
    segments = _segments(spec_path)
    return len(template) == len(segments) and all(
        want == WILDCARD or want == have for want, have in zip(template, segments)
    )


def unmatched(templates, spec_paths):
    """Templates that match no path in the spec, sorted."""
    return sorted(t for t in templates if not any(_matches(t, p) for p in spec_paths))


def _inline(node, schemas, stack):
    """Resolve local $refs recursively; a cycle becomes a named marker."""
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/components/schemas/"):
            name = ref.rsplit("/", 1)[-1]
            if name in stack:
                return {"$cycle": name}
            return _inline(schemas.get(name, {"$missing": name}), schemas, stack | {name})
        return {key: _inline(value, schemas, stack) for key, value in node.items()}
    if isinstance(node, list):
        return [_inline(value, schemas, stack) for value in node]
    return node


def _fingerprints(spec):
    schemas = spec.get("components", {}).get("schemas", {})
    prints = {}
    for spec_path, operations in spec.get("paths", {}).items():
        for method in METHODS:
            if method not in operations:
                continue
            body = _inline(operations[method], schemas, frozenset())
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
    drifted = bool(added or removed or changed or old_version != new_version)

    def is_called(key):
        return any(_matches(template, key[1]) for template in called)

    def section(title, keys):
        lines = [f"### {title}", ""]
        if not keys:
            return lines + ["_None._", ""]
        return lines + [f"- `{method} {path}`" for method, path in keys] + [""]

    lines = ["## SDC OpenAPI drift", ""]
    if old_version != new_version:
        lines += [f"`info.version`: {old_version} → {new_version}", ""]
    for label, keys in (("changed", changed), ("removed", removed), ("added", added)):
        lines.append(f"- {len(keys)} {label}")
    lines.append("")
    lines += section("Operations this server calls", [k for k in changed + removed if is_called(k)])
    lines += section("Other operations", [k for k in changed + removed if not is_called(k)] + added)
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

    report, drifted = diff(_load(args.old), _load(args.new), templates)
    print(report)
    return 3 if drifted else 0


if __name__ == "__main__":
    sys.exit(main())
