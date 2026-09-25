# Upstream Spec Drift Check Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close issue #154. A weekly job notices when Juniper changes the published SDC OpenAPI export and files a tracking issue, split into operations this server calls and the rest. It never commits.

**Architecture:** One stdlib-only Python script, `scripts/spec-drift.py`, with two subcommands. `self-check` extracts every path this server calls from the Rust source and fails if any does not exist in the vendored spec. It runs on every PR, which also keeps the extractor honest. `diff` compares two specs semantically: each operation with its `$ref`s inlined and canonicalised, plus `info.version`. A scheduled workflow fetches the live export through the existing `fetch-spec.sh`, runs `diff`, and opens or comments on one `spec-drift` issue.

**Tech Stack:** Python 3 stdlib (json, re, hashlib, argparse, unittest), GitHub Actions, `gh`.

**Spec:** GitHub issue fastrevmd-lab/rustsdcmcp#154.

## Global Constraints

- **No auto-commit.** A spec bump goes through a normal PR that re-runs `scripts/gen-endpoint-inventory.py` and the contract tests.
- A failed fetch or invalid JSON makes the scheduled run **red**. It is never "no drift".
- Compare semantically, not by raw bytes. Key reordering must not count as drift.
- Python stdlib only. CI installs nothing extra.
- Pin actions to the SHA `ci.yml` uses: `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1`.
- Workflow permissions are least-privilege: `contents: read`, and `issues: write` only on the drift job.
- Baseline fact (verified 2026-09-24 by running this plan's script): `self-check` reports **113 templates, 0 unmatched**. That is 81 distinct segment arrays in non-test Rust source, plus 32 `/{uuid}` item paths implied by `catalog.rs`. `self-check` must pass on `main` as-is. If it does not, the extractor is wrong. Do not "fix" `client.rs` to make it pass.
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`. Each task gets `codex exec review --commit <sha>`.
- Branch: `ci/spec-drift-154` from `origin/main`. This plan is independent of the other two and can go first.

## File map

- Create `scripts/spec-drift.py`: path extraction, `self-check` and `diff`.
- Create `scripts/tests/test_spec_drift.py`: unittest cases with synthetic specs and Rust snippets.
- Modify `docs/sdc-api/fetch-spec.sh`: honour an `SDC_SPEC_DEST` override.
- Modify `.github/workflows/ci.yml`: run the unit tests and `self-check`.
- Create `.github/workflows/spec-drift.yml`: weekly and on-dispatch drift job.
- Modify `CLAUDE.md` (the spec paragraph) and `CHANGELOG.md`.

---

### Task 1: The drift script and its tests

**Interfaces:**
- Produces, run from the repo root, with these exit codes:
  - `python3 scripts/spec-drift.py self-check [--spec PATH] [--src crates]`: 0 when every called template matches; 1 lists the unmatched templates.
  - `python3 scripts/spec-drift.py diff OLD NEW [--src crates]`: markdown on stdout. 0 means no drift, 3 means drift, 2 means an unreadable or invalid spec.

- [ ] **Step 1: Write the failing tests** in `scripts/tests/test_spec_drift.py`:

```python
"""Tests for scripts/spec-drift.py. Run: python3 -m unittest discover -s scripts/tests"""

import importlib.util
import json
import pathlib
import tempfile
import unittest

_SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "spec-drift.py"
_spec = importlib.util.spec_from_file_location("spec_drift", _SCRIPT)
drift = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(drift)


def spec(paths, version="1.0.0", schemas=None):
    return {
        "openapi": "3.0.0",
        "info": {"title": "t", "version": version},
        "paths": paths,
        "components": {"schemas": schemas or {}},
    }


def op(ref=None, params=()):
    body = {"parameters": [{"name": name, "in": "query"} for name in params]}
    if ref:
        body["responses"] = {"200": {"content": {"application/json": {"schema": {"$ref": ref}}}}}
    return body


class ExtractTemplates(unittest.TestCase):
    def write_src(self, files):
        root = pathlib.Path(tempfile.mkdtemp())
        for name, text in files.items():
            (root / name).write_text(text)
        return root

    def test_literals_identifiers_and_multiline_arrays(self):
        root = self.write_src({"client.rs": '''
            self.get(&["api", "v1", "devices", device_uuid, "config", "versions"], &[], ct)
            self.list(
                &[
                    "api",
                    "v2",
                    "tunnels",
                ],
                page,
            )
            self.get(&["api", "v1", "devices", device_uuid, "config", section.segment()], &[], ct)
        '''})
        self.assertEqual(
            drift.called_templates(root),
            {
                ("api", "v1", "devices", "{}", "config", "versions"),
                ("api", "v2", "tunnels"),
                ("api", "v1", "devices", "{}", "config", "{}"),
            },
        )

    def test_test_modules_are_ignored(self):
        root = self.write_src({"client.rs": 'x(&["api", "v1", "real"])\n#[cfg(test)]\nmod tests {\n x(&["api", "v1", "fake"])\n}\n'})
        self.assertEqual(drift.called_templates(root), {("api", "v1", "real")})

    def test_catalog_collections_also_imply_their_item_path(self):
        root = self.write_src({"catalog.rs": 'Self::Addresses => &["api", "v1", "addresses"],'})
        self.assertEqual(
            drift.called_templates(root),
            {("api", "v1", "addresses"), ("api", "v1", "addresses", "{}")},
        )


class SelfCheck(unittest.TestCase):
    def test_reports_templates_absent_from_the_spec(self):
        templates = {("api", "v1", "devices"), ("api", "v1", "nope")}
        paths = spec({"/api/v1/devices": {"get": op()}})["paths"]
        self.assertEqual(drift.unmatched(templates, paths), [("api", "v1", "nope")])

    def test_wildcard_matches_a_spec_parameter_or_literal(self):
        templates = {("api", "v1", "devices", "{}")}
        paths = spec({"/api/v1/devices/{device_uuid}": {"get": op()}})["paths"]
        self.assertEqual(drift.unmatched(templates, paths), [])


class Diff(unittest.TestCase):
    CALLED = {("api", "v1", "devices")}

    def test_identical_specs_with_reordered_keys_are_not_drift(self):
        def reverse_keys(node):
            if isinstance(node, dict):
                return {key: reverse_keys(node[key]) for key in reversed(list(node))}
            if isinstance(node, list):
                return [reverse_keys(value) for value in node]
            return node

        schemas = {"D": {"type": "object", "properties": {"a": {"type": "string"}, "b": {"type": "integer"}}}}
        old = spec({"/api/v1/devices": {"get": op("#/components/schemas/D", ["from", "size"])}},
                   schemas=schemas)
        new = reverse_keys(old)
        report, drifted = drift.diff(old, new, self.CALLED)
        self.assertFalse(drifted, report)

    def test_a_changed_referenced_schema_is_drift_on_a_called_operation(self):
        old = spec({"/api/v1/devices": {"get": op("#/components/schemas/D")}},
                   schemas={"D": {"type": "object", "properties": {"a": {"type": "string"}}}})
        new = spec({"/api/v1/devices": {"get": op("#/components/schemas/D")}},
                   schemas={"D": {"type": "object", "properties": {"a": {"type": "integer"}}}})
        report, drifted = drift.diff(old, new, self.CALLED)
        self.assertTrue(drifted)
        self.assertIn("### Operations this server calls", report)
        self.assertIn("GET /api/v1/devices", report.split("### Other operations")[0])

    def test_added_and_removed_operations_and_version_are_reported(self):
        old = spec({"/api/v1/devices": {"get": op()}, "/api/v1/gone": {"get": op()}}, version="1.0.0")
        new = spec({"/api/v1/devices": {"get": op()}, "/api/v1/new": {"post": op()}}, version="1.1.0")
        report, drifted = drift.diff(old, new, self.CALLED)
        self.assertTrue(drifted)
        self.assertIn("1.0.0 → 1.1.0", report)
        self.assertIn("POST /api/v1/new", report)
        self.assertIn("GET /api/v1/gone", report)

    def test_recursive_schemas_do_not_loop(self):
        schemas = {"N": {"type": "object", "properties": {"next": {"$ref": "#/components/schemas/N"}}}}
        s = spec({"/api/v1/devices": {"get": op("#/components/schemas/N")}}, schemas=schemas)
        _, drifted = drift.diff(s, s, self.CALLED)
        self.assertFalse(drifted)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run and confirm FAIL**

Run: `python3 -m unittest discover -s scripts/tests -v`
Expected: an error loading `spec-drift.py` (FileNotFoundError).

- [ ] **Step 3: Implement** `scripts/spec-drift.py`:

```python
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
```

- [ ] **Step 4: Run and confirm PASS.** Run `python3 -m unittest discover -s scripts/tests -v`; expect 9 tests OK. Then run `python3 scripts/spec-drift.py self-check`; expect exit 0 and output that includes `113 templates, 0 unmatched`. If the count differs from 113, find out why before continuing.

- [ ] **Step 5: Sabotage, one at a time.**
  (a) Delete the `_TEST_MODULE` cut and run the unittests: `test_test_modules_are_ignored` must FAIL. Restore.
  (b) Set `sort_keys=False` in `_fingerprints`: `test_identical_specs_with_reordered_keys_are_not_drift` must FAIL. Restore.
  (c) Change `client.rs` `"tunnels"` to `"tunnelz"` in `list_tunnels` and run `self-check`: expect exit 1 naming `/api/v2/tunnelz`. Restore it, and confirm `git diff crates/` is empty.

- [ ] **Step 6: Commit**

```bash
git add scripts/spec-drift.py scripts/tests/test_spec_drift.py
git commit -m "ci: add spec-drift script with self-check and semantic diff (#154)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

Then run the Codex gate.

---

### Task 2: Gate every PR on the self-check

**Files:** `.github/workflows/ci.yml`

- [ ] **Step 1: Add two steps** to the `Build, lint, and test` job, before `cargo fmt`:

```yaml
      - name: Spec-drift script unit tests
        run: python3 -m unittest discover -s scripts/tests -v
      - name: Every called SDC path exists in the vendored spec
        run: python3 scripts/spec-drift.py self-check
```

- [ ] **Step 2: Verify locally** that both commands exit 0.
- [ ] **Step 3: Commit** `ci: gate PRs on the spec self-check (#154)` plus the trailer. Push the branch, and confirm in the Actions log that both new steps ran and passed. A green job that skipped them is not a pass.

---

### Task 3: Scheduled drift workflow

**Files:** `docs/sdc-api/fetch-spec.sh`, `.github/workflows/spec-drift.yml`

- [ ] **Step 1: Let `fetch-spec.sh` write elsewhere.** Replace the `DEST=` line with:

```bash
DEST="${SDC_SPEC_DEST:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/security-director-cloud-apis-openapi3.json}"
```

Verify with `SDC_SPEC_DEST=/tmp/live.json docs/sdc-api/fetch-spec.sh`: expect `ok: … 227 paths`, and `git status` shows no change to the vendored file. Then run `python3 scripts/spec-drift.py diff docs/sdc-api/security-director-cloud-apis-openapi3.json /tmp/live.json` and expect exit 0, because the vendored copy is byte-identical to live as of 2026-09-24. If it exits 3, the report is the first real drift finding; paste it into the PR.

- [ ] **Step 2: Create** `.github/workflows/spec-drift.yml`:

```yaml
name: Spec drift

on:
  schedule:
    - cron: "17 6 * * 1"
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: spec-drift
  cancel-in-progress: false

jobs:
  drift:
    name: Compare vendored spec with the live export
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      issues: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      # A failed fetch or invalid document fails this step, so the run goes red
      # rather than reporting "no drift".
      - name: Fetch the live export
        run: SDC_SPEC_DEST="$RUNNER_TEMP/live.json" docs/sdc-api/fetch-spec.sh
      - name: Compare
        id: compare
        run: |
          set +e
          python3 scripts/spec-drift.py diff \
            docs/sdc-api/security-director-cloud-apis-openapi3.json \
            "$RUNNER_TEMP/live.json" > "$RUNNER_TEMP/report.md"
          code=$?
          set -e
          cat "$RUNNER_TEMP/report.md" >> "$GITHUB_STEP_SUMMARY"
          case "$code" in
            0) echo "drift=false" >> "$GITHUB_OUTPUT" ;;
            3) echo "drift=true" >> "$GITHUB_OUTPUT" ;;
            *) exit "$code" ;;
          esac
      - name: Open or update the tracking issue
        if: steps.compare.outputs.drift == 'true'
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          gh label create spec-drift --color D93F0B \
            --description "Upstream SDC OpenAPI export changed" --force
          existing=$(gh issue list --label spec-drift --state open --json number --jq '.[0].number // empty')
          if [ -n "$existing" ]; then
            gh issue comment "$existing" --body-file "$RUNNER_TEMP/report.md"
          else
            gh issue create --title "Upstream SDC OpenAPI export changed" \
              --label spec-drift --body-file "$RUNNER_TEMP/report.md"
          fi
```

- [ ] **Step 3: Lint** with `shellcheck docs/sdc-api/fetch-spec.sh`. If `actionlint` is available, also run `actionlint .github/workflows/spec-drift.yml`; if not, say that it was not run.

- [ ] **Step 4: Commit** `ci: weekly upstream spec-drift check (#154)` plus the trailer, then run the Codex gate.

- [ ] **Step 5: Prove the drift path end to end after merge.** A scheduled workflow only runs from the default branch.
  1. Run `gh workflow run spec-drift.yml`, wait for it, and confirm it is green with "No drift" in the step summary. Confirm no issue was opened.
  2. Sabotage on a throwaway branch: edit the vendored spec (change one `ListTunnels` parameter name), push, and run `gh workflow run spec-drift.yml --ref <branch>`. Expect a `spec-drift` issue listing `GET /api/v2/tunnels` under "Operations this server calls". Close that issue as not planned, noting it was a sabotage run, and delete the branch.
  3. Sabotage the fetch: on the same kind of branch, point `SPEC_URL` at a 404 and dispatch. Expect a **red** run. Delete the branch.

---

### Task 4: Docs

- [ ] **Step 1: In `CLAUDE.md`,** after the sentence naming `fetch-spec.sh` and `gen-endpoint-inventory.py`, add: "`scripts/spec-drift.py self-check` runs on every PR and fails if the client calls a path the vendored spec lacks. `.github/workflows/spec-drift.yml` compares against the live export weekly and files a `spec-drift` issue. It never commits."
- [ ] **Step 2: Add a `CHANGELOG.md` Unreleased entry:** "CI: weekly upstream spec-drift check and a per-PR check that every called path exists in the vendored spec (#154)."
- [ ] **Step 3: Commit** `docs: record the spec-drift check (#154)` plus the trailer, run the Codex gate, and open the PR with `Closes #154`.
