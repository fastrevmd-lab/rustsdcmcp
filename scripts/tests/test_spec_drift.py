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
                ("api", "v1", "devices", drift.PARAM, "config", "versions"),
                ("api", "v2", "tunnels"),
                ("api", "v1", "devices", drift.PARAM, "config", drift.ANY),
            },
        )

    def test_test_modules_are_ignored(self):
        root = self.write_src({"client.rs": 'x(&["api", "v1", "real"])\n#[cfg(test)]\nmod tests {\n x(&["api", "v1", "fake"])\n}\n'})
        self.assertEqual(drift.called_templates(root), {("api", "v1", "real")})

    def test_catalog_collections_also_imply_their_item_path(self):
        root = self.write_src({"catalog.rs": 'Self::Addresses => &["api", "v1", "addresses"],'})
        self.assertEqual(
            drift.called_templates(root),
            {("api", "v1", "addresses"), ("api", "v1", "addresses", drift.PARAM)},
        )


class SelfCheck(unittest.TestCase):
    def test_reports_templates_absent_from_the_spec(self):
        templates = {("api", "v1", "devices"), ("api", "v1", "nope")}
        paths = spec({"/api/v1/devices": {"get": op()}})["paths"]
        self.assertEqual(drift.unmatched(templates, paths), [("api", "v1", "nope")])

    def test_param_matches_only_spec_parameters(self):
        templates = {("api", "v1", "devices", drift.PARAM)}
        paths = spec({"/api/v1/devices/{device_uuid}": {"get": op()}})["paths"]
        self.assertEqual(drift.unmatched(templates, paths), [])

    def test_param_does_not_match_literal(self):
        templates = {("api", "v1", "devices", drift.PARAM)}
        paths = spec({"/api/v1/devices/sync": {"get": op()}})["paths"]
        self.assertEqual(drift.unmatched(templates, paths), [("api", "v1", "devices", drift.PARAM)])

    def test_any_matches_both_literal_and_parameter(self):
        templates = {("api", "v1", "config", drift.ANY)}
        paths = spec({
            "/api/v1/config/global": {"get": op()},
            "/api/v1/config/{section}": {"get": op()},
        })["paths"]
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

    def test_changed_servers_is_drift_in_document_level_section(self):
        old = spec({"/api/v1/devices": {"get": op()}})
        old["servers"] = [{"url": "https://old.example.com"}]
        new = spec({"/api/v1/devices": {"get": op()}})
        new["servers"] = [{"url": "https://new.example.com"}]
        report, drifted = drift.diff(old, new, self.CALLED)
        self.assertTrue(drifted)
        self.assertIn("### Document-level contract (affects every call)", report)

    def test_changed_path_level_parameter_is_drift(self):
        old_paths = {"/api/v1/devices": {"parameters": [{"name": "x", "in": "query"}], "get": op()}}
        new_paths = {"/api/v1/devices": {"parameters": [{"name": "y", "in": "query"}], "get": op()}}
        report, drifted = drift.diff(spec(old_paths), spec(new_paths), self.CALLED)
        self.assertTrue(drifted)
        self.assertIn("GET /api/v1/devices", report)

    def test_operation_level_parameter_overrides_path_level(self):
        # Operation-level param overrides path-level param with same (name, in)
        old_paths = {
            "/api/v1/devices": {
                "parameters": [{"name": "limit", "in": "query", "description": "path-level"}],
                "get": {
                    "parameters": [{"name": "limit", "in": "query", "description": "operation-level"}],
                    "responses": {},
                },
            }
        }
        new_paths_path_changed = {
            "/api/v1/devices": {
                "parameters": [{"name": "limit", "in": "query", "description": "CHANGED path-level"}],
                "get": {
                    "parameters": [{"name": "limit", "in": "query", "description": "operation-level"}],
                    "responses": {},
                },
            }
        }
        new_paths_op_changed = {
            "/api/v1/devices": {
                "parameters": [{"name": "limit", "in": "query", "description": "path-level"}],
                "get": {
                    "parameters": [{"name": "limit", "in": "query", "description": "CHANGED operation-level"}],
                    "responses": {},
                },
            }
        }
        # Changing only the overridden path-level parameter is NOT drift
        report1, drifted1 = drift.diff(spec(old_paths), spec(new_paths_path_changed), self.CALLED)
        self.assertFalse(drifted1, "Changing overridden path-level param should not be drift")
        # Changing the operation-level parameter IS drift
        report2, drifted2 = drift.diff(spec(old_paths), spec(new_paths_op_changed), self.CALLED)
        self.assertTrue(drifted2, "Changing operation-level param should be drift")
        self.assertIn("GET /api/v1/devices", report2)


if __name__ == "__main__":
    unittest.main()
