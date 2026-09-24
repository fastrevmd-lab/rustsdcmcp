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

    def test_ref_parameter_identity_resolves_to_name_and_in(self):
        # Operation uses $ref to Limit (resolves to name=limit, in=query)
        # Path declares limit directly with same name/in
        old_spec = {
            "openapi": "3.0.0",
            "info": {"title": "t", "version": "1.0.0"},
            "paths": {
                "/api/v1/devices": {
                    "parameters": [{"name": "limit", "in": "query", "description": "path-level"}],
                    "get": {
                        "parameters": [{"$ref": "#/components/parameters/Limit"}],
                        "responses": {},
                    },
                }
            },
            "components": {
                "schemas": {},
                "parameters": {
                    "Limit": {"name": "limit", "in": "query", "description": "component-level"}
                },
            },
        }
        new_spec_path_changed = {
            "openapi": "3.0.0",
            "info": {"title": "t", "version": "1.0.0"},
            "paths": {
                "/api/v1/devices": {
                    "parameters": [{"name": "limit", "in": "query", "description": "CHANGED path-level"}],
                    "get": {
                        "parameters": [{"$ref": "#/components/parameters/Limit"}],
                        "responses": {},
                    },
                }
            },
            "components": {
                "schemas": {},
                "parameters": {
                    "Limit": {"name": "limit", "in": "query", "description": "component-level"}
                },
            },
        }
        # Changing only the overridden path-level parameter is NOT drift
        report, drifted = drift.diff(old_spec, new_spec_path_changed, self.CALLED)
        self.assertFalse(drifted, "Changing overridden path-level param should not be drift even when op param is a $ref")

    def test_unresolvable_refs_are_distinct(self):
        # Operation has unresolvable $ref A, path has unresolvable $ref B
        old_paths = {
            "/api/v1/devices": {
                "parameters": [{"$ref": "#/components/parameters/B"}],
                "get": {
                    "parameters": [{"$ref": "#/components/parameters/A"}],
                    "responses": {},
                },
            }
        }
        new_paths = {
            "/api/v1/devices": {
                "parameters": [{"$ref": "#/components/parameters/C"}],  # B -> C
                "get": {
                    "parameters": [{"$ref": "#/components/parameters/A"}],
                    "responses": {},
                },
            }
        }
        # Changing the path-level unresolvable ref IS drift (A and B are different)
        report, drifted = drift.diff(spec(old_paths), spec(new_paths), self.CALLED)
        self.assertTrue(drifted, "Changing path-level unresolvable $ref should be drift")

    def test_path_level_parameter_schema_ref_change_is_drift(self):
        # Path-level parameter with schema $ref; changing the ref target is drift
        old_spec = {
            "openapi": "3.0.0",
            "info": {"title": "t", "version": "1.0.0"},
            "paths": {
                "/api/v1/devices": {
                    "parameters": [{"name": "filter", "in": "query", "schema": {"$ref": "#/components/schemas/Filter"}}],
                    "get": {"responses": {}},
                }
            },
            "components": {
                "schemas": {"Filter": {"type": "string"}},
            },
        }
        new_spec = {
            "openapi": "3.0.0",
            "info": {"title": "t", "version": "1.0.0"},
            "paths": {
                "/api/v1/devices": {
                    "parameters": [{"name": "filter", "in": "query", "schema": {"$ref": "#/components/schemas/Filter"}}],
                    "get": {"responses": {}},
                }
            },
            "components": {
                "schemas": {"Filter": {"type": "integer"}},  # changed string -> integer
            },
        }
        report, drifted = drift.diff(old_spec, new_spec, self.CALLED)
        self.assertTrue(drifted, "Changing path-level parameter's schema ref target should be drift")

    def test_component_parameter_schema_change_is_drift(self):
        # Operation uses #/components/parameters/L; changing L's schema is drift
        old_spec = {
            "openapi": "3.0.0",
            "info": {"title": "t", "version": "1.0.0"},
            "paths": {
                "/api/v1/devices": {
                    "get": {
                        "parameters": [{"$ref": "#/components/parameters/Limit"}],
                        "responses": {},
                    },
                }
            },
            "components": {
                "schemas": {},
                "parameters": {
                    "Limit": {"name": "limit", "in": "query", "schema": {"type": "integer", "minimum": 1}}
                },
            },
        }
        new_spec = {
            "openapi": "3.0.0",
            "info": {"title": "t", "version": "1.0.0"},
            "paths": {
                "/api/v1/devices": {
                    "get": {
                        "parameters": [{"$ref": "#/components/parameters/Limit"}],
                        "responses": {},
                    },
                }
            },
            "components": {
                "schemas": {},
                "parameters": {
                    "Limit": {"name": "limit", "in": "query", "schema": {"type": "integer", "minimum": 10}}  # changed 1 -> 10
                },
            },
        }
        report, drifted = drift.diff(old_spec, new_spec, self.CALLED)
        self.assertTrue(drifted, "Changing component parameter's schema should be drift")

    def test_reordering_parameters_is_not_drift(self):
        # Parameters sorted by (in, name) before hashing
        old_paths = {
            "/api/v1/devices": {
                "get": {
                    "parameters": [
                        {"name": "limit", "in": "query"},
                        {"name": "offset", "in": "query"},
                    ],
                    "responses": {},
                }
            }
        }
        new_paths = {
            "/api/v1/devices": {
                "get": {
                    "parameters": [
                        {"name": "offset", "in": "query"},  # reordered
                        {"name": "limit", "in": "query"},
                    ],
                    "responses": {},
                }
            }
        }
        report, drifted = drift.diff(spec(old_paths), spec(new_paths), self.CALLED)
        self.assertFalse(drifted, "Reordering parameters should not be drift")

    def test_no_drift_report_includes_no_drift_line(self):
        # When there's no drift, report must say "No drift."
        s = spec({"/api/v1/devices": {"get": op()}})
        report, drifted = drift.diff(s, s, self.CALLED)
        self.assertFalse(drifted)
        self.assertIn("No drift.", report)


class MainFunction(unittest.TestCase):
    def make_src_with_templates(self):
        """Create a src directory with template calls."""
        root = pathlib.Path(tempfile.mkdtemp())
        (root / "client.rs").write_text('self.get(&["api", "v1", "devices"], &[], ct)')
        return root

    def test_diff_exit_0_on_identical_specs(self):
        s = spec({"/api/v1/devices": {"get": op()}})
        src = self.make_src_with_templates()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(s, f)
            path = f.name
        try:
            result = drift.main(["diff", path, path, "--src", str(src)])
            self.assertEqual(result, 0)
        finally:
            pathlib.Path(path).unlink()

    def test_diff_exit_3_on_drift(self):
        old = spec({"/api/v1/devices": {"get": op()}}, version="1.0.0")
        new = spec({"/api/v1/devices": {"get": op()}}, version="1.1.0")
        src = self.make_src_with_templates()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f1, \
             tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f2:
            json.dump(old, f1)
            json.dump(new, f2)
            path1, path2 = f1.name, f2.name
        try:
            result = drift.main(["diff", path1, path2, "--src", str(src)])
            self.assertEqual(result, 3)
        finally:
            pathlib.Path(path1).unlink()
            pathlib.Path(path2).unlink()

    def test_diff_exit_2_on_non_openapi_file(self):
        src = self.make_src_with_templates()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"not": "openapi"}, f)
            path = f.name
        try:
            try:
                result = drift.main(["diff", path, path, "--src", str(src)])
            except SystemExit as e:
                result = e.code
            self.assertEqual(result, 2)
        finally:
            pathlib.Path(path).unlink()

    def test_self_check_exit_1_when_templates_empty(self):
        s = spec({"/api/v1/devices": {"get": op()}})
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(s, f)
            path = f.name
        try:
            result = drift.main(["self-check", "--spec", path, "--src", tempfile.mkdtemp()])
            self.assertEqual(result, 1)
        finally:
            pathlib.Path(path).unlink()

    def test_only_catalog_rs_implies_item_path(self):
        root = pathlib.Path(tempfile.mkdtemp())
        (root / "client.rs").write_text('Self::Addresses => &["api", "v1", "addresses"],')
        (root / "catalog.rs").write_text('Self::Devices => &["api", "v1", "devices"],')
        templates = drift.called_templates(root)
        # catalog.rs implies both collection and item path
        self.assertIn(("api", "v1", "devices"), templates)
        self.assertIn(("api", "v1", "devices", drift.PARAM), templates)
        # client.rs does not imply item path
        self.assertIn(("api", "v1", "addresses"), templates)
        self.assertNotIn(("api", "v1", "addresses", drift.PARAM), templates)


if __name__ == "__main__":
    unittest.main()
