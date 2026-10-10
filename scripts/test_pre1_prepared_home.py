"""Preparation ownership must not inherit the private execution HOME."""
import ast
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import pre1_package_execution as adapter


class PreparedHomeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.prepared = self.root / "prepared"
        self.case = self.root / "case"
        self.prepared.mkdir(mode=0o700)
        self.case.mkdir(mode=0o700)

    def test_legacy_preparation_defaults_to_home(self):
        with patch.dict(os.environ, {"HOME": str(self.prepared)}, clear=True):
            self.assertEqual(adapter.prepared_package_home(), self.prepared)

    def test_explicit_preparation_home_does_not_require_home(self):
        with patch.dict(os.environ,
                {"IICP_PRE1_PREPARED_PACKAGE_HOME": str(self.prepared)}, clear=True):
            self.assertEqual(adapter.prepared_package_home(), self.prepared)

    def test_execution_home_does_not_replace_preparation_owner(self):
        workspace = self.prepared / "workspace"
        installed = workspace / "payload"
        installed.mkdir(parents=True)
        source = self.root / "source"
        source.mkdir()
        env = {"HOME": str(self.case), "IICP_PRE1_PREPARED_PACKAGE_HOME": str(self.prepared)}
        with patch.dict(os.environ, env, clear=True):
            self.assertEqual(adapter.prepared_package_home(), self.prepared)
            adapter.validate_workspace_boundary(workspace, adapter.prepared_package_home(), installed, source)
            with self.assertRaises(ValueError):
                adapter.validate_workspace_boundary(workspace, self.case, installed, source)

    def test_wrong_explicit_preparation_boundary_is_rejected(self):
        workspace = self.prepared / "workspace"
        installed = workspace / "payload"
        installed.mkdir(parents=True)
        with patch.dict(os.environ, {"HOME": str(self.prepared),
                "IICP_PRE1_PREPARED_PACKAGE_HOME": str(self.case)}, clear=True):
            with self.assertRaises(ValueError):
                adapter.validate_workspace_boundary(workspace, adapter.prepared_package_home(), installed, self.root / "source")

    def test_symlink_preparation_boundary_is_rejected(self):
        alias = self.root / "alias"
        alias.symlink_to(self.prepared, target_is_directory=True)
        with patch.dict(os.environ, {"HOME": str(self.case),
                "IICP_PRE1_PREPARED_PACKAGE_HOME": str(alias)}, clear=True):
            with self.assertRaises(ValueError):
                adapter.prepared_package_home()

    def test_directory_binding_revalidates_with_private_case_home(self):
        workspace = self.prepared / "workspace"
        installed = workspace / "payload"
        installed.mkdir(parents=True)
        source = self.root / "source"
        source.mkdir()
        artifact = self.root / "artifact"
        artifact.write_bytes(b"bound diagnostic fixture")
        component = "directory-rust"
        runtime = "msrv-1.88"
        bindings = {key: "sha256:" + "a" * 64 for key in adapter.BINDINGS}
        env = {"HOME": str(self.case), "IICP_PRE1_PREPARED_PACKAGE_HOME": str(self.prepared)}
        with patch.dict(os.environ, env, clear=True), \
                patch.object(adapter, "directory_payload", return_value=({}, {})), \
                patch.object(adapter, "directory_fixtures", return_value={}):
            value = adapter.create_directory_binding(source, workspace, installed, artifact,
                component, runtime, "linux-aarch64", bindings, stage_fixtures=False)
            context = {"component": component, "runtime": runtime, "target": "linux-aarch64", **bindings}
            self.assertEqual(adapter.validate_directory_binding(value, context, artifact, source), workspace)
        with patch.dict(os.environ, {"HOME": str(self.case)}, clear=True):
            with self.assertRaisesRegex(ValueError, "run-isolated"):
                adapter.validate_directory_binding(value, context, artifact, source)

    def test_driver_preserves_preparation_boundary(self):
        # Execute the actual owning function without importing its driver (which
        # performs unrelated qualification-map initialization at import time).
        path = Path(adapter.__file__).with_name("run_pre1_qualification_case.py")
        tree = ast.parse(path.read_text())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "command_environment")
        namespace = {"os": os, "Path": Path, "json": json, "COMPONENT": "fixture"}
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(path), "exec"), namespace)
        manifest = self.root / "candidate.json"
        manifest.write_text(json.dumps({"components": [{"id": "fixture", "artifacts": [{"kind": "release-manifest", "name": "release.json"}]}]}))
        env = {"HOME": str(self.case), "IICP_HOME": str(self.case),
               "IICP_PRE1_PREPARED_PACKAGE_HOME": str(self.prepared)}
        for node in ast.walk(function):
            if isinstance(node, ast.For) and isinstance(node.iter, ast.Tuple):
                for value in node.iter.elts:
                    if isinstance(value, ast.Constant) and isinstance(value.value, str):
                        env[value.value] = "diagnostic-fixture"
        env.update(IICP_PRE1_CANDIDATE_MANIFEST=str(manifest), IICP_PRE1_ARTIFACT_ROOT=str(self.root))
        with patch.dict(os.environ, env, clear=True):
            result = namespace["command_environment"]({"env": {}, "programs": {name: "/runtime/" + name for name in ("python", "node", "cargo", "rustc", "php")}}, "fixture")
        self.assertEqual(result["HOME"], str(self.case))
        self.assertEqual(result["IICP_PRE1_PREPARED_PACKAGE_HOME"], str(self.prepared))


if __name__ == "__main__":
    unittest.main()
