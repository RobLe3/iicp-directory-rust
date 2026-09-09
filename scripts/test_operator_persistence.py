"""Portable safety/negative tests; mocks never grant runtime qualification."""
import argparse
import contextlib
import io as streams
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import operator_runtime_io as io
import rehearse_operator_persistence as ops


class SafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def test_pinned_image_only(self):
        self.assertEqual(io.image_reference("mysql:8.0@sha256:" + "a" * 64), "mysql:8.0@sha256:" + "a" * 64)
        for value in ("mysql:8.0", "--help", "mysql@sha256:" + "A" * 64, "x y@sha256:" + "a" * 64):
            with self.assertRaises(io.RehearsalError):
                io.image_reference(value)

    def test_output_is_new_private_and_outside_checkout(self):
        output = ops.output_directory(self.root / "out")
        self.assertEqual(output.stat().st_mode & 0o777, 0o700)
        with self.assertRaises(io.RehearsalError):
            ops.output_directory(output)
        with self.assertRaises(io.RehearsalError):
            ops.output_directory(Path(ops.__file__).resolve().parents[1] / "unsafe-output")
        (self.root / "link").symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            ops.output_directory(self.root / "link/out2")

    def test_capture_propagates_exit_and_both_streams(self):
        code, out, err = io.capture([sys.executable, "-c", "import sys;print('out');print('err',file=sys.stderr);sys.exit(7)"])
        self.assertEqual((code, out, err), (7, b"out\n", b"err\n"))

    def test_parent_traversal_cannot_bypass_checkout_guard(self):
        source = Path(ops.__file__).resolve().parents[1]
        path = source / "scripts" / ".." / "unsafe-output"
        with patch.object(Path, "mkdir") as mkdir:
            with self.assertRaisesRegex(io.RehearsalError, "outside_source"):
                ops.output_directory(path)
        mkdir.assert_not_called()

    def test_docker_mount_delimiter_is_refused(self):
        with self.assertRaisesRegex(io.RehearsalError, "mount_delimiter"):
            ops.output_directory(self.root / "output,readonly")

    def test_output_overflow_refuses_instead_of_passing(self):
        with self.assertRaisesRegex(io.RehearsalError, "output_limit"):
            io.capture([sys.executable, "-c", f"print('x'*{io.LIMIT+1})"])

    def test_timeout_including_blocked_stdin(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            io.capture([sys.executable, "-c", "import time;time.sleep(10)"], data=b"x" * io.LIMIT, timeout=.1)

    def test_logs_are_redacted_and_bounded(self):
        docker = io.Docker("test", self.root)
        docker.secrets = ["private-password"]
        docker.log(b"private-password mysql://user:secret@host/db\n")
        raw = (self.root / "diagnostics.log").read_text()
        self.assertNotIn("private-password", raw)
        self.assertNotIn("user:secret", raw)
        docker.log_bytes = 16 * io.LIMIT
        before = (self.root / "diagnostics.log").read_bytes()
        docker.log(b"not retained")
        self.assertEqual(before, (self.root / "diagnostics.log").read_bytes())

    def test_foreign_resource_is_never_removed(self):
        docker = io.Docker("owned", self.root)
        docker.owned = [("container", "foreign")]
        raw = json.dumps([{"Config": {"Labels": {io.LABEL: "other"}}}]).encode()
        with patch.object(docker, "call", return_value=(0, raw)) as call:
            self.assertEqual(docker.cleanup(), ["container"])
        self.assertEqual(call.call_count, 1)

    def test_daemon_failure_cannot_prove_absence(self):
        docker = io.Docker("owned", self.root)
        docker.owned = [("network", "owned-net")]
        with patch.object(docker, "call", side_effect=[(1, b""), io.RehearsalError("daemon_down")]):
            self.assertEqual(docker.cleanup(), ["network"])

    def test_cleanup_reversed_and_volume_list_uses_valid_flags(self):
        docker = io.Docker("owned", self.root)
        docker.owned = [("volume", "data"), ("container", "app")]
        app = json.dumps([{"Config": {"Labels": {io.LABEL: "owned"}}}]).encode()
        volume = json.dumps([{"Labels": {io.LABEL: "owned"}}]).encode()
        with patch.object(docker, "call", side_effect=[(0, app), (0,b""), (0,b""), (0,volume), (0,b""), (0,b"")]) as call:
            self.assertEqual(docker.cleanup(), [])
        self.assertIn(unittest.mock.call("volume", "ls", "-q", "--filter", "name=data"), call.call_args_list)

    def test_creation_timeout_is_still_owned_for_verified_cleanup(self):
        docker = io.Docker("owned", self.root)
        with patch.object(docker, "call", side_effect=[(1,b""), subprocess.TimeoutExpired("docker", 1)]):
            with self.assertRaises(subprocess.TimeoutExpired):
                docker.create("container", "owned-app", ["run"])
        self.assertEqual(docker.owned, [("container", "owned-app")])

    def test_runtime_config_uses_maintained_environment_names(self):
        docker = io.Docker("owned", self.root)
        runtime = ops.Runtime(docker, self.root, "runtime", "mysql", "0.1.15")
        with patch.object(docker, "create"), patch.object(runtime, "wait_database"), \
             patch.object(runtime, "sql", return_value=b"8.0.45"):
            runtime.start_database()
        env = (self.root / "app.env").read_text()
        source = (Path(ops.__file__).resolve().parents[1] / "src/config.rs").read_text()
        for name in ("IICP_DIRECTORY_DID", "IICP_DIRECTORY_ENDPOINT", "IICP_DB_POOL_ACQUIRE_TIMEOUT_MS"):
            self.assertIn(name + "=", env)
            self.assertIn('"' + name + '"', source)
        self.assertNotIn("iicp.network", env)
        self.assertIn("IICP_ALLOW_IN_MEMORY=false", env)

    def test_runtime_has_no_host_ports_and_cannot_pull(self):
        docker = io.Docker("owned", self.root)
        runtime = ops.Runtime(docker, self.root, "runtime", "mysql", "0.1.15")
        with patch.object(docker, "create") as create:
            runtime.start_app()
        args = create.call_args.args[2]
        self.assertIn("--pull=never", args)
        self.assertIn("--read-only", args)
        self.assertNotIn("-p", args)
        self.assertNotIn("--publish", args)
        self.assertNotIn("--privileged", args)

    def test_node_api_disagreement_rejects_sql_only_success(self):
        runtime = ops.Runtime(io.Docker("owned", self.root), self.root, "runtime", "mysql", "0.1.15")
        with patch.object(runtime, "sql", return_value=b"row"), patch.object(runtime, "api", return_value={"node_id": ops.NODE, "region": "wrong"}):
            with self.assertRaisesRegex(io.RehearsalError, "node_api_differs"):
                runtime.verify_rows(b"row")

    def test_node_api_uses_wire_identity_not_sql_column_name(self):
        runtime = ops.Runtime(io.Docker("owned", self.root), self.root, "runtime", "mysql", "0.1.15")
        source = (Path(ops.__file__).resolve().parents[1] / "src/types.rs").read_text()
        self.assertIn("pub node_id: String", source)
        with patch.object(runtime, "sql", return_value=b"row"), patch.object(runtime, "api", return_value={"node_id": ops.NODE, "region": "test-region"}):
            self.assertEqual(runtime.verify_rows(b"row"), ops.hashlib.sha256(b"row").hexdigest())

    def test_existing_public_workflow_retains_evidence_without_new_job(self):
        root = Path(ops.__file__).resolve().parents[1]
        workflow = (root / ".github/workflows/quality.yml").read_text()
        self.assertIn("python3 scripts/test_operator_persistence.py", workflow)
        self.assertIn("inputs.operator_artifact && github.ref == 'refs/heads/main'", workflow)
        self.assertIn("if: always()", workflow)
        self.assertIn("retention-days: 3", workflow)
        self.assertNotIn("rehearsal/backup.sql", workflow)
        self.assertNotIn("rehearsal/app.env", workflow)
        upload = workflow.split("      - name: Retain exact fragment", 1)[1].split("\n  event-log-concurrency:", 1)[0]
        self.assertNotIn("/../", upload)
        self.assertIn("${{ steps.operator.outputs.output }}/fragment/", upload)
        self.assertIn("printf 'output=%s\\n'", (root / "scripts/run_operator_artifact_ci.sh").read_text())

    def test_readiness_uses_actual_http_version_and_schema_check(self):
        docker = io.Docker("owned", self.root)
        runtime = ops.Runtime(docker, self.root, "runtime", "mysql", "0.1.15")
        source = (Path(ops.__file__).resolve().parents[1] / "src/main.rs").read_text()
        self.assertIn('concat!("v", env!("CARGO_PKG_VERSION"), "-rs")', source)
        with patch.object(runtime, "api", return_value={"ok": True, "version": "v0.1.15-rs"}), patch.object(docker, "call") as call:
            runtime.ready()
        self.assertIn("db-maintenance-status", call.call_args.args)

    def test_incompatible_health_version_fails_immediately(self):
        runtime = ops.Runtime(io.Docker("owned", self.root), self.root, "runtime", "mysql", "0.1.15")
        with patch.object(runtime, "api", return_value={"ok": True, "version": "0.1.15"}), patch.object(ops.time, "sleep") as sleep:
            with self.assertRaisesRegex(io.RehearsalError, "health_version_mismatch"):
                runtime.ready()
        sleep.assert_not_called()

    def test_upload_independent_console_evidence_is_redacted(self):
        docker = io.Docker("owned", self.root)
        docker.secrets = ["private-password"]
        docker.log(b"x" * 40000 + b"private-password")
        stream = streams.StringIO()
        with contextlib.redirect_stderr(stream):
            docker.console_failure()
        self.assertNotIn("private-password", stream.getvalue())
        self.assertIn("[REDACTED]", stream.getvalue())
        self.assertLess(len(stream.getvalue()), 33000)

    def arguments(self):
        return argparse.Namespace(fragment=self.root / "fragment.json", fragment_sha256="sha256:" + "b"*64,
                                  source_commit="a"*40, target="linux-x86_64", runtime_image="python@sha256:"+"a"*64,
                                  mysql_image="mysql@sha256:"+"b"*64, output=self.root / "output")

    def test_wrong_artifact_touches_no_docker(self):
        with patch.object(ops.admission, "prepare", side_effect=ValueError("wrong artifact")), patch.object(io.Docker, "call") as call:
            with self.assertRaises(ValueError):
                ops.rehearse(self.arguments())
        call.assert_not_called()

    def run_outcome(self, exercise_error=None, cleanup=None):
        args = self.arguments()
        def install(*values):
            if len(values) == 5:
                values[4].write_bytes(b"fake")
            return {"qualification_credit": 0, "source_version": "0.1.15"}
        with patch.object(ops.admission, "prepare", side_effect=install), \
             patch.object(io.Docker, "call", return_value=(0, b'[{"Os":"linux","Architecture":"amd64"}]')), \
             patch.object(io.Docker, "failure_evidence") as evidence, \
             patch.object(io.Docker, "cleanup", return_value=cleanup or []) as clean, \
             patch.object(ops.Runtime, "exercise", side_effect=exercise_error):
            result = ops.rehearse(args)
        self.assertEqual(evidence.call_count, 1)
        self.assertEqual(clean.call_count, 1)
        self.assertEqual(result["qualification_credit"], 0)
        return args, result

    def test_success_returns_owned_binary(self):
        args, result = self.run_outcome()
        self.assertEqual(result["status"], "PASS")
        self.assertFalse((args.output / "installed").exists())

    def test_failure_retains_evidence_and_cleans(self):
        args, result = self.run_outcome(io.RehearsalError("api_differs"))
        self.assertEqual(result["reason"], "api_differs")
        self.assertTrue(result["resources_absent"])
        self.assertTrue((args.output / "installed/directory").exists())

    def test_cleanup_failure_never_passes(self):
        _, result = self.run_outcome(cleanup=["container"])
        self.assertEqual(result["status"], "FAIL")
        self.assertFalse(result["resources_absent"])


if __name__ == "__main__":
    unittest.main()
