"""Negative controls for installed-payload and staged-assertion provenance."""
from __future__ import annotations

import copy
import io
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import pre1_package_execution as adapter


class PackageExecutionTests(unittest.TestCase):
    def directory_http_functions(self):
        import ast
        import signal
        import time
        import urllib.request
        import urllib.error
        parsed = ast.parse(adapter.DIRECTORY_PROBE)
        functions = ast.Module(body=[n for n in parsed.body if isinstance(n, ast.FunctionDef)], type_ignores=[])
        namespace = dict(json=json, os=os, signal=signal,
                         subprocess=subprocess, tempfile=tempfile, time=time, Path=Path, urllib=urllib)
        exec(compile(functions, "directory-probe.py", "exec"), namespace)
        return namespace

    def test_duplicate_registration_requires_damaged_reputation_and_identity_preservation(self):
        from unittest.mock import Mock
        check = self.directory_http_functions()["duplicate_registration_postcondition"]
        node = lambda score: {"node_id": "fixture-duplicate", "endpoint": "http://127.0.0.1:1", "reputation_score": score}
        rows = [(201, {"node_id": "fixture-duplicate", "node_token": "synthetic"}),
                (200, node(.5)), (200, {"ok": True}), (200, node(.3)),
                (201, {"node_id": "fixture-duplicate"}), (200, node(.3))]
        request = Mock(side_effect=rows)
        check(request)
        self.assertEqual(request.call_args_list[2].kwargs["headers"], {"Authorization": "Bearer synthetic"})
        self.assertEqual(request.call_args_list[4].args[1]["current_node_token"], "synthetic")
        for index, replacement in [(0, (201, {})), (1, (200, node(True))),
                (2, (200, {"ok": False})), (3, (200, node(.5))),
                (4, (201, {"node_id": "other"})), (5, (200, node(.5))),
                (5, (200, {**node(.3), "endpoint": "https://wrong.invalid"}))]:
            changed = list(rows); changed[index] = replacement
            with self.subTest(index=index, replacement=replacement), self.assertRaises(ValueError):
                check(Mock(side_effect=changed))

    def test_directory_http_postconditions_reject_status_only_false_positives(self):
        check = self.directory_http_functions()["http_postcondition"]
        for status in (200, 403, 404, 500):
            with self.subTest(status=status), self.assertRaises(ValueError):
                check(lambda *a: (status, {}), "credential-missing")
        check(lambda *a: (401, {}), "credential-missing")
        with self.assertRaises(ValueError):
            check(lambda *a: (422, {"message": "endpoint invalid"}), "unsupported-version")
        check(lambda *a: (422, {"message": "sdk_compatibility_version must match sdk_version when both are supplied"}), "unsupported-version")
        with self.assertRaises(ValueError):
            check(lambda *a: (200, {}), "backup-restore")

    def test_directory_expired_credential_requires_valid_signature_control_and_specific_cause(self):
        from unittest.mock import Mock
        check = self.directory_http_functions()["replica_snapshot_postcondition"]
        good = (401, {"error": {"message": "Replica not registered"}})
        expired = (401, {"error": {"code": "token_expired"}})
        request = Mock(side_effect=[good, expired])
        check(request, "credential-expired")
        first, second = [c.kwargs["headers"]["Authorization"] for c in request.call_args_list]
        self.assertNotEqual(first, second)
        self.assertTrue(first.startswith("Bearer "))
        for responses in ([expired, expired], [good, (401, {})], [good, (200, {})]):
            with self.subTest(responses=responses), self.assertRaises(ValueError):
                check(Mock(side_effect=responses), "credential-expired")

    def test_directory_synthetic_replica_jwt_has_deterministic_fixture_signature(self):
        import base64, hashlib, hmac
        from unittest.mock import Mock
        request = Mock(side_effect=[(401, {"error": {"message": "Replica not registered"}}),
                                   (401, {"error": {"code": "token_expired"}})])
        self.directory_http_functions()["replica_snapshot_postcondition"](request, "credential-expired")
        value = request.call_args_list[0].kwargs["headers"]["Authorization"][7:]
        header, claims, signature = value.split(".")
        decode = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
        self.assertEqual(json.loads(decode(header)), {"alg": "HS256", "typ": "JWT"})
        self.assertEqual(json.loads(decode(claims))["scope"], "GET /v1/snapshot")
        self.assertEqual(decode(signature), hmac.new(b"iicp-pre1-isolated-synthetic-key",
                         (header + "." + claims).encode(), hashlib.sha256).digest())

    def test_directory_rotated_credential_requires_old_refusal_and_replacement_success(self):
        from unittest.mock import Mock
        check = self.directory_http_functions()["replica_snapshot_postcondition"]
        rows = [(200, {"replica_id": "fixture", "replica_token": "old"}), (200, {}),
                (200, {"replica_id": "fixture", "replica_token": "new"}),
                (401, {"error": {"code": "unauthorized", "message": "Replica token has been rotated"}}), (200, {})]
        check(Mock(side_effect=rows), "credential-rotated")
        mutations = [(1, (401, {})), (2, rows[0]),
                     (2, (200, {"replica_id": "other", "replica_token": "new"})),
                     (3, (401, {"error": {"code": "token_expired"}})), (3, (200, {})), (4, (401, {}))]
        for index, value in mutations:
            changed = rows.copy(); changed[index] = value
            with self.subTest(index=index, value=value), self.assertRaises(ValueError):
                check(Mock(side_effect=changed), "credential-rotated")

    def test_directory_rate_burst_is_bounded_and_tests_recovery(self):
        from unittest.mock import Mock
        import time
        check = self.directory_http_functions()["registration_rate_postcondition"]
        normal = (422, {"message": "sdk_compatibility_version must match sdk_version"})
        limit = (429, {"error": "IICP-E034", "retry_after": 60})
        request = Mock(side_effect=[normal] * 60 + [limit] * 2 + [normal])
        with patch.object(time, "monotonic", return_value=10), patch.object(time, "sleep") as sleep:
            check(request)
        self.assertEqual(request.call_count, 63)
        sleep.assert_called_once_with(61)
        self.assertTrue(request.call_args.args[1]["capabilities"])

    def test_directory_rate_rejects_early_limit_wrong_reason_and_absent_recovery(self):
        from unittest.mock import Mock
        import time
        check = self.directory_http_functions()["registration_rate_postcondition"]
        normal = (422, {"message": "sdk_compatibility_version must match sdk_version"})
        limit = (429, {"error": "IICP-E034", "retry_after": 60})
        for rows in ([limit], [normal] * 60 + [(429, {})],
                     [normal] * 60 + [limit] * 2 + [limit]):
            with self.subTest(length=len(rows)), patch.object(time, "monotonic", return_value=0), \
                    patch.object(time, "sleep"), self.assertRaises(ValueError):
                check(Mock(side_effect=rows))
        with patch.object(time, "monotonic", side_effect=[0, 56]), \
                patch.object(time, "sleep") as sleep, self.assertRaisesRegex(ValueError, "window"):
            check(Mock(side_effect=[normal] * 60 + [limit] * 2))
        sleep.assert_not_called()

    def test_directory_route_readiness_requires_refusal_absent_identity_and_ready_control(self):
        import http.server, time
        from unittest.mock import Mock, MagicMock
        check = self.directory_http_functions()["initial_route_postcondition"]
        rows = [(422, {"error": {"code": "IICP-E036"}}), (404, {}),
                (201, {"node_id": "fixture-route"}), (200, {"endpoint": "http://127.0.0.1:12345"})]
        for changed in [rows, [(422, {})], [(422, {"error": "IICP-E036"})], [rows[0], (200, {})], rows[:2] + [(422, {})],
                        rows[:3] + [(200, {"endpoint": "http://other.invalid"})]]:
            server = MagicMock(); server.__enter__.return_value = server; server.server_port = 12345
            server.handle_request.side_effect = lambda: time.sleep(0.001)
            request = Mock(side_effect=changed)
            with self.subTest(rows=changed), patch.object(http.server, "HTTPServer", return_value=server):
                if changed == rows:
                    check(request)
                    self.assertEqual(request.call_count, 4)
                else:
                    with self.assertRaises(ValueError):
                        check(request)
            server.server_close.assert_called_once()

    def directory_network(self, active):
        import struct
        from unittest.mock import Mock
        from contextlib import ExitStack
        import socket
        stack = ExitStack()
        ioctl = Mock()
        ioctl.ioctl.side_effect = lambda fd, op, name: b"\0" * 16 + struct.pack("H", int(name.rstrip(b"\0").decode() in active))
        stack.enter_context(patch.dict("sys.modules", {"fcntl": ioctl}))
        stack.enter_context(patch.object(socket, "if_nameindex", return_value=[(1, "lo"), (2, "eth0"), (3, "gre0")]))
        return stack

    def test_directory_http_fixture_refuses_host_network_before_process_start(self):
        run = self.directory_http_functions()["rust_http_case"]
        with self.directory_network({"lo", "eth0"}), \
             patch.object(subprocess, "Popen") as launch:
            with self.assertRaisesRegex(ValueError, "loopback-only"):
                run(Path("/fixture/binary"), {}, "credential-missing", "0.1.15")
            launch.assert_not_called()

    def test_directory_http_fixture_wrong_identity_kills_owned_process(self):
        from unittest.mock import Mock, MagicMock
        import urllib.request
        run = self.directory_http_functions()["rust_http_case"]
        process = Mock(pid=123)
        process.poll.return_value = None
        response = MagicMock(code=200)
        response.__enter__.return_value = response
        response.read.return_value = b'{"ok":true,"version":"v9.9.9-rs"}'
        with self.directory_network({"lo"}), \
             patch.object(subprocess, "Popen", return_value=process), \
             patch.object(os, "pread", return_value=b"listening on 0.0.0.0:8090", create=True), \
             patch.object(os, "killpg", create=True) as kill, \
             patch.object(urllib.request, "build_opener") as opener:
            opener.return_value.open.return_value = response
            with self.assertRaisesRegex(ValueError, "identity differs"):
                run(Path("/fixture/binary"), {}, "credential-missing", "0.1.15")
            kill.assert_called_once()
            process.wait.assert_called_once_with(timeout=10)

    def test_directory_http_fixture_timeout_and_early_exit_preserve_cleanup(self):
        from unittest.mock import Mock
        import time
        run = self.directory_http_functions()["rust_http_case"]
        for exit_code, cause in ((None, "timed out"), (1, "exited before readiness")):
            process = Mock(pid=123)
            process.poll.return_value = exit_code
            with self.subTest(exit_code=exit_code), \
                 self.directory_network({"lo"}), \
                 patch.object(subprocess, "Popen", return_value=process), \
                 patch.object(os, "pread", return_value=b"", create=True), \
                 patch.object(os, "killpg", create=True) as kill, \
                 patch.object(time, "monotonic", side_effect=[0, 31]):
                with self.assertRaisesRegex(ValueError, cause):
                    run(Path("/fixture/binary"), {}, "credential-missing", "0.1.15")
                kill.assert_called_once()
                process.wait.assert_called_once_with(timeout=10)

    def directory_inputs(self, component="directory-rust"):
        import shutil
        shutil.rmtree(self.workspace)
        self.workspace.mkdir()
        (self.root / "qualification").mkdir(exist_ok=True)
        mapping = {"support": {"assertion": "support", "command": ["@php", "vendor/bin/phpunit"]},
                   "scenarios": {name: {"assertion": name, "command": ["@php", "vendor/bin/phpunit"]}
                     for name in ["package-version-self-report", "config-missing", "config-malformed", "backup-restore",
                                  "credential-missing", "unsupported-version", "credential-expired", "credential-rotated",
                                  "rate-limit", "dynamic-public-route-readiness", "duplicate-registration"]}}
        (self.root / "qualification/pre1-cases.json").write_text(json.dumps(mapping))
        if component == "directory-rust":
            artifact = self.home / "iicp-directory-rs-0.1.15-linux-aarch64"
            header = bytearray(20)
            header[:6] = b"\x7fELF\x02\x01"
            header[18:20] = (183).to_bytes(2, "little")
            artifact.write_bytes(header)
        else:
            artifact = self.home / "php.tar.gz"
            with tarfile.open(artifact, "w:gz") as archive:
                for name in ["artisan", "composer.json", "composer.lock", "app/runtime.php"]:
                    data = name.encode()
                    member = tarfile.TarInfo("iicp-directory-php-v1.10.94/" + name)
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
        installed = adapter.stage_directory_payload(artifact, self.workspace, component)
        if component == "directory-php":
            (installed / "vendor").mkdir()
            (installed / "vendor/autoload.php").write_text("locked vendor")
        value = adapter.create_binding(self.root, self.workspace, installed, artifact,
            component, "php-8.3" if component == "directory-php" else "rust-1.98.0", "linux-aarch64", self.bindings)
        context = {**self.context, "component": component, "runtime": value["runtime"],
                   "target": "linux-aarch64", "mode": "local-only", "scenario_id": "config-missing"}
        return artifact, installed, value, context

    def test_directory_binary_binding_and_proof_are_candidate_bound(self):
        artifact, installed, value, context = self.directory_inputs()
        self.assertEqual(adapter.validate_binding(value, context, artifact, self.root), self.workspace)
        proof = adapter.make_case_proof(value, context, "config-missing", 0, "directory-test")
        adapter.validate_case_proof(proof, context, 0, "directory-test",
            adapter.execution_summary(value), "config-missing")
        self.assertFalse(value["qualification_credit"])
        self.assertEqual((installed / "iicp-directory-rs").read_bytes(), artifact.read_bytes())

    def test_directory_binary_rehashed_tamper_and_wrong_architecture_fail(self):
        artifact, installed, value, context = self.directory_inputs()
        binary = installed / "iicp-directory-rs"
        binary.write_bytes(binary.read_bytes() + b"tamper")
        value["installed_payload_sha256"] = adapter.digest(adapter.tree(installed))
        value["binding_sha256"] = adapter.digest({**value, "binding_sha256": None})
        with self.assertRaises(ValueError):
            adapter.validate_binding(value, context, artifact, self.root)
        binary.write_bytes(artifact.read_bytes())
        with self.assertRaisesRegex(ValueError, "architecture differs"):
            adapter.create_binding(self.root, self.workspace, installed, artifact,
                "directory-rust", "rust-1.98.0", "linux-x86_64", self.bindings)

    def test_directory_fixtures_cannot_be_deleted_or_rehashed(self):
        artifact, installed, value, context = self.directory_inputs()
        (self.workspace / "directory-probe.py").unlink()
        with self.assertRaisesRegex(ValueError, "fixtures changed"):
            adapter.validate_binding(value, context, artifact, self.root)
        self.assertFalse((self.workspace / "directory-probe.py").exists())
        (self.workspace / "directory-probe.py").write_text("fake success")
        with self.assertRaises(ValueError):
            adapter.validate_binding(value, context, artifact, self.root)

    def test_directory_binary_modes_and_extra_runtime_files_fail(self):
        artifact, installed, value, context = self.directory_inputs()
        binary = installed / "iicp-directory-rs"
        binary.chmod(0o755)
        with self.assertRaises(ValueError):
            adapter.validate_binding(value, context, artifact, self.root)
        binary.chmod(0o700)
        (installed / "fallback-runtime").write_text("checkout substitute")
        with self.assertRaises(ValueError):
            adapter.validate_binding(value, context, artifact, self.root)

    def test_directory_archive_source_and_vendor_are_separately_bound(self):
        artifact, installed, value, context = self.directory_inputs("directory-php")
        self.assertEqual(adapter.validate_binding(value, context, artifact, self.root), self.workspace)
        (installed / "storage").mkdir(exist_ok=True)
        (installed / "storage/log.txt").write_text("volatile test log")
        adapter.validate_binding(value, context, artifact, self.root)
        (installed / "app/runtime.php").write_text("checkout fallback")
        with self.assertRaises(ValueError):
            adapter.validate_binding(value, context, artifact, self.root)

    def test_directory_archive_vendor_tamper_and_symlinks_fail(self):
        artifact, installed, value, context = self.directory_inputs("directory-php")
        (installed / "vendor/autoload.php").write_text("unlocked dependencies")
        with self.assertRaises(ValueError):
            adapter.validate_binding(value, context, artifact, self.root)
        (installed / "vendor/autoload.php").unlink()
        (installed / "vendor/autoload.php").symlink_to(self.root / "src/runtime.py")
        with self.assertRaises(ValueError):
            adapter.validate_binding(value, context, artifact, self.root)

    def test_directory_php_guard_checks_real_namespace_prefixes_and_cache_tamper(self):
        self.assertIn("'App\\\\'", adapter.DIRECTORY_ORIGIN)
        self.assertIn("'Tests\\\\'", adapter.DIRECTORY_ORIGIN)
        self.assertIn("'Database\\\\'", adapter.DIRECTORY_ORIGIN)
        self.assertIn("str_starts_with(realpath($file), $expected)", adapter.DIRECTORY_ORIGIN)
        self.assertNotIn("str_starts_with(realpath($file), $root . DIRECTORY_SEPARATOR)", adapter.DIRECTORY_ORIGIN)
        artifact, installed, value, context = self.directory_inputs("directory-php")
        (installed / "bootstrap/cache").mkdir(parents=True, exist_ok=True)
        (installed / "bootstrap/cache/services.php").write_text("unbound executable cache")
        with self.assertRaises(ValueError):
            adapter.validate_binding(value, context, artifact, self.root)

    def test_directory_archive_provisions_private_runtime_directories(self):
        import stat
        artifact, installed, value, context = self.directory_inputs("directory-php")
        for name in ("bootstrap/cache", "storage/logs", "storage/framework/cache/data",
                     "storage/framework/sessions", "storage/framework/views"):
            path = installed / name
            self.assertTrue(path.is_dir())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
        self.assertEqual(adapter.validate_binding(value, context, artifact, self.root), self.workspace)

    def test_directory_runtime_paths_refuse_symlink_and_file(self):
        import shutil
        artifact, installed, value, context = self.directory_inputs("directory-php")
        cache = installed / "bootstrap/cache"
        shutil.rmtree(cache)
        cache.symlink_to(self.home, target_is_directory=True)
        with self.assertRaises(ValueError):
            adapter.provision_directory_runtime_paths(installed)
        cache.unlink()
        cache.write_text("not a directory")
        with self.assertRaisesRegex(ValueError, "not a directory"):
            adapter.provision_directory_runtime_paths(installed)

    def test_directory_php_probe_self_report_and_junit_fail_closed(self):
        import sys
        artifact, installed, value, context = self.directory_inputs("directory-php")
        probe = self.workspace / "directory-probe.py"
        runtime = self.home / "fake-php"
        runtime.write_text("#!" + sys.executable + "\n" +
            "import sys, os\nfrom pathlib import Path\n" +
            "p = Path(sys.argv[sys.argv.index('--log-junit') + 1])\n" +
            "p.write_text(os.environ.get('FAKE_JUNIT', '<testsuite><testcase name=\"package-version-self-report\"/></testsuite>'))\n")
        runtime.chmod(0o700)
        context["scenario_id"] = "package-version-self-report"
        env = {**os.environ, "IICP_PRE1_EXECUTION_CONTEXT": json.dumps(context),
               "IICP_PRE1_DIRECTORY_INSTALLED": str(installed), "IICP_PRE1_DIRECTORY_PHP": str(runtime)}
        for document, expected in [
            ('<testsuite><testcase name="package-version-self-report"/></testsuite>', 0),
            ('<testsuite><testcase name="package-version-self-report"><skipped/></testcase></testsuite>', 1),
            ('<testsuite><testcase name="wrong"/></testsuite>', 1),
            ('<testsuite><testcase name="package-version-self-report"/><testcase name="extra"/></testsuite>', 1),
        ]:
            (self.workspace / "directory-junit.xml").unlink(missing_ok=True)
            # The child environment is intentionally sanitized; vary the fake
            # runtime itself instead of relying on inherited environment values.
            runtime.write_text("#!" + sys.executable + "\nimport sys\nfrom pathlib import Path\n" +
                "Path(sys.argv[sys.argv.index('--log-junit') + 1]).write_text(" + repr(document) + ")\n")
            result = subprocess.run([sys.executable, "-I", "-S", str(probe), "package-version-self-report"],
                cwd=self.workspace, env=env, capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, expected, result.stderr)
            self.assertEqual("IICP_PRE1_DIRECTORY_ASSERTION_PASS" in result.stdout, expected == 0)

    def test_directory_archive_refuses_links_traversal_and_multiple_roots(self):
        for name, kind in [("../escape", "file"), ("iicp-directory-php-v1.10.94/link", "link"), ("other/root", "file")]:
            artifact = self.home / "unsafe.tar.gz"
            with tarfile.open(artifact, "w:gz") as archive:
                member = tarfile.TarInfo(name)
                if kind == "link":
                    member.type, member.linkname = tarfile.SYMTYPE, "/outside"
                archive.addfile(member)
            with self.subTest(name=name), self.assertRaises(ValueError):
                adapter.directory_archive_payload(artifact)

    def test_directory_unimplemented_case_and_modes_never_use_checkout_commands(self):
        artifact, installed, value, context = self.directory_inputs()
        manifest = {"source_version": "0.1.15", "artifacts": [{"name": artifact.name,
            "kind": "release-artifact", "target": "linux-aarch64", "sha256": adapter.file_digest(artifact)}]}
        artifact_root = self.home / "artifacts"
        (artifact_root / "directory-rust").mkdir(parents=True)
        import shutil
        shutil.copyfile(artifact, artifact_root / "directory-rust" / artifact.name)
        for mutation in [{"mode": "restricted"}, {"mode": "public"}, {"scenario_id": "backup-restore"}]:
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                adapter.directory_package_command(self.root, {**context, **mutation}, manifest, artifact_root, {}, value)
        argv, env, cwd, proof = adapter.directory_package_command(self.root, context, manifest, artifact_root, {}, value)
        self.assertEqual(cwd, self.workspace)
        self.assertNotIn("cargo", argv)
        self.assertNotIn(str(self.root), " ".join(argv))

    def test_directory_http_commands_use_bound_installed_binary_not_source_tests(self):
        import shutil
        artifact, installed, value, context = self.directory_inputs()
        artifact_root = self.home / "artifacts"
        (artifact_root / "directory-rust").mkdir(parents=True)
        shutil.copyfile(artifact, artifact_root / "directory-rust" / artifact.name)
        manifest = {"source_version": "0.1.15", "artifacts": [{"name": artifact.name,
            "kind": "release-artifact", "target": "linux-aarch64", "sha256": adapter.file_digest(artifact)}]}
        for scenario in sorted(adapter.DIRECTORY_RUST_HTTP_SCENARIOS):
            argv, env, cwd, proof = adapter.directory_package_command(self.root,
                {**context, "scenario_id": scenario}, manifest, artifact_root, {}, value)
            self.assertEqual(argv[-1], scenario)
            self.assertEqual(env["IICP_PRE1_DIRECTORY_INSTALLED"], str(installed))
            self.assertEqual(json.loads(env["IICP_PRE1_EXECUTION_CONTEXT"])["scenario_id"], scenario)
            self.assertNotIn("cargo", argv)
            self.assertEqual(cwd, self.workspace)

    def management_artifact(self):
        self.workspace = self.home / "run/management"
        self.workspace.mkdir(parents=True)
        (self.root / "qualification").mkdir(exist_ok=True)
        case = {"assertion": "test_fixture", "command": ["@cargo", "test", "--locked", "--test", "fixture", "test_fixture", "--", "--exact"]}
        (self.root / "qualification/pre1-cases.json").write_text(json.dumps({
            "schema": "iicp.pre1-component-case-map.v2", "component": "management",
            "support": case, "scenarios": {}}))
        (self.root / "tests/fixture.rs").write_text("#[test]\nfn test_fixture() { assert!(true); }\n")
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        artifact = self.home / "iicp-management-core-0.11.0.crate"
        files = {"Cargo.toml": b'[package]\nname = "iicp-management-core"\nversion = "0.11.0"\nautotests = false\n[lib]\npath = "src/lib.rs"\n',
                 "Cargo.lock": b'unchanged lock', "src/lib.rs": b'pub fn frozen() {}',
                 "contracts/test.json": b'{"frozen":true}'}
        with tarfile.open(artifact, "w:gz") as archive:
            for name, data in files.items():
                row = tarfile.TarInfo(artifact.stem + "/" + name)
                row.size = len(data)
                archive.addfile(row, io.BytesIO(data))
        return artifact

    def test_management_manifest_bridge_requires_actual_candidate_and_retains_legacy(self):
        source = '    let Some(path) = env::var_os("IICP_RELEASE_MANIFEST") else {\n        return;\n    };\n    let manifest: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();\nassert_eq!(manifest["authorizes_deployment"], false);'
        staged = adapter.management_assertions("tests/release_manifest.rs", source)
        self.assertIn('component["source_commit"]', staged)
        self.assertIn('component["source_version"]', staged)
        self.assertNotIn('component["version"]', staged)
        self.assertIn('expect("release manifest required")', staged)
        self.assertIn('assert_eq!(manifest["authorizes_deployment"], false)', staged)
        self.assertIn('"management_service", "directory_authority"', staged)
        with self.assertRaisesRegex(ValueError, "fixture shape differs"):
            adapter.management_assertions("tests/release_manifest.rs", "unexpected")

    def test_management_consumer_keeps_frozen_source_and_lock(self):
        artifact = self.management_artifact()
        value = adapter.stage_management_consumer(self.root, artifact, self.workspace)
        consumer = adapter.validate_management_consumer(self.root, artifact, self.workspace, value)
        self.assertFalse(value["qualification_credit"])
        self.assertEqual((self.workspace / "payload/src/lib.rs").read_bytes(), b'pub fn frozen() {}')
        self.assertFalse((consumer / "src").exists())
        self.assertEqual((consumer / "Cargo.lock").read_bytes(), b'unchanged lock')
        self.assertIn('path = "../payload/src/lib.rs"', (consumer / "Cargo.toml").read_text())
        self.assertIn('name = "fixture"', (consumer / "Cargo.toml").read_text())
        self.assertEqual((consumer / "tests/fixture.rs").read_bytes(), (self.root / "tests/fixture.rs").read_bytes())

    def test_management_rehashed_consumer_tamper_fails(self):
        artifact = self.management_artifact()
        value = adapter.stage_management_consumer(self.root, artifact, self.workspace)
        (self.workspace / "consumer/tests/fixture.rs").write_text("weakened assertion")
        value["consumer_sha256"] = adapter.digest(adapter.tree(self.workspace / "consumer"))
        with self.assertRaisesRegex(ValueError, "reviewed fixtures changed"):
            adapter.validate_management_consumer(self.root, artifact, self.workspace, value)

    def test_management_runtime_tamper_and_extra_files_fail(self):
        artifact = self.management_artifact()
        value = adapter.stage_management_consumer(self.root, artifact, self.workspace)
        (self.workspace / "payload/src/lib.rs").write_text("checkout fallback")
        value["payload_sha256"] = adapter.digest(adapter.tree(self.workspace / "payload"))
        with self.assertRaises(ValueError):
            adapter.validate_management_consumer(self.root, artifact, self.workspace, value)

    def test_management_untracked_or_unsafe_test_name_fails(self):
        artifact = self.management_artifact()
        mapping = self.root / "qualification/pre1-cases.json"
        value = json.loads(mapping.read_text())
        for name in ["../escape", "untracked"]:
            value["support"]["command"][4] = name
            mapping.write_text(json.dumps(value))
            if (self.workspace / "payload").exists():
                import shutil
                shutil.rmtree(self.workspace / "payload")
            with self.subTest(name=name), self.assertRaises(ValueError):
                adapter.stage_management_consumer(self.root, artifact, self.workspace)

    def test_management_staging_refuses_nonempty_or_outside_home(self):
        artifact = self.management_artifact()
        (self.workspace / "preserved").write_text("user work")
        with self.assertRaises(ValueError):
            adapter.stage_management_consumer(self.root, artifact, self.workspace)
        self.assertEqual((self.workspace / "preserved").read_text(), "user work")

    def test_management_binding_is_context_bound_and_offline(self):
        artifact = self.management_artifact()
        adapter.stage_management_consumer(self.root, artifact, self.workspace)
        (self.workspace / "vendor").mkdir()
        (self.workspace / "vendor/dependency").write_text("locked dependency")
        (self.workspace / ".cargo").mkdir()
        config = ('[source.crates-io]\nreplace-with = "vendored-sources"\n\n'
                  '[source.vendored-sources]\ndirectory = ' + json.dumps(str(self.workspace / "vendor")) + '\n')
        (self.workspace / ".cargo/config.toml").write_text(config)
        installed = self.workspace / "consumer"
        value = adapter.create_binding(self.root, self.workspace, installed, artifact,
            "management", "rust-1.98.0", "macos-arm64", self.bindings)
        context = {**self.context, "component": "management", "runtime": "rust-1.98.0"}
        self.assertEqual(adapter.validate_binding(value, context, artifact, self.root), installed)
        self.assertEqual(adapter.make_case_proof(value, context, "test_fixture", 0, "test-run")["schema"], "iicp.pre1-packaged-case-proof.v2")
        with self.assertRaises(ValueError):
            adapter.validate_binding(value, {**context, "target": "wrong"}, artifact, self.root)
        (self.workspace / ".cargo/config.toml").write_text(config + '\n[build]\nrustc-wrapper = "fake"\n')
        with self.assertRaisesRegex(ValueError, "offline Cargo configuration differs"):
            adapter.validate_binding(value, context, artifact, self.root)

    def test_lifecycle_child_preserves_installed_import_environment(self):
        source = '    env = {**os.environ, "PYTHONPATH": str(Path(__file__).parents[1] / "src")}'
        bridged = adapter.packaged_assertions("tests/test_service_lifecycle.py", source)
        self.assertEqual(bridged, "    env = dict(os.environ)")
        with self.assertRaisesRegex(ValueError, "fixture shape differs"):
            adapter.packaged_assertions("tests/test_service_lifecycle.py", "changed")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pre1-package-test-")
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()
        self.root = self.home / "checkout"
        self.workspace = self.home / "run/workspace"
        self.root.mkdir()
        self.workspace.mkdir(parents=True)
        (self.root / "tests").mkdir()
        (self.root / "tests/test_fixture.py").write_text("def test_fixture(): pass\n")
        (self.root / "src").mkdir()
        (self.root / "src/runtime.py").write_text("must not be staged")
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        self.installed = self.workspace / "site/iicp_client"
        self.installed.mkdir(parents=True)
        (self.installed / "__init__.py").write_text("__version__ = '0.7.110'\n")
        self.artifact = self.home / "sdk.whl"
        with zipfile.ZipFile(self.artifact, "w") as archive:
            archive.write(self.installed / "__init__.py", "iicp_client/__init__.py")
        self.bindings = {key: "sha256:" + "a" * 64 for key in adapter.BINDINGS}
        self.context = {"component": "client-python", "runtime": "cpython-3.13",
                        "target": "macos-arm64", **self.bindings}
        self.env = patch.dict(os.environ, {"HOME": str(self.home)})
        self.env.start()
        self.addCleanup(self.env.stop)

    def binding(self):
        return adapter.create_binding(self.root, self.workspace, self.installed,
            self.artifact, "client-python", "cpython-3.13", "macos-arm64", self.bindings)

    def validate(self, value):
        return adapter.validate_binding(value, self.context, self.artifact, self.root)

    def test_exact_installed_payload_and_no_source_staging(self):
        value = self.binding()
        self.assertEqual(self.validate(value), self.workspace)
        self.assertFalse((self.workspace / "src").exists())
        self.assertFalse(value["qualification_credit"])

    def test_payload_missing_extra_and_modified_fail(self):
        self.binding()
        file = self.installed / "__init__.py"
        original = file.read_bytes()
        for action in (lambda: file.unlink(), lambda: file.write_text("modified")):
            action()
            with self.assertRaises(ValueError):
                adapter.installed_payload(self.artifact, self.installed, "client-python")
            file.write_bytes(original)
        (self.installed / "extra.py").write_text("extra")
        with self.assertRaises(ValueError):
            adapter.installed_payload(self.artifact, self.installed, "client-python")

    def test_each_immutable_dimension_fails_even_when_rehashed(self):
        value = self.binding()
        for key in ("component", "target", "runtime"):
            changed = copy.deepcopy(value)
            changed[key] = "wrong"
            changed["binding_sha256"] = None
            changed["binding_sha256"] = adapter.digest(changed)
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.validate(changed)
        for key in adapter.BINDINGS:
            changed = copy.deepcopy(value)
            changed["bindings"][key] = "sha256:" + "b" * 64
            changed["binding_sha256"] = None
            changed["binding_sha256"] = adapter.digest(changed)
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.validate(changed)

    def test_fixture_tamper_and_checkout_source_fallback_fail(self):
        value = self.binding()
        (self.workspace / "tests/test_fixture.py").write_text("tamper")
        with self.assertRaisesRegex(ValueError, "fixtures changed"):
            self.validate(value)
        (self.workspace / "src").mkdir()
        with self.assertRaisesRegex(ValueError, "runtime source"):
            self.validate(value)

    def test_staged_assertions_must_match_reviewed_mapping(self):
        adapter.stage(self.root, self.workspace, "client-python")
        (self.workspace / "tests/test_fixture.py").write_text("tamper")
        with self.assertRaisesRegex(ValueError, "reviewed source mapping"):
            self.binding()

    def test_symlinks_and_unsafe_ancestors_fail(self):
        value = self.binding()
        (self.installed / "link.py").symlink_to(self.root / "src/runtime.py")
        with self.assertRaises(ValueError):
            self.validate(value)
        alias = self.home / "alias"
        alias.symlink_to(self.workspace, target_is_directory=True)
        with self.assertRaises(ValueError):
            adapter.safe_path(alias / "tests")

    def test_dependency_tamper_fails(self):
        value = self.binding()
        (self.installed.parent / "pytest.py").write_text("injected")
        with self.assertRaisesRegex(ValueError, "dependencies changed"):
            self.validate(value)

    def test_rehashed_fixture_and_binding_cannot_replace_reviewed_assertions(self):
        value = self.binding()
        (self.workspace / "tests/test_fixture.py").write_text("def test_fixture(): assert True\n")
        value["fixtures_sha256"] = adapter.digest(adapter.fixture_tree(self.workspace))
        value["binding_sha256"] = None
        value["binding_sha256"] = adapter.digest(value)
        with self.assertRaisesRegex(ValueError, "reviewed source mapping"):
            self.validate(value)

    def test_cli_adapter_decodes_file_urls(self):
        fixture = 'const cli = readFileSync("src/cli.ts");\n  assert.match(cli, /version/);\n'
        staged = adapter.packaged_assertions("tests/pre1_release_boundaries.test.ts", fixture)
        self.assertIn('import { fileURLToPath } from "node:url"', staged)
        self.assertIn("fileURLToPath(new URL(", staged)
        self.assertNotIn(".pathname", staged)

    def test_cli_subprocess_with_spaces_and_unicode_path(self):
        import shutil
        node = shutil.which("node")
        if not node:
            self.fail("Node is required for the CLI portability regression")
        directory = self.home / "IICP space ü"
        directory.mkdir()
        cli = directory / "cli.mjs"
        cli.write_text('console.log("iicp-node 0.7.110");')
        script = '''import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
const result=spawnSync(process.execPath,[fileURLToPath(new URL(process.argv[1])),'--version'],{encoding:'utf8'});
process.stdout.write(result.stdout); process.exit(result.status ?? 1);'''
        result = subprocess.run([node, "--input-type=module", "-e", script, cli.as_uri()],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "iicp-node 0.7.110")

    def test_case_proof_is_portable_and_bound_to_result(self):
        value = adapter.make_case_proof(self.binding(), self.context, "test_fixture", 0, "pre1-test")
        adapter.validate_case_proof(value, self.context, 0, "pre1-test")
        self.assertNotIn(str(self.home), json.dumps(value))
        for field, replacement in (("run_id", "different"), ("exit_code", 1),
                                    ("context", {**self.context, "target": "windows-x86_64"})):
            changed = copy.deepcopy(value)
            changed[field] = replacement
            changed["proof_sha256"] = None
            changed["proof_sha256"] = adapter.digest(changed)
            with self.subTest(field=field), self.assertRaises(ValueError):
                adapter.validate_case_proof(changed, self.context, 0, "pre1-test")

    def test_case_proof_atomic_non_overwriting_and_safe(self):
        proof = adapter.make_case_proof(self.binding(), self.context, "test_fixture", 0, "pre1-test")
        output = self.home / "proof.json"
        with patch.dict(os.environ, {"IICP_PRE1_CASE_PROOF_OUTPUT": str(output)}):
            adapter.write_case_proof(proof)
            self.assertEqual(json.loads(output.read_text()), proof)
            with self.assertRaises(ValueError):
                adapter.write_case_proof(proof)
        self.assertEqual(list(self.home.glob(".case-proof-*")), [])
        link = self.home / "linked-proof"
        link.symlink_to(output)
        for unsafe in (link, self.home.parent / "outside-proof.json"):
            with patch.dict(os.environ, {"IICP_PRE1_CASE_PROOF_OUTPUT": str(unsafe)}), self.assertRaises(ValueError):
                adapter.write_case_proof(proof)

    def test_case_proof_refuses_unknown_fields_and_tampered_summary(self):
        value = adapter.make_case_proof(self.binding(), self.context, "test_fixture", 0, "pre1-test")
        for change in (lambda v: v.update(output="secret"),
                       lambda v: v["execution"].update(installed_package=str(self.installed)),
                       lambda v: v["execution"]["bindings"].update(runtime_map_sha256="wrong")):
            changed = copy.deepcopy(value)
            change(changed)
            changed["proof_sha256"] = None
            changed["proof_sha256"] = adapter.digest(changed)
            with self.assertRaises(ValueError):
                adapter.validate_case_proof(changed, self.context, 0, "pre1-test")

    def test_no_binding_cannot_run_source_case(self):
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(KeyError):
            adapter.package_command(self.root, self.context, {}, self.home, [], {})

    def test_crypto_bridge_uses_runtime_verifier_not_test_local_policy(self):
        text = "def _decision(vector: dict, keys: dict, signature_valid: bool):\n    return 'fake'\n\ndef _assert_fixture_decision(): pass\n"
        bridged = adapter.packaged_assertions("tests/test_dispatch_ticket_trust_crypto.py", text)
        self.assertIn("verify_dispatch_ticket_v2(", bridged)
        self.assertNotIn("return 'fake'", bridged)
        text = "function decision(vector: any, keys: Map<string, any>, signatureValid: boolean): string { return 'fake'; }\nfunction assertFixtureDecision(): void {}"
        bridged = adapter.packaged_assertions("tests/dispatch_ticket_trust_crypto.test.ts", text)
        self.assertIn("verifyDispatchTicketV2(", bridged)
        self.assertNotIn("return 'fake'", bridged)

    def test_cli_fixture_requires_reviewed_shape(self):
        with self.assertRaisesRegex(ValueError, "fixture shape differs"):
            adapter.packaged_assertions("tests/pre1_release_boundaries.test.ts", "changed fixture")

    def test_python_command_uses_only_installed_path_and_guard(self):
        value = self.binding()
        path = self.home / "binding.json"
        path.write_text(json.dumps(value))
        component = {"artifacts": [{"kind": "wheel", "name": "sdk.whl"}]}
        artifact_root = self.home / "artifacts"
        (artifact_root / "client-python").mkdir(parents=True)
        (artifact_root / "client-python/sdk.whl").write_bytes(self.artifact.read_bytes())
        with patch.dict(os.environ, {"IICP_PRE1_PACKAGE_EXECUTION_BINDING": str(path),
                "IICP_PRE1_PACKAGE_EXECUTION_SHA256": value["binding_sha256"]}):
            argv, env, cwd, _ = adapter.package_command(self.root, self.context,
                component, artifact_root, ["python", "-m", "pytest", "-q", "tests/test_fixture.py::test_fixture"], {})
        self.assertEqual(argv[3:5], ["-p", "pre1_origin_guard"])
        self.assertEqual(cwd, self.workspace)
        self.assertNotIn(str(self.root), env["PYTHONPATH"])

    def test_typescript_literals_and_child_worker_bind_to_dist(self):
        text = 'import x from "../src/client.js"; require("../src/trust"); import y from "./src/service_lifecycle.ts";'
        rewritten = adapter.rewrite_typescript(text)
        self.assertNotIn("src/", rewritten)
        self.assertIn('"./node_modules/@iicp/client/dist/service_lifecycle.js"', rewritten)
        with self.assertRaises(ValueError):
            adapter.rewrite_typescript('import "../src/../../escape.js"')

    def test_typescript_archive_and_missing_compiled_file(self):
        artifact = self.home / "sdk.tgz"
        installed = self.workspace / "node_modules/@iicp/client"
        (installed / "dist").mkdir(parents=True)
        (installed / "dist/client.js").write_bytes(b"compiled")
        with tarfile.open(artifact, "w:gz") as archive:
            info = tarfile.TarInfo("package/dist/client.js")
            info.size = len(b"compiled")
            archive.addfile(info, io.BytesIO(b"compiled"))
        adapter.installed_payload(artifact, installed, "client-typescript")
        (installed / "dist/client.js").unlink()
        with self.assertRaises(ValueError):
            adapter.installed_payload(artifact, installed, "client-typescript")



class RustPackageExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pre1-rust-package-test-")
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()
        self.root = self.home / "checkout"
        self.workspace = self.home / "workspace"
        self.root.mkdir()
        self.workspace.mkdir()
        self.mapping = b'{"support":{},"scenarios":{}}'
        (self.root / "qualification").mkdir()
        (self.root / "qualification/pre1-cases.json").write_bytes(self.mapping)
        self.files = {"Cargo.toml": b'[package]\nname="iicp-client"\nversion="0.7.110"\n',
            "Cargo.lock": b"# locked\n", "src/lib.rs": b"pub fn run() {}\n",
            "tests/exact.rs": b"#[test] fn exact() {}\n",
            "qualification/pre1-cases.json": self.mapping}
        self.artifact = self.home / "iicp-client-0.7.110.crate"
        self.vendor = self.home / "vendor.tar.gz"
        self.archive(self.artifact, {"iicp-client-0.7.110/" + k: v for k,v in self.files.items()})
        self.archive(self.vendor, {**{"source/"+k:v for k,v in self.files.items()},
            "vendor/dependency/src/lib.rs": b"pub fn dep() {}\n",
            ".cargo/config.toml": b'[source.crates-io]\nreplace-with="vendored-sources"\n'})
        self.env = patch.dict(os.environ, {"HOME": str(self.home)})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.installed = adapter.extract_rust_packages(self.artifact, self.vendor, self.workspace)
        self.bindings = {key: "sha256:"+"a"*64 for key in adapter.BINDINGS}
        self.context = {"component":"client-rust", "runtime":"msrv-1.86", "target":"macos-arm64", **self.bindings}

    def archive(self, path, files):
        with tarfile.open(path, "w:gz") as archive:
            for name,data in files.items():
                row=tarfile.TarInfo(name); row.size=len(data)
                archive.addfile(row, io.BytesIO(data))

    def binding(self):
        return adapter.create_binding(self.root, self.workspace, self.installed, self.artifact,
            "client-rust", "msrv-1.86", "macos-arm64", self.bindings, self.vendor)

    def validate(self, value):
        return adapter.validate_binding(value, self.context, self.artifact, self.root, self.vendor)

    def test_frozen_crate_and_vendor_source_are_identical(self):
        value=self.binding()
        self.assertEqual(self.validate(value), self.installed)
        self.assertFalse(value["qualification_credit"])
        proof=adapter.make_case_proof(value,self.context,"exact",0,"rust-test")
        adapter.validate_case_proof(proof,self.context,0,"rust-test")
        self.assertNotIn(str(self.home),json.dumps(proof))

    def test_modified_missing_extra_source_and_vendor_fail(self):
        value=self.binding()
        for file in (self.installed/"src/lib.rs",self.workspace/"vendor/dependency/src/lib.rs",self.workspace/".cargo/config.toml"):
            original=file.read_bytes(); file.write_bytes(b"tamper")
            with self.assertRaises(ValueError): self.validate(value)
            file.unlink()
            with self.assertRaises(ValueError): self.validate(value)
            file.write_bytes(original)
        (self.installed/"extra.rs").write_text("extra")
        with self.assertRaises(ValueError): self.validate(value)

    def test_forged_binding_cannot_replace_packaged_assertions(self):
        value=self.binding(); (self.installed/"tests/exact.rs").write_text("#[test] fn exact() {} // forged")
        value["installed_payload_sha256"]=adapter.digest(adapter.tree(self.installed))
        value["binding_sha256"]=None; value["binding_sha256"]=adapter.digest(value)
        with self.assertRaises(ValueError):self.validate(value)

    def test_all_semantic_dimensions_fail_even_after_rehash(self):
        value=self.binding()
        for key in ("component","runtime","target"):
            changed=copy.deepcopy(value); changed[key]="wrong"
            changed["binding_sha256"]=None; changed["binding_sha256"]=adapter.digest(changed)
            with self.assertRaises(ValueError):self.validate(changed)
        for key in adapter.BINDINGS:
            changed=copy.deepcopy(value); changed["bindings"][key]="sha256:"+"b"*64
            changed["binding_sha256"]=None; changed["binding_sha256"]=adapter.digest(changed)
            with self.assertRaises(ValueError):self.validate(changed)

    def test_vendor_artifact_must_be_bound_and_source_must_match(self):
        with self.assertRaises(ValueError):adapter.validate_binding(self.binding(),self.context,self.artifact,self.root)
        self.archive(self.vendor,{"source/forged.rs":b"forged"})
        with self.assertRaisesRegex(ValueError,"vendor source differs"):self.binding()

    def test_reviewed_mapping_and_symlink_checks(self):
        (self.root/"qualification/pre1-cases.json").write_text("changed")
        with self.assertRaisesRegex(ValueError,"mapping differs"):self.binding()
        (self.root/"qualification/pre1-cases.json").write_bytes(self.mapping)
        (self.workspace/"vendor/link").symlink_to(self.root)
        with self.assertRaises(ValueError):self.binding()

    def test_archive_rejects_traversal_links_and_duplicates(self):
        for name in ("../escape", "/absolute", "vendor/../escape", "vendor/a:b", "vendor/evil\\file"):
            self.archive(self.vendor,{name:b"unsafe"})
            with self.assertRaises(ValueError):adapter.rust_archive_files(self.vendor,"vendor/")
        for kind in (tarfile.SYMTYPE,tarfile.LNKTYPE,tarfile.FIFOTYPE):
            with tarfile.open(self.vendor,"w:gz") as archive:
                row=tarfile.TarInfo("vendor/link");row.type=kind;row.linkname="escape";archive.addfile(row)
            with self.assertRaises(ValueError):adapter.rust_archive_files(self.vendor,"vendor/")
        with tarfile.open(self.vendor,"w:gz") as archive:
            for _ in range(2):
                row=tarfile.TarInfo("vendor/same");row.size=1;archive.addfile(row,io.BytesIO(b"x"))
        with self.assertRaises(ValueError):adapter.rust_archive_files(self.vendor,"vendor/")

    def test_extraction_refuses_nonempty_workspace_and_has_restrictive_permissions(self):
        with self.assertRaisesRegex(ValueError,"empty"):adapter.extract_rust_packages(self.artifact,self.vendor,self.workspace)
        self.assertEqual((self.installed/"src/lib.rs").stat().st_mode & 0o777,0o600)

    def test_rust_archive_bytes_are_bounded_before_allocation(self):
        row=tarfile.TarInfo("vendor/large");row.size=1024*1024*1024+1
        from unittest.mock import MagicMock
        opened=MagicMock();opened.__enter__.return_value.__iter__.return_value=iter([row])
        with patch.object(adapter.tarfile,"open",return_value=opened):
            with self.assertRaisesRegex(ValueError,"bounded"):adapter.rust_archive_files(self.vendor,"vendor/")

if __name__ == "__main__":
    unittest.main()
