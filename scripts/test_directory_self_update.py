#!/usr/bin/env python3
import contextlib
import hashlib
import http.server
import json
import os
from pathlib import Path
import socketserver
import subprocess
import tarfile
import io
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/directory_self_update.sh"


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass


@contextlib.contextmanager
def fixture_server(files):
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        for name, content in files.items():
            (root / name).write_bytes(content)
        handler = lambda *args, **kwargs: QuietHandler(*args, directory=root, **kwargs)
        with socketserver.TCPServer(("127.0.0.1", 0), handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                yield f"http://127.0.0.1:{server.server_address[1]}", root
            finally:
                server.shutdown()
                thread.join()


def run_staged(base, env_file):
    env = os.environ | {
        "IICP_DIRECTORY_CRATES_API": f"{base}/api.json",
        "IICP_DIRECTORY_CRATE_URL": f"{base}/crate",
        "IICP_DIRECTORY_RELEASE_MANIFEST_URL": f"{base}/manifest.json",
    }
    return subprocess.run(
        [str(SCRIPT), "--staged", "--env-file", str(env_file), "--dry-run"],
        text=True,
        capture_output=True,
        env=env,
    )


class UpdaterContract(unittest.TestCase):
    COMMIT = "a" * 40

    def crate_bytes(self):
        buffer = io.BytesIO()
        payload = json.dumps({"git": {"sha1": self.COMMIT}, "path_in_vcs": ""}).encode()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            info = tarfile.TarInfo("iicp-directory-rs-0.1.11/.cargo_vcs_info.json")
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        return buffer.getvalue()

    def files(self, *, api_sha=None, manifest_sha=None):
        crate = self.crate_bytes()
        actual = hashlib.sha256(crate).hexdigest()
        api_sha = api_sha or actual
        manifest_sha = manifest_sha or actual
        return {
            "crate": crate,
            "api.json": json.dumps(
                {"versions": [{"num": "0.1.11", "checksum": api_sha, "yanked": False}]}
            ).encode(),
            "manifest.json": json.dumps(
                {"version": "0.1.11", "crate_sha256": manifest_sha,
                 "commit": self.COMMIT, "status": "operator_preview",
                 "production_authority": False, "genesis_cutover_authorized": False}
            ).encode(),
        }

    def test_exact_checksum_binding_passes_before_any_install(self):
        with fixture_server(self.files()) as (base, root):
            env_file = root / "directory.env"
            env_file.write_text("")
            result = run_staged(base, env_file)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("would install, verify schema, switch, restart and health-check", result.stdout)

    def test_registry_checksum_mismatch_fails_closed(self):
        with fixture_server(self.files(api_sha="0" * 64)) as (base, root):
            env_file = root / "directory.env"
            env_file.write_text("")
            result = run_staged(base, env_file)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("binding failed", result.stderr)

    def test_release_manifest_mismatch_fails_closed(self):
        with fixture_server(self.files(manifest_sha="f" * 64)) as (base, root):
            env_file = root / "directory.env"
            env_file.write_text("")
            result = run_staged(base, env_file)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("binding failed", result.stderr)

    def test_source_commit_mismatch_fails_closed(self):
        files = self.files()
        manifest = json.loads(files["manifest.json"])
        manifest["commit"] = "b" * 40
        files["manifest.json"] = json.dumps(manifest).encode()
        with fixture_server(files) as (base, root):
            env_file = root / "directory.env"
            env_file.write_text("")
            result = run_staged(base, env_file)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("source-commit/authority binding failed", result.stderr)

    def test_schema_check_precedes_symlink_and_restart(self):
        source = SCRIPT.read_text()
        self.assertLess(source.index('"$candidate" db-maintenance-status'), source.index("ln -sfn"))
        self.assertLess(source.index('"$candidate" db-maintenance-status'), source.index("systemctl --user restart"))

    def test_optional_timer_invokes_the_same_guarded_staged_path(self):
        with tempfile.TemporaryDirectory() as raw:
            env_file = Path(raw) / "directory.env"
            env_file.write_text("")
            result = subprocess.run(
                [str(SCRIPT), "--install-timer", "--env-file", str(env_file), "--dry-run"],
                text=True,
                capture_output=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--staged --env-file", result.stdout)
        self.assertIn("OnCalendar=daily", result.stdout)

    def test_failed_health_restores_baseline_then_valid_candidate_advances(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            package_dir = root / "iicp-directory-rs-0.1.11"
            package_dir.mkdir()
            (package_dir / "Cargo.toml").write_text("[package]\nname='fixture'\nversion='0.1.11'\n")
            (package_dir / ".cargo_vcs_info.json").write_text(
                json.dumps({"git": {"sha1": self.COMMIT}, "path_in_vcs": ""})
            )
            crate = root / "crate"
            with tarfile.open(crate, "w:gz") as archive:
                archive.add(package_dir, arcname=package_dir.name)
            sha = hashlib.sha256(crate.read_bytes()).hexdigest()
            files = {
                "crate": crate.read_bytes(),
                "api.json": json.dumps(
                    {"versions": [{"num": "0.1.11", "checksum": sha, "yanked": False}]}
                ).encode(),
                "manifest.json": json.dumps(
                    {"version": "0.1.11", "crate_sha256": sha,
                     "commit": self.COMMIT, "status": "operator_preview",
                     "production_authority": False, "genesis_cutover_authorized": False}
                ).encode(),
                "health": b'{"ok":true,"version":"v0.1.10-rs"}',
            }
            with fixture_server(files) as (base, served):
                tools = root / "tools"
                tools.mkdir()
                cargo = tools / "cargo"
                cargo.write_text(
                    "#!/bin/sh\n"
                    "while [ $# -gt 0 ]; do [ \"$1\" = --root ] && { shift; root=$1; }; shift; done\n"
                    "mkdir -p \"$root/bin\"\n"
                    "cat > \"$root/bin/iicp-directory-rs\" <<'EOF'\n"
                    "#!/bin/sh\n"
                    "[ \"${1:-}\" = --version ] && { echo 'iicp-directory-rs 0.1.11'; exit 0; }\n"
                    "[ \"${1:-}\" = db-maintenance-status ] && { echo '{}'; exit 0; }\n"
                    "exit 1\n"
                    "EOF\nchmod +x \"$root/bin/iicp-directory-rs\"\n"
                )
                systemctl = tools / "systemctl"
                systemctl.write_text("#!/bin/sh\nexit 0\n")
                cargo.chmod(0o755)
                systemctl.chmod(0o755)
                baseline = root / "baseline"
                baseline.write_text("#!/bin/sh\necho 'iicp-directory-rs 0.1.10'\n")
                baseline.chmod(0o755)
                stable = root / "bin/iicp-directory-rs"
                stable.parent.mkdir()
                stable.symlink_to(baseline)
                env_file = root / "directory.env"
                env_file.write_text("")
                env = os.environ | {
                    "PATH": f"{tools}:{os.environ['PATH']}",
                    "IICP_DIRECTORY_CRATES_API": f"{base}/api.json",
                    "IICP_DIRECTORY_CRATE_URL": f"{base}/crate",
                    "IICP_DIRECTORY_RELEASE_MANIFEST_URL": f"{base}/manifest.json",
                    "IICP_DIRECTORY_RELEASE_ROOT": str(root / "releases"),
                    "IICP_DIRECTORY_STABLE_BIN": str(stable),
                    "IICP_DIRECTORY_HEALTH_URL": f"{base}/health",
                }
                args = [str(SCRIPT), "--staged", "--env-file", str(env_file)]
                failed = subprocess.run(args, env=env, text=True, capture_output=True)
                self.assertNotEqual(failed.returncode, 0)
                self.assertEqual(stable.resolve(), baseline.resolve())
                (served / "health").write_text('{"ok":true,"version":"v0.1.11-rs"}')
                passed = subprocess.run(args, env=env, text=True, capture_output=True)
                self.assertEqual(passed.returncode, 0, passed.stderr)
                self.assertIn("0.1.11", str(stable.resolve()))


if __name__ == "__main__":
    unittest.main()
