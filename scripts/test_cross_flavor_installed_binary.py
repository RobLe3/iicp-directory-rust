"""Installed cross-flavor diagnostics must validate before touching a database."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parent / "run_cross_flavor_membership_compat.sh"


class InstalledCrossFlavorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.binary = self.root / "directory"
        self.binary.write_text('#!/bin/sh\nif [ "$1" = "--version" ]; then echo "iicp-directory-rs 0.1.16"; exit 0; fi\n'
            'echo "${1:-startup}" >> "' + str(self.root / 'calls') + '"\n'
            'if [ "$IICP_REPLICA_MODE" = true ]; then echo "restricted trust-domain federation is not implemented; replica mode cannot be combined with restricted-domain mode"; exit 1; fi\n'
            'if [ "$1" = trust-domain-membership-issue ]; then echo synthetic; fi\n')
        self.binary.chmod(0o700)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name, source in {
            "mysql": '#!/bin/sh\ncase "$*" in *COUNT*) echo 1;; esac\n',
            "php": '#!/bin/sh\nexit 0\n',
            "cargo": '#!/bin/sh\nexit 99\n',
            "timeout": '#!/bin/sh\nshift\nexec "$@"\n',
        }.items():
            path = self.bin / name
            path.write_text(source)
            path.chmod(0o700)
        (self.root / "artisan").write_text("synthetic")
        self.env = {"PATH": str(self.bin) + ":" + os.environ["PATH"],
            "IICP_CROSS_FLAVOR_RUST_BINARY": str(self.binary),
            "IICP_CROSS_FLAVOR_RUST_SHA256": "sha256:" + hashlib.sha256(self.binary.read_bytes()).hexdigest(),
            "IICP_CROSS_FLAVOR_RUST_VERSION": "0.1.16", "PHP_DIRECTORY_ROOT": str(self.root),
            "IICP_CROSS_FLAVOR_DATABASE_URL": "mysql://synthetic@127.0.0.1/iicp_cross_test",
            "IICP_CROSS_FLAVOR_DB_NAME": "iicp_cross_test"}

    def run_script(self):
        return subprocess.run(["/bin/bash", str(SCRIPT)], env=self.env, capture_output=True, timeout=15)

    def test_installed_path_never_invokes_cargo(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual((self.root / "calls").read_text().splitlines(),
            ["db-maintenance-status", "trust-domain-membership-issue", "trust-domain-membership-revoke", "startup"])

    def test_cleanup_failure_cannot_be_success(self):
        mysql = self.bin / "mysql"
        counter = self.root / "drops"
        mysql.write_text('#!/bin/sh\ncase "$*" in *DROP*)\n'
            ' if [ -f "' + str(counter) + '" ]; then exit 7; fi\n'
            ' touch "' + str(counter) + '";;\n *COUNT*) echo 1;; esac\n')
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"cleanup failed", result.stderr)
        self.assertNotIn(b"cleanup verified", result.stdout)
        self.assertTrue((self.root / "calls").exists())

    def test_initial_cleanup_failure_prevents_workload(self):
        (self.bin / "mysql").write_text('#!/bin/sh\nexit 7\n')
        result = self.run_script()
        self.assertEqual(result.returncode, 7)
        self.assertIn(b"cleanup failed", result.stderr)
        self.assertFalse((self.root / "calls").exists())

    def test_workload_failure_is_preserved_after_cleanup(self):
        (self.bin / "php").write_text('#!/bin/sh\nexit 13\n')
        result = self.run_script()
        self.assertEqual(result.returncode, 13)
        self.assertIn(b"cleanup verified", result.stdout)
        self.assertNotIn(b"membership checks passed", result.stdout)

    def test_database_name_cannot_inject_sql(self):
        for name in ("iicp_cross_test; DROP DATABASE unrelated", "iicp_cross_", "production",
                     "iicp_cross_" + "x" * 49, "iicp_cross_test-name"):
            self.env["IICP_CROSS_FLAVOR_DB_NAME"] = name
            with self.subTest(name=name):
                result = self.run_script()
                self.assertEqual(result.returncode, 2)
                self.assertIn(b"unsafe or non-disposable", result.stderr)
                self.assertFalse((self.root / "calls").exists())

    def test_digest_mismatch_fails_before_database_work(self):
        self.env["IICP_CROSS_FLAVOR_RUST_SHA256"] = "sha256:" + "0" * 64
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"digest differs", result.stderr)
        self.assertFalse((self.root / "calls").exists())

    def test_wrong_version_fails_before_database_work(self):
        self.env["IICP_CROSS_FLAVOR_RUST_VERSION"] = "0.1.15"
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"version differs", result.stderr)

    def test_symlink_is_not_an_installed_artifact(self):
        link = self.root / "link"
        link.symlink_to(self.binary)
        self.env["IICP_CROSS_FLAVOR_RUST_BINARY"] = str(link)
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"binary boundary", result.stderr)


if __name__ == "__main__":
    unittest.main()
