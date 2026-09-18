"""Regression controls for the known rustls TLS handshake advisory."""
import sys
import sys
import tomllib
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_dependency_policy as policy

class RustlsPolicyTests(unittest.TestCase):
    def violations(self, version):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Cargo.lock"
            path.write_text('[[package]]\nname = "rustls"\nversion = "' + version + '"\nsource = "' + policy.ALLOWED_REGISTRY + '"\n')
            return policy.violations(path)

    def test_affected_stable_range_is_denied(self):
        for patch in range(13, 45):
            with self.subTest(patch=patch):
                self.assertEqual(self.violations(f"0.23.{patch}"), [f"denied package rustls 0.23.{patch}"])

    def test_unaffected_boundary_and_patched_release_are_not_denied(self):
        for version in ["0.23.12", "0.23.45"]:
            with self.subTest(version=version):
                self.assertEqual(self.violations(version), [])

    def test_current_lock_passes(self):
        self.assertEqual(policy.violations(Path(__file__).resolve().parents[1] / "Cargo.lock"), [])

    def test_downstream_dependency_has_patched_security_floor(self):
        config = tomllib.loads((Path(__file__).resolve().parents[1] / "Cargo.toml").read_text())
        self.assertEqual(config["dependencies"]["rustls"], {"version": "0.23.45", "default-features": False})

if __name__ == "__main__":
    unittest.main()
