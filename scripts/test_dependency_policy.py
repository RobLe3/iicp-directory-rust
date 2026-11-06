"""Regression controls for source dependency security floors."""
import sys
import sys
import tomllib
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_dependency_policy as policy
from check_dependency_policy import violations

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

    def test_newly_affected_prior_boundaries_are_denied(self):
        for version in ["0.23.12", "0.23.45"]:
            with self.subTest(version=version):
                self.assertEqual(self.violations(version), [f"denied package rustls {version}"])

    def test_current_lock_passes(self):
        self.assertEqual(policy.violations(Path(__file__).resolve().parents[1] / "Cargo.lock"), [])

    def test_downstream_dependency_has_patched_security_floor(self):
        config = tomllib.loads((Path(__file__).resolve().parents[1] / "Cargo.toml").read_text())
        self.assertEqual(config["dependencies"]["rustls"], {"version": "0.23.46", "default-features": False})


class CurrentDependencySecurityTests(unittest.TestCase):
    def check_pair(self, name, version, source="registry+https://github.com/rust-lang/crates.io-index"):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Cargo.lock"
            path.write_text(f'[[package]]\nname="{name}"\nversion="{version}"\nsource="{source}"\n')
            return violations(path)

    def test_current_affected_series_are_denied(self):
        series = [("rustls", "0.23", 46), ("rustls-webpki", "0.103", 16),
                  ("webpki-roots", "1.0", 10), ("quinn-proto", "0.11", 18),
                  ("tokio", "1.51", 6), ("tokio", "1.52", 4), ("tokio", "1.53", 3)]
        for name, prefix, patches in series:
            for patch in range(patches):
                version = f"{prefix}.{patch}"
                with self.subTest(name=name, version=version):
                    self.assertEqual(self.check_pair(name, version), [f"denied package {name} {version}"])

    def test_patched_and_unaffected_controls_remain_usable(self):
        for name, version in [("rustls", "0.23.46"), ("rustls-webpki", "0.103.16"),
                              ("webpki-roots", "1.0.10"), ("webpki-roots", "0.26.11"),
                              ("quinn-proto", "0.11.18"), ("tokio", "1.51.6"),
                              ("tokio", "1.53.3"), ("safe", "1.0.0")]:
            with self.subTest(name=name, version=version):
                self.assertEqual(self.check_pair(name, version), [])

    def test_registry_is_not_widened_by_patched_version(self):
        self.assertEqual(self.check_pair("rustls", "0.23.46", "git+https://example.invalid/repo"),
                         ["unapproved source for rustls 0.23.46: git+https://example.invalid/repo"])

    def test_active_tls_floors_do_not_enable_defaults(self):
        config = tomllib.loads((Path(__file__).resolve().parents[1] / "Cargo.toml").read_text())
        deps = config["dependencies"]
        for name, version in [("rustls", "0.23.46"), ("rustls-webpki", "0.103.16"),
                              ("webpki-roots", "1.0.10")]:
            self.assertEqual(deps[name], {"version": version, "default-features": False})
        self.assertEqual(deps["tokio"]["version"], "1.53.3")
        if config["package"]["name"] == "iicp-management-core":
            self.assertEqual(deps["tokio"], {"version": "1.53.3", "default-features": False})
            self.assertEqual(config["dev-dependencies"]["tokio"]["version"], "1.53.3")

    def test_current_lock_contains_no_explicit_denied_pairs(self):
        self.assertEqual(violations(Path(__file__).resolve().parents[1] / "Cargo.lock"), [])

if __name__ == "__main__":
    unittest.main()
