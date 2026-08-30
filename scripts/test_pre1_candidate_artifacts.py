from __future__ import annotations

import json
import subprocess
import sys
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/build_pre1_candidate_artifacts.py"
DOCKERFILE = ROOT / "Dockerfile"


class Pre1CandidateArtifactBuilderTest(unittest.TestCase):
    def test_description_names_primary_and_target_artifacts(self) -> None:
        value = json.loads(
            subprocess.check_output([sys.executable, str(SCRIPT), "--describe"], text=True)
        )
        self.assertEqual(value["component"], "directory-rust")
        self.assertEqual(value["target_artifact"], "release-artifact")
        self.assertEqual(value["portable_artifacts_on"], "linux-x86_64")
        self.assertTrue(value["non_authorizing"])

    def test_fault_injection_fixture_is_not_built_by_the_default_gate(self) -> None:
        manifest = tomllib.loads((ROOT / "Cargo.toml").read_text())
        fixture = next(
            row
            for row in manifest["example"]
            if row["name"] == "systemd_watchdog_fixture"
        )
        self.assertEqual(
            fixture["required-features"],
            ["systemd-notify", "runtime-health-fault-injection"],
        )
        self.assertIn("COPY examples ./examples", DOCKERFILE.read_text().splitlines())


if __name__ == "__main__":
    unittest.main()
