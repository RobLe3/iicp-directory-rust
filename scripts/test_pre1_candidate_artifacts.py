from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/build_pre1_candidate_artifacts.py"


class Pre1CandidateArtifactBuilderTest(unittest.TestCase):
    def test_description_names_primary_and_target_artifacts(self) -> None:
        value = json.loads(
            subprocess.check_output([sys.executable, str(SCRIPT), "--describe"], text=True)
        )
        self.assertEqual(value["component"], "directory-rust")
        self.assertEqual(value["target_artifact"], "release-artifact")
        self.assertEqual(value["portable_artifacts_on"], "linux-x86_64")
        self.assertTrue(value["non_authorizing"])


if __name__ == "__main__":
    unittest.main()
