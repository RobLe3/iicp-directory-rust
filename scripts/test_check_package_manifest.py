#!/usr/bin/env python3
from __future__ import annotations

import unittest

from check_package_manifest import REQUIRED, violations


class PackageManifestTests(unittest.TestCase):
    def test_accepts_rooted_complete_manifest(self) -> None:
        self.assertEqual(violations({"package": {"include": sorted(REQUIRED)}}), [])

    def test_rejects_nested_readme_match_and_missing_boundary(self) -> None:
        include = sorted(REQUIRED - {"/README.md"}) + ["README.md"]
        errors = violations({"package": {"include": include}})
        self.assertTrue(any("not checkout-rooted" in error for error in errors))
        self.assertTrue(any("/README.md" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
