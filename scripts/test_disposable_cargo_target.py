#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "with_disposable_cargo_target.sh"


class DisposableCargoTargetTests(unittest.TestCase):
    def run_helper(
        self,
        base: Path,
        command: str,
        *,
        keep: bool = False,
        receipt: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = {
            **os.environ,
            "IICP_DISPOSABLE_TARGET_ROOT": str(base),
            "IICP_KEEP_FAILED_CARGO_TARGET": "1" if keep else "0",
        }
        if receipt is not None:
            env["IICP_DISPOSABLE_TARGET_RECEIPT"] = str(receipt)
        return subprocess.run(
            [str(HELPER), "--label", "fixture", "--", "sh", "-c", command],
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_success_cleans_exact_target_and_writes_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / "targets"
            receipt = Path(directory) / "receipt.json"
            result = self.run_helper(
                base,
                'test "$CARGO_INCREMENTAL" = 0; test "$IICP_DISPOSABLE_CARGO_ACTIVE" = 1; mkdir -p "$CARGO_TARGET_DIR/debug"; printf x >"$CARGO_TARGET_DIR/debug/file"',
                receipt=receipt,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(list(base.iterdir()), [])
            payload = json.loads(receipt.read_text())
            self.assertEqual(payload["exit_code"], 0)
            self.assertFalse(payload["preserved"])
            self.assertTrue(payload["content_free"])

    def test_failure_cleanup_is_default_and_keep_is_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / "targets"
            result = self.run_helper(base, 'printf x >"$CARGO_TARGET_DIR/file"; exit 7')
            self.assertEqual(result.returncode, 7)
            self.assertEqual(list(base.iterdir()), [])
            kept = self.run_helper(base, 'printf x >"$CARGO_TARGET_DIR/file"; exit 9', keep=True)
            self.assertEqual(kept.returncode, 9)
            entries = list(base.iterdir())
            self.assertEqual(len(entries), 1)
            self.assertIn("preserved after failure", kept.stderr)
            self.assertTrue((entries[0] / "file").is_file())

    def test_symlinked_root_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "real"
            real.mkdir()
            link = root / "link"
            link.symlink_to(real, target_is_directory=True)
            result = self.run_helper(link, "true")
            self.assertEqual(result.returncode, 1)
            self.assertIn("real directory", result.stderr)


if __name__ == "__main__":
    unittest.main()

