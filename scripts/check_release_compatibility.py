#!/usr/bin/env python3
"""Verify the content-free Rust release compatibility manifest."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    cargo = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    version_line = next(
        line for line in cargo.splitlines() if line.startswith("version = ")
    )
    version = version_line.split('"', 2)[1]
    manifest_path = ROOT / "compatibility" / f"v{version}.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest["implementation"] != {
        "flavor": "rust",
        "version": version,
        "status": "operator_preview",
    }:
        raise SystemExit("release compatibility implementation identity mismatch")
    for name, contract in manifest["contracts"].items():
        path = ROOT / contract["path"]
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != contract["sha256"]:
            raise SystemExit(f"{name} contract digest mismatch: {path}")
    forbidden = (
        "production_authority",
        "genesis_cutover_authorized",
        "php_deprecation_authorized",
    )
    if any(manifest[key] is not False for key in forbidden):
        raise SystemExit("preview manifest must not authorize production or deprecation")
    print(f"Rust v{version} compatibility manifest: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
