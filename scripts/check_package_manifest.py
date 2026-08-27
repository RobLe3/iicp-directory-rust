#!/usr/bin/env python3
"""Keep Cargo package inputs rooted in the authoritative checkout."""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {
    "/Cargo.toml",
    "/Cargo.lock",
    "/LICENSE",
    "/README.md",
    "/OPERATIONS.md",
    "/PARITY.md",
    "/RELEASE_POLICY.md",
    "/SECURITY.md",
    "/src/**",
    "/schema/**",
    "/migrations/**",
    "/parity/**",
    "/compatibility/**",
    "/tests/**",
}


def violations(manifest: dict) -> list[str]:
    include = manifest.get("package", {}).get("include")
    if not isinstance(include, list) or not include:
        return ["package.include must be a non-empty list"]
    errors = []
    for pattern in include:
        if not isinstance(pattern, str) or not pattern.startswith("/"):
            errors.append(f"package include is not checkout-rooted: {pattern!r}")
    missing = sorted(REQUIRED - set(include))
    if missing:
        errors.append("required package inputs are missing: " + ", ".join(missing))
    return errors


def main() -> int:
    manifest = tomllib.loads((ROOT / "Cargo.toml").read_text())
    errors = violations(manifest)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("package manifest boundary passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
