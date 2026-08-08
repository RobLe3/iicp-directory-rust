#!/usr/bin/env python3
"""Verify the content-free Rust release compatibility manifest and nested fixtures."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checked_child(root: Path, parent: Path, name: str) -> Path:
    """Resolve a nested fixture without allowing it to leave the checkout."""
    if Path(name).name != name:
        raise ValueError(f"nested fixture name must be a file name: {name!r}")
    child = (parent / name).resolve()
    if root.resolve() not in child.parents:
        raise ValueError(f"nested fixture path escapes repository: {name!r}")
    return child


def verify_nested_fixtures(root: Path, manifest_path: Path, payload: Any, seen: set[Path] | None = None) -> None:
    """Verify every SHA-256 named by a parity contract, recursively.

    A fixture map is a content-free integrity manifest: keys are sibling file
    names and values are lowercase 64-hex SHA-256 digests. Other JSON values do
    not participate in release compatibility validation.
    """
    if not isinstance(payload, dict) or "fixtures" not in payload:
        return
    fixtures = payload["fixtures"]
    if not isinstance(fixtures, dict):
        raise ValueError(f"nested fixture map must be an object: {manifest_path}")
    seen = set() if seen is None else seen
    for name, expected in fixtures.items():
        if not isinstance(name, str) or not isinstance(expected, str) or not SHA256_RE.fullmatch(expected):
            raise ValueError(f"nested fixture digest must be lowercase 64-hex SHA-256: {manifest_path}")
        child = checked_child(root, manifest_path.parent, name)
        if not child.is_file():
            raise ValueError(f"nested fixture is missing: {child}")
        actual = sha256(child)
        if actual != expected:
            raise ValueError(f"nested fixture digest mismatch: {child}")
        if child in seen:
            continue
        seen.add(child)
        try:
            child_payload = json.loads(child.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        verify_nested_fixtures(root, child, child_payload, seen)


def verify(root: Path = ROOT, manifest_name: str | None = None) -> str:
    cargo = (root / "Cargo.toml").read_text(encoding="utf-8")
    source_version = next(line for line in cargo.splitlines() if line.startswith("version = ")).split('"', 2)[1]
    manifest_path = root / "compatibility" / (manifest_name or f"v{source_version}.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    version = manifest.get("implementation", {}).get("version")
    if manifest["implementation"] != {"flavor": "rust", "version": version, "status": "operator_preview"}:
        raise ValueError("release compatibility implementation identity mismatch")
    if manifest_name is None and version != source_version:
        raise ValueError("default compatibility manifest must match the Cargo source version")
    for name, contract in manifest["contracts"].items():
        if not isinstance(contract, dict) or not isinstance(contract.get("path"), str) or not isinstance(contract.get("sha256"), str):
            raise ValueError(f"{name} contract entry is malformed")
        if not SHA256_RE.fullmatch(contract["sha256"]):
            raise ValueError(f"{name} contract digest must be lowercase 64-hex SHA-256")
        path = (root / contract["path"]).resolve()
        if root.resolve() not in path.parents or not path.is_file():
            raise ValueError(f"{name} contract path is invalid: {contract['path']}")
        if sha256(path) != contract["sha256"]:
            raise ValueError(f"{name} contract digest mismatch: {path}")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        verify_nested_fixtures(root, path, payload, {path})
    forbidden = ("production_authority", "genesis_cutover_authorized", "php_deprecation_authorized")
    if any(manifest[key] is not False for key in forbidden):
        raise ValueError("preview manifest must not authorize production or deprecation")
    return f"Rust v{version} compatibility manifest: PASS"


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Verify Rust release compatibility artifacts")
    parser.add_argument("--manifest", help="candidate manifest name under compatibility/ (for example v0.1.10.json)")
    args = parser.parse_args()
    try:
        print(verify(manifest_name=args.manifest))
    except (KeyError, OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(str(exc)) from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
