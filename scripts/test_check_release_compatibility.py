#!/usr/bin/env python3
"""Regression tests for recursive release-compatibility validation."""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_release_compatibility as compatibility

ROOT = Path(__file__).resolve().parents[1]


def fixture_root() -> Path:
    destination = Path(tempfile.mkdtemp(prefix="iicp-compatibility-test-")) / "repo"
    shutil.copytree(ROOT / "parity", destination / "parity")
    shutil.copytree(ROOT / "compatibility", destination / "compatibility")
    shutil.copytree(ROOT / "schema", destination / "schema")
    shutil.copy2(ROOT / "Cargo.toml", destination / "Cargo.toml")
    return destination


def test_current_contract_passes() -> tuple[bool, str]:
    root = fixture_root()
    try:
        return "PASS" in compatibility.verify(root), "current nested fixture contract passes"
    finally:
        shutil.rmtree(root.parent)


def test_tampered_nested_fixture_fails() -> tuple[bool, str]:
    root = fixture_root()
    try:
        target = root / "parity" / "replica-lifecycle-contract-v1.json"
        target.write_text(target.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        try:
            compatibility.verify(root)
        except ValueError as exc:
            return "nested fixture digest mismatch" in str(exc), str(exc)
        return False, "tampered nested fixture was accepted"
    finally:
        shutil.rmtree(root.parent)


def test_truncated_nested_digest_fails() -> tuple[bool, str]:
    root = fixture_root()
    try:
        contract = root / "parity" / "contract-v1.10.89.json"
        payload = json.loads(contract.read_text(encoding="utf-8"))
        payload["fixtures"]["replica-lifecycle-contract-v1.json"] = "a" * 48
        contract.write_text(json.dumps(payload), encoding="utf-8")
        manifest = root / "compatibility" / "v0.1.10.json"
        compat = json.loads(manifest.read_text(encoding="utf-8"))
        compat["contracts"]["parity_manifest"]["sha256"] = compatibility.sha256(contract)
        manifest.write_text(json.dumps(compat), encoding="utf-8")
        try:
            compatibility.verify(root)
        except ValueError as exc:
            return "nested fixture digest must be" in str(exc), str(exc)
        return False, "truncated nested digest was accepted"
    finally:
        shutil.rmtree(root.parent)



def test_missing_nested_fixture_fails() -> tuple[bool, str]:
    root = fixture_root()
    try:
        contract = root / "parity" / "contract-v1.10.89.json"
        payload = json.loads(contract.read_text(encoding="utf-8"))
        payload["fixtures"]["missing.json"] = "a" * 64
        contract.write_text(json.dumps(payload), encoding="utf-8")
        manifest = root / "compatibility" / "v0.1.10.json"
        compat = json.loads(manifest.read_text(encoding="utf-8"))
        compat["contracts"]["parity_manifest"]["sha256"] = compatibility.sha256(contract)
        manifest.write_text(json.dumps(compat), encoding="utf-8")
        try:
            compatibility.verify(root)
        except ValueError as exc:
            return "nested fixture is missing" in str(exc), str(exc)
        return False, "missing nested fixture was accepted"
    finally:
        shutil.rmtree(root.parent)


def test_substituted_nested_fixture_name_fails() -> tuple[bool, str]:
    root = fixture_root()
    try:
        contract = root / "parity" / "contract-v1.10.89.json"
        payload = json.loads(contract.read_text(encoding="utf-8"))
        digest = payload["fixtures"].pop("replica-lifecycle-contract-v1.json")
        payload["fixtures"]["../schema/contract-v1.json"] = digest
        contract.write_text(json.dumps(payload), encoding="utf-8")
        manifest = root / "compatibility" / "v0.1.10.json"
        compat = json.loads(manifest.read_text(encoding="utf-8"))
        compat["contracts"]["parity_manifest"]["sha256"] = compatibility.sha256(contract)
        manifest.write_text(json.dumps(compat), encoding="utf-8")
        try:
            compatibility.verify(root)
        except ValueError as exc:
            return "nested fixture name must be" in str(exc), str(exc)
        return False, "substituted nested fixture path was accepted"
    finally:
        shutil.rmtree(root.parent)

def main() -> int:
    failed = []
    for name, test in (("current_contract", test_current_contract_passes), ("tampered_nested", test_tampered_nested_fixture_fails), ("truncated_digest", test_truncated_nested_digest_fails), ("missing_nested", test_missing_nested_fixture_fails), ("substituted_name", test_substituted_nested_fixture_name_fails)):
        ok, detail = test()
        print(f"{'✓' if ok else '✗'} {name}: {detail}")
        if not ok:
            failed.append(name)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
