"""Separate qualification-tool identity from unchanged frozen product source.

This module is copied verbatim into component-owned qualification tooling. It
does not participate in a product runtime or grant qualification credit.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path


TOOL_ONLY_PATHS = frozenset({
    "scripts/run_pre1_qualification_case.py",
    "scripts/test_pre1_qualification_case.py",
    "scripts/pre1_harness_binding.py",
    "scripts/pre1_environment_contract.py",
    "scripts/pre1_package_execution.py",
    "scripts/test_pre1_package_execution.py",
    "scripts/test_pre1_prepared_home.py",
    "scripts/run_php83_local_ci.py",
    "scripts/test_php83_local_ci.py",
    "scripts/prepare_pre1_minimum_runtime.py",
})


# Quality workflows remain bound by the full harness commit/tree digest.
# This classification grants no merge, release or required-check authority.
CI_ONLY_PATHS = frozenset({
    ".github/workflows/quality.yml",
    ".github/workflows/ci.yml",
})


# This is an exact append-only qualification note, not a documentation wildcard.
# Both the released prefix and the reviewed addition remain immutable here.
REVIEWED_DOCUMENT_APPENDICES = {
    "OPERATIONS.md": {
        "base_sha256": "79602ed2ddc66383fe7777415e9cb125b29134e3bc4a553edce5f3aab796ea45",
        "append_sha256": "bc0a713ae89a67c8cb244d25edc15c7b6fd384ead6b0c54f4d39e59ffdc0f8b7",
    },
}


def validate_document_appendix(root: Path, path: str, product: str, harness: str) -> None:
    expected = REVIEWED_DOCUMENT_APPENDICES[path]
    before = git(root, "show", f"{product}:{path}")
    after = git(root, "show", f"{harness}:{path}")
    if (hashlib.sha256(before).hexdigest() != expected["base_sha256"]
            or not after.startswith(before)
            or hashlib.sha256(after[len(before):]).hexdigest() != expected["append_sha256"]):
        raise ValueError("qualification documentation differs from reviewed append-only note")


def git(root: Path, *argv: str) -> bytes:
    return subprocess.check_output(
        ["git", *argv], cwd=root, stderr=subprocess.PIPE, timeout=30
    )


def harness_identity(root: Path) -> dict[str, str]:
    """Hash the tracked Git tree manifest, including all assertions/fixtures.

    The manifest contains modes, Git blob IDs and paths. Its SHA-256 and exact
    commit together identify tooling; product payloads retain their own SHA-256.
    """
    commit = git(root, "rev-parse", "HEAD").decode().strip()
    tree = git(root, "ls-tree", "-r", "--full-tree", commit)
    return {
        "harness_source_commit": commit,
        "harness_sha256": "sha256:" + hashlib.sha256(tree).hexdigest(),
    }


def validate_harness_source(
    root: Path, product_source_commit: str, binding: dict[str, str]
) -> None:
    """Refuse dirty tooling, pin substitution or changes to any product file."""
    if not isinstance(binding, dict) or set(binding) != {
        "harness_source_commit", "harness_sha256"
    }:
        raise ValueError("qualification harness binding fields differ")
    if not re.fullmatch(r"[0-9a-f]{40}", str(binding["harness_source_commit"])):
        raise ValueError("qualification harness source commit is invalid")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(binding["harness_sha256"])):
        raise ValueError("qualification harness digest is invalid")
    if not re.fullmatch(r"[0-9a-f]{40}", str(product_source_commit)):
        raise ValueError("qualification product source commit is invalid")
    if harness_identity(root) != binding:
        raise ValueError("qualification harness source or digest differs")
    if git(root, "status", "--porcelain=v1", "--untracked-files=normal").strip():
        raise ValueError("qualification harness checkout is dirty")
    # --no-renames makes a move appear as both a deletion and an addition.
    changes = git(
        root, "diff", "--no-renames", "--name-only", "-z",
        product_source_commit, binding["harness_source_commit"], "--"
    ).decode().split("\0")
    remaining = set(filter(None, changes)) - (TOOL_ONLY_PATHS | CI_ONLY_PATHS)
    for path in remaining & REVIEWED_DOCUMENT_APPENDICES.keys():
        validate_document_appendix(root, path, product_source_commit, binding["harness_source_commit"])
        remaining.remove(path)
    if remaining:
        raise ValueError("qualification tooling revision changes frozen product source")
