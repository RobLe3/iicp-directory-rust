#!/usr/bin/env python3
"""Verify/install a pinned Linux operator binary; never start a service or build."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

import pre1_artifact_common as common

MAX_FRAGMENT_BYTES = 64 * 1024
MAX_BINARY_BYTES = 1024 * 1024 * 1024
MACHINES = {"linux-x86_64": 62, "linux-aarch64": 183}


class ArtifactError(ValueError):
    """An allowlisted content-free preflight failure."""


def safe_path(path: Path) -> Path:
    path = path.absolute()
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ArtifactError("operator artifact path traverses a symlink")
    return path


def read_fragment(path: Path, expected_digest: str) -> dict:
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_digest):
        raise ArtifactError("expected fragment digest is invalid")
    path = safe_path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ArtifactError("operator fragment is not a regular file")
        raw = stream.read(MAX_FRAGMENT_BYTES + 1)
    if len(raw) > MAX_FRAGMENT_BYTES:
        raise ArtifactError("operator fragment exceeds metadata bound")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ArtifactError("operator fragment must be an object")
    claimed = value.get("fragment_sha256")
    payload = {**value, "fragment_sha256": None}
    if claimed != expected_digest or common.canonical_sha256(payload) != expected_digest:
        raise ArtifactError("operator fragment digest differs")
    return value


def validate_identity(value: dict, commit: str, target: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ArtifactError("expected source commit is invalid")
    expected = {
        "schema": "iicp.pre1-artifact-fragment.v1", "component": "directory-rust",
        "source_commit": commit, "build_target": target,
        "content_free": True, "secrets_present": False, "non_authorizing": True,
        "gates": common.GATES,
    }
    if any(type(value.get(k)) is not type(v) or value[k] != v for k, v in expected.items()):
        raise ArtifactError("operator fragment identity or build gate differs")
    if target not in MACHINES or common.detected_target() != target:
        raise ArtifactError("operator target differs from the native Linux host")
    version = value.get("source_version")
    if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", version):
        raise ArtifactError("operator version is invalid")


def binary_record(value: dict, target: str) -> dict:
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, list) or not all(isinstance(row, dict) for row in artifacts):
        raise ArtifactError("operator artifact inventory is invalid")
    binaries = [row for row in artifacts if row.get("kind") == "release-artifact"]
    if len(binaries) != 1 or binaries[0].get("target") != target:
        raise ArtifactError("operator requires exactly one target binary")
    row = binaries[0]
    name = row.get("name")
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", name):
        raise ArtifactError("operator binary name is unsafe")
    size = row.get("size_bytes")
    if type(size) is not int or not 0 < size <= MAX_BINARY_BYTES:
        raise ArtifactError("operator binary size exceeds bound")
    if not isinstance(row.get("sha256"), str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", row["sha256"]):
        raise ArtifactError("operator binary digest is invalid")
    return row


def inspect_binary(stream, row: dict, target: str, output=None) -> None:
    metadata = os.fstat(stream.fileno())
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != row["size_bytes"]:
        raise ArtifactError("operator binary type or size differs")
    header = stream.read(64)
    if len(header) != 64 or header[:6] != b"\x7fELF\x02\x01":
        raise ArtifactError("operator binary is not little-endian ELF64")
    if int.from_bytes(header[18:20], "little") != MACHINES[target]:
        raise ArtifactError("operator ELF machine differs from target")
    stream.seek(0)
    digest = hashlib.sha256()
    remaining = row["size_bytes"]
    while remaining:
        block = stream.read(min(1024 * 1024, remaining))
        if not block:
            raise ArtifactError("operator binary was truncated")
        digest.update(block)
        remaining -= len(block)
        if output is not None:
            output.write(block)
    if stream.read(1) or "sha256:" + digest.hexdigest() != row["sha256"]:
        raise ArtifactError("operator binary content differs")


def install_binary(stream, row: dict, target: str, destination: Path) -> None:
    destination = safe_path(destination)
    parent = destination.parent.stat()
    if parent.st_uid != os.getuid() or parent.st_mode & 0o022:
        raise ArtifactError("operator install parent must be owned and non-writable by others")
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            stream.seek(0)
            inspect_binary(stream, row, target, output)
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), 0o500)
    except BaseException:
        destination.unlink()  # Only the exclusive file created by this invocation.
        raise


def prepare(fragment: Path, digest: str, commit: str, target: str, destination: Path | None = None) -> dict:
    value = read_fragment(fragment, digest)
    validate_identity(value, commit, target)
    row = binary_record(value, target)
    binary = safe_path(fragment.parent / row["name"])
    fd = os.open(binary, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        inspect_binary(stream, row, target)
        if destination is not None:
            install_binary(stream, row, target, destination)
    return {
        "schema": "iicp.directory-rust.operator-artifact-preflight.v1",
        "status": "INSTALLED" if destination is not None else "VERIFIED",
        "source_commit": commit, "source_version": value["source_version"],
        "target": target, "fragment_sha256": digest, "binary_sha256": row["sha256"],
        "binary_size_bytes": row["size_bytes"], "service_started": False,
        "operational_tests_run": False, "qualification_credit": 0, "non_authorizing": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fragment", type=Path, required=True)
    parser.add_argument("--fragment-sha256", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--target", choices=sorted(MACHINES), required=True)
    parser.add_argument("--install-to", type=Path)
    args = parser.parse_args()
    try:
        result = prepare(args.fragment, args.fragment_sha256, args.source_commit, args.target, args.install_to)
    except (OSError, ValueError, TypeError) as error:
        # Paths or parser excerpts may contain private values; expose only the class.
        print(json.dumps({"status": "FAIL", "reason": str(error) if isinstance(error, ArtifactError) else type(error).__name__, "qualification_credit": 0}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
