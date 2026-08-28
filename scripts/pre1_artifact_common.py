#!/usr/bin/env python3
"""Shared local helpers for component-owned pre-stable artifact builders."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
from pathlib import Path

GATES = {
    "locked_build": "PASS",
    "online_exact_install": "PASS",
    "offline_locked_install": "PASS",
    "package_version_self_report": "PASS",
}


def canonical_sha256(value: object) -> str:
    body = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return "sha256:" + hashlib.sha256(body).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def files_sha256(root: Path, paths: list[Path]) -> str:
    records = [
        {
            "path": path.relative_to(root).as_posix(),
            "sha256": file_sha256(path),
            "size_bytes": path.stat().st_size,
        }
        for path in sorted(paths)
    ]
    return canonical_sha256(records)


def tree_sha256(root: Path) -> str:
    records = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"dependency cache contains a symlink: {path.relative_to(root)}")
        if path.is_file():
            records.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "sha256": file_sha256(path),
                    "size_bytes": path.stat().st_size,
                }
            )
    return canonical_sha256(records)


def detected_target() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    arch = "x86_64" if machine in {"x86_64", "amd64"} else "arm64" if machine in {"arm64", "aarch64"} else None
    if arch is None:
        raise ValueError("unsupported build architecture")
    target = {
        "darwin": f"macos-{arch}",
        "linux": f"linux-{'aarch64' if arch == 'arm64' else arch}",
        "windows": f"windows-{arch}",
    }.get(system)
    if target is None:
        raise ValueError("unsupported build operating system")
    return target


def require_target(requested: str | None, allowed: set[str]) -> str:
    observed = detected_target()
    target = requested or observed
    if target != observed:
        raise ValueError(f"requested target {target} differs from observed target {observed}")
    if target not in allowed:
        raise ValueError(f"target is outside this component boundary: {target}")
    return target


def require_clean_source(root: Path) -> str:
    if subprocess.run(["git", "diff", "--quiet", "HEAD", "--"], cwd=root).returncode:
        raise ValueError("artifact build requires a clean tracked worktree")
    if subprocess.run(["git", "diff", "--cached", "--quiet", "HEAD", "--"], cwd=root).returncode:
        raise ValueError("artifact build requires a clean index")
    status = subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=normal"],
        cwd=root,
        text=True,
    ).strip()
    if status:
        raise ValueError("artifact build requires a clean worktree, including untracked files")
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise ValueError("artifact build source commit is invalid")
    return commit


def safe_output(path: Path) -> None:
    if path.exists() or path.is_symlink():
        raise ValueError("artifact output already exists")
    if not path.parent.is_dir() or path.parent.is_symlink():
        raise ValueError("artifact output parent is unavailable or unsafe")
    cursor = path.parent
    while cursor != cursor.parent:
        if cursor.is_symlink():
            raise ValueError("artifact output parent traverses a symlink")
        cursor = cursor.parent


def run(argv: list[str], cwd: Path, env: dict[str, str] | None = None) -> None:
    subprocess.run(argv, cwd=cwd, env=env, check=True)


def output(argv: list[str], cwd: Path, env: dict[str, str] | None = None) -> str:
    return subprocess.check_output(argv, cwd=cwd, env=env, text=True, stderr=subprocess.STDOUT).strip()


def artifact(kind: str, target: str, path: Path) -> dict:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"artifact is unavailable or unsafe: {path.name}")
    return {
        "kind": kind,
        "target": target,
        "name": path.name,
        "sha256": file_sha256(path),
        "size_bytes": path.stat().st_size,
    }


def emit_fragment(
    staging: Path,
    *,
    component: str,
    source_commit: str,
    source_version: str,
    build_target: str,
    artifacts: list[dict],
    lock_inputs_sha256: str,
    dependency_cache_sha256: str,
    toolchains: dict[str, str],
) -> dict:
    value = {
        "schema": "iicp.pre1-artifact-fragment.v1",
        "component": component,
        "source_commit": source_commit,
        "source_version": source_version,
        "build_target": build_target,
        "artifacts": sorted(artifacts, key=lambda row: (row["kind"], row["target"], row["name"])),
        "gates": dict(GATES),
        "inputs": {
            "lock_inputs_sha256": lock_inputs_sha256,
            "dependency_cache_sha256": dependency_cache_sha256,
        },
        "environment": {
            "os_name": platform.system().lower(),
            "os_release": platform.release(),
            "architecture": platform.machine().lower(),
            "toolchains": toolchains,
        },
        "content_free": True,
        "secrets_present": False,
        "non_authorizing": True,
        "fragment_sha256": None,
    }
    value["fragment_sha256"] = canonical_sha256(value)
    manifest = staging / "artifact-fragment.json"
    manifest.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    for path in staging.iterdir():
        if path.is_file() and not path.is_symlink():
            os.chmod(path, 0o600)
    return value


def publish_staging(staging: Path, destination: Path) -> None:
    safe_output(destination)
    os.replace(staging, destination)


def clean_failed_staging(staging: Path) -> None:
    shutil.rmtree(staging, ignore_errors=True)
