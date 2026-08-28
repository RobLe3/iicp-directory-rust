#!/usr/bin/env python3
"""Rust-specific helpers for component-owned pre-stable artifact builders."""

from __future__ import annotations

import gzip
import os
import shutil
import tarfile
from pathlib import Path, PurePosixPath

import pre1_artifact_common as common


def cargo_environment(run_root: Path, label: str) -> dict[str, str]:
    value = dict(os.environ)
    value.update(
        {
            "CARGO_HOME": str(run_root / f"cargo-home-{label}"),
            "CARGO_TARGET_DIR": str(run_root / f"target-{label}"),
            "CARGO_INCREMENTAL": "0",
        }
    )
    return value


def safe_extract_crate(crate: Path, destination: Path) -> Path:
    destination.mkdir()
    with tarfile.open(crate, "r:gz") as archive:
        members = archive.getmembers()
        roots: set[str] = set()
        for member in members:
            parsed = PurePosixPath(member.name)
            if (
                parsed.is_absolute()
                or ".." in parsed.parts
                or not parsed.parts
                or member.issym()
                or member.islnk()
            ):
                raise ValueError("crate contains an unsafe path or link")
            roots.add(parsed.parts[0])
        if len(roots) != 1:
            raise ValueError("crate does not contain one source root")
        archive.extractall(destination, members=members, filter="data")
    source = destination / next(iter(roots))
    if not source.is_dir() or source.is_symlink():
        raise ValueError("crate source root is unavailable or unsafe")
    return source


def deterministic_tar(source: Path, output: Path) -> None:
    with output.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                for path in sorted(source.rglob("*")):
                    if path.is_symlink():
                        raise ValueError("offline bundle contains a symlink")
                    relative = path.relative_to(source)
                    info = archive.gettarinfo(str(path), arcname=relative.as_posix())
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    info.mtime = 0
                    if info.isfile():
                        with path.open("rb") as handle:
                            archive.addfile(info, handle)
                    else:
                        archive.addfile(info)


def package_and_vendor(
    root: Path, run_root: Path, package_name: str, version: str
) -> tuple[Path, Path, Path, str]:
    package_env = cargo_environment(run_root, "package")
    common.run(["cargo", "package", "--locked"], root, package_env)
    crate = (
        Path(package_env["CARGO_TARGET_DIR"])
        / "package"
        / f"{package_name}-{version}.crate"
    )
    if not crate.is_file():
        raise ValueError("cargo package did not produce the expected crate")
    extracted = safe_extract_crate(crate, run_root / "extracted")

    bundle = run_root / "offline-bundle"
    bundle.mkdir()
    source = bundle / "source"
    shutil.copytree(extracted, source)
    vendor = bundle / "vendor"
    common.run(
        [
            "cargo",
            "vendor",
            "--locked",
            "--versioned-dirs",
            "--manifest-path",
            str(root / "Cargo.toml"),
            str(vendor),
        ],
        root,
        package_env,
    )
    cargo_config = bundle / ".cargo"
    cargo_config.mkdir()
    (cargo_config / "config.toml").write_text(
        '[source.crates-io]\nreplace-with = "vendored-sources"\n\n'
        '[source.vendored-sources]\ndirectory = "vendor"\n'
    )
    cache_digest = common.tree_sha256(vendor)
    return crate, extracted, bundle, cache_digest


def install_and_report(
    root: Path,
    run_root: Path,
    source: Path,
    binary: str,
    version: str,
    *,
    offline: bool,
) -> str:
    label = "offline" if offline else "online"
    install_root = run_root / f"install-{label}"
    environment = cargo_environment(run_root, label)
    argv = [
        "cargo",
        "install",
        "--path",
        str(source),
        "--locked",
        "--root",
        str(install_root),
    ]
    if offline:
        argv.append("--offline")
    common.run(argv, source if offline else root, environment)
    executable = install_root / "bin" / (binary + (".exe" if os.name == "nt" else ""))
    reported = common.output([str(executable), "--version"], source if offline else root)
    if version not in reported:
        raise ValueError(f"{label} Cargo package self-report differs")
    return reported
