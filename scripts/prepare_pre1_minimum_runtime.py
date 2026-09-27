#!/usr/bin/env python3
"""Prepare and diagnose a frozen-source MSRV build, never qualification credit.

Preparation may fetch locked dependencies. Verification must run in the existing
network-disabled native runner with read-only fixture inputs. Its source-built
binary is not a replacement for the frozen installed candidate.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import re
import subprocess
import tarfile
from pathlib import Path

import pre1_artifact_common as common
import pre1_package_execution as packages

SCHEMA = "iicp.pre1-directory-runtime-fixture.v1"
RUNTIMES = {"msrv-1.88": "1.88.0", "rust-1.98.0": "1.98.0"}
HOSTS = {"linux-aarch64": "aarch64-unknown-linux-gnu", "linux-x86_64": "x86_64-unknown-linux-gnu"}


# Published predecessor identity is the crate's source commit, not an assumed
# release-tag commit. This auxiliary input never substitutes a candidate asset.
PREDECESSOR_VERSION = "0.1.15"
PREDECESSOR_COMMIT = "4e8ef1fa9d03861ee5bd58584ef04a5a0bb3c0c1"
PREDECESSOR_CRATE_SHA256 = "337edf921e091c8dc6788d25b007895bbc9e89e5421b0e82231862f8d1bf54cf"
PREDECESSOR_MANIFEST_SHA256 = "f4fbdb75e5284dbfb7a31b9d2f07324caebea664f7c15a9b5051a5d8b953f11f"


def predecessor_identity(crate, manifest):
    """Verify exact published inputs before any predecessor preparation."""
    crate, manifest = packages.safe_path(crate), packages.safe_path(manifest)
    if (crate.stat().st_size > 64 * 1024 * 1024 or manifest.stat().st_size > 65536
            or common.file_sha256(crate) != "sha256:" + PREDECESSOR_CRATE_SHA256
            or common.file_sha256(manifest) != "sha256:" + PREDECESSOR_MANIFEST_SHA256):
        raise ValueError("predecessor published asset identity differs")
    value = json.loads(manifest.read_text())
    if (value.get("schema") != "iicp.directory-rust-release.v1"
            or value.get("version") != PREDECESSOR_VERSION
            or value.get("commit") != PREDECESSOR_COMMIT
            or value.get("crate_sha256") != PREDECESSOR_CRATE_SHA256
            or value.get("production_authority") is not False
            or value.get("genesis_cutover_authorized") is not False):
        raise ValueError("predecessor release provenance differs")
    with tarfile.open(crate, mode="r:gz") as archive:
        name = "iicp-directory-rs-" + PREDECESSOR_VERSION + "/.cargo_vcs_info.json"
        member = archive.getmember(name)
        if not member.isfile() or member.size > 4096:
            raise ValueError("predecessor crate source provenance is invalid")
        vcs = json.loads(archive.extractfile(member).read())
        if vcs.get("git", {}).get("sha1") != PREDECESSOR_COMMIT or vcs.get("path_in_vcs") != "":
            raise ValueError("predecessor crate source provenance differs")
    return {"source_version": PREDECESSOR_VERSION, "source_commit": PREDECESSOR_COMMIT,
            "crate_sha256": common.file_sha256(crate),
            "release_manifest_sha256": common.file_sha256(manifest),
            "qualification_credit": False, "non_authorizing": True}


def candidate_identity(path):
    path = packages.safe_path(path)
    candidate = json.loads(path.read_text())
    if (candidate.get("status") != "FROZEN" or candidate.get("immutable") is not True
            or candidate.get("non_authorizing") is not True):
        raise ValueError("runtime fixture requires the frozen non-authorizing candidate")
    row = candidate_component(candidate)
    return {"candidate_file_sha256": common.file_sha256(path),
            "source_commit": row["source_commit"], "source_version": row["source_version"]}


def candidate_component(candidate):
    rows = [r for r in candidate["components"] if r.get("id") == "directory-rust"]
    if len(rows) != 1:
        raise ValueError("runtime source commit is missing or ambiguous")
    row = rows[0]
    if (not re.fullmatch(r"[a-f0-9]{40}", row.get("source_commit", ""))
            or not re.fullmatch(r"0\.\d+\.\d+", row.get("source_version", ""))):
        raise ValueError("runtime source identity differs")
    return row


def extract_source(archive_bytes, destination):
    if len(archive_bytes) > 64 * 1024 * 1024:
        raise ValueError("runtime source archive exceeds bound")
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as archive:
        seen, total = set(), 0
        members = archive.getmembers()
        for member in members:
            total = packages.validate_rust_archive_member(member, member.name, seen, total)
            if total > 64 * 1024 * 1024 or len(seen) > 4096:
                raise ValueError("runtime source tree exceeds bound")
        if not {"Cargo.toml", "Cargo.lock", "src/main.rs"}.issubset(seen):
            raise ValueError("runtime source archive lacks the locked Directory source")
        destination.mkdir(mode=0o700)
        for member in members:
            if member.isdir():
                continue
            target = destination / member.name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with archive.extractfile(member) as source, target.open("xb") as output:
                output.write(source.read())
            target.chmod(0o600)


def fixture_tree(root):
    return {name: packages.tree(root / name) for name in ("source", "vendor")}


def executable(path):
    # Runtime maps use rustup's cargo/rustc symlinks. Preserve argv[0]; resolving
    # these to a binary named rustup would change the invoked tool.
    if not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError("runtime executable is unavailable or not absolute")
    return path


def prepare(root, candidate, destination, cargo):
    identity = candidate_identity(candidate)
    if destination.exists() or destination.is_symlink() or destination.is_relative_to(root):
        raise ValueError("runtime preparation needs a fresh external destination")
    packages.safe_path(destination.parent)
    destination.mkdir(mode=0o700)
    archive = subprocess.check_output(["git", "archive", "--format=tar", identity["source_commit"]],
                                     cwd=root, timeout=30)
    extract_source(archive, destination / "source")
    with (destination / "preparation.log").open("xb") as log:
        result = subprocess.run([str(cargo), "vendor", "--locked", "--versioned-dirs",
                                 str(destination / "vendor")], cwd=destination / "source",
                                stdout=log, stderr=subprocess.STDOUT, timeout=900, check=False)
    if result.returncode:
        raise ValueError("locked runtime fixture vendoring failed; retain preparation.log")
    value = {"schema": SCHEMA, **identity, "files": fixture_tree(destination),
             "qualification_credit": False, "non_authorizing": True}
    value["fixture_sha256"] = packages.digest(value)
    (destination / "fixture.json").write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    for path in destination.rglob("*"):
        if path.is_file():
            path.chmod(0o600)
        elif path.is_dir():
            path.chmod(0o700)
    return value


def validate_fixture(fixture, candidate):
    fixture = packages.safe_path(fixture)
    manifest = packages.safe_path(fixture / "fixture.json")
    if manifest.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("runtime fixture manifest exceeds bound")
    value = json.loads(manifest.read_text())
    unsigned = {k: v for k, v in value.items() if k != "fixture_sha256"}
    identity = candidate_identity(candidate)
    if (value.get("schema") != SCHEMA or value.get("qualification_credit") is not False
            or value.get("non_authorizing") is not True or value.get("fixture_sha256") != packages.digest(unsigned)
            or any(value.get(k) != v for k, v in identity.items())
            or value.get("files") != fixture_tree(fixture)):
        raise ValueError("runtime fixture candidate or dependency binding differs")
    return value


def active_interfaces():
    import fcntl
    import socket
    import struct
    # Network-none namespaces may contain inactive kernel tunnel devices.
    # Match the existing installed-package probe's active-interface boundary.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
        return {name for _, name in socket.if_nameindex()
                if struct.unpack_from("H", fcntl.ioctl(control.fileno(), 0x8913,
                    struct.pack("256s", name.encode())), 16)[0] & 1}


def require_isolated_native():
    if os.geteuid() == 0 or active_interfaces() != {"lo"}:
        raise ValueError("runtime verification requires non-root execution and loopback-only networking")


def verification_environment(fixture, output, cargo, rustc, runtime, target):
    if output.exists() or output.is_symlink() or output.is_relative_to(fixture):
        raise ValueError("runtime verification needs fresh output outside immutable inputs")
    packages.safe_path(output.parent)
    if common.detected_target() != target:
        raise ValueError("runtime verification must use the declared native Linux target")
    require_isolated_native()
    output.mkdir(mode=0o700)
    (output / "tmp").mkdir(mode=0o700)
    env = {"PATH": str(cargo.parent) + os.pathsep + "/usr/bin:/bin", "HOME": str(output),
           "CARGO_HOME": str(output / "cargo-home"), "CARGO_TARGET_DIR": str(output / "target"),
           "TMPDIR": str(output / "tmp"), "CARGO_BUILD_JOBS": "2",
           "CARGO_INCREMENTAL": "0", "CARGO_NET_OFFLINE": "true", "RUSTC": str(rustc),
           "RUSTUP_TOOLCHAIN": RUNTIMES[runtime]}
    if os.environ.get("RUSTUP_HOME"):
        env["RUSTUP_HOME"] = os.environ["RUSTUP_HOME"]
    return env


def compiler_identity(rustc, env, runtime, target):
    observed = subprocess.check_output([str(rustc), "-vV"], env=env, timeout=10, text=True)
    if (f"release: {RUNTIMES[runtime]}\n" not in observed
            or f"host: {HOSTS[target]}\n" not in observed):
        raise ValueError("selected runtime compiler version or native host differs")
    return observed


def verify(fixture, candidate, output, cargo, rustc, runtime, target, expected_fixture_sha256, *, build_timeout=1800):
    if build_timeout not in (150, 1800):
        raise ValueError("runtime build timeout is outside the reviewed execution budgets")
    value = validate_fixture(fixture, candidate)
    if (not re.fullmatch(r"sha256:[a-f0-9]{64}", expected_fixture_sha256)
            or value["fixture_sha256"] != expected_fixture_sha256):
        raise ValueError("runtime fixture differs from the externally pinned preparation")
    env = verification_environment(fixture, output, cargo, rustc, runtime, target)
    observed = compiler_identity(rustc, env, runtime, target)
    argv = [str(cargo), "--config", 'source.crates-io.replace-with="pre1-vendor"',
            "--config", "source.pre1-vendor.directory=" + json.dumps(str(fixture / "vendor")),
            "build", "--offline", "--locked", "--bin", "iicp-directory-rs"]
    receipt = {"schema": "iicp.pre1-directory-runtime-diagnostic.v1", "status": "FAIL",
               "runtime": runtime, "target": target, "fixture_sha256": value["fixture_sha256"],
               "source_commit": value["source_commit"], "qualification_credit": False,
               "non_authorizing": True, "evidence_scope": "source-build-only"}
    try:
        with (output / "build.log").open("xb") as log:
            result = subprocess.run(argv, cwd=fixture / "source", env=env, stdout=log,
                                    stderr=subprocess.STDOUT, timeout=build_timeout, check=False)
        receipt["build_exit_code"] = result.returncode
        if result.returncode:
            raise ValueError("offline locked minimum-runtime build failed; retain build.log")
        binary = packages.safe_path(output / "target/debug/iicp-directory-rs")
        reported = subprocess.check_output([str(binary), "--version"], env=env, text=True, timeout=10)
        if reported.strip() != "iicp-directory-rs " + value["source_version"]:
            raise ValueError("source-built Directory version differs")
        validate_fixture(fixture, candidate)
        receipt.update(status="PASS", compiler=observed, source_binary_sha256=common.file_sha256(binary))
        return receipt
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        receipt["failure_class"] = type(error).__name__
        raise
    finally:
        (output / "result.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        for name in ("build.log", "result.json"):
            if (output / name).exists():
                (output / name).chmod(0o600)


def stream_evidence(output):
    import base64
    # tmpfs disappears when the container stops. Emit bounded evidence while
    # it still exists; the controller retains this private stream before cleanup.
    for name, limit in (("result.json", 65536), ("build.log", 8 * 1024 * 1024)):
        path = output / name
        if not path.exists():
            continue
        packages.safe_path(path)
        with path.open("rb") as handle:
            raw = handle.read(limit + 1)
        if len(raw) > limit:
            raise ValueError("runtime diagnostic evidence exceeds stream bound")
        print("IICP_PRE1_RUNTIME_EVIDENCE " + json.dumps({"name": name,
              "sha256": common.file_sha256(path), "base64": base64.b64encode(raw).decode()}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "verify"))
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--cargo", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--rustc", type=Path)
    parser.add_argument("--runtime", choices=RUNTIMES)
    parser.add_argument("--target", choices=HOSTS)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--fixture-sha256")
    args = parser.parse_args()
    os.umask(0o077)
    if args.phase == "prepare":
        prepare(packages.safe_path(args.root), args.candidate, args.fixture, executable(args.cargo))
    else:
        if not all((args.rustc, args.runtime, args.target, args.output, args.fixture_sha256)):
            parser.error("verify requires --rustc, --runtime, --target, --output and --fixture-sha256")
        existed = args.output.exists() or args.output.is_symlink()
        try:
            verify(args.fixture, args.candidate, args.output, executable(args.cargo),
                   executable(args.rustc), args.runtime, args.target, args.fixture_sha256)
        finally:
            if not existed and args.output.is_dir() and not args.output.is_symlink():
                stream_evidence(args.output)


if __name__ == "__main__":
    main()
