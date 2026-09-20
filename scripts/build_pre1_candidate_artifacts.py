#!/usr/bin/env python3
"""Build and prove one Rust Directory target artifact fragment."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
import tomllib
from pathlib import Path

import pre1_artifact_common as common
import pre1_rust_build as rust_build


ROOT = Path(__file__).resolve().parents[1]
COMPONENT = "directory-rust"
TARGETS = {"linux-x86_64", "linux-aarch64"}
PRIMARY_TARGET = "linux-x86_64"
ARTIFACT_DOCKERFILE = ROOT / "ops" / "pre1-artifact" / "Dockerfile"
BUILDER_IMAGE = (
    "rust:1.98-bookworm@"
    "sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e"
)
RUNTIME_IMAGE = (
    "debian:bookworm-slim@"
    "sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818"
)
MINIMUM_GLIBC = "2.36"
PLATFORMS = {
    "linux-x86_64": "linux/amd64",
    "linux-aarch64": "linux/arm64",
}


def build_portable_binary(run_root: Path, target: str, version: str) -> tuple[Path, str]:
    """Build and execute the retained binary on the declared oldest runtime."""

    platform = PLATFORMS[target]
    exported = run_root / "bookworm-artifact"
    exported.mkdir()
    common.run(
        [
            "docker",
            "buildx",
            "build",
            "--pull",
            "--platform",
            platform,
            "--target",
            "artifact-export",
            "--output",
            f"type=local,dest={exported}",
            "--file",
            str(ARTIFACT_DOCKERFILE),
            str(ROOT),
        ],
        ROOT,
    )
    binary = exported / "iicp-directory-rs"
    if not binary.is_file() or binary.is_symlink():
        raise ValueError("Bookworm builder did not export the Rust Directory binary")

    runtime_glibc = common.output(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--platform",
            platform,
            RUNTIME_IMAGE,
            "getconf",
            "GNU_LIBC_VERSION",
        ],
        ROOT,
    )
    # Docker may prepend pull progress to captured stderr/stdout on the first
    # use of a digest-pinned runtime. Only the final non-empty command line is
    # the getconf result.
    runtime_glibc = next(
        (line.strip() for line in reversed(runtime_glibc.splitlines()) if line.strip()),
        "",
    )
    match = re.fullmatch(r"glibc ([0-9]+\.[0-9]+)", runtime_glibc)
    if match is None or match.group(1) != MINIMUM_GLIBC:
        raise ValueError("oldest supported Linux runtime glibc differs")

    reported = common.output(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--user",
            "65534:65534",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--platform",
            platform,
            "--volume",
            f"{binary}:/usr/local/bin/iicp-directory-rs:ro",
            "--entrypoint",
            "/usr/local/bin/iicp-directory-rs",
            RUNTIME_IMAGE,
            "--version",
        ],
        ROOT,
    )
    if version not in reported:
        raise ValueError("Bookworm runtime binary self-report differs")
    return binary, runtime_glibc


def describe() -> dict:
    return {
        "schema": "iicp.pre1-artifact-builder-description.v1",
        "component": COMPONENT,
        "targets": sorted(TARGETS),
        "target_artifact": "release-artifact",
        "portable_artifacts_on": PRIMARY_TARGET,
        "portable_artifacts": ["release-manifest"],
        "gates": sorted(common.GATES),
        "requires_clean_source": True,
        "requires_docker_buildx": True,
        "minimum_linux_runtime": {
            "distribution": "debian-bookworm",
            "glibc": MINIMUM_GLIBC,
            "runtime_image": RUNTIME_IMAGE,
        },
        "non_authorizing": True,
    }


def build(destination: Path, requested_target: str | None) -> dict:
    common.safe_output(destination)
    target = common.require_target(requested_target, TARGETS)
    commit = common.require_clean_source(ROOT)
    package = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]
    version = package["version"]
    if package.get("rust-version") != "1.88":
        raise ValueError("Rust Directory MSRV differs from the qualification policy")
    run_root = Path(tempfile.mkdtemp(prefix="iicp-pre1-rust-directory-", dir=destination.parent))
    staging = run_root / "fragment"
    staging.mkdir()
    try:
        quality_env = rust_build.cargo_environment(run_root, "quality")
        common.run(["cargo", "test", "--locked"], ROOT, quality_env)
        built_binary, runtime_glibc = build_portable_binary(run_root, target, version)
        crate, extracted, bundle, cache_digest = rust_build.package_and_vendor(
            ROOT, run_root, "iicp-directory-rs", version
        )
        del crate
        online = rust_build.install_and_report(
            ROOT, run_root, extracted, "iicp-directory-rs", version, offline=False
        )
        offline = rust_build.install_and_report(
            ROOT, run_root, bundle / "source", "iicp-directory-rs", version, offline=True
        )
        if online != offline:
            raise ValueError("online and offline Rust Directory self-reports differ")

        suffix = ".exe" if os.name == "nt" else ""
        binary = staging / f"iicp-directory-rs-{version}-{target}{suffix}"
        shutil.copyfile(built_binary, binary)
        artifacts = [common.artifact("release-artifact", target, binary)]
        if target == PRIMARY_TARGET:
            manifest_path = staging / f"iicp-directory-rs-{version}-release-manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "schema": "iicp.pre1-directory-rust-release-manifest.v1",
                        "product": "iicp-directory-rs",
                        "version": version,
                        "source_commit": commit,
                        "status": "operator_preview",
                        "production_authority": False,
                        "genesis_cutover_authorized": False,
                        "publication_authorized": False,
                        "non_authorizing": True,
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            )
            artifacts.append(common.artifact("release-manifest", "any", manifest_path))
        fragment = common.emit_fragment(
            staging,
            component=COMPONENT,
            source_commit=commit,
            source_version=version,
            build_target=target,
            artifacts=artifacts,
            lock_inputs_sha256=common.files_sha256(
                ROOT,
                [ROOT / "Cargo.toml", ROOT / "Cargo.lock", ARTIFACT_DOCKERFILE],
            ),
            dependency_cache_sha256=cache_digest,
            toolchains={
                "cargo": common.output(["cargo", "--version"], ROOT),
                "rustc": common.output(["rustc", "--version"], ROOT),
                "retained_binary_builder_image": BUILDER_IMAGE,
                "retained_binary_runtime_image": RUNTIME_IMAGE,
                "retained_binary_runtime_glibc": runtime_glibc,
            },
        )
        common.publish_staging(staging, destination)
        return fragment
    finally:
        common.clean_failed_staging(run_root)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--describe", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--target")
    args = parser.parse_args()
    if args.describe:
        print(json.dumps(describe(), indent=2, sort_keys=True))
        return 0
    if args.output is None:
        parser.error("--output is required unless --describe is used")
    try:
        value = build(args.output.resolve(), args.target)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(value, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
