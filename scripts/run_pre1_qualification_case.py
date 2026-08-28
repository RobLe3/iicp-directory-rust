#!/usr/bin/env python3
"""Run one exact, content-free pre-1.0 qualification case for directory-rust."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPONENT = 'directory-rust'
RUNTIMES = ['msrv-1.88', 'rust-1.98.0']
TARGETS = ['linux-x86_64', 'linux-aarch64']
DIRECTORIES = ['rust']
MODES = ['public', 'restricted', 'local-only']
CASE_MAP_PATH = ROOT / "qualification/pre1-cases.json"
CASE_MAP = json.loads(CASE_MAP_PATH.read_text(encoding="utf-8"))
if (
    CASE_MAP.get("schema") != "iicp.pre1-component-case-map.v2"
    or CASE_MAP.get("component") != COMPONENT
    or CASE_MAP.get("network_policy") != "isolated-fixtures-only"
    or CASE_MAP.get("evidence_policy") != "digest-only"
    or CASE_MAP.get("non_authorizing") is not True
):
    raise RuntimeError("invalid component qualification case map")
SUPPORT_CASE = CASE_MAP["support"]
SCENARIO_CASES = CASE_MAP["scenarios"]


def _case_command(value: object, label: str) -> list[str]:
    if not isinstance(value, dict) or set(value) != {"assertion", "command"}:
        raise RuntimeError(f"invalid exact qualification case: {label}")
    assertion = value.get("assertion")
    command = value.get("command")
    if (
        not isinstance(assertion, str)
        or not assertion
        or not isinstance(command, list)
        or not command
        or not all(isinstance(row, str) and row for row in command)
        or command[:3] != ["@cargo", "test", "--locked"]
        or command[-3] != assertion
        or command[-2:] != ["--", "--exact"]
    ):
        raise RuntimeError(f"qualification case is not an exact Rust assertion: {label}")
    return command


SUPPORT_COMMAND = _case_command(SUPPORT_CASE, "support")
SCENARIO_COMMANDS = {
    scenario: _case_command(value, scenario)
    for scenario, value in SCENARIO_CASES.items()
}
_assertions = [
    SUPPORT_CASE["assertion"],
    *(row["assertion"] for row in SCENARIO_CASES.values()),
]
if len(_assertions) != len(set(_assertions)):
    raise RuntimeError("qualification cases must bind unique exact Rust assertions")


def canonical_sha256(value: object) -> str:
    body = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return "sha256:" + hashlib.sha256(body).hexdigest()


def description() -> dict:
    return {
        "schema": "iicp.pre1-component-driver-description.v1",
        "component": COMPONENT,
        "runtimes": RUNTIMES,
        "targets": TARGETS,
        "directory_flavors": DIRECTORIES,
        "modes": MODES,
        "scenarios": sorted(SCENARIO_COMMANDS),
        "network_policy": "isolated-fixtures-only",
        "evidence_policy": "digest-only",
        "artifact_consumption": "verified-candidate-root",
        "source_commit_binding": True,
        "semantic_binding": {
            "contract": "iicp.pre1-semantic-assertion-binding.v1",
            "exact_assertion_per_scenario": True,
            "exact_assertion_discovery_required": True,
            "cell_dimensions_consumed": [
                "runtime",
                "target",
                "directory_flavor",
                "mode",
                "cell_id",
                "scenario_id",
            ],
            "negative_controls_passed": True,
            "packaged_artifact_gate": "required-per-execution",
            "offline_environment_gate": "required-per-execution",
        },
        "commands_sha256": canonical_sha256({"support": SUPPORT_COMMAND, "scenarios": SCENARIO_COMMANDS}),
        "non_authorizing": True,
    }


def parse_cell(value: str) -> tuple[str, str, str, str, str]:
    parts = tuple(value.split("|"))
    if len(parts) != 5:
        raise ValueError("qualification cell must contain five fields")
    component, runtime, target, directory, mode = parts
    if component != COMPONENT:
        raise ValueError("qualification cell belongs to a different component")
    if runtime not in RUNTIMES or target not in TARGETS or directory not in DIRECTORIES or mode not in MODES:
        raise ValueError("qualification cell is outside the component support boundary")
    return component, runtime, target, directory, mode


def detected_target() -> str | None:
    system = platform.system().lower()
    machine = platform.machine().lower()
    arch = "x86_64" if machine in {"x86_64", "amd64"} else "arm64" if machine in {"arm64", "aarch64"} else None
    if arch is None:
        return None
    return {"darwin": f"macos-{arch}", "linux": f"linux-{'aarch64' if arch == 'arm64' else arch}", "windows": f"windows-{arch}"}.get(system)


def load_json_environment(name: str) -> tuple[Path, dict]:
    raw = os.environ.get(name)
    if not raw:
        raise ValueError(f"missing {name}")
    path = Path(raw)
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"unsafe {name}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"invalid {name}")
    return path, value


def valid_digest(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def artifact_materialization_sha256(manifest: dict, artifact_root: Path) -> str:
    records: list[dict] = []
    expected_directories = {row["id"] for row in manifest.get("components", [])}
    if {entry.name for entry in artifact_root.iterdir()} != expected_directories:
        raise ValueError("qualification artifact materialization component set differs")
    for component in manifest.get("components", []):
        component_root = artifact_root / component["id"]
        expected = {row["name"] for row in component.get("artifacts", [])} | {
            "package-manifest.json",
            "build-receipt.json",
        }
        if (
            not component_root.is_dir()
            or component_root.is_symlink()
            or {entry.name for entry in component_root.iterdir()} != expected
        ):
            raise ValueError("qualification component artifact set differs")
        for artifact in component.get("artifacts", []):
            path = component_root / artifact["name"]
            if not path.is_file() or path.is_symlink():
                raise ValueError("qualification artifact is unsafe")
            digest = file_sha256(path)
            size = path.stat().st_size
            if digest != artifact.get("sha256") or size != artifact.get("size_bytes"):
                raise ValueError("qualification artifact digest or size differs")
            records.append(
                {
                    "component": component["id"],
                    "name": artifact["name"],
                    "kind": artifact["kind"],
                    "target": artifact["target"],
                    "size_bytes": size,
                    "sha256": digest,
                }
            )
        for name, kind, digest_field in (
            ("package-manifest.json", "package_manifest", "package_manifest_sha256"),
            ("build-receipt.json", "build_receipt", "build_receipt_sha256"),
        ):
            path = component_root / name
            if not path.is_file() or path.is_symlink():
                raise ValueError("qualification artifact companion is unsafe")
            digest = file_sha256(path)
            if digest != component.get(digest_field):
                raise ValueError("qualification artifact companion digest differs")
            records.append(
                {
                    "component": component["id"],
                    "name": name,
                    "kind": kind,
                    "target": "any",
                    "size_bytes": path.stat().st_size,
                    "sha256": digest,
                }
            )
    return canonical_sha256(sorted(records, key=lambda row: (row["component"], row["name"])))


def semantic_execution_context(
    cell: str,
    scenario: str | None,
    candidate_digest: str,
    materialization_digest: str,
    runtime_map_digest: str,
    environment_digest: str,
) -> dict:
    component, runtime, target, directory, mode = parse_cell(cell)
    return {
        "schema": "iicp.pre1-semantic-execution-context.v1",
        "component": component,
        "runtime": runtime,
        "target": target,
        "directory_flavor": directory,
        "mode": mode,
        "cell_id": cell,
        "scenario_id": scenario or "support",
        "candidate_manifest_sha256": candidate_digest,
        "artifact_materialization_sha256": materialization_digest,
        "runtime_map_sha256": runtime_map_digest,
        "qualification_environment_sha256": environment_digest,
        "network_policy": "isolated-fixtures-only",
        "evidence_policy": "digest-only",
    }


def _validate_environment_manifest(
    value: dict,
    *,
    target: str,
    runtime: str,
    candidate_digest: str,
    materialization_digest: str,
    runtime_map_digest: str,
) -> str:
    if (
        value.get("schema") != "iicp.pre1-qualification-environment.v1"
        or value.get("status") != "READY"
        or value.get("target") != target
        or value.get("content_free") is not True
        or value.get("secrets_present") is not False
        or value.get("non_authorizing") is not True
    ):
        raise ValueError("qualification environment boundary differs")
    bindings = value.get("bindings", {})
    expected = {
        "candidate_manifest_sha256": candidate_digest,
        "artifact_materialization_sha256": materialization_digest,
        "runtime_map_sha256": runtime_map_digest,
    }
    if any(bindings.get(name) != digest for name, digest in expected.items()):
        raise ValueError("qualification environment immutable binding differs")
    runtime_row = value.get("runtimes", {}).get(runtime)
    if not isinstance(runtime_row, dict) or any(
        runtime_row.get(field) != "PASS"
        for field in (
            "online_prepare_status",
            "offline_install_status",
            "package_artifact_smoke_status",
        )
    ):
        raise ValueError("qualification package or offline environment gate differs")
    if (
        runtime_row.get("egress_disabled_during_offline") is not True
        or runtime_row.get("empty_volatile_cache_at_start") is not True
    ):
        raise ValueError("qualification offline safety boundary differs")
    claimed = value.get("environment_sha256")
    copy = json.loads(json.dumps(value))
    copy["environment_sha256"] = None
    if not valid_digest(claimed) or claimed != canonical_sha256(copy):
        raise ValueError("qualification environment digest differs")
    return str(claimed)


def validate_context(cell: str, scenario: str | None) -> tuple[str, dict, dict, dict]:
    _component, runtime, target, directory, mode = parse_cell(cell)
    if detected_target() != target:
        raise ValueError("qualification target differs from the actual host")
    if os.environ.get("IICP_PRE1_CELL_ID") != cell:
        raise ValueError("qualification cell environment differs")
    if os.environ.get("IICP_PRE1_SCENARIO_ID") != (scenario or "support"):
        raise ValueError("qualification scenario environment differs")
    if os.environ.get("IICP_PRE1_NETWORK_POLICY") != "isolated-fixtures-only":
        raise ValueError("qualification network policy differs")
    if os.environ.get("IICP_PRE1_EVIDENCE_POLICY") != "digest-only":
        raise ValueError("qualification evidence policy differs")
    home = Path(os.environ.get("HOME", ""))
    iicp_home = Path(os.environ.get("IICP_HOME", ""))
    if (
        not home.is_dir()
        or home.is_symlink()
        or not iicp_home.resolve(strict=False).is_relative_to(home.resolve())
    ):
        raise ValueError("qualification HOME is not isolated")

    _manifest_path, manifest = load_json_environment("IICP_PRE1_CANDIDATE_MANIFEST")
    candidate_digest = os.environ.get("IICP_PRE1_CANDIDATE_DIGEST")
    if manifest.get("status") != "FROZEN" or manifest.get("immutable") is not True or manifest.get("manifest_sha256") != candidate_digest:
        raise ValueError("qualification candidate binding is not immutable")
    component = next((row for row in manifest.get("components", []) if row.get("id") == COMPONENT), None)
    if not isinstance(component, dict) or component.get("state") != "BUILT":
        raise ValueError("qualification component artifact set is not built")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if head != component.get("source_commit"):
        raise ValueError("qualification source commit differs from the candidate")

    artifact_root = Path(os.environ.get("IICP_PRE1_ARTIFACT_ROOT", ""))
    component_root = artifact_root / COMPONENT
    if not artifact_root.is_dir() or artifact_root.is_symlink() or not component_root.is_dir() or component_root.is_symlink():
        raise ValueError("qualification artifact root is unsafe")
    materialization_digest = artifact_materialization_sha256(manifest, artifact_root)
    if os.environ.get("IICP_PRE1_ARTIFACT_MATERIALIZATION_SHA256") != materialization_digest:
        raise ValueError("qualification artifact materialization binding differs")

    _runtime_path, runtime_map = load_json_environment("IICP_PRE1_RUNTIME_MAP")
    if runtime_map.get("schema") != "iicp.pre1-runtime-map.v1" or runtime_map.get("target") != target:
        raise ValueError("qualification runtime map target differs")
    runtime_row = runtime_map.get("runtimes", {}).get(runtime)
    if not isinstance(runtime_row, dict):
        raise ValueError("qualification runtime is unavailable")
    runtime_map_digest = runtime_map.get("map_sha256")
    if (
        not valid_digest(runtime_map_digest)
        or os.environ.get("IICP_PRE1_RUNTIME_MAP_SHA256") != runtime_map_digest
    ):
        raise ValueError("qualification runtime map binding differs")
    _environment_path, environment = load_json_environment(
        "IICP_PRE1_ENVIRONMENT_MANIFEST"
    )
    environment_digest = _validate_environment_manifest(
        environment,
        target=target,
        runtime=runtime,
        candidate_digest=str(candidate_digest),
        materialization_digest=materialization_digest,
        runtime_map_digest=str(runtime_map_digest),
    )
    if os.environ.get("IICP_PRE1_QUALIFICATION_ENVIRONMENT_SHA256") != environment_digest:
        raise ValueError("qualification environment binding differs")
    context = semantic_execution_context(
        cell,
        scenario,
        str(candidate_digest),
        materialization_digest,
        str(runtime_map_digest),
        environment_digest,
    )
    expected_environment = {
        "IICP_PRE1_RUNTIME": runtime,
        "IICP_PRE1_TARGET": target,
        "IICP_PRE1_DIRECTORY_FLAVOR": directory,
        "IICP_PRE1_MODE": mode,
        "IICP_PRE1_CONTEXT_SHA256": canonical_sha256(context),
    }
    if any(os.environ.get(name) != value for name, value in expected_environment.items()):
        raise ValueError("qualification semantic context differs")
    return runtime, runtime_row, manifest, context


def expected_runtime_version(runtime: str, manifest: dict) -> str:
    if runtime.startswith("cpython-") or runtime.startswith("node-") or runtime.startswith("php-"):
        return runtime.split("-", 1)[1]
    if runtime.startswith("rust-"):
        expected = str(manifest["toolchains"]["rust_stable"])
        if runtime != f"rust-{expected}":
            raise ValueError("qualification stable Rust runtime differs from the candidate")
        return expected
    field = {"client-rust": "rust_client_msrv", "directory-rust": "rust_directory_msrv", "management": "management_msrv"}[COMPONENT]
    return str(manifest["toolchains"][field])


def validate_runtime(runtime: str, runtime_row: dict, manifest: dict) -> None:
    programs = runtime_row.get("programs", {})
    expected = expected_runtime_version(runtime, manifest)
    if runtime.startswith("cpython-"):
        argv = [programs["python"], "-c", "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"]
    elif runtime.startswith("node-"):
        argv = [programs["node"], "-p", "process.versions.node.split('.').slice(0,1).join('.')"]
    elif runtime.startswith("php-"):
        argv = [programs["php"], "-r", "echo PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION;"]
    else:
        argv = [programs["rustc"], "--version"]
    observed = subprocess.check_output(argv, cwd=ROOT, env=command_environment(runtime_row, runtime), text=True, stderr=subprocess.STDOUT).strip()
    if runtime.startswith(("cpython-", "node-", "php-")):
        if observed != expected:
            raise ValueError("qualification runtime version differs")
    else:
        match = re.match(r"rustc (\d+\.\d+\.\d+)", observed)
        if match is None or match.group(1) != expected:
            raise ValueError("qualification Rust version differs")


def command_environment(runtime_row: dict, runtime: str) -> dict[str, str]:
    allowed = {"PATH", "HOME", "IICP_HOME", "LANG", "LC_ALL", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP", "TMPDIR", "RUSTUP_HOME"}
    env = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    for name in (
        "IICP_PRE1_CELL_ID",
        "IICP_PRE1_SCENARIO_ID",
        "IICP_PRE1_NETWORK_POLICY",
        "IICP_PRE1_EVIDENCE_POLICY",
        "IICP_PRE1_ARTIFACT_ROOT",
        "IICP_PRE1_CANDIDATE_MANIFEST",
        "IICP_PRE1_CANDIDATE_DIGEST",
        "IICP_PRE1_RUNTIME_MAP",
        "IICP_PRE1_ENVIRONMENT_MANIFEST",
        "IICP_PRE1_RUNTIME",
        "IICP_PRE1_TARGET",
        "IICP_PRE1_DIRECTORY_FLAVOR",
        "IICP_PRE1_MODE",
        "IICP_PRE1_ARTIFACT_MATERIALIZATION_SHA256",
        "IICP_PRE1_RUNTIME_MAP_SHA256",
        "IICP_PRE1_QUALIFICATION_ENVIRONMENT_SHA256",
        "IICP_PRE1_CONTEXT_SHA256",
    ):
        env[name] = os.environ[name]
    env.update(runtime_row.get("env", {}))
    cache = Path(env["IICP_HOME"]) / "qualification-cache" / COMPONENT / runtime
    cache.mkdir(parents=True, exist_ok=True)
    env["CARGO_TARGET_DIR"] = str(cache / "cargo-target")
    env["PIP_NO_INDEX"] = "1"
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    env["npm_config_offline"] = "true"
    env["npm_config_audit"] = "false"
    env["npm_config_update_notifier"] = "false"
    env["NO_COLOR"] = "1"
    manifest = json.loads(Path(env["IICP_PRE1_CANDIDATE_MANIFEST"]).read_text())
    component = next(row for row in manifest["components"] if row["id"] == COMPONENT)
    release_manifest = next(
        row for row in component["artifacts"] if row["kind"] == "release-manifest"
    )
    env["IICP_RELEASE_MANIFEST"] = str(
        Path(env["IICP_PRE1_ARTIFACT_ROOT"])
        / COMPONENT
        / release_manifest["name"]
    )
    return env


def expand_command(template: list[str], runtime_row: dict) -> list[str]:
    programs = runtime_row["programs"]
    aliases = {"@python": "python", "@node": "node", "@npm": "npm", "@npx": "npx", "@cargo": "cargo", "@rustc": "rustc", "@php": "php"}
    first = aliases.get(template[0])
    if first is None or first not in programs:
        raise ValueError("qualification command is not bound to the selected runtime")
    return [programs[first], *template[1:]]


def exact_assertion_is_listed(output: str, assertion: str) -> bool:
    matches = [
        line
        for line in output.splitlines()
        if line.strip() == f"{assertion}: test"
    ]
    return len(matches) == 1


def verify_exact_assertion(argv: list[str], assertion: str, env: dict[str, str]) -> None:
    probe = subprocess.run(
        [*argv, "--list"],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if probe.returncode != 0 or not exact_assertion_is_listed(
        probe.stdout, assertion
    ):
        raise ValueError("qualification exact assertion is unavailable on this target")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cell")
    parser.add_argument("--scenario")
    parser.add_argument("--evidence-mode", choices=["digest-only"])
    parser.add_argument("--describe", action="store_true")
    args = parser.parse_args()
    if args.describe:
        if args.cell or args.scenario or args.evidence_mode:
            parser.error("--describe cannot execute a qualification case")
        print(json.dumps(description(), sort_keys=True))
        return 0
    if not args.cell or args.evidence_mode != "digest-only":
        parser.error("qualification execution requires --cell and --evidence-mode digest-only")
    if args.scenario is not None and args.scenario not in SCENARIO_COMMANDS:
        parser.error("scenario is not owned by this component")
    try:
        runtime, runtime_row, manifest, _context = validate_context(
            args.cell, args.scenario
        )
        validate_runtime(runtime, runtime_row, manifest)
        case = SCENARIO_CASES[args.scenario] if args.scenario else SUPPORT_CASE
        template = case["command"]
        argv = expand_command(template, runtime_row)
        env = command_environment(runtime_row, runtime)
        verify_exact_assertion(argv, case["assertion"], env)
        result = subprocess.run(argv, cwd=ROOT, env=env, check=False)
    except (KeyError, OSError, ValueError, json.JSONDecodeError, subprocess.CalledProcessError) as error:
        print(f"pre-1.0 {COMPONENT} case refused: {error}", file=sys.stderr)
        return 2
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
