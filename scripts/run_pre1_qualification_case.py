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
RUNTIMES = ['msrv-1.88', 'candidate-stable-pinned']
TARGETS = ['linux-x86_64', 'linux-aarch64']
DIRECTORIES = ['rust']
MODES = ['public', 'restricted', 'local-only']
CASE_MAP_PATH = ROOT / "qualification/pre1-cases.json"
CASE_MAP = json.loads(CASE_MAP_PATH.read_text(encoding="utf-8"))
if (
    CASE_MAP.get("schema") != "iicp.pre1-component-case-map.v1"
    or CASE_MAP.get("component") != COMPONENT
    or CASE_MAP.get("network_policy") != "isolated-fixtures-only"
    or CASE_MAP.get("evidence_policy") != "digest-only"
    or CASE_MAP.get("non_authorizing") is not True
):
    raise RuntimeError("invalid component qualification case map")
SUPPORT_COMMAND = CASE_MAP["support_command"]
SCENARIO_COMMANDS = CASE_MAP["scenario_commands"]


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


def validate_context(cell: str, scenario: str | None) -> tuple[str, dict, dict]:
    _component, runtime, target, _directory, _mode = parse_cell(cell)
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

    manifest_path, manifest = load_json_environment("IICP_PRE1_CANDIDATE_MANIFEST")
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
    expected = {row["name"] for row in component.get("artifacts", [])} | {"package-manifest.json", "build-receipt.json"}
    if {entry.name for entry in component_root.iterdir()} != expected or any(entry.is_symlink() for entry in component_root.iterdir()):
        raise ValueError("qualification component artifact set differs")

    _runtime_path, runtime_map = load_json_environment("IICP_PRE1_RUNTIME_MAP")
    if runtime_map.get("schema") != "iicp.pre1-runtime-map.v1" or runtime_map.get("target") != target:
        raise ValueError("qualification runtime map target differs")
    runtime_row = runtime_map.get("runtimes", {}).get(runtime)
    if not isinstance(runtime_row, dict):
        raise ValueError("qualification runtime is unavailable")
    return runtime, runtime_row, manifest


def expected_runtime_version(runtime: str, manifest: dict) -> str:
    if runtime.startswith("cpython-") or runtime.startswith("node-") or runtime.startswith("php-"):
        return runtime.split("-", 1)[1]
    if runtime == "candidate-stable-pinned":
        return str(manifest["toolchains"]["rust_stable"])
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
    for name in ("IICP_PRE1_CELL_ID", "IICP_PRE1_SCENARIO_ID", "IICP_PRE1_NETWORK_POLICY", "IICP_PRE1_EVIDENCE_POLICY", "IICP_PRE1_ARTIFACT_ROOT", "IICP_PRE1_CANDIDATE_MANIFEST", "IICP_PRE1_CANDIDATE_DIGEST", "IICP_PRE1_RUNTIME_MAP"):
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
    return env


def expand_command(template: list[str], runtime_row: dict) -> list[str]:
    programs = runtime_row["programs"]
    aliases = {"@python": "python", "@node": "node", "@npm": "npm", "@npx": "npx", "@cargo": "cargo", "@rustc": "rustc", "@php": "php"}
    first = aliases.get(template[0])
    if first is None or first not in programs:
        raise ValueError("qualification command is not bound to the selected runtime")
    return [programs[first], *template[1:]]


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
        runtime, runtime_row, manifest = validate_context(args.cell, args.scenario)
        validate_runtime(runtime, runtime_row, manifest)
        template = SCENARIO_COMMANDS[args.scenario] if args.scenario else SUPPORT_COMMAND
        argv = expand_command(template, runtime_row)
        result = subprocess.run(argv, cwd=ROOT, env=command_environment(runtime_row, runtime), check=False)
    except (KeyError, OSError, ValueError, json.JSONDecodeError, subprocess.CalledProcessError) as error:
        print(f"pre-1.0 {COMPONENT} case refused: {error}", file=sys.stderr)
        return 2
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
