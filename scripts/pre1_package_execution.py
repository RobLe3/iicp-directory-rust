"""Bind staged assertions to byte-verified installed frozen component payloads.

Preparation never installs dependencies or grants qualification credit. The
caller owns network isolation, runtime selection and workspace lifetime.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

def directory_output_exit_code(code, output, context, assertion, root):
    """Preserve native failure; accept only the owned scenario's bounded output."""
    if code:
        return code
    try:
        validate_directory_output(output, context, assertion, root)
    except (ValueError, KeyError, TypeError, OSError, UnicodeError):
        return 2
    return 0


def validate_directory_output(output, context, assertion, root):
    if not isinstance(output, str) or len(output.encode()) > 1048576:
        raise ValueError("Directory output exceeds bound")
    rows = output.splitlines()
    marker = "IICP_PRE1_DIRECTORY_ASSERTION_PASS " + assertion
    if context["scenario_id"] == "no-dual-authority":
        validate_comparative_topology_output(rows, marker, context)
        return
    if context["scenario_id"] != "cross-flavor-equivalence":
        if rows != [marker]:
            raise ValueError("Directory exact assertion output differs")
        return
    if len(rows) != 5 or rows[-1] != marker or rows[1] != "IICP_PRE1_REGISTRATION_TRANSPORT tcp":
        raise ValueError("Directory observed assertion output differs")
    registration = directory_observation_json(rows[0], "IICP_PRE1_REGISTRATION_OBSERVATION ")
    discovery = directory_observation_json(rows[2], "IICP_PRE1_INSTALLED_DISCOVERY_OBSERVATION ")
    path = safe_path(root / "parity/behavior-contract-v1.json")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != "61f84608db554cf2a3da02c46e01f27c77e57c9553ade0da8c5a017860d73f3f":
        raise ValueError("Directory output fixture differs")
    contract = json.loads(raw)
    expected = {row["name"]: row["expected"] for row in contract["registration_cases"]}
    if not directory_observation_equal(registration, expected):
        raise ValueError("Directory registration output differs")
    validate_directory_discovery_output(discovery, context, contract)
    endpoints = directory_observation_json(rows[3], "IICP_PRE1_INSTALLED_ENDPOINT_OBSERVATION ")
    validate_directory_endpoint_output(endpoints, context, contract)


def validate_comparative_topology_output(rows, marker, context):
    if len(rows) != 2 or rows[1] != marker:
        raise ValueError("Directory comparative topology output differs")
    value = directory_observation_json(rows[0], "IICP_PRE1_DIRECTORY_TOPOLOGY ")
    component = context["component"]
    expected = {"schema": "iicp.pre1-directory-comparative-topology.v1",
        "component": component, "mode": context["mode"],
        "peer_port": 8090 if component == "directory-php" else 8091,
        "own_http_observed": True,
        "scope": "declared-peer-port-in-one-isolated-network-namespace",
        "global_authority_established": False}
    if (not isinstance(value, dict) or set(value) != {*expected, "address_families", "own_listener_observations"}
            or any(value.get(key) != item for key, item in expected.items())
            or value.get("address_families") not in (["ipv4"], ["ipv4", "ipv6"])
            or type(value.get("own_listener_observations")) is not int
            or not 1 <= value["own_listener_observations"] <= 10000):
        raise ValueError("Directory comparative topology proof differs")


def directory_observation_json(row, prefix):
    if not row.startswith(prefix) or len(row.encode()) > 65536:
        raise ValueError("Directory observation marker differs")
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Directory duplicate observation key")
            value[key] = item
        return value
    def invalid(value):
        raise ValueError("Directory nonfinite observation")
    return json.loads(row[len(prefix):], object_pairs_hook=unique, parse_constant=invalid)


def directory_observation_equal(actual, expected):
    import math
    if type(expected) in (int, float):
        return type(actual) in (int, float) and math.isfinite(actual) and actual == expected
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(actual) == set(expected) and all(directory_observation_equal(actual[k], v) for k, v in expected.items())
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(directory_observation_equal(a, b) for a, b in zip(actual, expected))
    return actual == expected


def validate_directory_discovery_output(value, context, contract):
    fields = {"scope", "mode", "fixture_sha256", "observations", "qualification_credit", "production_endpoint_validation"}
    flavor = context["component"]
    if (not isinstance(value, dict) or set(value) != fields or flavor not in {"directory-php", "directory-rust"}
            or context["mode"] not in {"local-only", "public", "restricted"} or value["mode"] != context["mode"]
            or value["scope"] != "installed-" + flavor.removeprefix("directory-") + "-tcp-discovery-and-registration-pricing"
            or value["fixture_sha256"] != "sha256:61f84608db554cf2a3da02c46e01f27c77e57c9553ade0da8c5a017860d73f3f"
            or value["qualification_credit"] is not False or value["production_endpoint_validation"] is not False):
        raise ValueError("Directory discovery output scope differs")
    expected = {group + "/" + row["name"]: (group, row)
        for group in ("eligibility_cases", "ranking_cases", "pricing_cases") for row in contract[group]}
    rows = value["observations"]
    if not isinstance(rows, dict) or set(rows) != set(expected):
        raise ValueError("Directory discovery output coverage differs")
    for key, (group, case) in expected.items():
        if group == "pricing_cases":
            if not directory_observation_equal(rows[key], case["expected"]):
                raise ValueError("Directory pricing output differs")
        else:
            validate_directory_selection_output(rows[key], group, case)


def validate_directory_endpoint_output(value, context, contract):
    fields = {"scope", "mode", "fixture_sha256", "app_env", "observations", "qualification_credit"}
    flavor = context["component"]
    if (not isinstance(value, dict) or set(value) != fields
            or flavor not in {"directory-php", "directory-rust"}
            or context["mode"] not in {"local-only", "public", "restricted"}
            or value["mode"] != context["mode"] or value["app_env"] != "production"
            or value["scope"] != "installed-" + flavor.removeprefix("directory-") + "-tcp-production-endpoints"
            or value["fixture_sha256"] != "sha256:61f84608db554cf2a3da02c46e01f27c77e57c9553ade0da8c5a017860d73f3f"
            or value["qualification_credit"] is not False):
        raise ValueError("Directory endpoint output scope differs")
    expected = {"endpoint_cases/" + row["name"]: {
        "blocked": row["blocked"], "status": 422, "reason": "IICP-E035" if row["blocked"] else "IICP-E036",
        "node_rows": 0, "capability_rows": 0, "availability_rows": 0} for row in contract["endpoint_cases"]}
    if not directory_observation_equal(value["observations"], expected):
        raise ValueError("Directory endpoint output coverage or refusal differs")


def validate_directory_selection_output(value, group, case):
    if not isinstance(value, dict) or set(value) != {"eligible_ids", "recommendation_order", "scores"}:
        raise ValueError("Directory selection output differs")
    ids, order, scores = value["eligible_ids"], value["recommendation_order"], value["scores"]
    validate_directory_selection_values(ids, order, scores)
    expected = sorted(case["expected_ids"]) if group == "eligibility_cases" else (
        [] if case["requested_model"] == "missing-model" else ["fixture-http-ranking"])
    if ids != expected or (group == "ranking_cases" and ids and scores != [case["expected"]]):
        raise ValueError("Directory selection output contract differs")



def validate_directory_selection_values(ids, order, scores):
    import math
    if any(not isinstance(value, list) for value in (ids, order, scores)):
        raise ValueError("Directory selection output lists differ")
    if any(not isinstance(value, str) for value in ids + order):
        raise ValueError("Directory selection output identifiers differ")
    if len(set(order)) != len(order) or sorted(order) != ids or len(scores) != len(order):
        raise ValueError("Directory selection output coverage differs")
    if any(type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 1 for value in scores):
        raise ValueError("Directory selection output scores differ")
    if scores != sorted(scores, reverse=True):
        raise ValueError("Directory selection output order differs")


SCHEMA = "iicp.pre1-package-execution.v1"
BINDINGS = (
    "candidate_manifest_sha256", "artifact_materialization_sha256",
    "runtime_map_sha256", "qualification_environment_sha256",
)
PYTHON_GUARD = '''import os, sys
from pathlib import Path
import pytest

def check_origin():
    import iicp_client
    root = Path(os.environ["IICP_PRE1_INSTALLED_PACKAGE"]).resolve()
    for name, module in tuple(sys.modules.items()):
        if name == "iicp_client" or name.startswith("iicp_client."):
            origin = getattr(module, "__file__", None)
            if origin is None or not Path(origin).resolve().is_relative_to(root):
                raise RuntimeError("packaged Python import origin differs")

def pytest_sessionstart(session):
    check_origin()

reports = []

def pytest_runtest_logreport(report):
    reports.append(report)

def pytest_sessionfinish(session, exitstatus):
    calls = [report for report in reports if report.when == "call"]
    if len(calls) != 1 or any(not r.passed or hasattr(r, "wasxfail") for r in reports):
        session.exitstatus = 2
    check_origin()

@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item):
    check_origin()
    yield
    check_origin()
'''


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode()).hexdigest()


def file_digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def safe_path(path: Path) -> Path:
    if not path.is_absolute() or not path.exists():
        raise ValueError("package execution path must exist and be absolute")
    if any(unsafe_link(p) for p in (path, *path.parents)):
        raise ValueError("package execution path contains a symlink")
    return path.resolve()


def unsafe_link(path: Path) -> bool:
    attributes = getattr(path.lstat(), "st_file_attributes", 0)
    return path.is_symlink() or bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def tree(path: Path) -> dict[str, str]:
    safe_path(path)
    result = {}
    for item in sorted(path.rglob("*")):
        if unsafe_link(item):
            raise ValueError("package execution tree contains a symlink")
        if item.is_file():
            if "__pycache__" in item.parts or item.suffix == ".pyc":
                continue
            result[item.relative_to(path).as_posix()] = file_digest(item)
        elif not item.is_dir():
            raise ValueError("package execution tree contains a special file")
    return result


def installed_payload(artifact: Path, installed: Path, component: str) -> dict[str, str]:
    """Require exact package-file equality, not a self-reported install receipt."""
    safe_path(artifact)
    readers = {"client-python": wheel_payload, "client-typescript": tarball_payload}
    if component not in readers:
        raise ValueError("no packaged adapter for this component")
    expected = readers[component](artifact)
    if not expected or any(
        Path(name).is_absolute() or ".." in Path(name).parts for name in expected
    ) or tree(installed) != expected:
        raise ValueError("installed SDK differs from the frozen package payload")
    return expected



def wheel_payload(artifact: Path) -> dict[str, str]:
    expected = {}
    with zipfile.ZipFile(artifact, "r") as archive:
        for row in archive.infolist():
            if row.filename.startswith("iicp_client/") and not row.is_dir():
                name = row.filename.removeprefix("iicp_client/")
                expected[name] = "sha256:" + hashlib.sha256(archive.read(row)).hexdigest()
    return expected


def tarball_payload(artifact: Path) -> dict[str, str]:
    expected = {}
    with tarfile.open(artifact, "r:gz") as archive:
        for row in archive.getmembers():
            if row.isfile() and row.name.startswith("package/"):
                name = row.name.removeprefix("package/")
                handle = archive.extractfile(row)
                if handle is None:
                    raise ValueError("package archive file is unavailable")
                expected[name] = "sha256:" + hashlib.sha256(handle.read()).hexdigest()
            elif row.issym() or row.islnk():
                raise ValueError("package archive contains a link")
    return expected


def dependencies(workspace: Path, installed: Path, component: str) -> dict[str, str]:
    base = installed.parent if component == "client-python" else workspace / "node_modules"
    rows = {}
    safe_path(base)
    for item in sorted(base.rglob("*")):
        name = item.relative_to(base).as_posix()
        if "__pycache__" in item.parts or item.suffix == ".pyc":
            continue
        if unsafe_link(item):
            if not item.is_symlink() or component != "client-typescript" or not name.startswith(".bin/") or not item.resolve().is_relative_to(base):
                raise ValueError("test dependency contains an unsafe link")
            rows[name] = digest({"link": os.readlink(item), "target_sha256": file_digest(item.resolve())})
        elif item.is_file():
            rows[name] = file_digest(item)
        elif not item.is_dir():
            raise ValueError("test dependency contains a special file")
    return rows


def rewrite_typescript(text: str) -> str:
    """Redirect literal runtime/worker paths only; leave assertions unchanged."""
    def replace(match):
        prefix, name = match.groups()
        if ".." in Path(name).parts:
            raise ValueError("unsafe TypeScript source reference")
        name = re.sub(r"\.ts$", ".js", name)
        if not Path(name).suffix:
            name += ".js"
        return f"{prefix}node_modules/@iicp/client/dist/{name}"
    return re.sub(r"(\.{1,2}/)src/([A-Za-z0-9_./-]+)", replace, text)


def packaged_assertions(name: str, text: str) -> str:
    """Strengthen three reviewed source fixtures without changing their vectors.

    Crypto cases use the same canonical runtime API already exercised by each
    SDK's runtime-verifier suite. No test-local eligibility engine survives.
    Version qualification observes the compiled CLI, not its source spelling.
    These substitutions are fixture-digest and harness-commit bound.
    """
    if name == "tests/test_dispatch_ticket_trust_crypto.py":
        start = text.index("def _decision(vector: dict,")
        end = text.index("def _assert_fixture_decision", start)
        replacement = '''from iicp_client.dispatch_ticket_trust import (
    LocalReplayCache, TicketBindings, TrustBundle, verify_dispatch_ticket_v2,
)

def _decision(vector: dict, keys: dict[str, dict], signature_valid: bool) -> str:
    claims = vector["claims"]
    bundle = TrustBundle.from_dict({
        "bundle_version": 4,
        "keys": [keys[key_id] for key_id in vector["trust_bundle_key_ids"]],
    })
    replay = LocalReplayCache()
    if vector["jti_seen"]:
        replay.remember(claims["jti"], claims["expires_at"])
    return verify_dispatch_ticket_v2(
        claims, vector["signature_b64url"], bundle,
        TicketBindings(claims["issuer"], claims["provider_id"], claims["intent"], claims["constraints_digest"]),
        now=vector["now"], minimum_bundle_version=4, replay_cache=replay,
    ).code


'''
        return text[:start] + replacement + text[end:]
    if name == "tests/dispatch_ticket_trust_crypto.test.ts":
        start = text.index("function decision(vector: any,")
        end = text.index("function assertFixtureDecision", start)
        replacement = '''import { LocalDispatchReplayCache, verifyDispatchTicketV2 } from "../node_modules/@iicp/client/dist/dispatch_ticket_trust.js";

function decision(vector: any, keys: Map<string, any>, signatureValid: boolean): string {
  const replayCache = new LocalDispatchReplayCache();
  if (vector.jti_seen) replayCache.remember(vector.claims.jti, vector.claims.expires_at);
  return verifyDispatchTicketV2(
    vector.claims, vector.signature_b64url,
    { bundle_version: 4, keys: vector.trust_bundle_key_ids.map((id: string) => keys.get(id)) },
    { issuer: vector.claims.issuer, provider_id: vector.claims.provider_id,
      intent: vector.claims.intent, constraints_digest: vector.claims.constraints_digest },
    { now: vector.now, minimumBundleVersion: 4, replayCache },
  ).code;
}

'''
        return text[:start] + replacement + text[end:]
    if name == "tests/test_service_lifecycle.py":
        source_override = '    env = {**os.environ, "PYTHONPATH": str(Path(__file__).parents[1] / "src")}'
        if text.count(source_override) != 1:
            raise ValueError("reviewed lifecycle subprocess fixture shape differs")
        return text.replace(source_override, "    env = dict(os.environ)")
    if name == "tests/pre1_release_boundaries.test.ts":
        lines = text.splitlines()
        source_check = [line for line in lines if "assert.match(cli," in line]
        source_read = [line for line in lines if line.startswith("const cli = ")]
        if len(source_check) != 1 or len(source_read) != 1:
            raise ValueError("reviewed CLI source fixture shape differs")
        text = text.replace(source_read[0], 'import { spawnSync } from "node:child_process";\nimport { fileURLToPath } from "node:url";')
        return text.replace(source_check[0], '''  const version = spawnSync(process.execPath, [fileURLToPath(new URL("../node_modules/@iicp/client/dist/cli.js", import.meta.url)), "--version"], { encoding: "utf8" });
  assert.equal(version.status, 0);
  assert.equal(version.stdout.trim(), `iicp-node ${pkg.version}`);''')
    return text


def fixture_tree(workspace: Path) -> dict[str, str]:
    rows = {}
    for name in ("tests", "parity", "scripts", ".github"):
        if (workspace / name).exists():
            rows.update({f"{name}/{p}": h for p, h in tree(workspace / name).items()})
    for name in ("package.json", "package-lock.json", "pyproject.toml", "uv.lock", "pre1_origin_guard.py"):
        if (workspace / name).exists():
            safe_path(workspace / name)
            rows[name] = file_digest(workspace / name)
    if (workspace / "src").exists() or (workspace / "iicp_client").exists():
        raise ValueError("staged workspace contains checkout runtime source")
    return rows


def assertion_files(root: Path, component: str) -> dict[str, bytes]:
    metadata = {"pyproject.toml", "uv.lock", "package.json", "package-lock.json",
                "scripts/run_sdk_quality.py", "scripts/run-sdk-quality.mjs",
                ".github/workflows/release.yml"}
    result = {}
    files = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode().split("\0")
    for name in filter(None, files):
        if not (name.startswith(("tests/", "parity/")) or name in metadata):
            continue
        source = safe_path(root / name)
        if component == "client-typescript" and name.endswith(".ts"):
            result[name] = packaged_assertions(name, rewrite_typescript(source.read_text())).encode()
        elif component == "client-python" and name.endswith(".py"):
            result[name] = packaged_assertions(name, source.read_text()).encode()
        else:
            result[name] = source.read_bytes()
    if component == "client-python":
        result["pre1_origin_guard.py"] = PYTHON_GUARD.encode()
    return result


def stage(root: Path, workspace: Path, component: str) -> dict[str, str]:
    """Copy only Git-bound fixtures/metadata; never copy SDK runtime sources."""
    root, workspace = safe_path(root), safe_path(workspace)
    if workspace == root or workspace.is_relative_to(root):
        raise ValueError("package workspace must be outside the checkout")
    if fixture_tree(workspace):
        raise ValueError("package assertion staging is not empty")
    for name, data in assertion_files(root, component).items():
        dest = workspace / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
    return fixture_tree(workspace)



def validate_immutable_bindings(bindings: dict) -> None:
    if set(bindings) != set(BINDINGS) or any(
        re.fullmatch(r"sha256:[0-9a-f]{64}", str(v)) is None for v in bindings.values()
    ):
        raise ValueError("package execution immutable bindings differ")

def create_binding(root: Path, workspace: Path, installed: Path, artifact: Path,
                   component: str, runtime: str, target: str, bindings: dict,
                   vendor_artifact: Path | None = None) -> dict:
    if component in {"directory-php", "directory-rust"}:
        return create_directory_binding(root, workspace, installed, artifact, component, runtime, target, bindings)
    if component == "management":
        return create_management_binding(root, workspace, installed, artifact, runtime, target, bindings)
    if component == "client-rust":
        return create_rust_binding(root, workspace, installed, artifact, runtime, target, bindings, vendor_artifact)
    validate_immutable_bindings(bindings)
    if not safe_path(installed).is_relative_to(safe_path(workspace)):
        raise ValueError("installed package must be in the run workspace")
    payload = installed_payload(artifact, installed, component)
    fixtures = fixture_tree(workspace) or stage(root, workspace, component)
    expected_fixtures = {name: "sha256:" + hashlib.sha256(data).hexdigest()
                         for name, data in assertion_files(root, component).items()}
    if fixtures != expected_fixtures:
        raise ValueError("staged assertions differ from the reviewed source mapping")
    value = {
        "schema": SCHEMA, "component": component, "runtime": runtime, "target": target,
        "bindings": bindings, "workspace": str(workspace), "installed_package": str(installed),
        "artifact_sha256": file_digest(artifact), "installed_payload_sha256": digest(payload),
        "fixtures_sha256": digest(fixtures), "binding_sha256": None,
        "test_dependencies_sha256": digest(dependencies(workspace, installed, component)),
        "assertion_adapter": "canonical-runtime-verifier-and-cli.v1",
        "non_authorizing": True, "qualification_credit": False,
    }
    value["binding_sha256"] = digest(value)
    return value



def validate_binding_identity(value: dict) -> None:
    copy = dict(value)
    copy["binding_sha256"] = None
    if value.get("schema") != SCHEMA or value.get("binding_sha256") != digest(copy):
        raise ValueError("package execution binding digest differs")
    if value.get("non_authorizing") is not True or value.get("qualification_credit") is not False:
        raise ValueError("package execution binding cannot authorize or grant credit")
    if value.get("assertion_adapter") != "canonical-runtime-verifier-and-cli.v1":
        raise ValueError("package assertion adapter binding differs")


def validate_binding_context(value: dict, context: dict) -> None:
    if any(value.get(k) != context[k] for k in ("component", "runtime", "target")) or value.get("bindings") != {k: context[k] for k in BINDINGS}:
        raise ValueError("package execution candidate/environment/runtime binding differs")

def prepared_package_home() -> Path:
    """Keep the immutable preparation boundary separate from per-case HOME."""
    return safe_path(
        Path(os.environ.get("IICP_PRE1_PREPARED_PACKAGE_HOME", os.environ["HOME"]))
    )


def validate_binding(value: dict, context: dict, artifact: Path, root: Path,
                     vendor_artifact: Path | None = None) -> Path:
    if context["component"] in {"directory-php", "directory-rust"}:
        return validate_directory_binding(value, context, artifact, root)
    if context["component"] == "management":
        return validate_management_binding(value, context, artifact, root)
    if context["component"] == "client-rust":
        return validate_rust_binding(value, context, artifact, root, vendor_artifact)
    validate_binding_identity(value)
    validate_binding_context(value, context)
    workspace = safe_path(Path(value["workspace"]))
    home = prepared_package_home()
    installed = safe_path(Path(value["installed_package"]))
    validate_workspace_boundary(workspace, home, installed, root)
    if value["artifact_sha256"] != file_digest(artifact) or value["installed_payload_sha256"] != digest(installed_payload(artifact, installed, context["component"])):
        raise ValueError("package execution installed artifact binding differs")
    if value["fixtures_sha256"] != digest(fixture_tree(workspace)):
        raise ValueError("package assertion fixtures changed")
    expected = {name: "sha256:" + hashlib.sha256(data).hexdigest()
                for name, data in assertion_files(root, context["component"]).items()}
    if fixture_tree(workspace) != expected:
        raise ValueError("package assertions differ from the reviewed source mapping")
    if value["test_dependencies_sha256"] != digest(dependencies(workspace, installed, context["component"])):
        raise ValueError("package test dependencies changed")
    return workspace



def validate_workspace_boundary(workspace: Path, home: Path, installed: Path, root: Path) -> None:
    if not workspace.is_relative_to(home) or workspace == home or workspace.is_relative_to(root.resolve()) or not installed.is_relative_to(workspace):
        raise ValueError("package execution workspace is not run-isolated")

def package_command(root: Path, context: dict, component_manifest: dict,
                    artifact_root: Path, argv: list[str], env: dict) -> tuple[list[str], dict, Path, dict]:
    path = safe_path(Path(os.environ["IICP_PRE1_PACKAGE_EXECUTION_BINDING"]))
    value = json.loads(path.read_text())
    if value.get("binding_sha256") != os.environ.get("IICP_PRE1_PACKAGE_EXECUTION_SHA256"):
        raise ValueError("package execution binding pin differs")
    if context["component"] in {"directory-php", "directory-rust"}:
        return directory_package_command(root, context, component_manifest, artifact_root, env, value)
    if context["component"] == "client-rust":
        return rust_package_command(root, context, component_manifest, artifact_root, argv, env, value)
    if context["component"] == "management":
        rows = [r for r in component_manifest["artifacts"] if r["kind"] == "crate"]
        if len(rows) != 1:
            raise ValueError("Management candidate crate is ambiguous")
        artifact = safe_path(artifact_root / "management" / rows[0]["name"])
        if file_digest(artifact) != rows[0]["sha256"]:
            raise ValueError("Management candidate crate digest differs")
        consumer = validate_management_binding(value, context, artifact, root)
        home = safe_path(Path(env["HOME"]))
        cargo_home = home / "rust-cargo-home"
        cargo_home.mkdir(mode=0o700, exist_ok=True)
        reject_inherited_cargo_config(home, safe_path(cargo_home))
        env = {**env, "CARGO_HOME": str(cargo_home), "CARGO_NET_OFFLINE": "true", "CARGO_INCREMENTAL": "0"}
        argv = [*argv[:3], "--offline", *argv[3:]]
        return argv, env, consumer, {"value": value, "artifact": artifact, "vendor_artifact": None}
    kind = "wheel" if context["component"] == "client-python" else "npm-tarball"
    artifacts = [r for r in component_manifest["artifacts"] if r["kind"] == kind]
    if len(artifacts) != 1:
        raise ValueError("candidate SDK install artifact is ambiguous")
    artifact = artifact_root / context["component"] / artifacts[0]["name"]
    workspace = validate_binding(value, context, artifact, root)
    if context["component"] == "client-python":
        argv = [*argv[:3], "-p", "pre1_origin_guard", *argv[3:]]
        env["PYTHONPATH"] = os.pathsep.join((str(Path(value["installed_package"]).parent), str(workspace)))
        env["IICP_PRE1_INSTALLED_PACKAGE"] = value["installed_package"]
        env["PYTHONNOUSERSITE"] = "1"
        env["PYTHONDONTWRITEBYTECODE"] = "1"
    else:
        expected = workspace / "node_modules/@iicp/client"
        if Path(value["installed_package"]) != expected:
            raise ValueError("TypeScript installed module path differs")
    return argv, env, workspace, {"value": value, "artifact": artifact}


def execution_summary(value: dict) -> dict:
    """Portable evidence; private execution paths never enter a receipt."""
    keys = ("component", "runtime", "target", "bindings", "artifact_sha256",
            "installed_payload_sha256", "fixtures_sha256", "test_dependencies_sha256")
    return {"schema": "iicp.pre1-package-execution-summary.v1",
            **{key: value[key] for key in keys},
            "package_execution_sha256": value["binding_sha256"],
            "non_authorizing": True}


def make_case_proof(value: dict, context: dict, assertion: str, exit_code: int,
                    run_id: str) -> dict:
    if not isinstance(exit_code, int) or isinstance(exit_code, bool):
        raise ValueError("case proof exit code is invalid")
    if not isinstance(run_id, str) or not re.fullmatch(r"[a-zA-Z0-9._-]+", run_id):
        raise ValueError("case proof run identifier is invalid")
    if not isinstance(assertion, str) or not assertion:
        raise ValueError("case proof assertion is missing")
    result = {"schema": "iicp.pre1-packaged-case-proof.v2", "run_id": run_id,
              "execution": execution_summary(value), "context": context,
              "assertion": assertion, "exit_code": exit_code,
              "non_authorizing": True, "proof_sha256": None}
    result["proof_sha256"] = digest(result)
    return result


def validate_case_proof(value: dict, context: dict, exit_code: int,
                        run_id: str, expected_execution: dict | None = None,
                        expected_assertion: str | None = None) -> None:
    validate_case_proof_identity(value)
    validate_proof_result(value, context, exit_code, run_id)
    summary = value["execution"]
    if expected_execution is not None and summary != expected_execution:
        raise ValueError("case proof installed execution differs")
    validate_execution_summary(summary, context)
    validate_proof_assertion(value, expected_assertion)


def validate_case_proof_identity(value: dict) -> None:
    fields = {"schema", "run_id", "execution", "context", "assertion", "exit_code",
              "non_authorizing", "proof_sha256"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("case proof fields differ")
    copy = {**value, "proof_sha256": None}
    if value["schema"] != "iicp.pre1-packaged-case-proof.v2" or value["proof_sha256"] != digest(copy):
        raise ValueError("case proof schema or digest differs")
    validate_proof_result_fields(value)



def validate_proof_result(value: dict, context: dict, exit_code: int, run_id: str) -> None:
    if value["context"] != context or value["exit_code"] != exit_code or value["run_id"] != run_id:
        raise ValueError("case proof execution context or result differs")


def validate_proof_assertion(value: dict, expected_assertion: str | None) -> None:
    if not isinstance(value["assertion"], str) or not value["assertion"]:
        raise ValueError("case proof assertion is missing")
    if expected_assertion is not None and value["assertion"] != expected_assertion:
        raise ValueError("case proof assertion differs from the owned mapping")



def validate_proof_result_fields(value: dict) -> None:
    if not isinstance(value["exit_code"], int) or isinstance(value["exit_code"], bool) or value["non_authorizing"] is not True:
        raise ValueError("case proof authority or exit code differs")
    if not isinstance(value["run_id"], str) or not re.fullmatch(r"[a-zA-Z0-9._-]+", value["run_id"]):
        raise ValueError("case proof run identifier is invalid")
def validate_execution_summary(summary: dict, context: dict) -> None:
    validate_summary_identity(summary)
    if any(summary[key] != context[key] for key in ("component", "runtime", "target")):
        raise ValueError("package execution summary target differs")
    if summary["bindings"] != {key: context[key] for key in BINDINGS}:
        raise ValueError("package execution summary immutable bindings differ")


def validate_summary_identity(summary: dict) -> None:
    fields = {"schema", "component", "runtime", "target", "bindings",
              "artifact_sha256", "installed_payload_sha256", "fixtures_sha256",
              "test_dependencies_sha256", "package_execution_sha256", "non_authorizing"}
    if not isinstance(summary, dict) or set(summary) != fields:
        raise ValueError("package execution summary fields differ")
    if summary["schema"] != "iicp.pre1-package-execution-summary.v1" or summary["non_authorizing"] is not True:
        raise ValueError("package execution summary schema or authority differs")
    for key in fields - {"schema", "component", "runtime", "target", "bindings", "non_authorizing"}:
        if re.fullmatch(r"sha256:[0-9a-f]{64}", str(summary[key])) is None:
            raise ValueError("package execution summary digest is invalid")


def write_case_proof(value: dict) -> Path:
    """Publish a complete sidecar atomically, without overwriting earlier evidence."""
    path = Path(os.environ["IICP_PRE1_CASE_PROOF_OUTPUT"])
    home = prepared_package_home()
    parent = safe_path(path.parent)
    if not path.is_absolute() or not parent.is_relative_to(home) or path.exists() or path.is_symlink():
        raise ValueError("case proof output is unsafe or already exists")
    descriptor, temporary = tempfile.mkstemp(prefix=".case-proof-", dir=parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return path


# Rust uses the unchanged crate payload, including its packaged assertions.
# The vendor bundle supplies only dependency/config files, never runtime source.
def rust_archive_files(artifact: Path, prefix: str) -> dict[str, str]:
    safe_path(artifact)
    result, seen, total = {}, set(), 0
    with tarfile.open(artifact, "r|gz") as archive:
        for row in archive:
            name = row.name.rstrip("/")
            total = validate_rust_archive_member(row, name, seen, total)
            if row.isfile() and name.startswith(prefix):
                handle = archive.extractfile(row)
                if handle is None:
                    raise ValueError("Rust archive member is unavailable")
                h = hashlib.sha256()
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    h.update(chunk)
                result[name.removeprefix(prefix)] = "sha256:" + h.hexdigest()
    if not result:
        raise ValueError("Rust archive payload is empty")
    return result




def validate_rust_archive_name(name):
    if not name or name.startswith("/") or "\\" in name or ":" in name:
        raise ValueError("Rust archive contains an unsafe member name")
    if any(part in {"", ".", ".."} for part in name.split("/")):
        raise ValueError("Rust archive contains an unsafe member path")


def validate_rust_archive_member(row, name, seen, total):
    validate_rust_archive_name(name)
    if name in seen or not (row.isfile() or row.isdir()):
        raise ValueError("Rust archive contains an unsafe or duplicate member")
    seen.add(name)
    total += row.size
    if len(seen) > 20000 or total > 1024 * 1024 * 1024:
        raise ValueError("Rust archive exceeds bounded extraction limits")
    return total


def rust_dependencies(workspace: Path) -> dict[str, str]:
    return {**{"vendor/" + k: v for k, v in tree(workspace / "vendor").items()},
            **{".cargo/" + k: v for k, v in tree(workspace / ".cargo").items()}}


def verify_rust_payload(workspace, installed, artifact, vendor_artifact):
    if vendor_artifact is None:
        raise ValueError("Rust vendor artifact must be candidate-bound")
    crate = rust_archive_files(artifact, artifact.stem + "/")
    if tree(installed) != crate:
        raise ValueError("installed Rust SDK differs from the frozen crate")
    source = rust_archive_files(vendor_artifact, "source/")
    if source != crate:
        raise ValueError("Rust vendor source differs from the frozen crate")
    vendor = rust_archive_files(vendor_artifact, "vendor/")
    config = rust_archive_files(vendor_artifact, ".cargo/")
    expected = {**{"vendor/" + k: v for k, v in vendor.items()},
                **{".cargo/" + k: v for k, v in config.items()}}
    if rust_dependencies(workspace) != expected:
        raise ValueError("Rust vendor dependencies/config differ from the candidate")
    return crate, expected


def rust_fixtures(root: Path, installed: Path) -> dict[str, str]:
    mapping = "qualification/pre1-cases.json"
    if (installed / mapping).read_bytes() != (root / mapping).read_bytes():
        raise ValueError("Rust packaged assertion mapping differs from reviewed source")
    return {mapping: file_digest(installed / mapping),
            **{"tests/" + k: v for k, v in tree(installed / "tests").items()}}


def create_rust_binding(root, workspace, installed, artifact, runtime, target, bindings, vendor_artifact):
    validate_immutable_bindings(bindings)
    validate_workspace_boundary(safe_path(workspace), prepared_package_home(),
                               safe_path(installed), root)
    payload, deps = verify_rust_payload(workspace, installed, artifact, vendor_artifact)
    value = {"schema": SCHEMA, "component": "client-rust", "runtime": runtime,
        "target": target, "bindings": bindings, "workspace": str(workspace),
        "installed_package": str(installed), "artifact_sha256": file_digest(artifact),
        "vendor_artifact_sha256": file_digest(vendor_artifact),
        "installed_payload_sha256": digest(payload),
        "fixtures_sha256": digest(rust_fixtures(root, installed)),
        "test_dependencies_sha256": digest(deps), "binding_sha256": None,
        "assertion_adapter": "canonical-runtime-verifier-and-cli.v1",
        "non_authorizing": True, "qualification_credit": False}
    value["binding_sha256"] = digest(value)
    return value


def validate_rust_binding(value, context, artifact, root, vendor_artifact):
    validate_binding_identity(value)
    validate_binding_context(value, context)
    workspace = safe_path(Path(value["workspace"]))
    installed = safe_path(Path(value["installed_package"]))
    validate_workspace_boundary(workspace, prepared_package_home(), installed, root)
    payload, deps = verify_rust_payload(workspace, installed, artifact, vendor_artifact)
    expected = {"artifact_sha256": file_digest(artifact),
                "vendor_artifact_sha256": file_digest(vendor_artifact),
                "installed_payload_sha256": digest(payload),
                "test_dependencies_sha256": digest(deps),
                "fixtures_sha256": digest(rust_fixtures(root, installed))}
    if any(value.get(k) != v for k, v in expected.items()):
        raise ValueError("Rust package execution inputs changed")
    return installed


def rust_artifacts(component, artifact_root):
    paths = []
    for kind in ("crate", "vendored-offline-package"):
        rows = [row for row in component["artifacts"] if row["kind"] == kind]
        if len(rows) != 1:
            raise ValueError("Rust candidate artifact is ambiguous")
        path = safe_path(artifact_root / "client-rust" / rows[0]["name"])
        if file_digest(path) != rows[0]["sha256"]:
            raise ValueError("Rust candidate artifact digest differs")
        paths.append(path)
    return paths


def rust_package_command(root, context, component, artifact_root, argv, env, value):
    artifact, vendor = rust_artifacts(component, artifact_root)
    installed = validate_binding(value, context, artifact, root, vendor)
    workspace = safe_path(Path(value["workspace"]))
    home = safe_path(Path(env["HOME"]))
    cargo_home = home / "rust-cargo-home"
    cargo_home.mkdir(mode=0o700, exist_ok=True)
    safe_path(cargo_home)
    target = home / "rust-build" / context["runtime"]
    target.mkdir(mode=0o700, parents=True, exist_ok=True)
    safe_path(target)
    env = {**env, "CARGO_HOME": str(cargo_home), "CARGO_TARGET_DIR": str(target),
           "CARGO_NET_OFFLINE": "true", "CARGO_INCREMENTAL": "0"}
    # Cargo can otherwise discover unrelated configs above the run workspace.
    if workspace.parent != home or installed.parent != workspace:
        raise ValueError("Rust package workspace layout differs")
    reject_inherited_cargo_config(home, cargo_home)
    argv = [*argv[:3], "--offline", *argv[3:]]
    return argv, env, installed, {"value": value, "artifact": artifact, "vendor_artifact": vendor}



def extract_rust_packages(artifact: Path, vendor_artifact: Path, workspace: Path) -> Path:
    """Extract only into an empty caller-owned workspace after validating both archives."""
    safe_path(workspace)
    if any(workspace.iterdir()):
        raise ValueError("Rust extraction workspace must be empty")
    crate = rust_archive_files(artifact, artifact.stem + "/")
    if crate != rust_archive_files(vendor_artifact, "source/"):
        raise ValueError("Rust vendor source differs from the frozen crate")
    rust_archive_files(vendor_artifact, "vendor/")
    rust_archive_files(vendor_artifact, ".cargo/")
    extract_rust_prefix(artifact, artifact.stem + "/", workspace / "source")
    extract_rust_prefix(vendor_artifact, "vendor/", workspace / "vendor")
    extract_rust_prefix(vendor_artifact, ".cargo/", workspace / ".cargo")
    return safe_path(workspace / "source")


def extract_rust_prefix(artifact: Path, prefix: str, destination: Path) -> None:
    destination.mkdir(mode=0o700)
    with tarfile.open(artifact, "r|gz") as archive:
        for row in archive:
            if not row.isfile() or not row.name.startswith(prefix):
                continue
            extract_rust_file(archive, row, prefix, destination)


def extract_rust_file(archive, row, prefix, destination):
    relative = row.name.removeprefix(prefix)
    if Path(relative).is_absolute() or any(p in {"", ".", ".."} for p in relative.split("/")):
        raise ValueError("Rust extraction path is unsafe")
    path = destination / relative
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    safe_path(path.parent)
    handle = archive.extractfile(row)
    if handle is None:
        raise ValueError("Rust extraction member is unavailable")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700 if row.mode & 0o111 else 0o600)
    with os.fdopen(fd, "wb") as output:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            output.write(chunk)


def reject_inherited_cargo_config(home, cargo_home):
    for ancestor in (home, *home.parents):
        for name in ("config", "config.toml"):
            path = ancestor / ".cargo" / name
            if path.exists() or path.is_symlink():
                raise ValueError("Rust inherited Cargo configuration is forbidden")
    if (cargo_home / "config").exists() or (cargo_home / "config.toml").exists():
        raise ValueError("Rust inherited Cargo home configuration is forbidden")


def management_consumer_files(root: Path, payload: Path) -> dict[str, bytes]:
    """Keep frozen runtime source separate from reviewed external assertions.

    Cargo disables automatic tests in the published Management crate. A
    separate consumer manifest names only the existing mapped integration
    fixtures and points its library/binaries at the untouched crate source.
    No dependency, lockfile, assertion or runtime source is rewritten.
    """
    root, payload = safe_path(root), safe_path(payload)
    mapping = safe_path(root / "qualification/pre1-cases.json")
    cases = json.loads(mapping.read_text())
    if cases.get("component") != "management" or cases.get("schema") != "iicp.pre1-component-case-map.v2":
        raise ValueError("Management consumer case map differs")
    names = set()
    for case in [cases["support"], *cases["scenarios"].values()]:
        command = case["command"]
        if "--test" in command:
            name = command[command.index("--test") + 1]
            if not isinstance(name, str) or re.fullmatch(r"[a-z][a-z0-9_]*", name) is None:
                raise ValueError("Management consumer test name is unsafe")
            names.add(name)
    tracked = set(subprocess.check_output(["git", "ls-files", "-z", "--", "tests"], cwd=root).decode().split("\0"))
    files = {}
    for name in sorted(names):
        path = f"tests/{name}.rs"
        if path not in tracked:
            raise ValueError("Management consumer assertion is not Git-bound")
        source = safe_path(root / path).read_text()
        files[path] = management_assertions(path, source).encode()
    for name in tree(payload):
        if not name.startswith(("src/", "examples/")) and name != "Cargo.toml":
            files[name] = (payload / name).read_bytes()
    manifest = (payload / "Cargo.toml").read_text()
    for path in re.findall(r'^path = "([^"\n]+)"$', manifest, flags=re.M):
        validate_rust_archive_name(path)
        if not path.startswith(("src/", "examples/")):
            raise ValueError("Management consumer manifest source path differs")
    manifest = re.sub(r'^path = "((?:src|examples)/[^"\n]+)"$',
                      lambda match: f'path = "../payload/{match[1]}"', manifest, flags=re.M)
    for name in sorted(names):
        manifest += f'\n[[test]]\nname = "{name}"\npath = "tests/{name}.rs"\n'
    files["Cargo.toml"] = manifest.encode()
    return files


def management_assertions(name, source):
    """Validate pre-1 builder metadata; retain the older publisher assertions."""
    if name != "tests/release_manifest.rs":
        return source
    marker = '    let manifest: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();'
    optional = '    let Some(path) = env::var_os("IICP_RELEASE_MANIFEST") else {\n        return;\n    };'
    if source.count(marker) != 1 or source.count(optional) != 1:
        raise ValueError("Management release fixture shape differs")
    branch = '''
    if manifest["schema"] == "iicp.pre1-management-release-manifest.v1" {
        let candidate: Value = serde_json::from_str(&fs::read_to_string(
            env::var_os("IICP_PRE1_CANDIDATE_MANIFEST").expect("candidate required")
        ).unwrap()).unwrap();
        let component = candidate["components"].as_array().unwrap().iter()
            .find(|row| row["id"] == "management").unwrap();
        assert_eq!(manifest["source_commit"], component["source_commit"]);
        assert_eq!(manifest["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(manifest["version"], component["source_version"]);
        assert_eq!(manifest["product"], "iicp-management-core");
        assert_eq!(manifest["channel"], "developer-preview");
        assert_eq!(manifest["non_authorizing"], true);
        for flag in ["publication_authorized", "deployment_authorized", "management_service", "directory_authority"] {
            assert_eq!(manifest[flag], false);
        }
        assert_eq!(manifest["binaries"], json!(["iicp-management", "iicp-management-controller", "iicp-management-conformance"]));
        assert_eq!(manifest.as_object().unwrap().len(), 11);
        return;
    }
'''
    return source.replace(optional, '    let path = env::var_os("IICP_RELEASE_MANIFEST").expect("release manifest required");').replace(marker, marker + branch)


def stage_management_consumer(root: Path, artifact: Path, workspace: Path) -> dict:
    """Prepare only; the caller owns dependency acquisition and isolation."""
    root, artifact, workspace = safe_path(root), safe_path(artifact), safe_path(workspace)
    home = prepared_package_home()
    if workspace == home or not workspace.is_relative_to(home) or workspace.is_relative_to(root) or any(workspace.iterdir()):
        raise ValueError("Management consumer workspace is not empty and run-isolated")
    expected = rust_archive_files(artifact, artifact.stem + "/")
    extract_rust_prefix(artifact, artifact.stem + "/", workspace / "payload")
    payload = workspace / "payload"
    if tree(payload) != expected:
        raise ValueError("Management extracted crate differs")
    files = management_consumer_files(root, payload)
    consumer = workspace / "consumer"
    consumer.mkdir(mode=0o700)
    for name, data in files.items():
        path = consumer / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(data)
    return {"schema": "iicp.pre1-management-consumer.v1",
            "artifact_sha256": file_digest(artifact), "payload_sha256": digest(expected),
            "consumer_sha256": digest(tree(consumer)),
            "non_authorizing": True, "qualification_credit": False}


def validate_management_consumer(root: Path, artifact: Path, workspace: Path, binding: dict) -> Path:
    """Recheck artifact and reviewed assertions, even after a forged rehash."""
    workspace = safe_path(workspace)
    home = prepared_package_home()
    if workspace == home or not workspace.is_relative_to(home) or workspace.is_relative_to(root.resolve()):
        raise ValueError("Management consumer workspace is not run-isolated")
    payload = safe_path(workspace / "payload")
    consumer = safe_path(workspace / "consumer")
    expected = rust_archive_files(artifact, artifact.stem + "/")
    actual = tree(consumer)
    fixtures = {name: "sha256:" + hashlib.sha256(data).hexdigest()
                for name, data in management_consumer_files(root, payload).items()}
    if binding != {"schema": "iicp.pre1-management-consumer.v1",
                   "artifact_sha256": file_digest(artifact), "payload_sha256": digest(expected),
                   "consumer_sha256": digest(actual),
                   "non_authorizing": True, "qualification_credit": False} or tree(payload) != expected or actual != fixtures:
        raise ValueError("Management consumer artifact or reviewed fixtures changed")
    return consumer


def management_consumer_binding(artifact, workspace):
    return {"schema": "iicp.pre1-management-consumer.v1",
            "artifact_sha256": file_digest(artifact),
            "payload_sha256": digest(rust_archive_files(artifact, artifact.stem + "/")),
            "consumer_sha256": digest(tree(workspace / "consumer")),
            "non_authorizing": True, "qualification_credit": False}


def management_dependencies(workspace):
    expected = ('[source.crates-io]\nreplace-with = "vendored-sources"\n\n'
                '[source.vendored-sources]\ndirectory = ' + json.dumps(str(workspace / "vendor")) + '\n')
    if tree(workspace / ".cargo") != {"config.toml": "sha256:" + hashlib.sha256(expected.encode()).hexdigest()}:
        raise ValueError("Management offline Cargo configuration differs")
    return rust_dependencies(workspace)


def create_management_binding(root, workspace, installed, artifact, runtime, target, bindings):
    validate_immutable_bindings(bindings)
    staged = management_consumer_binding(artifact, workspace)
    if safe_path(installed) != validate_management_consumer(root, artifact, workspace, staged):
        raise ValueError("Management consumer path differs")
    value = {"schema": SCHEMA, "component": "management", "runtime": runtime,
        "target": target, "bindings": bindings, "workspace": str(workspace),
        "installed_package": str(installed), "artifact_sha256": staged["artifact_sha256"],
        "installed_payload_sha256": staged["payload_sha256"],
        "fixtures_sha256": staged["consumer_sha256"],
        "test_dependencies_sha256": digest(management_dependencies(workspace)),
        "binding_sha256": None, "assertion_adapter": "canonical-runtime-verifier-and-cli.v1",
        "non_authorizing": True, "qualification_credit": False}
    value["binding_sha256"] = digest(value)
    return value


def validate_management_binding(value, context, artifact, root):
    validate_binding_identity(value)
    validate_binding_context(value, context)
    workspace = safe_path(Path(value["workspace"]))
    expected = create_management_binding(root, workspace, Path(value["installed_package"]),
        artifact, context["runtime"], context["target"], {key: context[key] for key in BINDINGS})
    if value != expected:
        raise ValueError("Management package execution inputs changed")
    return safe_path(workspace / "consumer")

# Directory adapters deliberately refuse unimplemented cases and modes. A
# source-test command is never used as a fallback for a released binary.
DIRECTORY_RUST_HTTP_SCENARIOS = frozenset({"credential-missing", "unsupported-version",
    "credential-expired", "credential-rotated", "rate-limit", "dynamic-public-route-readiness", "duplicate-registration", "config-permission-denied", "disk-full", "process-crash-restart", "stale-pid-or-lock", "interrupted-write"})
DIRECTORY_RUST_DATABASE_SCENARIOS = frozenset({"credential-replayed", "migration-interrupted", "signature-mismatch", "backup-restore", "rollback-last-supported", "cross-flavor-equivalence"})
DIRECTORY_RUST_SCENARIOS = DIRECTORY_RUST_HTTP_SCENARIOS | DIRECTORY_RUST_DATABASE_SCENARIOS | frozenset({
    "support", "package-version-self-report", "config-missing", "config-malformed", "offline-locked-install", "minimum-version", "no-dual-authority"})

DIRECTORY_PROBE = r'''import json, os, resource, signal, subprocess, sys, tempfile, time
from pathlib import Path
import xml.etree.ElementTree as ET
import urllib.request, urllib.error


def registration_scenario_postcondition(binary, env, version):
    # Public synthetic delegation signed by the registration test seed;
    # not an operator credential. Its fixed expiry must fail closed.
    contract = Path("directory-support-behavior.json").read_bytes()
    delegation = json.loads(Path("directory-registration-delegation.json").read_bytes())
    observed = []
    def observe(raw_request, request, active_binary, launch_env):
        observed.append(registration_fixture_postcondition(
            request, lambda query: directory_fixture_sql(env, query), contract, delegation))
    reset_directory_database(env)
    try:
        rust_http_case(binary, env, "cross-flavor-equivalence", version,
            database=True, postcondition=observe, request_timeout=10)
        if len(observed) != 1:
            raise ValueError("Directory registration execution was not observed")
        return observed[0]
    finally:
        reset_directory_database(env)


def discovery_scenario_postcondition(binary, env, version, mode):
    import importlib.util
    spec = importlib.util.spec_from_file_location("installed_discovery", "directory-discovery.py")
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    contract = helper.read_contract("directory-support-behavior.json")
    observed = []
    def observe(raw_request, request, active_binary, launch_env):
        observed.append(helper.observe(request, raw_request,
            lambda query: directory_fixture_sql(env, query),
            lambda subject: restricted_membership_command(active_binary, launch_env,
                "issue", subject, "registration", "node"), contract, mode))
    reset_directory_database(env)
    try:
        rust_http_case(binary, env, "cross-flavor-equivalence", version,
            database=True, postcondition=observe, request_timeout=10)
        if len(observed) != 1:
            raise ValueError("Directory discovery execution was not observed")
        return observed[0]
    finally:
        reset_directory_database(env)


def endpoint_scenario_postcondition(binary, env, version, mode):
    import importlib.util
    spec = importlib.util.spec_from_file_location("installed_endpoints", "directory-discovery.py")
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    contract = helper.read_contract("directory-support-behavior.json")
    production = {**env, "APP_ENV": "production", "IICP_SKIP_LIVENESS_CHECK": "false",
        "IICP_DEV_ALLOW_INSECURE_TLS": "false",
        "IICP_GENESIS_ED25519_SECRET_KEY": "11" * 32
            + "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"}
    observed = []
    def observe(raw_request, request, active_binary, launch_env):
        if any(launch_env.get(key) != production[key] for key in
                ("APP_ENV", "IICP_SKIP_LIVENESS_CHECK", "IICP_DEV_ALLOW_INSECURE_TLS")):
            raise ValueError("Directory endpoint environment differs")
        observed.append(helper.observe_endpoints(request, raw_request,
            lambda query: directory_fixture_sql(production, query), contract, mode))
    reset_directory_database(production)
    try:
        rust_http_case(binary, production, "cross-flavor-equivalence", version,
            database=True, postcondition=observe, request_timeout=10)
        if len(observed) != 1:
            raise ValueError("Directory endpoint execution was not observed")
        return observed[0]
    finally:
        reset_directory_database(production)


def replica_snapshot_postcondition(request, scenario):
    # This key belongs only to the isolated synthetic fixture. Never inherit
    # APP_KEY or credentials from the operator environment.
    import base64, hashlib, hmac
    def token(expiry):
        now = int(time.time())
        encode = lambda value: base64.urlsafe_b64encode(json.dumps(
            value, separators=(",", ":")).encode()).rstrip(b"=")
        header = encode({"alg": "HS256", "typ": "JWT"})
        claims = encode({"sub": "fixture-unregistered", "iss": "iicp.network",
            "iat": now - 7200, "exp": expiry, "role": "replica",
            "scope": "GET /v1/snapshot", "jti": "0" * 32})
        message = header + b"." + claims
        signature = base64.urlsafe_b64encode(hmac.new(
            b"iicp-pre1-isolated-synthetic-key", message, hashlib.sha256).digest()).rstrip(b"=")
        return (message + b"." + signature).decode()
    def snapshot(credential):
        return request("/v1/snapshot", headers={"Authorization": "Bearer " + credential})
    if scenario == "credential-expired":
        status, value = snapshot(token(int(time.time()) + 300))
        if status != 401 or value.get("error", {}).get("message") != "Replica not registered":
            raise ValueError("non-expired signature positive control differs")
        status, value = snapshot(token(int(time.time()) - 3600))
        if status != 401 or value.get("error", {}).get("code") != "token_expired":
            raise ValueError("expired credential refusal cause differs")
    else:
        body = {"did": "did:web:replica-fixture.invalid", "endpoint": "http://127.0.0.1:1/v1"}
        def register():
            status, value = request("/v1/replicas/register", body)
            if (status != 200 or not isinstance(value.get("replica_id"), str)
                    or not value["replica_id"] or not isinstance(value.get("replica_token"), str)
                    or not value["replica_token"]):
                raise ValueError("synthetic replica registration differs")
            return value
        first = register()
        if snapshot(first["replica_token"])[0] != 200:
            raise ValueError("first replica credential positive control failed")
        second = register()
        if (first["replica_id"] != second["replica_id"]
                or first["replica_token"] == second["replica_token"]):
            raise ValueError("replica rotation identity or credential differs")
        status, value = snapshot(first["replica_token"])
        if (status != 401 or value.get("error", {}).get("code") != "unauthorized"
                or "token has been rotated" not in value.get("error", {}).get("message", "")):
            raise ValueError("rotated credential refusal cause differs")
        if snapshot(second["replica_token"])[0] != 200:
            raise ValueError("replacement replica credential failed")

def registration_rate_postcondition(request):
    # Validation failures still consume admission capacity, without DNS probes,
    # providers, persistence, or external traffic. A fresh child owns this window.
    body = {"endpoint": "http://127.0.0.1:1",
            "capabilities": [{"intent": "urn:iicp:intent:llm:chat:v1"}],
            "sdk_compatibility_version": "0.7.101", "sdk_version": "0.7.100"}
    def validation():
        status, value = request("/v1/register", body)
        if status != 422 or "sdk_compatibility_version must match sdk_version" not in json.dumps(value):
            raise ValueError("registration admission validation control differs")
    started = time.monotonic()
    for _ in range(60):
        validation()
    for _ in range(2):
        status, value = request("/v1/register", body)
        if (status != 429 or value.get("error") != "IICP-E034"
                or type(value.get("retry_after")) is not int or value["retry_after"] != 60):
            raise ValueError("registration rate rejection differs")
    if time.monotonic() - started >= 55:
        raise ValueError("registration burst exceeded safe fixture window")
    time.sleep(max(0, 61 - (time.monotonic() - started)))
    validation()

def initial_route_postcondition(request):
    import http.server, threading
    class Provider(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200 if self.path == "/iicp/health" else 404)
            self.end_headers()
        def log_message(self, *args):
            pass
    with http.server.HTTPServer(("127.0.0.1", 0), Provider) as server:
        endpoint = "http://127.0.0.1:" + str(server.server_port)
        body = {"node_id": "fixture-route", "endpoint": endpoint,
            "nat_type": "symmetric", "transport_method": "external_tunnel",
            "capabilities": [{"intent": "urn:iicp:intent:llm:chat:v1"}]}
        # The reserved socket is not listening during the refusal control.
        server.server_close()
        status, value = request("/v1/register", body)
        if (status != 422 or not isinstance(value.get("error"), dict)
                or value["error"].get("code") != "IICP-E036"):
            raise ValueError("unready external route registration was not refused")
        if request("/v1/node/fixture-route")[0] != 404:
            raise ValueError("unready route identity was persisted")
        with http.server.HTTPServer(("127.0.0.1", int(endpoint.rsplit(":", 1)[1])), Provider) as ready:
            ready.timeout = 0.1
            stopping = threading.Event()
            def serve():
                while not stopping.is_set():
                    ready.handle_request()
            worker = threading.Thread(target=serve)
            worker.start()
            try:
                status, value = request("/v1/register", body)
                if status != 201 or value.get("node_id") != body["node_id"]:
                    raise ValueError("ready external route registration failed")
                status, value = request("/v1/node/fixture-route")
                if status != 200 or value.get("endpoint") != endpoint:
                    raise ValueError("ready route endpoint was not persisted")
            finally:
                stopping.set()
                worker.join(timeout=3)
                if worker.is_alive():
                    raise ValueError("synthetic route worker did not stop")

def duplicate_registration_postcondition(request):
    # Declared direct reachability skips external probes; the reserved .invalid
    # identity and loopback endpoint can never target a production provider.
    body = {"node_id": "fixture-duplicate", "endpoint": "http://127.0.0.1:1",
        "nat_type": "public", "transport_method": "direct_ipv4",
        "capabilities": [{"intent": "urn:iicp:intent:llm:chat:v1"}]}
    status, first = request("/v1/register", body)
    if (status != 201 or first.get("node_id") != body["node_id"]
            or not isinstance(first.get("node_token"), str) or not first["node_token"]):
        raise ValueError("duplicate fixture first registration differs")
    def detail():
        status, value = request("/v1/node/" + body["node_id"])
        score = value.get("reputation_score")
        if (status != 200 or value.get("node_id") != body["node_id"]
                or type(score) not in (int, float) or not 0 <= score <= 1):
            raise ValueError("duplicate fixture node evidence differs")
        return value
    baseline = detail()["reputation_score"]
    status, heartbeat = request("/v1/heartbeat", {"node_id": body["node_id"],
        "available": True, "metrics": {"tasks_success": 0, "tasks_failed": 5,
                                       "avg_latency_ms": 0}},
        headers={"Authorization": "Bearer " + first["node_token"]})
    if status != 200 or heartbeat.get("ok") is not True:
        raise ValueError("duplicate fixture damaging heartbeat failed")
    damaged = detail()["reputation_score"]
    if damaged >= baseline:
        raise ValueError("duplicate fixture reputation was not damaged")
    status, second = request("/v1/register", {**body, "current_node_token": first["node_token"]})
    if status != 201 or second.get("node_id") != body["node_id"]:
        raise ValueError("duplicate fixture re-registration identity differs")
    after = detail()
    if after["reputation_score"] != damaged or after.get("endpoint") != body["endpoint"]:
        raise ValueError("duplicate registration reset reputation or changed endpoint")

def registration_fixture_postcondition(request, sql, contract_bytes, delegation):
    """Observe the two canonical HTTP/state cases, not primitive parity.

    The caller owns an isolated empty database and the installed process.
    A valid synthetic delegation must first bind an active operator; a generic
    422, bad signature or partial transaction cannot satisfy revoked rollback.
    This helper alone neither admits a scenario nor grants qualification.
    """
    import hashlib, re
    if hashlib.sha256(contract_bytes).hexdigest() != "61f84608db554cf2a3da02c46e01f27c77e57c9553ade0da8c5a017860d73f3f":
        raise ValueError("registration behavior fixture differs")
    cases = {row["name"]: row["expected"] for row in json.loads(contract_bytes)["registration_cases"]}
    node_id = "fixture-revoked-registration"
    if (not isinstance(delegation, dict) or set(delegation) != {"node_id", "operator_pub", "not_after", "sig"}
            or delegation["node_id"] != node_id
            or not isinstance(delegation["operator_pub"], str)
            or not re.fullmatch(r"[A-Za-z0-9+/]{43}=", delegation["operator_pub"])
            or type(delegation["not_after"]) is not int
            or delegation["not_after"] <= int(time.time()) + 60
            or not isinstance(delegation["sig"], str)
            or not re.fullmatch(r"[A-Za-z0-9+/]{86}==", delegation["sig"])):
        raise ValueError("registration synthetic delegation differs")
    def counts():
        raw = sql("SELECT (SELECT COUNT(*) FROM nodes), (SELECT COUNT(*) FROM capabilities), "
                  "(SELECT COUNT(*) FROM availability_windows)")
        if not re.fullmatch(rb"[0-9]+\t[0-9]+\t[0-9]+\n", raw):
            raise ValueError("registration relation counts differ")
        return dict(zip(("node_rows", "capability_rows", "availability_rows"), map(int, raw.split())))
    if any(counts().values()):
        raise ValueError("registration fixture database is not empty")
    def body(identifier, model, start):
        # Explicit direct reachability keeps the isolated registration fixture
        # from attempting external endpoint probes. This is not reachability proof.
        return {"node_id": identifier, "endpoint": "https://1.1.1.1", "region": "eu-central",
            "nat_type": "public", "transport_method": "direct_ipv4",
            "capabilities": [{"intent": "urn:iicp:intent:llm:chat:v1", "models": [model], "max_tokens": 4096}],
            "availability": [{"start": start, "end": "17:00", "share": 1.0}],
            "limits": {"max_concurrent": 4, "tokens_per_min": 10000}}
    recovery_id = "fixture-recovery-registration"
    status, first = request("/v1/register", body(recovery_id, "model-a", "08:00"))
    if status != 201 or first.get("node_id") != recovery_id or not isinstance(first.get("node_token"), str) or not first["node_token"]:
        raise ValueError("registration recovery seed failed")
    status, second = request("/v1/register", {**body(recovery_id, "model-b", "09:00"),
        "current_node_token": first["node_token"]})
    if status != 201 or second.get("node_id") != recovery_id or second.get("recovered") is not True:
        raise ValueError("registration recovery result differs")
    recovery = {**counts(), "recovered": second["recovered"]}
    models = sql("SELECT CAST(models AS CHAR) FROM capabilities WHERE node_id = 'fixture-recovery-registration'")
    start = sql("SELECT TIME_FORMAT(start_time, '%H:%i') FROM availability_windows WHERE node_id = 'fixture-recovery-registration'")
    if json.loads(models) != ["model-b"] or start != b"09:00\n" or recovery != cases["recovery_replaces_relations"]:
        raise ValueError("registration recovery did not replace relations")
    def remove_node(identifier):
        # Identifiers here are fixed fixture constants, never user SQL.
        sql("DELETE FROM capabilities WHERE node_id = '" + identifier + "'; "
            "DELETE FROM availability_windows WHERE node_id = '" + identifier + "'; "
            "DELETE FROM nodes WHERE id = '" + identifier + "'")
    remove_node(recovery_id)
    status, positive = request("/v1/register", {**body(node_id, "model-a", "08:00"), "operator_delegation": delegation})
    pub_hex = delegation["operator_pub"].encode().hex()
    verified = sql("SELECT operator_verified FROM nodes WHERE id = 'fixture-revoked-registration' "
        "AND CAST(operator_pubkey AS BINARY) = 0x" + pub_hex)
    if status != 201 or positive.get("node_id") != node_id or verified != b"1\n":
        raise ValueError("registration delegation positive control failed")
    remove_node(node_id)
    sql("UPDATE operators SET identity_status = 'revoked' WHERE CAST(operator_pubkey AS BINARY) = 0x" + pub_hex)
    if sql("SELECT identity_status FROM operators WHERE CAST(operator_pubkey AS BINARY) = 0x" + pub_hex) != b"revoked\n":
        raise ValueError("registration operator revocation fixture failed")
    status, refused = request("/v1/register", {**body(node_id, "model-a", "08:00"), "operator_delegation": delegation})
    if (status != 422 or refused.get("error", {}).get("code") != "validation_error"
            or refused["error"].get("message") != "operator delegation references an inactive identity"):
        raise ValueError("registration revoked refusal cause differs")
    rollback = {**counts(), "status": status}
    if rollback != cases["revoked_operator_rolls_back"]:
        raise ValueError("registration revoked rollback left partial rows")
    return {"recovery_replaces_relations": recovery, "revoked_operator_rolls_back": rollback}

def http_postcondition(request, scenario):
    if scenario == "environment-public":
        status, value = request("/v1/discover?intent=urn:iicp:intent:llm:chat:v1")
        if (status != 200 or value.get("nodes") != [] or type(value.get("count")) is not int
                or value["count"] != 0 or "restricted_domain_decision" in value or "error" in value):
            raise ValueError("Directory public-mode discovery differs")
    elif scenario == "credential-missing":
        status, value = request("/v1/peers", {"node_id": "fixture", "known_peers": []})
        if status != 401:
            raise ValueError("unauthenticated peer access was not refused")
    elif scenario == "unsupported-version":
        status, value = request("/v1/register", {
            "endpoint": "https://provider.invalid", "region": "eu-central",
            "capabilities": [{"intent": "urn:iicp:intent:llm:chat:v1", "models": ["fixture"]}],
            "sdk_compatibility_version": "0.7.101", "sdk_version": "0.7.100"})
        if status != 422 or "sdk_compatibility_version must match sdk_version" not in json.dumps(value):
            raise ValueError("conflicted version refusal cause differs")
    elif scenario in {"credential-expired", "credential-rotated"}:
        replica_snapshot_postcondition(request, scenario)
    elif scenario == "duplicate-registration":
        duplicate_registration_postcondition(request)
    elif scenario == "rate-limit":
        registration_rate_postcondition(request)
    elif scenario == "dynamic-public-route-readiness":
        initial_route_postcondition(request)
    else:
        raise ValueError("Directory HTTP scenario remains unimplemented")

def require_loopback_only():
    # The frozen listener binds 0.0.0.0:8090. Admit this in-memory fixture only
    # in a Linux network namespace with loopback alone, never on the host LAN.
    import fcntl, socket, struct
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
        active = {name for _, name in socket.if_nameindex()
            if struct.unpack_from("H", fcntl.ioctl(control.fileno(), 0x8913,
                struct.pack("256s", name.encode())), 16)[0] & 1}
    if active != {"lo"}:
        raise ValueError("Directory HTTP fixture requires loopback-only isolation")

def private_case_home(env):
    home = Path(env["HOME"])
    workspace = Path.cwd().resolve()
    if (not home.is_absolute() or home.is_symlink() or not home.is_dir()
        or home.stat().st_mode & 0o077 or home == workspace or workspace in home.parents):
        raise ValueError("Directory state requires a private case HOME outside the prepared workspace")
    return home

def database_fixture_inputs():
    import re, stat
    workspace = Path.cwd()
    config_path = workspace / "directory-operator-fixture.json"
    secret = workspace / "directory-operator-password"
    if config_path.is_symlink() or secret.is_symlink():
        raise ValueError("Directory database fixture paths must not be symlinks")
    if config_path.stat().st_size > 4096 or not 16 <= secret.stat().st_size <= 128:
        raise ValueError("Directory database fixture inputs exceed bounds")
    config = json.loads(config_path.read_text())
    if (set(config) != {"schema", "database", "username", "port"}
        or config["schema"] != "iicp.pre1-directory-operator-fixture.v1"
        or not re.fullmatch(r"iicp_pre1_[a-f0-9]{16}", config["database"])
        or config["username"] != "iicp_pre1_fixture" or config["port"] != 3306
        or stat.S_IMODE(secret.stat().st_mode) != 0o600):
        raise ValueError("Directory database fixture configuration differs")
    return config, secret.read_text().strip()

def offline_locked_install_postcondition(installed, version, artifact_sha256):
    import hashlib, re, stat
    binary = installed / "iicp-directory-rs"
    if (installed.is_symlink() or binary.is_symlink() or not binary.is_file()
            or stat.S_IMODE(binary.stat().st_mode) != 0o700
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", artifact_sha256)):
        raise ValueError("Directory offline installed payload boundary differs")
    digest = hashlib.sha256()
    with binary.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    if "sha256:" + digest.hexdigest() != artifact_sha256:
        raise ValueError("Directory offline installed binary differs from frozen artifact")
    with tempfile.TemporaryFile() as output:
        result = subprocess.run([str(binary), "--version"], cwd=installed, env={
            key: value for key, value in os.environ.items() if key in {"PATH", "HOME", "TMPDIR"}
        }, stdout=output, stderr=subprocess.DEVNULL, timeout=30, check=False)
        output.seek(0)
        reported = output.read(4097)
    if (result.returncode != 0 or len(reported) > 4096
            or reported.decode("utf-8", errors="replace").strip() != "iicp-directory-rs " + version):
        raise ValueError("Directory offline installed binary did not self-report candidate version")

def database_observation():
    require_loopback_only()
    config, password = database_fixture_inputs()
    tools = Path.cwd() / "directory-database-tools"
    argv = [str(tools / "loader"), "--library-path", str(tools / "lib"), str(tools / "mysql"),
        "--no-defaults", "--batch", "--raw", "--skip-column-names", "--protocol=TCP", "--host=127.0.0.1",
        "--port=3306", "--connect-timeout=3", "--user=" + config["username"],
        "--database=" + config["database"], "--execute",
        "SELECT UNIX_TIMESTAMP(liveness_verified_at), liveness_challenge FROM nodes WHERE id = 'fixture-replay'"]
    with tempfile.TemporaryDirectory(prefix="directory-oracle-home-", dir=private_case_home(os.environ)) as private_home, tempfile.TemporaryFile() as output:
        result = subprocess.run(argv, env={"PATH": os.environ.get("PATH", ""), "MYSQL_PWD": password, "HOME": private_home},
            stdout=output, stderr=subprocess.DEVNULL, timeout=10)
        output.seek(0); raw = output.read(4097)
    if result.returncode or len(raw) > 4096:
        raise ValueError("Directory database observation failed")
    text = raw.decode().strip()
    if not text:
        return None
    rows = text.splitlines()
    if len(rows) != 1 or len(rows[0].split("\t")) != 2:
        raise ValueError("Directory database observation shape differs")
    verified, challenge = rows[0].split("\t")
    if (verified != "NULL" and not verified.isdigit()) or not challenge or challenge == "NULL":
        raise ValueError("Directory database observation state differs")
    return {"verified_at": None if verified == "NULL" else int(verified), "challenge": challenge}

def credential_replay_postcondition(request, observe):
    import hmac, hashlib
    if observe() is not None:
        raise ValueError("Directory replay fixture identity already exists")
    body = {"node_id": "fixture-replay", "endpoint": "http://127.0.0.1:1/v1/task",
        "region": "eu-central", "nat_type": "public", "transport_method": "direct_ipv4",
        "capabilities": [{"intent": "urn:iicp:intent:llm:chat:v1", "models": ["fixture"]}]}
    status, registered = request("/v1/register", body)
    token, key = registered.get("node_token"), registered.get("node_hmac_key")
    if status != 201 or registered.get("node_id") != body["node_id"] or not token or not key:
        raise ValueError("Directory replay registration positive control differs")
    headers = {"Authorization": "Bearer " + token}
    def heartbeat(response=None):
        payload = {"node_id": body["node_id"], "available": False}
        if response is not None:
            payload["challenge_response"] = response
        code, value = request("/v1/heartbeat", payload, headers)
        challenge = value.get("challenge")
        if code != 200 or value.get("ok") is not True or not isinstance(challenge, str) or not challenge:
            raise ValueError("Directory replay heartbeat positive control differs")
        return challenge
    def answer(challenge):
        return hmac.new(key.encode(), challenge.encode(), hashlib.sha256).hexdigest()
    first = heartbeat()
    initial = observe()
    if initial != {"verified_at": None, "challenge": first}:
        raise ValueError("Directory replay initial database state differs")
    response = answer(first)
    second = heartbeat(response)
    accepted = observe()
    if not accepted or accepted["verified_at"] is None or accepted["challenge"] != second or second == first:
        raise ValueError("Directory replay valid response was not verified and rotated")
    time.sleep(1.1)  # MySQL NOW() records whole seconds; do not alias replay to the positive control.
    third = heartbeat(response)
    replay = observe()
    if replay != {"verified_at": accepted["verified_at"], "challenge": third} or third in {first, second}:
        raise ValueError("Directory replay updated verification or failed to rotate")
    time.sleep(1.1)
    fourth = heartbeat(answer(third))
    recovered = observe()
    if (not recovered or recovered["verified_at"] is None or recovered["verified_at"] <= accepted["verified_at"]
        or recovered["challenge"] != fourth or fourth in {first, second, third}):
        raise ValueError("Directory replay fresh response recovery differs")

def signature_mismatch_postcondition(request, observe):
    # A heartbeat can accept metrics while refusing cryptographic liveness.
    # Check persisted verification, not merely its HTTP success response.
    import hmac, hashlib
    if observe() is not None:
        raise ValueError("Directory signature fixture identity already exists")
    body = {"node_id": "fixture-replay", "endpoint": "http://127.0.0.1:1/v1/task",
        "region": "eu-central", "nat_type": "public", "transport_method": "direct_ipv4",
        "capabilities": [{"intent": "urn:iicp:intent:llm:chat:v1", "models": ["fixture"]}]}
    code, registered = request("/v1/register", body)
    token, key = registered.get("node_token"), registered.get("node_hmac_key")
    if code != 201 or registered.get("node_id") != body["node_id"] or not token or not key:
        raise ValueError("Directory signature registration positive control differs")
    def heartbeat(response=None):
        payload = {"node_id": body["node_id"], "available": False}
        if response is not None:
            payload["challenge_response"] = response
        status, value = request("/v1/heartbeat", payload, {"Authorization": "Bearer " + token})
        challenge = value.get("challenge")
        if status != 200 or value.get("ok") is not True or not isinstance(challenge, str) or not challenge:
            raise ValueError("Directory signature heartbeat positive control differs")
        return challenge
    def answer(challenge):
        return hmac.new(key.encode(), challenge.encode(), hashlib.sha256).hexdigest()
    first = heartbeat()
    if observe() != {"verified_at": None, "challenge": first}:
        raise ValueError("Directory signature initial state differs")
    second = heartbeat(answer(first))
    accepted = observe()
    if not accepted or accepted["verified_at"] is None or accepted["challenge"] != second or second == first:
        raise ValueError("Directory signature valid response was not verified")
    time.sleep(1.1)
    valid = answer(second)
    tampered = ("0" if valid[0] != "0" else "1") + valid[1:]
    third = heartbeat(tampered)
    if observe() != {"verified_at": accepted["verified_at"], "challenge": third} or third in {first, second}:
        raise ValueError("Directory signature mismatch advanced verification or failed rotation")
    time.sleep(1.1)
    fourth = heartbeat(answer(third))
    recovered = observe()
    if (not recovered or recovered["verified_at"] is None or recovered["verified_at"] <= accepted["verified_at"]
        or recovered["challenge"] != fourth or fourth in {first, second, third}):
        raise ValueError("Directory signature valid recovery differs")

def snapshot_checkpoint(path, pid):
    import stat
    if path.is_symlink() or not path.is_file() or not 1 <= path.stat().st_size <= 8192:
        raise ValueError("Directory snapshot file boundary differs")
    if stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise ValueError("Directory snapshot permissions differ")
    value = json.loads(path.read_bytes())
    if (value.get("health_schema_version") != 1 or value.get("pid") != pid
        or type(value.get("sequence")) is not int or value["sequence"] < 1):
        raise ValueError("Directory snapshot identity differs")
    return value["sequence"], path.read_bytes()

def wait_snapshot_checkpoint(process, snapshot, previous=None):
    deadline = time.monotonic() + 12
    while True:
        if process.poll() is not None:
            raise ValueError("Directory snapshot writer exited")
        if snapshot.exists():
            value = snapshot_checkpoint(snapshot, process.pid)
            if previous is None or value[0] > previous:
                return value
        if time.monotonic() >= deadline:
            raise ValueError("Directory snapshot progress timed out")
        time.sleep(0.1)

def permission_snapshot_postcondition(process, snapshot, log, request):
    # Exercise the released writer, not an injected source-test implementation.
    if os.geteuid() == 0:
        raise ValueError("Directory permission fixture requires unprivileged execution")
    sequence, verified = wait_snapshot_checkpoint(process, snapshot)
    directory = snapshot.parent
    offset = os.fstat(log.fileno()).st_size
    directory.chmod(0o500)
    try:
        if os.access(directory, os.W_OK):
            raise ValueError("Directory permission fixture did not deny writes")
        deadline = time.monotonic() + 12
        while b"snapshot write failed: Permission denied (os error 13)" not in os.pread(log.fileno(), 65536, offset):
            if process.poll() is not None or time.monotonic() >= deadline:
                raise ValueError("Directory snapshot permission refusal was not observed")
            time.sleep(0.1)
        if snapshot_checkpoint(snapshot, process.pid)[1] != verified or list(directory.glob("*.tmp-*")):
            raise ValueError("Directory denied write changed verified snapshot")
        if request("/health")[0] != 200:
            raise ValueError("Directory permission failure broke runtime health")
    finally:
        directory.chmod(0o700)
    recovered, _ = wait_snapshot_checkpoint(process, snapshot, sequence)
    if recovered <= sequence or request("/health")[0] != 200:
        raise ValueError("Directory snapshot recovery differs")

def bounded_snapshot_filesystem(directory):
    # Never fill a host bind mount or an unbounded developer filesystem.
    import stat
    if directory.is_symlink() or directory.parent.is_symlink():
        raise ValueError("Directory disk-full fixture path is unsafe")
    directory = directory.resolve(strict=True)
    parent = directory.parent.stat()
    if stat.S_IMODE(parent.st_mode) != 0o700 or parent.st_uid != os.getuid():
        raise ValueError("Directory disk-full fixture mount must be private and owned")
    mounts = []
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        fields = line.split()
        mount = Path(fields[4])
        if directory == mount or mount in directory.parents:
            mounts.append((len(mount.parts), fields[fields.index('-') + 1], mount))
    info = os.statvfs(directory)
    ceiling = info.f_blocks * info.f_frsize
    selected = max(mounts, key=lambda row: row[0]) if mounts else None
    if not selected or selected[1] != 'tmpfs' or selected[2] != directory.parent or not 0 < ceiling <= 16 * 1024 * 1024:
        raise ValueError('Directory disk-full fixture requires bounded Linux tmpfs')
    return ceiling

def exhaust_snapshot_filesystem(directory, ceiling):
    import errno
    filler = directory / 'disk-full.fixture'
    try:
        with filler.open('xb', buffering=0) as stream:
            block = b'\0' * 65536
            written = 0
            while written <= ceiling:
                try:
                    count = stream.write(block)
                    if not count:
                        raise ValueError('Directory disk-full fixture made no progress')
                    written += count
                except OSError as error:
                    if error.errno != errno.ENOSPC:
                        raise
                    return filler
        raise ValueError('Directory disk-full fixture did not exhaust storage')
    except BaseException:
        # Only remove a file created here; exclusive creation protects existing paths.
        if 'stream' in locals():
            filler.unlink(missing_ok=True)
        raise

def disk_full_snapshot_postcondition(process, snapshot, log, request):
    ceiling = bounded_snapshot_filesystem(snapshot.parent)
    sequence, verified = wait_snapshot_checkpoint(process, snapshot)
    offset = os.fstat(log.fileno()).st_size
    filler = exhaust_snapshot_filesystem(snapshot.parent, ceiling)
    try:
        deadline = time.monotonic() + 12
        refusal = b'snapshot write failed: No space left on device (os error 28)'
        while refusal not in os.pread(log.fileno(), 65536, offset):
            if process.poll() is not None or time.monotonic() >= deadline:
                raise ValueError('Directory snapshot disk-full refusal was not observed')
            time.sleep(0.1)
        if snapshot_checkpoint(snapshot, process.pid)[1] != verified or list(snapshot.parent.glob('*.tmp-*')):
            raise ValueError('Directory disk-full write changed verified snapshot')
        if request('/health')[0] != 200:
            raise ValueError('Directory disk-full failure broke runtime health')
    finally:
        filler.unlink()
    recovered, _ = wait_snapshot_checkpoint(process, snapshot, sequence)
    if recovered <= sequence or request('/health')[0] != 200:
        raise ValueError('Directory disk-full snapshot recovery differs')

def crash_restart_snapshot_postcondition(process, snapshot, request, restart, version):
    # Observe a real crash, preserve evidence, then require a new writer identity.
    wait_snapshot_checkpoint(process, snapshot)
    os.killpg(process.pid, signal.SIGKILL)
    if process.wait(timeout=10) != -signal.SIGKILL:
        raise ValueError("Directory fixture was not killed by SIGKILL")
    _, verified = snapshot_checkpoint(snapshot, process.pid)
    if snapshot.read_bytes() != verified:
        raise ValueError("Directory crashed snapshot is not stable")
    return replacement_snapshot_postcondition(process, snapshot, request, restart, version)

def replacement_snapshot_postcondition(process, snapshot, request, restart, version):
    replacement = restart()
    try:
        if replacement.pid == process.pid:
            raise ValueError("Directory replacement process identity was reused")
        deadline = time.monotonic() + 30
        while True:
            if replacement.poll() is not None:
                raise ValueError("Directory replacement exited before snapshot readiness")
            # An old snapshot is retained, but never counts as new readiness.
            value = json.loads(snapshot.read_bytes())
            if value.get("pid") == replacement.pid:
                sequence, _ = snapshot_checkpoint(snapshot, replacement.pid)
                break
            if time.monotonic() >= deadline:
                raise ValueError("Directory replacement snapshot timed out")
            time.sleep(0.1)
        status, health = request("/health")
        if status != 200 or health.get("ok") is not True or health.get("version") != "v" + version + "-rs":
            raise ValueError("Directory replacement HTTP identity differs")
        wait_snapshot_checkpoint(replacement, snapshot, sequence)
        return replacement
    except BaseException:
        try:
            os.killpg(replacement.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        replacement.wait(timeout=10)
        raise

def wait_stopped_writer(process):
    deadline = time.monotonic() + 2
    while True:
        pid, status = os.waitpid(process.pid, os.WUNTRACED | os.WNOHANG)
        if pid == process.pid:
            if not os.WIFSTOPPED(status):
                raise ValueError("Directory writer exited before interruption boundary")
            return
        if time.monotonic() >= deadline:
            raise ValueError("Directory writer pause timed out")
        time.sleep(0.01)

def pause_snapshot_writer(process, snapshot):
    # Pause only this owned child, between writes. Never truncate an active file
    # or mistake a concurrent committed generation for failed preservation.
    deadline = time.monotonic() + 12
    while True:
        os.kill(process.pid, signal.SIGSTOP)
        try:
            wait_stopped_writer(process)
            sequence, verified = snapshot_checkpoint(snapshot, process.pid)
            if not snapshot.with_suffix('.tmp-' + str(process.pid)).exists():
                return verified
        except BaseException:
            os.kill(process.pid, signal.SIGCONT)
            raise
        os.kill(process.pid, signal.SIGCONT)
        wait_snapshot_checkpoint(process, snapshot, sequence)
        if time.monotonic() >= deadline:
            raise ValueError("Directory writer did not reach an interruption boundary")

def partial_snapshot_reader_postcondition(binary, env, partial):
    # Invoke the installed reader. A missing loader, unrelated error, accepted
    # partial JSON, or unbounded output cannot satisfy this negative control.
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        result = subprocess.run([str(binary), 'healthcheck', '--json', '--file', str(partial)],
            cwd=binary.parent, env=env, stdout=stdout, stderr=stderr, timeout=10)
        stdout.seek(0); out = stdout.read(4097)
        stderr.seek(0); err = stderr.read(4097)
    if (result.returncode != 2 or out or len(err) > 4096
            or not err.startswith(b'INDETERMINATE: invalid snapshot:')):
        raise ValueError("Directory installed reader did not reject the partial generation")

def interrupted_snapshot_evidence(process, snapshot, verified):
    import stat
    if process.wait(timeout=12) != -signal.SIGXFSZ:
        raise ValueError("Directory writer was not interrupted by the bounded file limit")
    if snapshot_checkpoint(snapshot, process.pid)[1] != verified:
        raise ValueError("Directory interrupted write changed the committed generation")
    partial = snapshot.with_suffix('.tmp-' + str(process.pid))
    info = partial.lstat()
    if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_uid != os.getuid() or info.st_size != 64):
        raise ValueError("Directory interrupted writer did not leave a private partial generation")
    try:
        json.loads(partial.read_bytes())
    except (ValueError, UnicodeDecodeError):
        return partial
    raise ValueError("Directory interrupted generation was unexpectedly complete")

def interrupted_snapshot_postcondition(process, snapshot, request, restart, version, binary, env):
    wait_snapshot_checkpoint(process, snapshot)
    verified = pause_snapshot_writer(process, snapshot)
    try:
        # Linux prlimit changes only the owned writer, not this controller or
        # the replacement. The released serializer writes 64 real bytes before
        # SIGXFSZ terminates it. Disable core dumps; retain bounded evidence.
        resource.prlimit(process.pid, resource.RLIMIT_CORE, (0, 0))
        resource.prlimit(process.pid, resource.RLIMIT_FSIZE, (64, 64))
    finally:
        os.kill(process.pid, signal.SIGCONT)
    partial = interrupted_snapshot_evidence(process, snapshot, verified)
    partial_snapshot_reader_postcondition(binary, env, partial)
    partial.unlink()
    return replacement_snapshot_postcondition(process, snapshot, request, restart, version)

def stale_owner_postcondition(process, snapshot, request, contender, contender_log, restart, version):
    # A competing owner must fail closed without displacing the healthy writer.
    sequence, _ = wait_snapshot_checkpoint(process, snapshot)
    try:
        contender.wait(timeout=10)
    except subprocess.TimeoutExpired as error:
        try:
            os.killpg(contender.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        contender.wait(timeout=10)
        raise ValueError("Directory competing owner did not terminate") from error
    output = os.pread(contender_log.fileno(), 65537, 0)
    if contender.returncode == 0 or len(output) > 65536 or b"Address already in use" not in output:
        raise ValueError("Directory competing owner did not fail on the occupied endpoint")
    if process.poll() is not None or snapshot_checkpoint(snapshot, process.pid)[0] < sequence:
        raise ValueError("Directory competing owner displaced the active writer")
    status, health = request("/health")
    if status != 200 or health.get("ok") is not True or health.get("version") != "v" + version + "-rs":
        raise ValueError("Directory active owner health changed after contention")
    wait_snapshot_checkpoint(process, snapshot, sequence)
    return crash_restart_snapshot_postcondition(process, snapshot, request, restart, version)

def restricted_membership_command(binary, env, action, subject, scope="discovery", kind="client"):
    import re
    if (action not in {"issue", "revoke"} or kind not in {"node", "client"}
            or not isinstance(subject, str) or len(subject) > 128
            or (subject not in {"fallback-capability", "empty-health", "unstable-backend",
                                "eligible", "below-realtime", "realtime"}
                and not re.fullmatch(r"fixture(?:-[a-z0-9-]+)?|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", subject))
            or scope not in {"registration", "discovery", "bootstrap", "heartbeat", "peers", "consumer_token", "dispatch", "relay"}):
        raise ValueError("Directory membership fixture command differs")
    argv = [str(binary), "trust-domain-membership-" + action,
        "--kind", kind, "--subject", subject]
    if action == "issue":
        argv += ["--scopes", scope, "--ttl-seconds", "3600"]
    with tempfile.TemporaryFile(dir=private_case_home(env)) as output:
        result = subprocess.run(argv, cwd=binary.parent, env=env, stdout=output,
            stderr=subprocess.DEVNULL, timeout=30, check=False)
        output.seek(0)
        raw = output.read(4097)
    if result.returncode != 0 or len(raw) > 4096:
        raise ValueError("Directory membership fixture administration failed")
    value = raw.decode("utf-8").strip()
    if ((action == "issue" and not re.fullmatch(r"iicp_mem_[0-9a-f]{64}", value))
            or (action == "revoke" and value != "revoked")):
        raise ValueError("Directory membership fixture output differs")
    return value

def restricted_mode_postcondition(request, administer):
    discover = "/v1/discover?intent=urn:iicp:intent:llm:chat:v1"
    def denied(headers=None, path=discover):
        status, body = request(path, headers=headers)
        if (status != 401 or body.get("error", {}).get("code") != "restricted_domain_denied"
                or "restricted_domain_decision" in body):
            raise ValueError("Directory restricted-mode denial differs")
    denied()
    token = administer("issue", "fixture-client", "discovery")
    headers = {"X-IICP-Membership": token, "X-IICP-Subject-Id": "fixture-client"}
    def eligible(credential):
        status, body = request(discover, headers={**headers, "X-IICP-Membership": credential})
        decision = body.get("restricted_domain_decision", {})
        if (status != 200 or body.get("nodes") != [] or type(body.get("count")) is not int
                or body["count"] != 0 or "error" in body
                or decision.get("schema") != "iicp.restricted-trust-domain.directory-decision.v0"
                or decision.get("profile") != "urn:iicp:profile:restricted-trust-domain:v1"
                or decision.get("decision") != "eligible" or decision.get("operation") != "discovery"
                or decision.get("domain_id") != "example.internal"
                or decision.get("authority_id") != "did:key:directory"
                or decision.get("subject_kind") != "client"
                or type(decision.get("membership_generation")) is not int or decision["membership_generation"] < 1
                or type(decision.get("membership_expires_at")) is not int
                or decision["membership_expires_at"] <= int(time.time())):
            raise ValueError("Directory restricted-mode eligibility differs")
    eligible(token)
    denied(headers, "/v1/bootstrap")
    denied({**headers, "X-IICP-Subject-Id": "fixture-other"})
    denied({**headers, "X-IICP-Membership": token[:-1] + ("a" if token[-1] != "a" else "b")})
    wrong_scope = administer("issue", "fixture-other", "bootstrap")
    denied({"X-IICP-Membership": wrong_scope, "X-IICP-Subject-Id": "fixture-other"})
    rotated = administer("issue", "fixture-client", "discovery")
    if rotated == token:
        raise ValueError("Directory membership rotation did not replace credential")
    denied(headers)
    eligible(rotated)
    administer("revoke", "fixture-client", "discovery")
    denied({**headers, "X-IICP-Membership": rotated})
    administer("revoke", "fixture-other", "bootstrap")

def directory_support_postcondition():
    import hashlib
    workspace = Path.cwd()
    paths = [workspace / ("directory-support-" + name + ".json") for name in ("contract", "behavior", "http")]
    if any(path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 1024 * 1024 for path in paths):
        raise ValueError("Directory support fixtures are missing or unsafe")
    contract = json.loads(paths[0].read_text())
    expected = {"behavior-contract-v1.json": "61f84608db554cf2a3da02c46e01f27c77e57c9553ade0da8c5a017860d73f3f",
        "http-contract-v1.json": "62fad592a33305a754353c43f6476d257f01ccf6e3cfdbf391d03717ce4796b5"}
    if (contract.get("contract_version") != "v1.10.80" or contract.get("fixtures") != expected
            or [hashlib.sha256(path.read_bytes()).hexdigest() for path in paths[1:]] != list(expected.values())):
        raise ValueError("Directory support fixture contract differs")

def rust_mode_environment(env, mode):
    result = dict(env)
    if mode == "restricted":
        result.update(IICP_RESTRICTED_DOMAIN_ENABLED="true", IICP_REPLICA_MODE="false",
            IICP_TRUST_DOMAIN_ID="example.internal", IICP_TRUST_DOMAIN_AUTHORITY_ID="did:key:directory",
            IICP_TRUST_DOMAIN_MEMBERSHIP_EPOCH="1")
    elif mode == "public":
        result["IICP_RESTRICTED_DOMAIN_ENABLED"] = "false"
    elif mode != "local-only":
        raise ValueError("Directory mode differs")
    return result

def reset_directory_database(env):
    require_loopback_only()
    config, password = database_fixture_inputs()
    tools = Path.cwd() / "directory-database-tools"
    sql = "DROP DATABASE IF EXISTS `" + config["database"] + "`; CREATE DATABASE `" + config["database"] + "`"
    argv = [str(tools / "loader"), "--library-path", str(tools / "lib"), str(tools / "mysql"),
        "--no-defaults", "--batch", "--protocol=TCP", "--host=127.0.0.1", "--port=3306",
        "--connect-timeout=3", "--user=" + config["username"], "--execute", sql]
    with tempfile.TemporaryDirectory(prefix="directory-reset-home-", dir=private_case_home(env)) as home:
        result = subprocess.run(argv, env={"PATH": env.get("PATH", ""), "MYSQL_PWD": password, "HOME": home},
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False)
    if result.returncode:
        raise ValueError("Directory disposable database reset failed")

def initialize_disposable_directory_schema(env):
    require_loopback_only()
    table_count = directory_fixture_sql(env,
        "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE()")
    try:
        existing_tables = int(table_count.decode("ascii").strip())
    except (UnicodeDecodeError, ValueError):
        raise ValueError("Directory disposable schema state differs")
    if existing_tables < 0:
        raise ValueError("Directory disposable schema state differs")
    if existing_tables:
        return
    config, password = database_fixture_inputs()
    schema = Path.cwd() / "directory-baseline-v1.sql"
    if (schema.is_symlink() or not schema.is_file() or not 0 < schema.stat().st_size <= 1024 * 1024):
        raise ValueError("Directory schema fixture is missing or unsafe")
    tools = Path.cwd() / "directory-database-tools"
    argv = [str(tools / "loader"), "--library-path", str(tools / "lib"), str(tools / "mysql"),
        "--no-defaults", "--batch", "--protocol=TCP", "--host=127.0.0.1", "--port=3306",
        "--connect-timeout=3", "--user=" + config["username"], "--database=" + config["database"]]
    with tempfile.TemporaryDirectory(prefix="directory-schema-home-", dir=private_case_home(env)) as home, schema.open("rb") as source, tempfile.TemporaryFile() as errors:
        result = subprocess.run(argv, env={"PATH": env.get("PATH", ""), "MYSQL_PWD": password, "HOME": home},
            stdin=source, stdout=subprocess.DEVNULL, stderr=errors, timeout=30, check=False)
        errors.seek(0); failure = errors.read(65536)
    if result.returncode:
        retain_sql_failure(failure, password)
        raise ValueError("Directory disposable schema initialization failed; bounded private error retained")


def directory_fixture_sql(env, sql):
    require_loopback_only()
    config, password = database_fixture_inputs()
    tools = Path.cwd() / "directory-database-tools"
    argv = [str(tools / "loader"), "--library-path", str(tools / "lib"), str(tools / "mysql"),
        "--no-defaults", "--batch", "--raw", "--skip-column-names", "--protocol=TCP",
        "--host=127.0.0.1", "--port=3306", "--connect-timeout=3",
        "--user=" + config["username"], "--database=" + config["database"], "--execute", sql]
    with tempfile.TemporaryDirectory(prefix="directory-schema-home-", dir=private_case_home(env)) as home, tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        result = subprocess.run(argv, env={"PATH": env.get("PATH", ""), "MYSQL_PWD": password, "HOME": home},
            stdout=output, stderr=errors, timeout=10, check=False)
        output.seek(0); observed = output.read(65537)
        errors.seek(0); failure = errors.read(65536)
    if result.returncode or len(observed) > 65536:
        retain_sql_failure(failure, password)
        raise ValueError("Directory isolated schema oracle failed; bounded private error retained")
    return observed

def retain_sql_failure(failure, password):
    # Never retain stdout, argv, SQL text, or the credential-bearing environment.
    # MySQL error diagnostics are bounded, private and redact the actual password.
    destination = os.environ.get("IICP_PRE1_CASE_EVIDENCE_ROOT")
    if destination:
        safe = failure[:65536].replace(password.encode(), b"[REDACTED]")[:65536]
        with tempfile.NamedTemporaryFile(prefix="directory-sql-failure-", suffix=".log",
                dir=destination, delete=False) as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(safe)


def directory_database_export(env):
    require_loopback_only()
    config, password = database_fixture_inputs()
    tools = Path.cwd() / "directory-database-tools"
    dump = tools / "mysqldump"
    if not dump.is_file() or dump.is_symlink():
        raise ValueError("Directory backup requires pinned mysqldump fixture")
    argv = [str(tools / "loader"), "--library-path", str(tools / "lib"), str(dump),
        "--no-defaults", "--protocol=TCP", "--host=127.0.0.1", "--port=3306",
        "--user=" + config["username"], "--single-transaction",
        "--skip-comments", "--skip-dump-date", "--skip-extended-insert", "--order-by-primary",
        "--no-tablespaces", "--set-gtid-purged=OFF", config["database"]]
    limit = 8 * 1024 * 1024
    with tempfile.TemporaryDirectory(prefix="directory-backup-home-", dir=private_case_home(env)) as home, tempfile.TemporaryFile(dir=home) as output, tempfile.TemporaryFile(dir=home) as errors:
        result = subprocess.run(argv, env={"PATH": env.get("PATH", ""), "MYSQL_PWD": password, "HOME": home},
            stdout=output, stderr=errors, timeout=20, check=False,
            preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit)))
        output.seek(0); value = output.read(limit + 1)
        errors.seek(0); diagnostic = errors.read(4096).decode("utf-8", errors="replace").replace(password, "[REDACTED]")
    if result.returncode or not value or len(value) > limit or b"CREATE TABLE" not in value:
        raise ValueError("Directory bounded database export failed: exit=" + str(result.returncode) + " " + diagnostic)
    return value

def directory_database_import(env, backup):
    require_loopback_only()
    if not isinstance(backup, bytes) or not 0 < len(backup) <= 8 * 1024 * 1024:
        raise ValueError("Directory restore input exceeds bound")
    config, password = database_fixture_inputs()
    tools = Path.cwd() / "directory-database-tools"
    argv = [str(tools / "loader"), "--library-path", str(tools / "lib"), str(tools / "mysql"),
        "--no-defaults", "--protocol=TCP", "--host=127.0.0.1", "--port=3306",
        "--connect-timeout=3", "--user=" + config["username"], "--database=" + config["database"]]
    with tempfile.TemporaryDirectory(prefix="directory-restore-home-", dir=private_case_home(env)) as home:
        result = subprocess.run(argv, input=backup,
            env={"PATH": env.get("PATH", ""), "MYSQL_PWD": password, "HOME": home},
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20, check=False)
    if result.returncode:
        raise ValueError("Directory isolated database restore failed")

def directory_database_state(env):
    # Compare actual schema/data, not mysqldump's optional CHARACTER SET spelling.
    import re
    schema = directory_fixture_sql(env,
        "SELECT TABLE_NAME,COLUMN_NAME,COLUMN_TYPE,IS_NULLABLE,COALESCE(COLUMN_DEFAULT,'NULL'),COLUMN_DEFAULT IS NULL,EXTRA,GENERATION_EXPRESSION,"
        "COALESCE(CHARACTER_SET_NAME,'NULL'),COALESCE(COLLATION_NAME,'NULL') "
        "FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME,ORDINAL_POSITION;"
        "SELECT TABLE_NAME,INDEX_NAME,COLUMN_NAME,NON_UNIQUE,SEQ_IN_INDEX,SUB_PART,INDEX_TYPE,IS_VISIBLE,EXPRESSION FROM information_schema.STATISTICS "
        "WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME,INDEX_NAME,SEQ_IN_INDEX;"
        "SELECT TABLE_NAME,TABLE_TYPE,ENGINE,TABLE_COLLATION,CREATE_OPTIONS FROM information_schema.TABLES "
        "WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME;"
        "SELECT TABLE_NAME,CONSTRAINT_NAME,COLUMN_NAME,REFERENCED_TABLE_NAME,REFERENCED_COLUMN_NAME "
        "FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME,CONSTRAINT_NAME,ORDINAL_POSITION;"
        "SELECT TABLE_NAME,CONSTRAINT_NAME,UPDATE_RULE,DELETE_RULE FROM information_schema.REFERENTIAL_CONSTRAINTS "
        "WHERE CONSTRAINT_SCHEMA=DATABASE() ORDER BY TABLE_NAME,CONSTRAINT_NAME;"
        "SELECT CONSTRAINT_NAME,CHECK_CLAUSE FROM information_schema.CHECK_CONSTRAINTS "
        "WHERE CONSTRAINT_SCHEMA=DATABASE() ORDER BY CONSTRAINT_NAME;")
    raw = directory_fixture_sql(env, "SELECT TABLE_NAME,COLUMN_NAME FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME,ORDINAL_POSITION;")
    columns = {}
    for line in raw.decode("ascii").splitlines():
        parts = line.split("\t")
        if len(parts) != 2 or any(not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", name) for name in parts):
            raise ValueError("Directory database observation identifiers differ")
        columns.setdefault(parts[0], []).append(parts[1])
    if not columns or len(columns) > 64 or any(len(names) > 128 for names in columns.values()):
        raise ValueError("Directory database observation exceeds table/column bounds")
    rows = {}
    for table, names in columns.items():
        fields = ",".join("IF(`" + name + "` IS NULL,'NULL',HEX(CAST(`" + name + "` AS BINARY)))" for name in names)
        rows[table] = directory_fixture_sql(env, "SELECT " + fields + " FROM `" + table + "` ORDER BY "
            + ",".join(str(i + 1) for i in range(len(names))))
    if len(schema) + sum(len(value) for value in rows.values()) > 8 * 1024 * 1024:
        raise ValueError("Directory database state exceeds bound")
    return {"schema": schema, "rows": rows}

def rollback_request_state(before, after, expected_count):
    # Successful discovery is intentionally accounted by the released service.
    # Verify its exact increment rather than ignoring telemetry or all-row drift.
    if before["schema"] != after["schema"] or set(before["rows"]) != set(after["rows"]):
        raise ValueError("Directory rollback request changed schema")
    for table in before["rows"]:
        if table != "dispatch_usage_daily" and before["rows"][table] != after["rows"][table]:
            raise ValueError("Directory rollback request changed non-accounting data")
    def usage(raw):
        return [line.split(b"\t") for line in raw.splitlines()]
    original, updated = usage(before["rows"]["dispatch_usage_daily"]), usage(after["rows"]["dispatch_usage_daily"])
    if len(original) != len(updated) or not original:
        raise ValueError("Directory rollback accounting row identity differs")
    delta = 0
    for old, new in zip(original, updated):
        if len(old) != 6 or len(new) != 6 or old[:3] != new[:3] or old[4] != new[4]:
            raise ValueError("Directory rollback accounting identity differs")
        count = int(bytes.fromhex(new[3].decode())) - int(bytes.fromhex(old[3].decode()))
        if count not in (0, 1) or new[5] < old[5] or (count == 0 and new != old):
            raise ValueError("Directory rollback accounting mutation differs")
        if count and bytes.fromhex(old[2].decode()) != b"legacy_dispatch":
            raise ValueError("Directory rollback accounting mode differs")
        delta += count
    if delta != expected_count:
        raise ValueError("Directory rollback accounting increment differs")

def rollback_postcondition(binary, env, version, predecessor, predecessor_sha256):
    # The caller must supply a preparation-bound predecessor. This probe is not
    # admitted into qualification until its fixture is in the package binding.
    import hashlib
    import re
    if (predecessor.is_symlink() or not predecessor.is_file()
            or not re.fullmatch(r"sha256:[a-f0-9]{64}", predecessor_sha256)
            or "sha256:" + hashlib.sha256(predecessor.read_bytes()).hexdigest() != predecessor_sha256):
        raise ValueError("Directory rollback predecessor binding differs")
    observed = subprocess.check_output([str(predecessor), "--version"], env=env, text=True, timeout=10)
    if observed.strip() != "iicp-directory-rs 0.1.15":
        raise ValueError("Directory rollback predecessor version differs")
    baseline = {}
    def authorization(request):
        for subject, expected in (("fixture-rollback-allowed", 200), ("fixture-rollback-denied", 401)):
            request_before = directory_database_state(env) if "state" in baseline else None
            code, result = request("/v1/discover?intent=urn:iicp:intent:llm:chat:v1", headers=baseline[subject])
            if request_before is not None:
                rollback_request_state(request_before, directory_database_state(env), 1 if expected == 200 else 0)
            if code != expected:
                raise ValueError("Directory rollback authorization or revocation differs")
            if expected == 200:
                decision = result.get("restricted_domain_decision", {})
                if (decision.get("decision") != "eligible" or decision.get("domain_id") != "example.internal"
                        or decision.get("authority_id") != "did:key:directory"):
                    raise ValueError("Directory rollback authority projection differs")
            elif result.get("error", {}).get("code") != "restricted_domain_denied":
                raise ValueError("Directory rollback denial cause differs")
    def seed(request, scenario_request, executable, launch_env):
        body = {"node_id": "fixture-rollback", "endpoint": "http://127.0.0.1:1/v1/task",
            "region": "eu-central", "nat_type": "public", "transport_method": "direct_ipv4",
            "capabilities": [{"intent": "urn:iicp:intent:llm:chat:v1", "models": ["fixture"]}]}
        code, registered = scenario_request("/v1/register", body)
        if code != 201 or registered.get("node_id") != body["node_id"] or not registered.get("node_token"):
            raise ValueError("Directory rollback registration positive control differs")
        code, detail = request("/v1/node/fixture-rollback")
        if code != 200 or detail.get("node_id") != body["node_id"]:
            raise ValueError("Directory rollback seed observation differs")
        baseline["detail"] = detail
        if launch_env.get("IICP_RESTRICTED_DOMAIN_ENABLED") == "true":
            for subject in ("fixture-rollback-allowed", "fixture-rollback-denied"):
                token = restricted_membership_command(executable, launch_env, "issue", subject, "discovery")
                baseline[subject] = {"X-IICP-Membership": token, "X-IICP-Subject-Id": subject}
            restricted_membership_command(executable, launch_env, "revoke", "fixture-rollback-denied", "discovery")
            authorization(request)
    def readback(request, scenario_request, executable, launch_env):
        code, detail = request("/v1/node/fixture-rollback")
        if code != 200 or detail != baseline["detail"]:
            raise ValueError("Directory rollback persistent HTTP state differs")
        if directory_database_state(env) != baseline["state"]:
            raise ValueError("Directory rollback startup changed persistent state")
        if launch_env.get("IICP_RESTRICTED_DOMAIN_ENABLED") == "true":
            authorization(request)
        baseline["state"] = directory_database_state(env)
    reset_directory_database(env)
    try:
        with tempfile.TemporaryDirectory(prefix="directory-rollback-", dir=private_case_home(env)) as directory:
            active = Path(directory) / "current"
            def select(executable):
                pending = active.with_name("next")
                pending.symlink_to(executable)
                os.replace(pending, active)
            select(predecessor)
            rust_http_case(active, env, "rollback-seed", "0.1.15", database=True, postcondition=seed)
            baseline["state"] = directory_database_state(env)
            select(binary)
            rust_http_case(active, env, "rollback-upgrade", version, database=True, postcondition=readback)
            before = baseline["state"]
            after_upgrade = directory_database_state(env)
            if after_upgrade != before:
                evidence = os.environ.get("IICP_PRE1_CASE_EVIDENCE_ROOT")
                if evidence:
                    changed = {name: {"before_sha256": hashlib.sha256(value).hexdigest(),
                        "after_sha256": hashlib.sha256(after_upgrade["rows"].get(name, b"")).hexdigest()}
                        for name, value in before["rows"].items()
                        if value != after_upgrade["rows"].get(name)}
                    destination = Path(tempfile.mkdtemp(prefix="directory-rollback-state-", dir=evidence))
                    path = destination / "changed-tables.json"
                    path.write_text(json.dumps({"schema_changed": before["schema"] != after_upgrade["schema"],
                        "tables": changed, "qualification_credit": False}) + "\n")
                    path.chmod(0o600)
                raise ValueError("Directory upgrade changed rollback persistent state")
            failure_env = {**env, "APP_ENV": "local", "IICP_ALLOW_IN_MEMORY": "false"}
            failure_env.pop("DATABASE_URL", None)
            # Do not accept an arbitrary crash as the intended failed upgrade.
            with tempfile.TemporaryFile(dir=private_case_home(env)) as log:
                result = subprocess.run([str(active)], cwd=active.parent, env=failure_env,
                    stdout=log, stderr=subprocess.STDOUT, timeout=10, check=False)
                output = os.pread(log.fileno(), 65537, 0)
                evidence = os.environ.get("IICP_PRE1_CASE_EVIDENCE_ROOT")
                if evidence:
                    destination = Path(tempfile.mkdtemp(prefix="directory-rollback-failure-", dir=evidence))
                    (destination / "stdout.log").write_bytes(output[:65536])
                    (destination / "result.json").write_text(json.dumps({"exit_code": result.returncode,
                        "qualification_credit": False, "stage": "failed-upgrade"}) + "\n")
                    for item in destination.iterdir():
                        item.chmod(0o600)
                refusal = b"FATAL: DATABASE_URL is required; ephemeral memory requires non-production APP_ENV and IICP_ALLOW_IN_MEMORY=true"
                if (result.returncode != 1 or len(output) > 65536
                        or refusal not in output
                        or b"listening on" in output):
                    raise ValueError("Directory failed-upgrade cause differs")
            if directory_database_state(env) != before:
                raise ValueError("Directory failed upgrade changed persistent state")
            select(predecessor)
            if active.resolve() != predecessor.resolve():
                raise ValueError("Directory predecessor managed path was not restored")
            rust_http_case(active, env, "rollback-restart", "0.1.15", database=True, postcondition=readback)
            if directory_database_state(env) != baseline["state"]:
                raise ValueError("Directory rollback changed schema or persistent data")
    finally:
        reset_directory_database(env)

def backup_restore_postcondition(binary, env, version):
    baseline = {}
    def seed(request, scenario_request, binary, launch_env):
        body = {"node_id": "fixture-backup", "endpoint": "http://127.0.0.1:1/v1/task",
            "region": "eu-central", "nat_type": "public", "transport_method": "direct_ipv4",
            "capabilities": [{"intent": "urn:iicp:intent:llm:chat:v1", "models": ["fixture"]}]}
        status, registered = scenario_request("/v1/register", body)
        if status != 201 or registered.get("node_id") != body["node_id"] or not registered.get("node_token"):
            raise ValueError("Directory backup registration positive control differs")
        code, detail = request("/v1/node/fixture-backup")
        if code != 200 or detail.get("node_id") != "fixture-backup":
            raise ValueError("Directory backup HTTP observation differs")
        baseline["detail"] = detail
        if launch_env.get("IICP_RESTRICTED_DOMAIN_ENABLED") == "true":
            for subject in ("fixture-backup-allowed", "fixture-backup-denied"):
                token = restricted_membership_command(binary, launch_env, "issue", subject, "discovery")
                baseline[subject] = {"X-IICP-Membership": token, "X-IICP-Subject-Id": subject}
            restricted_membership_command(binary, launch_env, "revoke", "fixture-backup-denied", "discovery")
            authorization(request)
    def authorization(request):
        for subject, expected in (("fixture-backup-allowed", 200), ("fixture-backup-denied", 401)):
            code, value = request("/v1/discover?intent=urn:iicp:intent:llm:chat:v1", headers=baseline[subject])
            if code != expected:
                raise ValueError("Directory restored authorization or revocation differs")
            if expected == 200:
                decision = value.get("restricted_domain_decision", {})
                if (decision.get("decision") != "eligible" or decision.get("domain_id") != "example.internal"
                        or decision.get("authority_id") != "did:key:directory"):
                    raise ValueError("Directory restored authority projection differs")
            elif value.get("error", {}).get("code") != "restricted_domain_denied":
                raise ValueError("Directory restore denial cause differs")
    def readback(request, scenario_request, binary, launch_env):
        code, detail = request("/v1/node/fixture-backup")
        if code != 200 or detail != baseline["detail"]:
            raise ValueError("Directory restored installed HTTP state differs")
        if launch_env.get("IICP_RESTRICTED_DOMAIN_ENABLED") == "true":
            authorization(request)
    reset_directory_database(env)
    try:
        rust_http_case(binary, env, "backup-seed", version, database=True, postcondition=seed)
        before = directory_database_state(env)
        backup = directory_database_export(env)
        reset_directory_database(env)
        directory_database_import(env, backup)
        if directory_database_state(env) != before:
            raise ValueError("Directory restored schema or persistent data differs")
        directory_fixture_sql(env, "UPDATE nodes SET endpoint='http://127.0.0.1:2/v1/task' WHERE id='fixture-backup';")
        if directory_database_state(env) == before:
            raise ValueError("Directory backup state oracle ignored deliberate corruption")
        reset_directory_database(env)
        directory_database_import(env, backup)
        if directory_database_state(env) != before:
            raise ValueError("Directory backup failed to recover deliberate corruption")
        rust_http_case(binary, env, "backup-readback", version, database=True, postcondition=readback)
    finally:
        reset_directory_database(env)

def migration_interrupted_postcondition(binary, env, version):
    # The released boundary is verify-only for an existing database. Never
    # simulate recovery by repairing it from the harness after startup.
    require_loopback_only()
    config, password = database_fixture_inputs()
    from urllib.parse import quote
    launch_env = {**env, "APP_KEY": "iicp-pre1-isolated-synthetic-key",
        "DATABASE_URL": "mysql://" + config["username"] + ":" + quote(password, safe="")
            + "@127.0.0.1:3306/" + config["database"]}
    observation = (
        "SELECT TABLE_NAME,COLUMN_NAME,COLUMN_TYPE,IS_NULLABLE,COALESCE(COLUMN_DEFAULT,'NULL'),EXTRA "
        "FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME,ORDINAL_POSITION;"
        "SELECT TABLE_NAME,INDEX_NAME,COLUMN_NAME,NON_UNIQUE FROM information_schema.STATISTICS "
        "WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME,INDEX_NAME,SEQ_IN_INDEX;"
        "SELECT TABLE_NAME,TABLE_TYPE,ENGINE,TABLE_COLLATION,CREATE_OPTIONS FROM information_schema.TABLES "
        "WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME;"
        "SELECT TABLE_NAME,CONSTRAINT_NAME,COLUMN_NAME,REFERENCED_TABLE_NAME,REFERENCED_COLUMN_NAME "
        "FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA=DATABASE() "
        "ORDER BY TABLE_NAME,CONSTRAINT_NAME,ORDINAL_POSITION;"
        "SELECT id FROM nodes ORDER BY id;")
    reset_directory_database(env)
    try:
        # Same installed binary must first bootstrap an empty, valid fixture
        # and serve its real HTTP contract before the negative control.
        rust_http_case(binary, env, "credential-missing", version, database=True)
        reset_directory_database(env)
        directory_fixture_sql(env, "CREATE TABLE nodes (id VARCHAR(128) NOT NULL PRIMARY KEY);"
            "INSERT INTO nodes (id) VALUES ('fixture-interrupted-schema');")
        before = directory_fixture_sql(env, observation)
        if not before.startswith(b"nodes\tid\t") or not before.endswith(b"fixture-interrupted-schema\n"):
            raise ValueError("Directory interrupted schema fixture differs")
        with tempfile.TemporaryFile(dir=private_case_home(env)) as log:
            result = subprocess.run([str(binary)], cwd=binary.parent, env=launch_env,
                stdout=log, stderr=subprocess.STDOUT, timeout=30, check=False)
            log.seek(0); output = log.read(65537)
        after = directory_fixture_sql(env, observation)
        if (result.returncode != 1 or len(output) > 65536
                or b"FATAL: MySQL schema verification failed: schema incompatible (" not in output
                or b"listening on" in output or b"using InMemoryRepo" in output
                or before != after):
            raise ValueError("Directory installed startup did not preserve and reject the interrupted schema")
    finally:
        reset_directory_database(env)

def restricted_request_adapter(request, binary, env):
    operations = {("POST", "/v1/register"): "registration", ("GET", "/v1/discover"): "discovery",
        ("GET", "/v1/bootstrap"): "bootstrap", ("POST", "/v1/heartbeat"): "heartbeat",
        ("POST", "/v1/peers"): "peers", ("POST", "/v1/consumer-token"): "consumer_token",
        ("POST", "/v1/dispatch/ticket"): "dispatch", ("POST", "/v1/relay/ticket"): "relay"}
    projected = {"registration": "registration", "discovery": "discovery", "bootstrap": "bootstrap",
        "consumer_token": "consumer_token", "dispatch": "dispatch_ticket"}
    def execute(path, body=None, headers=None):
        operation = operations.get(("GET" if body is None else "POST", path.split("?", 1)[0]))
        if operation is None:
            return request(path, body, headers)
        supplied = dict(headers or {})
        if any(key.lower() in {"x-iicp-membership", "x-iicp-subject-id"} for key in supplied):
            raise ValueError("Directory scenario must not override fixture membership")
        subject = body.get("node_id", "fixture-client") if isinstance(body, dict) else "fixture-client"
        kind = "node" if operation in {"registration", "heartbeat", "peers"} else "client"
        token = restricted_membership_command(binary, env, "issue", subject, operation, kind)
        status, value = request(path, body, {**supplied, "X-IICP-Membership": token, "X-IICP-Subject-Id": subject})
        error = value.get("error")
        if isinstance(error, dict) and error.get("code") in {"restricted_domain_denied", "restricted_domain_unavailable"}:
            raise ValueError("Directory membership rejection masked scenario behavior")
        if 200 <= status < 300 and operation in projected:
            decision = value.get("restricted_domain_decision")
            if (not isinstance(decision, dict) or decision.get("decision") != "eligible"
                    or decision.get("operation") != projected[operation]
                    or decision.get("domain_id") != "example.internal"
                    or decision.get("authority_id") != "did:key:directory"
                    or decision.get("subject_kind") != kind):
                raise ValueError("Directory scenario restricted projection differs")
        return status, value
    return execute

def rust_http_case(binary, env, scenario, version, database=False, postcondition=None, request_timeout=2,
                   listener_check=None):
    # Transactional registration includes password hashing on bounded CI CPUs;
    # this functional budget is not a latency qualification threshold.
    if type(request_timeout) not in {int, float} or not 0 < request_timeout <= 10:
        raise ValueError("Directory HTTP request budget differs")
    require_loopback_only()
    if scenario == "environment-restricted" and (not database
            or env.get("IICP_RESTRICTED_DOMAIN_ENABLED") != "true"
            or env.get("IICP_REPLICA_MODE") != "false"
            or env.get("IICP_TRUST_DOMAIN_ID") != "example.internal"
            or env.get("IICP_TRUST_DOMAIN_AUTHORITY_ID") != "did:key:directory"):
        raise ValueError("Directory restricted fixture requires isolated database and exact mode")
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    def request(path, body=None, headers=None):
        req = urllib.request.Request("http://127.0.0.1:8090" + path,
            data=None if body is None else json.dumps(body).encode(),
            headers={"Content-Type": "application/json", **(headers or {})})
        try:
            response = opener.open(req, timeout=request_timeout)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read(65537)
            if len(raw) > 65536:
                raise ValueError("Directory HTTP evidence exceeds bound")
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError("Directory HTTP evidence must be an object")
            return response.code, value
    launch_env = {**env, "APP_KEY": "iicp-pre1-isolated-synthetic-key",
        "IICP_GENESIS_ED25519_SECRET_KEY": "11" * 32
            + "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"}
    if database:
        initialize_disposable_directory_schema(env)
        config, password = database_fixture_inputs()
        from urllib.parse import quote
        launch_env["DATABASE_URL"] = ("mysql://" + config["username"] + ":" + quote(password, safe="")
            + "@127.0.0.1:3306/" + config["database"])
    else:
        launch_env["IICP_ALLOW_IN_MEMORY"] = "true"
    scenario_request = (restricted_request_adapter(request, binary, launch_env)
        if env.get("IICP_RESTRICTED_DOMAIN_ENABLED") == "true" and scenario != "environment-restricted"
        else request)
    with tempfile.TemporaryDirectory(prefix="directory-health-", dir=private_case_home(env)) as health_dir, tempfile.TemporaryFile(dir=private_case_home(env)) as log:
        snapshot = Path(health_dir) / "health.json"
        launch_env["IICP_RUNTIME_HEALTH_FILE"] = str(snapshot)
        process = subprocess.Popen([str(binary)], cwd=binary.parent,
            env=launch_env, stdout=log, stderr=subprocess.STDOUT,
            start_new_session=True)
        try:
            deadline = time.monotonic() + 30
            while True:
                if process.poll() is not None:
                    raise ValueError("Directory HTTP fixture exited before readiness")
                listening = b"listening on 0.0.0.0:8090" in os.pread(log.fileno(), 65536, 0)
                if listening:
                    status, health = request("/health")
                    if status != 200 or health.get("ok") is not True or health.get("version") != "v" + version + "-rs":
                        raise ValueError("Directory HTTP fixture identity differs")
                    break
                if time.monotonic() >= deadline:
                    raise ValueError("Directory HTTP fixture readiness timed out")
                time.sleep(0.1)
            if listener_check is not None:
                listener_check()
            if postcondition is not None:
                postcondition(request, scenario_request, binary, launch_env)
            elif scenario == "environment-restricted":
                restricted_mode_postcondition(request, lambda action, subject, scope:
                    restricted_membership_command(binary, launch_env, action, subject, scope))
            elif scenario == "config-permission-denied":
                permission_snapshot_postcondition(process, snapshot, log, request)
            elif scenario == "disk-full":
                disk_full_snapshot_postcondition(process, snapshot, log, request)
            elif scenario in {"process-crash-restart", "stale-pid-or-lock", "interrupted-write"}:
                def restart():
                    return subprocess.Popen([str(binary)], cwd=binary.parent,
                        env=launch_env, stdout=log, stderr=subprocess.STDOUT,
                        start_new_session=True)
                if scenario == "interrupted-write":
                    process = interrupted_snapshot_postcondition(process, snapshot, request, restart, version, binary, env)
                elif scenario == "stale-pid-or-lock":
                    with tempfile.TemporaryDirectory(prefix="directory-contender-", dir=private_case_home(env)) as contender_dir, tempfile.TemporaryFile() as contender_log:
                        contender_env = {**launch_env, "IICP_RUNTIME_HEALTH_FILE": str(Path(contender_dir) / "health.json")}
                        contender = subprocess.Popen([str(binary)], cwd=binary.parent,
                            env=contender_env, stdout=contender_log, stderr=subprocess.STDOUT,
                            start_new_session=True)
                        process = stale_owner_postcondition(process, snapshot, request, contender, contender_log, restart, version)
                else:
                    process = crash_restart_snapshot_postcondition(process, snapshot, request, restart, version)
            elif scenario == "signature-mismatch":
                signature_mismatch_postcondition(scenario_request, database_observation)
            elif scenario == "credential-replayed":
                credential_replay_postcondition(scenario_request, database_observation)
            else:
                http_postcondition(scenario_request, scenario)
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=10)

def retain_runtime_evidence(helper, output, env):
    import shutil
    root = helper.packages.safe_path(Path(os.environ["IICP_PRE1_CASE_EVIDENCE_ROOT"]))
    destination_root = Path(tempfile.mkdtemp(prefix="directory-runtime-", dir=root))
    (destination_root / "context.json").write_text(json.dumps(context, sort_keys=True) + "\n")
    (destination_root / "context.json").chmod(0o600)
    for name, limit in (("result.json", 65536), ("build.log", 8 * 1024 * 1024)):
        source = output / name
        if source.exists():
            helper.packages.safe_path(source)
            if source.stat().st_size > limit:
                raise ValueError("runtime evidence exceeds private retention bound")
            destination = destination_root / name
            if destination.exists() or destination.is_symlink():
                raise ValueError("runtime evidence destination already exists")
            shutil.copyfile(source, destination)
            destination.chmod(0o600)

def minimum_runtime_postcondition(binary, env, version):
    import importlib
    workspace = Path.cwd()
    tools = workspace / "directory-runtime-tools"
    # These exact owning sources are staged and hashed by the package binding.
    sys.path.insert(0, str(tools))
    previous_bytecode_policy = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        helper = importlib.import_module("prepare_pre1_minimum_runtime")
        cache = Path(os.environ["IICP_PRE1_DIRECTORY_RUNTIME_OUTPUT"])
        helper.packages.safe_path(cache)
        if not cache.is_absolute() or cache.is_relative_to(workspace):
            raise ValueError("runtime build storage must be separate from prepared inputs")
        with tempfile.TemporaryDirectory(prefix="directory-runtime-", dir=cache) as temporary:
            output = Path(temporary) / "build"
            try:
                result = helper.verify(workspace / "directory-runtime-fixture",
                    workspace / "directory-runtime-candidate.json", output,
                    Path(os.environ["IICP_PRE1_DIRECTORY_CARGO"]),
                    Path(os.environ["IICP_PRE1_DIRECTORY_RUSTC"]),
                    context["runtime"], context["target"],
                    os.environ["IICP_PRE1_DIRECTORY_RUNTIME_FIXTURE_SHA256"], build_timeout=150)
                if result["status"] != "PASS" or result["qualification_credit"] is not False:
                    raise ValueError("runtime source diagnosis is not a passing non-authorizing proof")
            finally:
                retain_runtime_evidence(helper, output, env)
    finally:
        sys.path.pop(0)
        sys.dont_write_bytecode = previous_bytecode_policy
    # A source build never substitutes for the immutable installed artifact.
    reported = subprocess.check_output([str(binary), "--version"], env=env, text=True, timeout=10)
    if reported.strip() != "iicp-directory-rs " + version:
        raise ValueError("installed minimum-runtime Directory identity differs")
    rust_http_case(binary, env, "credential-missing", version,
                   database=context["mode"] == "restricted")

def rust_mode_postcondition(binary, env, mode, version):
    if mode == "local-only":
        return
    if mode == "restricted":
        rust_http_case(binary, rust_mode_environment(env, mode), "environment-restricted", version, database=True)
        return
    if mode != "public":
        raise ValueError("Directory restricted mode remains unimplemented")
    # Independent fresh children prove both released default and explicit input.
    for enabled in (None, "false"):
        launch_env = dict(env)
        launch_env.pop("IICP_RESTRICTED_DOMAIN_ENABLED", None)
        if enabled is not None:
            launch_env["IICP_RESTRICTED_DOMAIN_ENABLED"] = enabled
        rust_http_case(binary, launch_env, "environment-public", version)

def php_operator_case(installed, env, scenario, version):
    require_loopback_only()
    import hashlib, re, stat
    workspace = Path.cwd()
    config = json.loads((workspace / "directory-operator-fixture.json").read_text())
    if (set(config) != {"schema", "database", "username", "port"}
        or config["schema"] != "iicp.pre1-directory-operator-fixture.v1"
        or not re.fullmatch(r"iicp_pre1_[a-f0-9]{16}", config["database"])
        or config["username"] != "iicp_pre1_fixture" or config["port"] != 3306):
        raise ValueError("Directory operator fixture configuration differs")
    secret = workspace / "directory-operator-password"
    if secret.is_symlink() or stat.S_IMODE(secret.stat().st_mode) != 0o600:
        raise ValueError("Directory operator secret must be a private regular file")
    previous = workspace / "previous/payload"
    base = {**env, "APP_ENV": "testing", "DB_CONNECTION": "mysql", "DB_HOST": "127.0.0.1",
        "DB_PORT": "3306", "DB_DATABASE": config["database"], "DB_USERNAME": config["username"],
        "DB_PASSWORD": secret.read_text().strip(), "CACHE_STORE": "array", "SESSION_DRIVER": "array",
        "QUEUE_CONNECTION": "sync", "LOG_CHANNEL": "stderr", "APP_URL": "http://localhost"}
    php = os.environ["IICP_PRE1_DIRECTORY_PHP"]
    helper = str(workspace / "directory-operator.php")
    def command(root, args):
        with tempfile.TemporaryFile() as output:
            process = subprocess.Popen([php, *args], cwd=root, env=base,
                stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                process.wait(timeout=120)
                if process.returncode != 0:
                    raise ValueError("Directory packaged operator command failed")
                output.seek(0)
                data = output.read(65537)
                if len(data) > 65536:
                    raise ValueError("Directory operator output exceeds bound")
                return data.decode()
            finally:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=10)
    def migrate(root):
        command(root, ["artisan", "migrate", "--force", "--no-interaction"])
    def ready(root, expected):
        value = json.loads(command(root, [helper, "ready"]))
        if value != {"ready": True, "version": expected}:
            raise ValueError("Directory packaged operator readiness differs")
    def verify(root):
        if command(root, [helper, "digest"]).strip() != hashlib.sha256(b"1:alpha|2:beta").hexdigest():
            raise ValueError("Directory persistent fixture digest differs")
    # Each case gets an empty, disposable schema. Never erase a pre-existing schema.
    if command(installed, [helper, "empty"]).strip() != "true":
        raise ValueError("Directory operator database is not empty")
    backup = private_case_home(env) / "directory-backup.json"
    if backup.exists() or backup.is_symlink():
        raise ValueError("Directory operator backup already exists")
    try:
        migrate(previous)
        ready(previous, "1.10.93")
        command(previous, [helper, "seed"])
        verify(previous)
        command(previous, [helper, "backup", str(backup)])
        backup_digest = hashlib.sha256(backup.read_bytes()).hexdigest()
        if scenario == "migration-interrupted":
            interrupt_migration(installed, workspace, php, base, command, helper)
            verify(previous)
        elif scenario not in {"backup-restore", "rollback-last-supported"}:
            raise ValueError("Directory operator scenario remains unimplemented")
        migrate(installed)
        ready(installed, version)
        verify(installed)
        command(installed, [helper, "tamper"])
        if hashlib.sha256(backup.read_bytes()).hexdigest() != backup_digest:
            raise ValueError("Directory operator backup changed")
        command(installed, [helper, "restore", str(backup)])
        ready(previous, "1.10.93")
        command(previous, ["artisan", "migrate:status", "--no-interaction"])
        verify(previous)
        migrate(installed)
        ready(installed, version)
        verify(installed)
    finally:
        # Only the checked synthetic schema. The allocation controller separately owns the DB process.
        command(installed, [helper, "reset"])
        if command(installed, [helper, "empty"]).strip() != "true":
            raise ValueError("Directory operator schema cleanup failed")
        backup.unlink(missing_ok=True)

def interrupt_migration(installed, workspace, php, env, command, helper):
    checkpoint = private_case_home(env) / "directory-interruption-ready"
    if checkpoint.exists() or checkpoint.is_symlink():
        raise ValueError("Directory interruption checkpoint already exists")
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen([php, "artisan", "migrate", "--force", "--no-interaction",
            "--realpath", "--path=" + str(workspace / "directory-interruption.php")], cwd=installed,
            env={**env, "IICP_PRE1_INTERRUPTION_READY": str(checkpoint)},
            stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            deadline = time.monotonic() + 20
            while not checkpoint.exists():
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise ValueError("Directory migration interruption was not observed")
                time.sleep(0.1)
            if checkpoint.is_symlink() or checkpoint.read_text() != "transaction-open":
                raise ValueError("Directory interruption checkpoint differs")
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=10)
            checkpoint.unlink(missing_ok=True)
    if process.returncode != -signal.SIGKILL:
        raise ValueError("Directory migration was not interrupted")

context = json.loads(os.environ["IICP_PRE1_EXECUTION_CONTEXT"])
component, scenario = context["component"], context["scenario_id"]
if ((component == "directory-rust" and context["mode"] not in {"local-only", "public", "restricted"})
        or (component != "directory-rust" and context["mode"] != "local-only")):
    raise ValueError("Directory packaged mode is not implemented")
installed = Path(os.environ["IICP_PRE1_DIRECTORY_INSTALLED"])
assertion = sys.argv[1]
env = {k: os.environ[k] for k in ("HOME", "PATH", "TMPDIR", "TEMP", "TMP") if k in os.environ}
env.update(APP_ENV="testing", NO_COLOR="1")
case_home = private_case_home(env)
if scenario == "no-dual-authority":
    import runpy
    case = json.loads(Path("directory-case-map.json").read_text())["scenarios"][scenario]
    if case != {"assertion": assertion, "command": ["@installed"]}:
        raise ValueError("comparative Directory case map differs")
    topology = runpy.run_path(str(Path("directory-topology.py").resolve()))
    with topology["hold_peer_port"](component, require_loopback_only) as lease:
        def observe_listener():
            topology["observe_own_listener"](component, lease, require_loopback_only)
        if component == "directory-rust":
            launch = rust_mode_environment(env, context["mode"])
            if context["mode"] == "restricted":
                reset_directory_database(launch)
            rust_mode_postcondition(installed / "iicp-directory-rs", launch,
                context["mode"], os.environ["IICP_PRE1_DIRECTORY_VERSION"])
            if context["mode"] == "restricted":
                reset_directory_database(launch)
            rust_http_case(installed / "iicp-directory-rs", launch, "credential-missing",
                os.environ["IICP_PRE1_DIRECTORY_VERSION"],
                database=(Path.cwd() / "directory-operator-fixture.json").exists(),
                listener_check=observe_listener)
        else:
            php_mode_postcondition(installed, env, context["mode"])
            observation = runpy.run_path(str(Path("directory-discovery.py").resolve()))["execute"](
                installed, os.environ["IICP_PRE1_DIRECTORY_PHP"], env, context["mode"],
                listener_check=observe_listener)
            if (not isinstance(observation, dict) or observation.get("mode") != context["mode"]
                    or observation.get("scope") != "installed-php-tcp-discovery-and-registration-pricing"
                    or observation.get("qualification_credit") is not False
                    or not isinstance(observation.get("observations"), dict)
                    or not observation["observations"]):
                raise ValueError("installed PHP Directory TCP observation differs")
        topology_result = topology["result"](component, context["mode"], lease)
    print("IICP_PRE1_DIRECTORY_TOPOLOGY " + json.dumps(
        topology_result, sort_keys=True))
    print("IICP_PRE1_DIRECTORY_ASSERTION_PASS " + assertion)
    raise SystemExit(0)
if component == "directory-rust":
    argv = [str(installed / "iicp-directory-rs")]
    env = rust_mode_environment(env, context["mode"])
    if context["mode"] == "restricted":
        reset_directory_database(env)
    rust_mode_postcondition(Path(argv[0]), env, context["mode"], os.environ["IICP_PRE1_DIRECTORY_VERSION"])
    if context["mode"] == "restricted":
        reset_directory_database(env)
    if scenario == "cross-flavor-equivalence":
        observed = registration_scenario_postcondition(Path(argv[0]), env, os.environ["IICP_PRE1_DIRECTORY_VERSION"])
        print("IICP_PRE1_REGISTRATION_OBSERVATION " + json.dumps(observed, sort_keys=True))
        print("IICP_PRE1_REGISTRATION_TRANSPORT tcp")
        discovery = discovery_scenario_postcondition(Path(argv[0]), env,
            os.environ["IICP_PRE1_DIRECTORY_VERSION"], context["mode"])
        print("IICP_PRE1_INSTALLED_DISCOVERY_OBSERVATION " + json.dumps(discovery, sort_keys=True))
        endpoints = endpoint_scenario_postcondition(Path(argv[0]), env,
            os.environ["IICP_PRE1_DIRECTORY_VERSION"], context["mode"])
        print("IICP_PRE1_INSTALLED_ENDPOINT_OBSERVATION " + json.dumps(endpoints, sort_keys=True))
        print("IICP_PRE1_DIRECTORY_ASSERTION_PASS " + assertion)
        raise SystemExit(0)
    if scenario == "minimum-version":
        minimum_runtime_postcondition(Path(argv[0]), env, os.environ["IICP_PRE1_DIRECTORY_VERSION"])
        print("IICP_PRE1_DIRECTORY_ASSERTION_PASS " + assertion)
        raise SystemExit(0)
    if scenario == "offline-locked-install":
        offline_locked_install_postcondition(installed, os.environ["IICP_PRE1_DIRECTORY_VERSION"],
            os.environ["IICP_PRE1_DIRECTORY_ARTIFACT_SHA256"])
        print("IICP_PRE1_DIRECTORY_ASSERTION_PASS " + assertion)
        raise SystemExit(0)
    if scenario == "rollback-last-supported":
        rollback_postcondition(Path(argv[0]), env, os.environ["IICP_PRE1_DIRECTORY_VERSION"],
            Path(os.environ["IICP_PRE1_ROLLBACK_PREDECESSOR"]), os.environ["IICP_PRE1_ROLLBACK_PREDECESSOR_SHA256"])
        print("IICP_PRE1_DIRECTORY_ASSERTION_PASS " + assertion)
        raise SystemExit(0)
    if scenario == "backup-restore":
        backup_restore_postcondition(Path(argv[0]), env, os.environ["IICP_PRE1_DIRECTORY_VERSION"])
        print("IICP_PRE1_DIRECTORY_ASSERTION_PASS " + assertion)
        raise SystemExit(0)
    if scenario == "migration-interrupted":
        resource.setrlimit(resource.RLIMIT_FSIZE, (32 * 1024 * 1024, 32 * 1024 * 1024))
        migration_interrupted_postcondition(Path(argv[0]), env, os.environ["IICP_PRE1_DIRECTORY_VERSION"])
        print("IICP_PRE1_DIRECTORY_ASSERTION_PASS " + assertion)
        raise SystemExit(0)
    if scenario in {"credential-missing", "unsupported-version", "credential-expired",
                    "credential-rotated", "rate-limit", "dynamic-public-route-readiness", "duplicate-registration", "config-permission-denied", "disk-full", "process-crash-restart", "stale-pid-or-lock", "interrupted-write"}:
        resource.setrlimit(resource.RLIMIT_FSIZE, (32 * 1024 * 1024, 32 * 1024 * 1024))
        rust_http_case(Path(argv[0]), env, scenario, os.environ["IICP_PRE1_DIRECTORY_VERSION"],
            database=(Path.cwd() / "directory-operator-fixture.json").exists())
        print("IICP_PRE1_DIRECTORY_ASSERTION_PASS " + assertion)
        raise SystemExit(0)
    elif scenario in {"credential-replayed", "signature-mismatch"}:
        if scenario == "signature-mismatch":
            reset_directory_database(env)
        try:
            rust_http_case(installed / "iicp-directory-rs", env, scenario, os.environ["IICP_PRE1_DIRECTORY_VERSION"], database=True)
        finally:
            if scenario == "signature-mismatch":
                reset_directory_database(env)
        print("IICP_PRE1_DIRECTORY_ASSERTION_PASS " + assertion)
        raise SystemExit(0)
    elif scenario in {"package-version-self-report", "support"}:
        if scenario == "support":
            directory_support_postcondition()
        argv.append("--version")
        expected = "iicp-directory-rs " + os.environ["IICP_PRE1_DIRECTORY_VERSION"]
        expected_code = 0
    elif scenario == "config-missing":
        expected = "DATABASE_URL is required"
        expected_code = 1
    elif scenario == "config-malformed":
        env.update(IICP_ALLOW_IN_MEMORY="true", IICP_REPLICA_MODE="true",
            IICP_SEED_URL="https://seed.invalid/v1", IICP_SEED_DID="did:web:seed.invalid",
            IICP_REPLICA_DID="did:web:replica.invalid", IICP_REPLICA_ENDPOINT="https://replica.invalid/v1",
            IICP_DIRECTORY_DID="did:web:other.invalid")
        expected = ("restricted trust-domain federation is not implemented; replica mode cannot be combined with restricted-domain mode"
            if context["mode"] == "restricted" else "IICP_DIRECTORY_DID must equal IICP_REPLICA_DID")
        expected_code = 1
    else:
        raise ValueError("Directory packaged scenario is not implemented")
else:
    if scenario in {"backup-restore", "migration-interrupted", "rollback-last-supported"}:
        resource.setrlimit(resource.RLIMIT_FSIZE, (32 * 1024 * 1024, 32 * 1024 * 1024))
        php_operator_case(installed, env, scenario, os.environ["IICP_PRE1_DIRECTORY_VERSION"])
        print("IICP_PRE1_DIRECTORY_ASSERTION_PASS " + assertion)
        raise SystemExit(0)
    mapping = json.loads(Path("directory-case-map.json").read_text())
    case = mapping["support"] if scenario == "support" else mapping["scenarios"][scenario]
    argv = [os.environ["IICP_PRE1_DIRECTORY_PHP"], *case["command"][1:]]
    if case["command"][0] != "@php" or case["assertion"] != assertion:
        raise ValueError("structural Python checks are not packaged Directory operations")
    report = case_home / "directory-junit.xml"
    if report.exists():
        raise ValueError("Directory case result already exists")
    argv.extend(["--do-not-cache-result", "--bootstrap", str(Path("directory-origin.php").resolve()),
                 "--log-junit", str(report)])
    env.update(PRE1_DIRECTORY_INSTALLED=str(installed))
    expected_code, expected = 0, None
limit = 32 * 1024 * 1024
resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
with tempfile.NamedTemporaryFile(prefix="directory-output-", dir=case_home, delete=False) as log:
    output_file = Path(log.name)
    process = subprocess.Popen(argv, cwd=installed, env=env, stdout=log, stderr=subprocess.STDOUT,
                               start_new_session=True)
    try:
        process.wait(timeout=180)
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=10)
    size = log.tell()
    if size > 32 * 1024 * 1024:
        raise ValueError("Directory case output exceeds the diagnostic bound")
    log.seek(0)
    output = log.read().decode("utf-8", errors="replace")
if process.returncode != expected_code or (expected is not None and expected not in output) or (
    component == "directory-rust" and scenario in {"package-version-self-report", "support"} and output.strip() != expected
):
    raise ValueError("Directory packaged postcondition failed")
if component == "directory-php":
    document = ET.parse(report)
    cases = list(document.iter("testcase"))
    if len(cases) != 1 or cases[0].get("name") != assertion or any(
        list(document.iter(tag)) for tag in ("skipped", "failure", "error")
    ):
        raise ValueError("Directory exact assertion did not pass once without skips")
    report.unlink()
output_file.unlink()
print("IICP_PRE1_DIRECTORY_ASSERTION_PASS " + assertion)
'''
DIRECTORY_ORIGIN = r'''<?php
$root = realpath(getenv('PRE1_DIRECTORY_INSTALLED'));
if (!$root) { throw new RuntimeException('Directory package root unavailable'); }
require $root . '/vendor/autoload.php';
register_shutdown_function(function () use ($root) {
    foreach (get_declared_classes() as $class) {
        $expected = null;
        foreach (['App\\' => 'app', 'Tests\\' => 'tests', 'Database\\' => 'database'] as $prefix => $directory) {
            if (str_starts_with($class, $prefix)) {
                $expected = $root . DIRECTORY_SEPARATOR . $directory . DIRECTORY_SEPARATOR;
                break;
            }
        }
        if ($expected !== null) {
            $file = (new ReflectionClass($class))->getFileName();
            if (!$file || !str_starts_with(realpath($file), $expected)) {
                fwrite(STDERR, "Directory application class escaped packaged origin\n");
                exit(2);
            }
        }
    }
});
'''


def directory_archive_payload(artifact):
    files = rust_archive_files(artifact, "")
    prefixes = {name.split("/", 1)[0] for name in files}
    if len(prefixes) != 1:
        raise ValueError("Directory archive must have one package root")
    prefix = prefixes.pop() + "/"
    if not re.fullmatch(r"iicp-directory-php-v\d+\.\d+\.\d+/", prefix):
        raise ValueError("Directory archive package root differs")
    result = {name.removeprefix(prefix): value for name, value in files.items()}
    if not {"artisan", "composer.json", "composer.lock"}.issubset(result) or any(
        name.startswith("vendor/") for name in result
    ):
        raise ValueError("Directory archive lacks locked source or contains vendor")
    return result


def stage_directory_payload(artifact, workspace, component):
    workspace = safe_path(workspace)
    home = prepared_package_home()
    if workspace == home or not workspace.is_relative_to(home) or list(workspace.iterdir()):
        raise ValueError("Directory staging requires an empty run workspace")
    safe_path(artifact)
    installed = workspace / "payload"
    if component == "directory-rust":
        installed.mkdir(mode=0o700)
        (installed / "iicp-directory-rs").write_bytes(artifact.read_bytes())
        (installed / "iicp-directory-rs").chmod(0o700)
    elif component == "directory-php":
        expected = directory_archive_payload(artifact)
        installed.mkdir(mode=0o700)
        with tarfile.open(artifact, "r:gz") as archive:
            for row in archive:
                if row.isfile():
                    name = row.name.split("/", 1)[1]
                    if name not in expected:
                        raise ValueError("Directory archive contains an unexpected member")
                    dest = installed / name
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    handle = archive.extractfile(row)
                    if handle is None:
                        raise ValueError("Directory archive member unavailable")
                    with dest.open("xb") as output:
                        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                            output.write(chunk)
                    dest.chmod(0o600)
        if tree(installed) != expected:
            raise ValueError("Directory staged archive differs")
        provision_directory_runtime_paths(installed)
    else:
        raise ValueError("Directory staging component differs")
    return installed


def provision_directory_runtime_paths(installed):
    # Release archives need not contain empty runtime directories. Provision
    # only Laravel's private writable paths before Composer's locked scripts
    # execute; these are not alternate application or dependency sources.
    for relative in ("bootstrap/cache", "storage/logs", "storage/framework/cache/data",
                     "storage/framework/sessions", "storage/framework/views"):
        directory = installed
        for part in relative.split("/"):
            directory = directory / part
            if directory.exists() or directory.is_symlink():
                safe_path(directory)
                if not directory.is_dir():
                    raise ValueError("Directory runtime path is not a directory")
            else:
                directory.mkdir(mode=0o700)


def directory_fixtures(root, component):
    result = {"directory-probe.py": DIRECTORY_PROBE.encode(),
              "directory-case-map.json": safe_path(root / "qualification/pre1-cases.json").read_bytes(),
              "directory-topology.py": safe_path(root / "scripts/pre1_comparative_topology.py").read_bytes()}
    if component == "directory-php":
        result["directory-origin.php"] = DIRECTORY_ORIGIN.encode()
    elif component == "directory-rust":
        # The installed Rust Directory is deliberately verify-only and never
        # migrates operator databases. Bind the canonical schema snapshot as a
        # test fixture so each newly reset disposable database can be
        # initialized before the frozen binary starts.
        result["directory-baseline-v1.sql"] = safe_path(root / "schema/baseline-v1.sql").read_bytes()
        result["directory-discovery.py"] = safe_path(root / "scripts/pre1_installed_discovery.py").read_bytes()
        result["directory-registration-delegation.json"] = safe_path(
            root / "qualification/registration-delegation-v1.json").read_bytes()
        for name, source in {"contract": "contract-v1.10.80.json", "behavior": "behavior-contract-v1.json", "http": "http-contract-v1.json"}.items():
            result["directory-support-" + name + ".json"] = safe_path(root / "parity" / source).read_bytes()
    return result


def directory_runtime_dependencies(workspace, bindings):
    fixture = workspace / "directory-runtime-fixture"
    candidate = workspace / "directory-runtime-candidate.json"
    if not any(path.exists() or path.is_symlink() for path in (fixture, candidate)):
        return {}
    import prepare_pre1_minimum_runtime as helper
    value = helper.validate_fixture(fixture, candidate)
    if json.loads(candidate.read_text()).get("manifest_sha256") != bindings["candidate_manifest_sha256"]:
        raise ValueError("runtime fixture candidate differs from installed package binding")
    return {"runtime-fixture": value["fixture_sha256"], "runtime-candidate": file_digest(candidate)}


def directory_rollback_dependencies(workspace, target):
    fixture = workspace / "directory-rollback-fixture"
    if not fixture.exists() and not fixture.is_symlink():
        return {}
    import prepare_pre1_minimum_runtime as helper
    value = helper.validate_rollback_fixture(fixture, target)
    return {"rollback-fixture": value["fixture_sha256"]}


def directory_rollback_environment(workspace, context, version, env):
    dependencies = directory_rollback_dependencies(workspace, context["target"])
    if not dependencies or version != "0.1.16":
        raise ValueError("Directory rollback requires the pinned profile-compatible successor fixture")
    fixture = workspace / "directory-rollback-fixture"
    return {**env, "IICP_PRE1_ROLLBACK_PREDECESSOR": str(fixture / "predecessor"),
            "IICP_PRE1_ROLLBACK_PREDECESSOR_SHA256": file_digest(fixture / "predecessor")}


def directory_auxiliary_environment(workspace, context, component_manifest, env):
    if context["component"] != "directory-rust":
        return env
    if context["scenario_id"] == "minimum-version":
        return directory_minimum_runtime_environment(workspace, context, env)
    if context["scenario_id"] == "rollback-last-supported":
        return directory_rollback_environment(workspace, context, component_manifest["source_version"], env)
    return env


def directory_payload(artifact, installed, component, target):
    files = tree(installed)
    if component == "directory-rust":
        binary = safe_path(installed / "iicp-directory-rs")
        with binary.open("rb") as handle:
            header = handle.read(20)
        machine = {"linux-aarch64": 183, "linux-x86_64": 62}.get(target)
        if len(header) != 20 or header[:6] != b"\x7fELF\x02\x01" or machine is None or int.from_bytes(header[18:20], "little") != machine:
            raise ValueError("Directory binary architecture differs")
        if stat.S_IMODE(binary.stat().st_mode) != 0o700 or files != {"iicp-directory-rs": file_digest(artifact)}:
            raise ValueError("Directory installed binary differs")
        return files, {}
    expected = directory_archive_payload(artifact)
    volatile = ("vendor/", "storage/", "bootstrap/cache/")
    immutable = {k: v for k, v in files.items() if not k.startswith(volatile)}
    if immutable != {k: v for k, v in expected.items() if not k.startswith(volatile)}:
        raise ValueError("Directory installed archive differs")
    deps = {"vendor/" + k: v for k, v in tree(safe_path(installed / "vendor")).items()}
    cache = installed / "bootstrap/cache"
    if cache.exists() or cache.is_symlink():
        deps.update({"bootstrap-cache/" + k: v for k, v in tree(safe_path(cache)).items()})
    return immutable, deps




def directory_operator_config(config):
    safe_path(config)
    if not config.is_file() or config.stat().st_size > 4096:
        raise ValueError("Directory operator fixture configuration exceeds bound")
    raw = config.read_bytes()
    value = json.loads(raw)
    if (not isinstance(value, dict) or set(value) != {"schema", "database", "username", "port"}
        or value["schema"] != "iicp.pre1-directory-operator-fixture.v1"
        or not re.fullmatch(r"iicp_pre1_[a-f0-9]{16}", str(value["database"]))
        or value["username"] != "iicp_pre1_fixture" or value["port"] != 3306):
        raise ValueError("Directory operator fixture configuration differs")
    return raw

def directory_database_dependencies(workspace):
    config = workspace / "directory-operator-fixture.json"
    password = workspace / "directory-operator-password"
    tools = workspace / "directory-database-tools"
    if not any(path.exists() or path.is_symlink() for path in (config, password, tools)):
        return {}
    raw = directory_operator_config(config)
    safe_path(password); safe_path(tools)
    if (not stat.S_ISREG(password.stat().st_mode) or stat.S_IMODE(password.stat().st_mode) != 0o600
        or not 16 <= password.stat().st_size <= 128 or not tools.is_dir()):
        raise ValueError("Directory database fixture dependency differs")
    files = tree(tools)
    if (not {"loader", "mysql"}.issubset(files) or not 3 <= len(files) <= 32
        or any(not re.fullmatch(r"(?:loader|mysql|mysqldump|lib/[a-zA-Z0-9._+-]+)", name) for name in files)
        or sum((tools / name).stat().st_size for name in files) > 64 * 1024 * 1024):
        raise ValueError("Directory database tool snapshot differs")
    return {"database-config": "sha256:" + hashlib.sha256(raw).hexdigest(),
            "database-password": file_digest(password), "database-tools": digest(files)}

def create_directory_binding(root, workspace, installed, artifact, component, runtime, target, bindings, *, stage_fixtures=True):
    validate_immutable_bindings(bindings)
    validate_workspace_boundary(safe_path(workspace), prepared_package_home(), safe_path(installed), root)
    payload, deps = directory_payload(artifact, installed, component, target)
    if component == "directory-rust":
        deps.update(directory_database_dependencies(workspace))
        deps.update(directory_runtime_dependencies(workspace, bindings))
        deps.update(directory_rollback_dependencies(workspace, target))
    fixtures = directory_fixtures(root, component)
    if "runtime-fixture" in deps:
        for name in ("prepare_pre1_minimum_runtime.py", "pre1_package_execution.py", "pre1_artifact_common.py"):
            fixtures["directory-runtime-tools/" + name] = safe_path(root / "scripts" / name).read_bytes()
    for name, data in fixtures.items():
        dest = workspace / name
        if not dest.exists() and stage_fixtures:
            dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with dest.open("xb") as output:
                output.write(data)
            dest.chmod(0o600)
        if not dest.exists() or dest.is_symlink() or dest.read_bytes() != data:
            raise ValueError("Directory packaged fixtures changed")
    value = {"schema": SCHEMA, "component": component, "runtime": runtime, "target": target,
        "bindings": bindings, "workspace": str(workspace), "installed_package": str(installed),
        "artifact_sha256": file_digest(artifact), "installed_payload_sha256": digest(payload),
        "fixtures_sha256": digest({k: "sha256:" + hashlib.sha256(v).hexdigest() for k, v in fixtures.items()}),
        "test_dependencies_sha256": digest(deps), "binding_sha256": None,
        "assertion_adapter": "canonical-runtime-verifier-and-cli.v1",
        "non_authorizing": True, "qualification_credit": False}
    value["binding_sha256"] = digest(value)
    return value


def validate_directory_binding(value, context, artifact, root):
    validate_binding_identity(value)
    validate_binding_context(value, context)
    expected = create_directory_binding(root, Path(value["workspace"]), Path(value["installed_package"]),
        artifact, context["component"], context["runtime"], context["target"], {k: context[k] for k in BINDINGS}, stage_fixtures=False)
    if value != expected:
        raise ValueError("Directory package execution inputs changed")
    return safe_path(Path(value["workspace"]))



def require_directory_database_fixture(component, scenario, workspace, mode="local-only"):
    if component == "directory-rust" and (scenario in DIRECTORY_RUST_DATABASE_SCENARIOS or mode == "restricted"):
        if not directory_database_dependencies(workspace):
            raise ValueError("Directory packaged database fixture is missing")
        if scenario == "backup-restore" and not (workspace / "directory-database-tools/mysqldump").is_file():
            raise ValueError("Directory backup requires pinned mysqldump fixture")


def directory_package_command(root, context, component_manifest, artifact_root, env, value):
    component, scenario = context["component"], context["scenario_id"]
    if ((component == "directory-rust" and context["mode"] not in {"local-only", "public", "restricted"})
            or (component != "directory-rust" and context["mode"] != "local-only")):
        raise ValueError("Directory packaged mode remains unimplemented")
    kind = "release-artifact" if component == "directory-rust" else "release-archive"
    rows = [r for r in component_manifest["artifacts"] if r["kind"] == kind and r["target"] in {context["target"], "any"}]
    if len(rows) != 1:
        raise ValueError("Directory execution artifact is ambiguous")
    artifact = safe_path(artifact_root / component / rows[0]["name"])
    if file_digest(artifact) != rows[0]["sha256"]:
        raise ValueError("Directory candidate artifact digest differs")
    workspace = validate_directory_binding(value, context, artifact, root)
    mapping = json.loads((workspace / "directory-case-map.json").read_text())
    case = mapping["support"] if scenario == "support" else mapping["scenarios"][scenario]
    if component == "directory-rust" and scenario not in DIRECTORY_RUST_SCENARIOS:
        raise ValueError("Directory black-box scenario remains unimplemented")
    if component == "directory-php" and scenario != "no-dual-authority" and case["command"][0] != "@php":
        raise ValueError("Directory structural checks are not packaged operation evidence")
    env = {**env, "IICP_PRE1_EXECUTION_CONTEXT": json.dumps(context, sort_keys=True),
           "IICP_PRE1_DIRECTORY_INSTALLED": value["installed_package"],
           "IICP_PRE1_DIRECTORY_VERSION": component_manifest["source_version"],
           "IICP_PRE1_DIRECTORY_ARTIFACT_SHA256": rows[0]["sha256"]}
    require_directory_database_fixture(component, scenario, workspace, context["mode"])
    env = directory_auxiliary_environment(workspace, context, component_manifest, env)
    if component == "directory-php":
        runtime_map = json.loads(Path(os.environ["IICP_PRE1_RUNTIME_MAP"]).read_text())
        env["IICP_PRE1_DIRECTORY_PHP"] = runtime_map["runtimes"][context["runtime"]]["programs"]["php"]
    argv = [sys.executable, "-I", "-S", str(workspace / "directory-probe.py"), case["assertion"]]
    return argv, env, workspace, {"value": value, "artifact": artifact, "vendor_artifact": None}


def directory_minimum_runtime_environment(workspace, context, env):
    deps = directory_runtime_dependencies(workspace, {key: context[key] for key in BINDINGS})
    if not deps:
        raise ValueError("Directory minimum runtime requires the pinned frozen-source fixture")
    runtime_map = json.loads(safe_path(Path(env["IICP_PRE1_RUNTIME_MAP"])).read_text())
    if (runtime_map.get("target") != context["target"]
            or runtime_map.get("map_sha256") != context["runtime_map_sha256"]):
        raise ValueError("Directory runtime map binding differs")
    row = runtime_map["runtimes"][context["runtime"]]
    programs = row["programs"]
    import prepare_pre1_minimum_runtime as helper
    for name in ("cargo", "rustc"):
        helper.executable(Path(programs[name]))
    output = safe_path(Path(env["IICP_PRE1_RUN_ROOT"]))
    evidence = safe_path(Path(env["IICP_PRE1_CASE_EVIDENCE_ROOT"]))
    home = safe_path(Path(env["HOME"]))
    if any(path.is_relative_to(workspace) or path.is_relative_to(home) for path in (output, evidence)):
        raise ValueError("Directory runtime output cannot mutate prepared inputs")
    return {**env, "IICP_PRE1_DIRECTORY_CARGO": programs["cargo"],
            "IICP_PRE1_DIRECTORY_RUSTC": programs["rustc"],
            "IICP_PRE1_DIRECTORY_RUNTIME_OUTPUT": str(output),
            "IICP_PRE1_DIRECTORY_RUNTIME_FIXTURE_SHA256": deps["runtime-fixture"]}
