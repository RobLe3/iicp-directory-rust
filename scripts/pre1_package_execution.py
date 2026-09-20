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
    home = safe_path(Path(os.environ["HOME"]))
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
    home = safe_path(Path(os.environ["HOME"]))
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
    validate_workspace_boundary(safe_path(workspace), safe_path(Path(os.environ["HOME"])),
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
    validate_workspace_boundary(workspace, safe_path(Path(os.environ["HOME"])), installed, root)
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
    home = safe_path(Path(os.environ["HOME"]))
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
    home = safe_path(Path(os.environ["HOME"]))
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
    "credential-expired", "credential-rotated", "rate-limit", "dynamic-public-route-readiness", "duplicate-registration", "config-permission-denied", "disk-full", "process-crash-restart", "stale-pid-or-lock"})
DIRECTORY_RUST_DATABASE_SCENARIOS = frozenset({"credential-replayed"})
DIRECTORY_RUST_SCENARIOS = DIRECTORY_RUST_HTTP_SCENARIOS | DIRECTORY_RUST_DATABASE_SCENARIOS | frozenset({
    "package-version-self-report", "config-missing", "config-malformed"})

DIRECTORY_PROBE = r'''import json, os, resource, signal, subprocess, sys, tempfile, time
from pathlib import Path
import xml.etree.ElementTree as ET
import urllib.request, urllib.error


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

def http_postcondition(request, scenario):
    if scenario == "credential-missing":
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

def database_observation():
    require_loopback_only()
    config, password = database_fixture_inputs()
    tools = Path.cwd() / "directory-database-tools"
    argv = [str(tools / "loader"), "--library-path", str(tools / "lib"), str(tools / "mysql"),
        "--no-defaults", "--batch", "--raw", "--skip-column-names", "--protocol=TCP", "--host=127.0.0.1",
        "--port=3306", "--connect-timeout=3", "--user=" + config["username"],
        "--database=" + config["database"], "--execute",
        "SELECT UNIX_TIMESTAMP(liveness_verified_at), liveness_challenge FROM nodes WHERE id = 'fixture-replay'"]
    with tempfile.TemporaryDirectory(prefix="directory-oracle-home-", dir=Path.cwd()) as private_home, tempfile.TemporaryFile() as output:
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

def rust_http_case(binary, env, scenario, version, database=False):
    require_loopback_only()
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    def request(path, body=None, headers=None):
        req = urllib.request.Request("http://127.0.0.1:8090" + path,
            data=None if body is None else json.dumps(body).encode(),
            headers={"Content-Type": "application/json", **(headers or {})})
        try:
            response = opener.open(req, timeout=2)
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
    launch_env = {**env, "APP_KEY": "iicp-pre1-isolated-synthetic-key"}
    if database:
        config, password = database_fixture_inputs()
        from urllib.parse import quote
        launch_env["DATABASE_URL"] = ("mysql://" + config["username"] + ":" + quote(password, safe="")
            + "@127.0.0.1:3306/" + config["database"])
    else:
        launch_env["IICP_ALLOW_IN_MEMORY"] = "true"
    with tempfile.TemporaryDirectory(prefix="directory-health-", dir=Path(env.get("TMPDIR", str(Path.cwd())))) as health_dir, tempfile.TemporaryFile(dir=binary.parent if scenario == "disk-full" else None) as log:
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
            if scenario == "config-permission-denied":
                permission_snapshot_postcondition(process, snapshot, log, request)
            elif scenario == "disk-full":
                disk_full_snapshot_postcondition(process, snapshot, log, request)
            elif scenario in {"process-crash-restart", "stale-pid-or-lock"}:
                def restart():
                    return subprocess.Popen([str(binary)], cwd=binary.parent,
                        env=launch_env, stdout=log, stderr=subprocess.STDOUT,
                        start_new_session=True)
                if scenario == "stale-pid-or-lock":
                    with tempfile.TemporaryDirectory(prefix="directory-contender-", dir=Path(env.get("TMPDIR", str(Path.cwd())))) as contender_dir, tempfile.TemporaryFile() as contender_log:
                        contender_env = {**launch_env, "IICP_RUNTIME_HEALTH_FILE": str(Path(contender_dir) / "health.json")}
                        contender = subprocess.Popen([str(binary)], cwd=binary.parent,
                            env=contender_env, stdout=contender_log, stderr=subprocess.STDOUT,
                            start_new_session=True)
                        process = stale_owner_postcondition(process, snapshot, request, contender, contender_log, restart, version)
                else:
                    process = crash_restart_snapshot_postcondition(process, snapshot, request, restart, version)
            elif scenario == "credential-replayed":
                credential_replay_postcondition(request, database_observation)
            else:
                http_postcondition(request, scenario)
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=10)

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
    backup = workspace / "directory-backup.json"
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
    checkpoint = workspace / "directory-interruption-ready"
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
if context["mode"] != "local-only":
    raise ValueError("Directory packaged mode is not implemented")
installed = Path(os.environ["IICP_PRE1_DIRECTORY_INSTALLED"])
assertion = sys.argv[1]
env = {k: os.environ[k] for k in ("HOME", "PATH", "TMPDIR", "TEMP", "TMP") if k in os.environ}
env.update(APP_ENV="testing", NO_COLOR="1")
if component == "directory-rust":
    argv = [str(installed / "iicp-directory-rs")]
    if scenario in {"credential-missing", "unsupported-version", "credential-expired",
                    "credential-rotated", "rate-limit", "dynamic-public-route-readiness", "duplicate-registration", "config-permission-denied", "disk-full", "process-crash-restart", "stale-pid-or-lock"}:
        resource.setrlimit(resource.RLIMIT_FSIZE, (32 * 1024 * 1024, 32 * 1024 * 1024))
        rust_http_case(Path(argv[0]), env, scenario, os.environ["IICP_PRE1_DIRECTORY_VERSION"],
            database=(Path.cwd() / "directory-operator-fixture.json").exists())
        print("IICP_PRE1_DIRECTORY_ASSERTION_PASS " + assertion)
        raise SystemExit(0)
    elif scenario == "credential-replayed":
        rust_http_case(installed / "iicp-directory-rs", env, scenario, os.environ["IICP_PRE1_DIRECTORY_VERSION"], database=True)
        print("IICP_PRE1_DIRECTORY_ASSERTION_PASS " + assertion)
        raise SystemExit(0)
    elif scenario == "package-version-self-report":
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
        expected = "IICP_DIRECTORY_DID must equal IICP_REPLICA_DID"
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
    report = Path("directory-junit.xml").resolve()
    if report.exists():
        raise ValueError("Directory case result already exists")
    argv.extend(["--do-not-cache-result", "--bootstrap", str(Path("directory-origin.php").resolve()),
                 "--log-junit", str(report)])
    env.update(PRE1_DIRECTORY_INSTALLED=str(installed))
    expected_code, expected = 0, None
limit = 32 * 1024 * 1024
resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
with tempfile.NamedTemporaryFile(prefix="directory-output-", dir=Path.cwd(), delete=False) as log:
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
    component == "directory-rust" and scenario == "package-version-self-report" and output.strip() != expected
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
    home = safe_path(Path(os.environ["HOME"]))
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
              "directory-case-map.json": safe_path(root / "qualification/pre1-cases.json").read_bytes()}
    if component == "directory-php":
        result["directory-origin.php"] = DIRECTORY_ORIGIN.encode()
    return result


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
        or any(not re.fullmatch(r"(?:loader|mysql|lib/[a-zA-Z0-9._+-]+)", name) for name in files)
        or sum((tools / name).stat().st_size for name in files) > 64 * 1024 * 1024):
        raise ValueError("Directory database tool snapshot differs")
    return {"database-config": "sha256:" + hashlib.sha256(raw).hexdigest(),
            "database-password": file_digest(password), "database-tools": digest(files)}

def create_directory_binding(root, workspace, installed, artifact, component, runtime, target, bindings, *, stage_fixtures=True):
    validate_immutable_bindings(bindings)
    validate_workspace_boundary(safe_path(workspace), safe_path(Path(os.environ["HOME"])), safe_path(installed), root)
    payload, deps = directory_payload(artifact, installed, component, target)
    if component == "directory-rust":
        deps.update(directory_database_dependencies(workspace))
    fixtures = directory_fixtures(root, component)
    for name, data in fixtures.items():
        dest = workspace / name
        if not dest.exists() and stage_fixtures:
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



def require_directory_database_fixture(component, scenario, workspace):
    if component == "directory-rust" and scenario in DIRECTORY_RUST_DATABASE_SCENARIOS:
        if not directory_database_dependencies(workspace):
            raise ValueError("Directory packaged database fixture is missing")


def directory_package_command(root, context, component_manifest, artifact_root, env, value):
    component, scenario = context["component"], context["scenario_id"]
    if context["mode"] != "local-only":
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
    if component == "directory-php" and case["command"][0] != "@php":
        raise ValueError("Directory structural checks are not packaged operation evidence")
    env = {**env, "IICP_PRE1_EXECUTION_CONTEXT": json.dumps(context, sort_keys=True),
           "IICP_PRE1_DIRECTORY_INSTALLED": value["installed_package"],
           "IICP_PRE1_DIRECTORY_VERSION": component_manifest["source_version"]}
    require_directory_database_fixture(component, scenario, workspace)
    if component == "directory-php":
        runtime_map = json.loads(Path(os.environ["IICP_PRE1_RUNTIME_MAP"]).read_text())
        env["IICP_PRE1_DIRECTORY_PHP"] = runtime_map["runtimes"][context["runtime"]]["programs"]["php"]
    argv = [sys.executable, "-I", "-S", str(workspace / "directory-probe.py"), case["assertion"]]
    return argv, env, workspace, {"value": value, "artifact": artifact, "vendor_artifact": None}
