"""Portable qualification environment contract; mirrored from the hub validator.

Only qualification tooling imports this module. No product runtime dependency.
"""
from __future__ import annotations
import hashlib
import json
import re


def canonical_sha256(value: object) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return "sha256:" + hashlib.sha256(data).hexdigest()


def valid_digest(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


RUNTIME_FIELDS = {
    "lock_inputs_sha256",
    "dependency_cache_sha256",
    "online_prepare_status",
    "offline_install_status",
    "package_artifact_smoke_status",
    "egress_disabled_during_offline",
    "empty_volatile_cache_at_start",
}
TOP_LEVEL_FIELDS = {
    "schema",
    "status",
    "target",
    "bindings",
    "network",
    "source_state",
    "runtimes",
    "content_free",
    "secrets_present",
    "non_authorizing",
    "environment_sha256",
}
V2_TOP_LEVEL_FIELDS = TOP_LEVEL_FIELDS | {"execution"}
V3_TOP_LEVEL_FIELDS = V2_TOP_LEVEL_FIELDS | {"isolation"}
EXECUTION_FIELDS = {
    "execution_kind",
    "evidence_scope",
    "host_architecture",
    "guest_architecture",
    "container_engine",
    "container_engine_version",
    "emulation_mechanism",
    "image_digest",
}
EXECUTION_KINDS = {
    "native",
    "isolated_vm",
    "container_native",
    "container_emulated",
}


def _architecture(value: object) -> str:
    normalized = str(value).lower()
    if normalized in {"amd64", "x86_64"}:
        return "x86_64"
    if normalized in {"arm64", "aarch64"}:
        return "aarch64"
    return normalized


def _target_architecture(target: str) -> str:
    return "x86_64" if target.endswith("x86_64") else "aarch64"


def _validate_container_execution(execution: dict, kind: object) -> list[str]:
    container_fields = (
        "container_engine",
        "container_engine_version",
        "image_digest",
    )
    if kind in {"container_native", "container_emulated"}:
        errors = (
            ["qualification environment container provenance is incomplete"]
            if not all(
                isinstance(execution.get(field), str) and execution[field]
                for field in container_fields
            )
            else []
        )
        if not valid_digest(execution.get("image_digest")):
            errors.append("qualification environment image digest is invalid")
        return errors
    if any(execution.get(field) is not None for field in container_fields):
        return ["non-container qualification environment claims container provenance"]
    return []


def _validate_execution_architecture(
    execution: dict, target: str, kind: object
) -> list[str]:
    host = _architecture(execution.get("host_architecture"))
    guest = _architecture(execution.get("guest_architecture"))
    errors = (
        []
        if guest == _target_architecture(target)
        else ["qualification environment guest architecture differs"]
    )
    if kind == "container_emulated":
        if target != "linux-x86_64":
            errors.append("emulated qualification is limited to Linux x86-64")
        if (host, guest) != ("aarch64", "x86_64"):
            errors.append("Linux x86-64 emulation architecture provenance differs")
    elif kind in {"native", "container_native"} and host != guest:
        errors.append("native qualification host and guest architectures differ")
    return errors


def _validate_emulation(execution: dict, kind: object) -> list[str]:
    mechanism = execution.get("emulation_mechanism")
    if kind == "container_emulated":
        if not isinstance(mechanism, str) or not mechanism:
            return ["emulated qualification lacks its mechanism"]
    elif mechanism is not None:
        return ["non-emulated qualification claims an emulation mechanism"]
    return []


def _validate_isolation(value: dict, schema: object) -> list[str]:
    if schema != "iicp.pre1-qualification-environment.v3":
        return []
    isolation = value.get("isolation")
    if not isinstance(isolation, dict) or set(isolation) != {
        "kind",
        "identity",
        "evidence_sha256",
    }:
        return ["qualification environment isolation provenance differs"]
    if not _valid_isolation_values(isolation):
        return ["qualification environment isolation evidence is invalid"]
    return []


def _valid_isolation_values(isolation: dict) -> bool:
    text_values = (isolation.get("kind"), isolation.get("identity"))
    return all(map(_nonempty_string, text_values)) and valid_digest(
        isolation.get("evidence_sha256")
    )


def _nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _validate_execution(
    value: dict, target: str, expected_kind: str | None
) -> list[str]:
    execution = value.get("execution")
    if not isinstance(execution, dict) or set(execution) != EXECUTION_FIELDS:
        return ["qualification environment execution provenance differs"]
    errors: list[str] = []
    kind = execution.get("execution_kind")
    if kind not in EXECUTION_KINDS:
        errors.append("qualification environment execution kind is invalid")
    if expected_kind is not None and kind != expected_kind:
        errors.append("qualification environment execution kind differs")
    scope = execution.get("evidence_scope")
    expected_scope = (
        "functional-only"
        if kind == "container_emulated"
        else "functional-and-performance"
    )
    if scope != expected_scope:
        errors.append("qualification environment evidence scope differs")
    return (
        errors
        + _validate_container_execution(execution, kind)
        + _validate_execution_architecture(execution, target, kind)
        + _validate_emulation(execution, kind)
    )


def validate_runtime(runtime: str, value: object) -> list[str]:
    if not isinstance(value, dict) or set(value) != RUNTIME_FIELDS:
        return [f"qualification environment runtime fields differ: {runtime}"]
    errors: list[str] = []
    for field in ("lock_inputs_sha256", "dependency_cache_sha256"):
        if not valid_digest(value.get(field)):
            errors.append(f"qualification environment has invalid {field}: {runtime}")
    for field in (
        "online_prepare_status",
        "offline_install_status",
        "package_artifact_smoke_status",
    ):
        if value.get(field) != "PASS":
            errors.append(
                f"qualification environment gate is not PASS: {runtime}:{field}"
            )
    for field in ("egress_disabled_during_offline", "empty_volatile_cache_at_start"):
        if value.get(field) is not True:
            errors.append(
                f"qualification environment safety gate differs: {runtime}:{field}"
            )
    return errors


def _validate_header(value: dict, target: str, execution_kind: str | None) -> list[str]:
    errors: list[str] = []
    schema = value.get("schema")
    expected_fields = (
        V3_TOP_LEVEL_FIELDS
        if schema == "iicp.pre1-qualification-environment.v3"
        else (
            V2_TOP_LEVEL_FIELDS
            if schema == "iicp.pre1-qualification-environment.v2"
            else TOP_LEVEL_FIELDS
        )
    )
    if set(value) != expected_fields:
        errors.append("qualification environment fields differ")
    if schema not in {
        "iicp.pre1-qualification-environment.v1",
        "iicp.pre1-qualification-environment.v2",
        "iicp.pre1-qualification-environment.v3",
    }:
        errors.append("unexpected qualification-environment schema")
    if execution_kind == "container_emulated" and schema not in {
        "iicp.pre1-qualification-environment.v2",
        "iicp.pre1-qualification-environment.v3",
    }:
        errors.append("emulated qualification requires execution provenance")
    errors.extend(_validate_isolation(value, schema))
    if value.get("status") != "READY":
        errors.append("qualification environment is not ready")
    if value.get("target") != target:
        errors.append("qualification environment target differs")
    if (
        value.get("content_free") is not True
        or value.get("secrets_present") is not False
    ):
        errors.append("qualification environment must be content-free and secret-free")
    if value.get("non_authorizing") is not True:
        errors.append("qualification environment must remain non-authorizing")
    if schema in {
        "iicp.pre1-qualification-environment.v2",
        "iicp.pre1-qualification-environment.v3",
    }:
        errors.extend(_validate_execution(value, target, execution_kind))
    return errors


def _validate_bindings(value: dict, expected_bindings: dict) -> list[str]:
    errors: list[str] = []
    bindings = value.get("bindings")
    if not isinstance(bindings, dict) or set(bindings) != set(expected_bindings):
        return ["qualification environment bindings differ"]
    for field, expected in expected_bindings.items():
        if not valid_digest(bindings.get(field)):
            errors.append(f"qualification environment has invalid binding: {field}")
        if expected is not None and bindings.get(field) != expected:
            errors.append(f"qualification environment binds a different {field}")
    return errors


def _validate_boundaries(value: dict) -> list[str]:
    errors: list[str] = []
    if value.get("network") != {
        "preparation_egress": "dependency-download-only",
        "qualification_egress": "disabled",
        "loopback_fixtures": True,
    }:
        errors.append("qualification environment network boundary differs")
    if value.get("source_state") != {
        "clean_checkout": True,
        "empty_volatile_caches_at_start": True,
        "product_artifacts_separate": True,
    }:
        errors.append("qualification environment source-state boundary differs")
    return errors


def _validate_digest(value: dict) -> list[str]:
    copy = json.loads(json.dumps(value))
    claimed = copy.get("environment_sha256")
    copy["environment_sha256"] = None
    if not valid_digest(claimed) or claimed != canonical_sha256(copy):
        return ["qualification environment digest differs"]
    return []


def validate_modern_environment(value: dict, *, target: str, bindings: dict) -> None:
    if value.get("schema") not in {
        "iicp.pre1-qualification-environment.v2",
        "iicp.pre1-qualification-environment.v3",
    }:
        raise ValueError("qualification modern environment schema differs")
    errors = (_validate_header(value, target, None)
              + _validate_bindings(value, bindings)
              + _validate_boundaries(value) + _validate_digest(value))
    runtimes = value.get("runtimes")
    if not isinstance(runtimes, dict) or not runtimes:
        errors.append("qualification environment runtimes are missing")
    else:
        for runtime, row in runtimes.items():
            errors.extend(validate_runtime(runtime, row))
    if errors:
        raise ValueError("; ".join(errors))
