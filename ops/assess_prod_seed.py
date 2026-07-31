#!/usr/bin/env python3
"""Assess the public Genesis event tail without retaining node or route material."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import statistics
import time
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


SCHEMA = "iicp.rust_directory.public_seed_assessment.v1"
GENESIS_ROOT = "c44802bedf3e63b5a3f1634c5d19263634f92f26dd15401b09b06dd53a80cf9d"
ACTIVE_EVENTS = {"REGISTER", "REACTIVATE"}
INACTIVE_EVENTS = {"EVICT", "DEREGISTER"}


def validate_base(value: str) -> str:
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("Genesis base must use https")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Genesis base must not contain credentials, queries, or fragments")
    return value.rstrip("/")


def fetch_json(base: str, path: str, timeout: float) -> tuple[dict[str, Any], float]:
    started = time.perf_counter()
    request = urllib.request.Request(
        base + path,
        headers={"Accept": "application/json", "User-Agent": "iicp-shadow-assessment/1.0"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - operator URL
        if response.status != 200:
            raise RuntimeError(f"unexpected HTTP status: {response.status}")
        value = json.load(response)
    if not isinstance(value, dict):
        raise ValueError("public evidence endpoint did not return an object")
    return value, (time.perf_counter() - started) * 1000


def public_key_from_did(document: dict[str, Any]) -> Ed25519PublicKey:
    for method in document.get("verificationMethod", []):
        jwk = method.get("publicKeyJwk") if isinstance(method, dict) else None
        if not isinstance(jwk, dict) or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            continue
        encoded = jwk.get("x")
        if not isinstance(encoded, str):
            continue
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        if len(raw) == 32:
            return Ed25519PublicKey.from_public_bytes(raw)
    raise ValueError("Genesis DID does not contain a usable Ed25519 key")


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def signing_message(event: dict[str, Any]) -> bytes:
    payload_hash = hashlib.sha256(canonical_json(event.get("payload", {})).encode()).hexdigest()
    prev_hash = event.get("prev_hash") or GENESIS_ROOT
    service_id = event.get("service_id")
    fields = (
        f"{event['event_id']}:{event['event_type']}:{event['seq']}:"
        f"{event['ts_ms']}:{payload_hash}:{prev_hash}"
    )
    if service_id is not None:
        fields = f"iicp-event-v2:{service_id}:{fields}"
    return hashlib.sha256(fields.encode()).digest()


def verify_event(public_key: Ed25519PublicKey, event: dict[str, Any]) -> bool:
    signature = event.get("sig")
    if not isinstance(signature, str) or not signature:
        return False
    try:
        public_key.verify(bytes.fromhex(signature), signing_message(event))
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def expected_prev_hash(previous_signature: str | None) -> str:
    if not previous_signature:
        return GENESIS_ROOT
    return hashlib.sha256(previous_signature.encode()).hexdigest()


def analyze_events(events: list[dict[str, Any]], public_key: Ed25519PublicKey) -> dict[str, Any]:
    active: set[str] = set()
    verified_lifecycle_nodes: set[str] = set()
    unsigned = invalid = chain_failures = verified = 0
    event_types: Counter[str] = Counter()
    previous_signature: str | None = None
    first_signed_seq: int | None = None
    last_signed_seq: int | None = None

    for event in events:
        event_type = str(event.get("event_type", "unknown"))
        event_types[event_type] += 1
        signature = event.get("sig")
        if not isinstance(signature, str) or not signature:
            unsigned += 1
            previous_signature = None
            continue
        if event.get("prev_hash") != expected_prev_hash(previous_signature):
            chain_failures += 1
            previous_signature = None
            continue
        if not verify_event(public_key, event):
            invalid += 1
            previous_signature = None
            continue
        verified += 1
        first_signed_seq = first_signed_seq or int(event["seq"])
        last_signed_seq = int(event["seq"])
        previous_signature = signature
        node_id = event.get("node_id")
        if isinstance(node_id, str) and node_id:
            if event_type in ACTIVE_EVENTS:
                active.add(node_id)
                verified_lifecycle_nodes.add(node_id)
            elif event_type in INACTIVE_EVENTS:
                active.discard(node_id)
                verified_lifecycle_nodes.add(node_id)

    return {
        "active": active,
        "verified_lifecycle_nodes": verified_lifecycle_nodes,
        "event_count": len(events),
        "event_type_counts": dict(sorted(event_types.items())),
        "unsigned_count": unsigned,
        "verified_count": verified,
        "invalid_signature_count": invalid,
        "chain_failure_count": chain_failures,
        "first_verified_seq": first_signed_seq,
        "last_verified_seq": last_signed_seq,
    }


def registry_prefixes(document: dict[str, Any]) -> set[str]:
    nodes = document.get("nodes")
    if not isinstance(nodes, list):
        raise ValueError("registry response has no node list")
    return {
        prefix
        for node in nodes
        if isinstance(node, dict)
        and isinstance((prefix := node.get("node_id_prefix")), str)
        and prefix
    }


def collect_events(base: str, timeout: float, page_limit: int) -> tuple[list[dict[str, Any]], list[float], int]:
    events: list[dict[str, Any]] = []
    timings: list[float] = []
    since = 0
    lag_ms = 0
    while True:
        page, elapsed = fetch_json(base, f"/api/v1/events?since_seq={since}&limit={page_limit}", timeout)
        timings.append(elapsed)
        batch = page.get("events")
        if not isinstance(batch, list):
            raise ValueError("event response has no event list")
        events.extend(event for event in batch if isinstance(event, dict))
        lag_ms = int(page.get("replica_lag_ms") or 0)
        next_seq = int(page.get("next_seq") or since)
        if not page.get("has_more") or not batch:
            break
        if next_seq <= since:
            raise ValueError("event pagination did not advance")
        since = next_seq
    return events, timings, lag_ms


def run(base: str, timeout: float, page_limit: int) -> dict[str, Any]:
    base = validate_base(base)
    did, did_ms = fetch_json(base, "/.well-known/did.json", timeout)
    public_key = public_key_from_did(did)
    events, timings, lag_ms = collect_events(base, timeout, page_limit)
    registry, registry_ms = fetch_json(base, "/api/v1/registry/nodes?limit=100", timeout)
    analysis = analyze_events(events, public_key)
    public_prefixes = registry_prefixes(registry)
    reconstructed_prefixes = {node_id[:8] for node_id in analysis.pop("active")}
    lifecycle_prefixes = {node_id[:8] for node_id in analysis.pop("verified_lifecycle_nodes")}
    missing = public_prefixes - reconstructed_prefixes
    extra = reconstructed_prefixes - public_prefixes
    complete_public_reconstruction = not missing and not extra and public_prefixes <= lifecycle_prefixes
    verification_complete = (
        analysis["invalid_signature_count"] == 0 and analysis["chain_failure_count"] == 0
    )
    timings.extend([did_ms, registry_ms])
    return {
        "schema": SCHEMA,
        "observed_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "content_free": True,
        "production_mutated": False,
        "snapshot_used": False,
        "replica_registered": False,
        "verification_complete": verification_complete,
        "complete_public_reconstruction": complete_public_reconstruction,
        "requires_authenticated_snapshot": not complete_public_reconstruction,
        "public_node_count": len(public_prefixes),
        "reconstructed_active_count": len(reconstructed_prefixes),
        "missing_public_count": len(missing),
        "extra_reconstructed_count": len(extra),
        "replica_lag_ms": lag_ms,
        "request_p50_ms": statistics.median(timings),
        "request_max_ms": max(timings),
        **analysis,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--genesis-base", default="https://iicp.network")
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--page-limit", type=int, default=1000)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.timeout <= 0 or not 1 <= args.page_limit <= 1000:
        parser.error("timeout must be positive and page-limit must be 1..1000")
    report = run(args.genesis_base, args.timeout, args.page_limit)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["verification_complete"] and report["complete_public_reconstruction"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
