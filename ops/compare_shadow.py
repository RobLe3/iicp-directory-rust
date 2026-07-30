#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compare public PHP Genesis and Rust-shadow observations without retaining routes."""

from __future__ import annotations

import argparse
import json
import statistics
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "iicp.rust_directory.shadow_comparison.v1"
DISCOVERY_QUERY = "intent=urn%3Aiicp%3Aintent%3Allm%3Achat%3Av1&view=public"
ROUTE_FIELDS = {
    "endpoint",
    "node_id",
    "transport_endpoint",
    "transport_metadata",
    "cx_public_key",
    "public_key",
}


def validate_base(value: str) -> str:
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("base URLs must use http or https")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("base URLs must not contain credentials, queries, or fragments")
    return value.rstrip("/")


def fetch(base: str, path: str, timeout: float) -> tuple[dict[str, Any], float]:
    started = time.perf_counter()
    request = urllib.request.Request(
        base + path,
        headers={"Accept": "application/json", "User-Agent": "iicp-shadow-comparison/1.0"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - operator URL
        if response.status != 200:
            raise RuntimeError(f"unexpected HTTP status {response.status}")
        value = json.load(response)
    if not isinstance(value, dict):
        raise ValueError("comparison endpoint did not return a JSON object")
    return value, (time.perf_counter() - started) * 1000


def has_route_material(value: Any) -> bool:
    if isinstance(value, dict):
        if ROUTE_FIELDS.intersection(value):
            return True
        return any(has_route_material(child) for child in value.values())
    if isinstance(value, list):
        return any(has_route_material(child) for child in value)
    return False


def normalize_discovery(payload: dict[str, Any]) -> dict[str, Any]:
    nodes = payload.get("nodes")
    if not isinstance(nodes, list):
        nodes = []
    field_names = sorted(
        {
            str(key)
            for node in nodes
            if isinstance(node, dict)
            for key in node
            if key not in ROUTE_FIELDS
        }
    )
    return {
        "view": payload.get("view"),
        "node_count": len(nodes),
        # The top-level redaction descriptor intentionally names omitted fields.
        # Inspect node projections only so that descriptor is not a false alarm.
        "route_fields_present": has_route_material(nodes),
        "public_node_fields": field_names,
        "relay_available": payload.get("relay_available"),
        "ticketed_dispatch_available": payload.get("ticketed_dispatch_available"),
    }


def normalize_stats(payload: dict[str, Any]) -> dict[str, Any]:
    server = payload.get("server") if isinstance(payload.get("server"), dict) else {}
    adoption = payload.get("sdk_adoption") if isinstance(payload.get("sdk_adoption"), dict) else {}
    return {
        "active_nodes": server.get("active_nodes"),
        "public_routable_nodes": server.get("public_routable_nodes"),
        "heartbeating_nodes": server.get("heartbeating_nodes"),
        "key_ready_nodes": server.get("key_ready_nodes"),
        "sdk_adoption_total": adoption.get("total_active"),
        "stats_fields": sorted(str(key) for key in payload),
        "server_fields": sorted(str(key) for key in server),
    }


def compare_sample(genesis: dict[str, Any], shadow: dict[str, Any], tolerance: int) -> list[str]:
    mismatches: list[str] = []
    gd = genesis["discovery"]
    sd = shadow["discovery"]
    if gd["view"] != "public" or sd["view"] != "public":
        mismatches.append("both discovery responses must identify the public view")
    if gd["route_fields_present"] or sd["route_fields_present"]:
        mismatches.append("public discovery exposed route-bearing material")
    if abs(gd["node_count"] - sd["node_count"]) > tolerance:
        mismatches.append("public discovery node counts exceed the allowed tolerance")
    for field in ("relay_available", "ticketed_dispatch_available"):
        if gd[field] != sd[field]:
            mismatches.append(f"discovery capability differs: {field}")
    if set(gd["public_node_fields"]) != set(sd["public_node_fields"]):
        mismatches.append("public discovery field sets differ")
    return mismatches


def observe(base: str, timeout: float) -> tuple[dict[str, Any], list[float]]:
    stats, stats_ms = fetch(base, "/api/v1/stats", timeout)
    discovery, discovery_ms = fetch(base, f"/api/v1/discover?{DISCOVERY_QUERY}", timeout)
    return {
        "stats": normalize_stats(stats),
        "discovery": normalize_discovery(discovery),
    }, [stats_ms, discovery_ms]


def run(
    genesis_base: str,
    shadow_base: str,
    *,
    samples: int,
    interval: float,
    timeout: float,
    node_count_tolerance: int,
) -> dict[str, Any]:
    genesis_base = validate_base(genesis_base)
    shadow_base = validate_base(shadow_base)
    mismatches: list[dict[str, Any]] = []
    genesis_timings: list[float] = []
    shadow_timings: list[float] = []
    last_genesis: dict[str, Any] = {}
    last_shadow: dict[str, Any] = {}
    for index in range(samples):
        last_genesis, timings = observe(genesis_base, timeout)
        genesis_timings.extend(timings)
        last_shadow, timings = observe(shadow_base, timeout)
        shadow_timings.extend(timings)
        reasons = compare_sample(last_genesis, last_shadow, node_count_tolerance)
        if reasons:
            mismatches.append({"sample": index + 1, "reasons": reasons})
        if interval and index + 1 < samples:
            time.sleep(interval)
    return {
        "schema": SCHEMA,
        "observed_at": datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "content_free": True,
        "production_mutated": False,
        "samples": samples,
        "node_count_tolerance": node_count_tolerance,
        "semantic_parity": not mismatches,
        "mismatches": mismatches,
        "genesis": {
            "last_observation": last_genesis,
            "request_p50_ms": statistics.median(genesis_timings),
            "request_max_ms": max(genesis_timings),
        },
        "shadow": {
            "last_observation": last_shadow,
            "request_p50_ms": statistics.median(shadow_timings),
            "request_max_ms": max(shadow_timings),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--genesis-base", default="https://iicp.network")
    parser.add_argument("--shadow-base", required=True)
    parser.add_argument("--samples", type=int, default=1)
    parser.add_argument("--interval", type=float, default=0.0)
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--node-count-tolerance", type=int, default=0)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.samples < 1 or args.timeout <= 0 or args.interval < 0 or args.node_count_tolerance < 0:
        parser.error("samples/timeout must be positive; interval/tolerance must be non-negative")
    report = run(
        args.genesis_base,
        args.shadow_base,
        samples=args.samples,
        interval=args.interval,
        timeout=args.timeout,
        node_count_tolerance=args.node_count_tolerance,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["semantic_parity"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
