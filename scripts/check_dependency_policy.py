#!/usr/bin/env python3
"""Fail closed on denied Cargo.lock packages before product compilation."""
from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path

DENIED_EXACT = {
    ("arrayref", "0.3.10"),
    ("internment", "0.8.7"),
    ("append-only-vec", "0.1.9"),
}
# RUSTSEC-2026-0285 / GHSA-2mjx-qc3c-rqvc; fresh audit remains required.
DENIED_EXACT |= {("rustls", f"0.23.{patch}") for patch in range(13, 45)}

# Fresh RustSec source-supported series (2026-11-06). This fast deny gate
# complements, and never replaces, a fresh advisory audit or applicability review.
DENIED_EXACT |= {("rustls", f"0.23.{patch}") for patch in range(46)}
DENIED_EXACT |= {("rustls-webpki", f"0.103.{patch}") for patch in range(16)}
DENIED_EXACT |= {("webpki-roots", f"1.0.{patch}") for patch in range(10)}
DENIED_EXACT |= {("quinn-proto", f"0.11.{patch}") for patch in range(18)}
DENIED_EXACT |= {("tokio", f"1.51.{patch}") for patch in range(6)}
DENIED_EXACT |= {("tokio", f"1.52.{patch}") for patch in range(4)}
DENIED_EXACT |= {("tokio", f"1.53.{patch}") for patch in range(3)}

DENIED_NAMES = {"proc-macro1", "proc-macro-en", "aovine", "arone", "aronenao", "tinymember"}
ALLOWED_REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"


def violations(lock: Path) -> list[str]:
    packages = tomllib.loads(lock.read_text()).get("package", [])
    found: list[str] = []
    for package in packages:
        name, version = package.get("name", ""), package.get("version", "")
        source = package.get("source")
        if name in DENIED_NAMES or (name, version) in DENIED_EXACT:
            found.append(f"denied package {name} {version}")
        if source and source != ALLOWED_REGISTRY:
            found.append(f"unapproved source for {name} {version}: {source}")
    return sorted(found)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("lock", nargs="?", type=Path, default=Path("Cargo.lock"))
    args = parser.parse_args()
    problems = violations(args.lock)
    if problems:
        print("dependency policy rejected Cargo.lock:", file=sys.stderr)
        for problem in problems:
            print(f"- {problem}", file=sys.stderr)
        return 1
    print("dependency policy passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
