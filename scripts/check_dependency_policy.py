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
