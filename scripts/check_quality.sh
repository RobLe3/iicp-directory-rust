#!/usr/bin/env bash
set -euo pipefail

cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked

if command -v cargo-llvm-cov >/dev/null 2>&1; then
  # The first measured operator-preview baseline is 74.05% line coverage.
  # Keep a conservative 70% blocking floor and ratchet it upward; never lower
  # the floor merely to accept a regression.
  if command -v rustup >/dev/null 2>&1; then
    rustup run stable cargo llvm-cov --locked --summary-only --fail-under-lines 70
  else
    cargo llvm-cov --locked --summary-only --fail-under-lines 70
  fi
else
  echo 'cargo-llvm-cov is required (cargo install cargo-llvm-cov --locked)' >&2
  exit 1
fi

if command -v cargo-audit >/dev/null 2>&1; then
  # RUSTSEC-2023-0071 is inherited from sqlx-mysql -> rsa. RustSec lists no
  # fixed release; IICP does not use RSA for protocol signing. Keep this
  # narrow exception visible while failing on every other vulnerability.
  cargo audit --ignore RUSTSEC-2023-0071
else
  echo 'cargo-audit is required (cargo install cargo-audit --locked)' >&2
  exit 1
fi
