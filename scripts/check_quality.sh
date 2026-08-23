#!/usr/bin/env bash
set -euo pipefail

python3 scripts/check_dependency_policy.py
cargo fmt --check
cargo clippy --locked --all-features --all-targets -- -D warnings
cargo test --locked --all-features
# This developer gate must validate the exact candidate before it is committed.
# The release lane separately requires a clean worktree and packages the tagged
# commit without this allowance.
cargo package --locked --allow-dirty
python3 scripts/test_directory_self_update.py

# The original embedded test module inflated coverage by counting test source.
# Preserve the 70% floor while measuring production code with both ordinary and
# disposable-MySQL execution.
./scripts/check_coverage.sh

if command -v cargo-audit >/dev/null 2>&1; then
  # RUSTSEC-2023-0071 is inherited from sqlx-mysql -> rsa. RustSec lists no
  # fixed release; IICP does not use RSA for protocol signing. Keep this
  # narrow exception visible while failing on every other vulnerability.
  ./scripts/check_rustsec.sh
else
  echo 'cargo-audit is required (cargo install cargo-audit --locked)' >&2
  exit 1
fi
