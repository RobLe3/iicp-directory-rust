#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "${IICP_DISPOSABLE_CARGO_ACTIVE:-0}" != 1 ]]; then
  exec "$ROOT/scripts/with_disposable_cargo_target.sh" --label directory-release -- "$0" "$@"
fi
VERSION="${1:-}"
ALLOW_UNTAGGED=0
[[ "${2:-}" == "--allow-untagged" ]] && ALLOW_UNTAGGED=1

if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "usage: $0 VERSION [--allow-untagged]" >&2
  exit 2
fi

SOURCE_VERSION="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)"
[[ "$SOURCE_VERSION" == "$VERSION" ]] || {
  echo "Cargo version $SOURCE_VERSION does not match $VERSION" >&2
  exit 1
}
[[ -z "$(git -C "$ROOT" status --porcelain)" ]] || {
  echo "release source must be clean" >&2
  exit 1
}

TAG="v$VERSION"
COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
if git -C "$ROOT" show-ref --verify --quiet "refs/tags/$TAG"; then
  [[ "$(git -C "$ROOT" rev-parse "$TAG^{commit}")" == "$COMMIT" ]] || {
    echo "$TAG does not identify HEAD" >&2
    exit 1
  }
elif [[ "$ALLOW_UNTAGGED" != 1 ]]; then
  echo "immutable tag $TAG is required" >&2
  exit 1
fi

python3 "$ROOT/scripts/check_release_compatibility.py"
cargo fmt --manifest-path "$ROOT/Cargo.toml" --check
cargo test --manifest-path "$ROOT/Cargo.toml" --locked --all-features
cargo package --manifest-path "$ROOT/Cargo.toml" --locked

OUT="$ROOT/releases/$TAG"
rm -rf "$OUT"
mkdir -p "$OUT"
ARCHIVE="$OUT/iicp-directory-rust-$TAG.tar.gz"
CRATE="$OUT/iicp-directory-rs-$VERSION.crate"
git -C "$ROOT" archive --format=tar.gz --prefix="iicp-directory-rust-$TAG/" \
  -o "$ARCHIVE" "$COMMIT"
ARCHIVE_SHA="$(shasum -a 256 "$ARCHIVE" | awk '{print $1}')"
cp "${CARGO_TARGET_DIR:?missing disposable Cargo target}/package/iicp-directory-rs-$VERSION.crate" "$CRATE"
CRATE_SHA="$(shasum -a 256 "$CRATE" | awk '{print $1}')"
COMPAT_SHA="$(shasum -a 256 "$ROOT/compatibility/$TAG.json" | awk '{print $1}')"

python3 - "$OUT/release-manifest.json" "$VERSION" "$COMMIT" "$ARCHIVE_SHA" "$CRATE_SHA" "$COMPAT_SHA" <<'PY'
import json, sys
path, version, commit, archive_sha, crate_sha, compatibility_sha = sys.argv[1:]
payload = {
    "schema": "iicp.directory-rust-release.v1",
    "version": version,
    "commit": commit,
    "status": "operator_preview",
    "archive_sha256": archive_sha,
    "crate_sha256": crate_sha,
    "compatibility_manifest_sha256": compatibility_sha,
    "production_authority": False,
    "genesis_cutover_authorized": False,
}
open(path, "w", encoding="utf-8").write(
    json.dumps(payload, indent=2, sort_keys=True) + "\n"
)
PY

(
  cd "$OUT"
  shasum -a 256 "$(basename "$ARCHIVE")" "$(basename "$CRATE")" release-manifest.json > SHA256SUMS
  shasum -a 256 -c SHA256SUMS
)
echo "Rust operator-preview artifacts: $OUT"
