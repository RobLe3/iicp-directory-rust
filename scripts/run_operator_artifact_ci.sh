#!/usr/bin/env bash
# Existing public-CI lane only. No AWS, publisher or permanent service.
set -euo pipefail
[[ $# == 1 ]] || { echo 'one new private output directory required' >&2; exit 2; }
[[ ${GITHUB_ACTIONS:-} == true && ${GITHUB_REF:-} == refs/heads/main ]] || {
  echo 'reviewed main GitHub execution required' >&2; exit 2;
}
umask 077
output=$1
[[ ! -e "$output" && ! -L "$output" ]] || { echo 'output already exists' >&2; exit 2; }
mkdir -m 700 -- "$output"
output=$(cd "$output" && pwd -P)
printf 'output=%s\n' "$output" >> "$GITHUB_OUTPUT"
runtime='python:3.12-slim-trixie@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea'
database='mysql:8.0@sha256:7dcddc01f13bab2f15cde676d44d01f61fc9f99fe7785e86196dfc07d358ae2b'
[[ $(rustc --version) == 'rustc 1.98.0 '* ]] || { echo 'exact artifact toolchain required' >&2; exit 2; }
python3 scripts/build_pre1_candidate_artifacts.py --target linux-x86_64 --output "$output/fragment"
docker pull --platform linux/amd64 "$runtime"
docker pull --platform linux/amd64 "$database"
fragment="$output/fragment/artifact-fragment.json"
digest=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["fragment_sha256"])' "$fragment")
python3 scripts/rehearse_operator_persistence.py \
  --fragment "$fragment" --fragment-sha256 "$digest" \
  --source-commit "$(git rev-parse HEAD)" --target linux-x86_64 \
  --runtime-image "$runtime" --mysql-image "$database" --output "$output/rehearsal"
