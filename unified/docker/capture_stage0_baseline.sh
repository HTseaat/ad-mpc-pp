#!/usr/bin/env bash
set -euo pipefail

output_dir="${1:-/opt/benchmark-baselines/aws-deployment-stage0-arm-baseline}"
mkdir -p "$output_dir"

native_libraries=(
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/kzg_ped_out.so
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/libbulletproofs_amcl.so
  /opt/admpc/adkg/ntl/_hbmpc_ntl_helpers.cpython-38-aarch64-linux-gnu.so
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/optimizedhbmpc/ntl/_hbmpc_ntl_helpers.cpython-38-aarch64-linux-gnu.so
)

{
  echo "captured_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "architecture=$(uname -m)"
  echo "kernel=$(uname -sr)"
  echo "continuum_python=$(/opt/venv/continuum/bin/python3 --version 2>&1)"
  echo "admpc_python=$(/opt/venv/admpc/bin/python3 --version 2>&1)"
  echo "go=$(go version 2>&1 || true)"
  echo "rustc=$(rustc --version 2>&1 || true)"
  echo "cargo=$(cargo --version 2>&1 || true)"
  if command -v docker >/dev/null 2>&1; then
    echo "docker=$(docker --version 2>&1)"
  else
    echo "docker=unavailable"
  fi
} > "$output_dir/environment.txt"

file "${native_libraries[@]}" > "$output_dir/native-libraries.file.txt"
sha256sum "${native_libraries[@]}" > "$output_dir/native-libraries.sha256"
/opt/venv/continuum/bin/pip freeze > "$output_dir/continuum-pip-freeze.txt"
/opt/venv/admpc/bin/pip freeze > "$output_dir/admpc-pip-freeze.txt"

source_roots=(
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/committee_election
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/scripts
  /opt/dumbo-mpc/gnark-crypto/kzg_ped_bls12-381
  /opt/dumbo-mpc/bulletproofs-amcl/src
  /opt/admpc/adkg
  /opt/admpc/scripts
  /opt/unified
)

find "${source_roots[@]}" -type f \
  \( -name '*.py' -o -name '*.sh' -o -name '*.go' -o -name '*.rs' \) \
  -print0 \
  | sort -z \
  | xargs -0 sha256sum \
  > "$output_dir/source-manifest.sha256"

sha256sum "$output_dir/source-manifest.sha256" \
  > "$output_dir/source-manifest.digest"

echo "Stage 0 baseline written to $output_dir"

