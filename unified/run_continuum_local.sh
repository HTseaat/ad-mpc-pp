#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 4 || $# -gt 5 ]]; then
  echo "Usage: run-continuum-local <n> <t> <layers> <total_cm> [mixed|linear|nonlinear]" >&2
  exit 1
fi

n="$1"
t="$2"
layers="$3"
total_cm="$4"
mode="${5:-mixed}"

if (( n < 3 * t + 1 )); then
  echo "Invalid params: n=${n}, t=${t}. Must satisfy n >= 3*t+1." >&2
  exit 1
fi

if (( n > 3 * t + 1 )); then
  echo "Note: using n=${n}, t=${t} (n > 3*t+1). This is supported; fault tolerance remains t=${t}."
fi

case "$mode" in
  mixed)
    task="ad-mpc2"
    ;;
  linear)
    task="ad-mpc2-linear"
    ;;
  nonlinear|mul|multiplication)
    task="ad-mpc2-nonlinear"
    ;;
  *)
    echo "Invalid mode: ${mode}. Expected one of: mixed, linear, nonlinear" >&2
    exit 1
    ;;
esac

source /opt/venv/continuum/bin/activate
export PYTHONPATH="/opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen:${PYTHONPATH:-}"

# Rebuild KZG shared library on demand if missing in runtime container.
if [[ ! -f /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/kzg_ped_out.so ]]; then
  echo "kzg_ped_out.so missing, rebuilding..."
  mkdir -p /tmp/go-build-cache /tmp/go/pkg/mod
  (
    cd /opt/dumbo-mpc/gnark-crypto/kzg_ped_bls12-381
    GOCACHE=/tmp/go-build-cache GOPATH=/tmp/go GOMODCACHE=/tmp/go/pkg/mod bash ./build_shared_library.sh
    cp -f kzg_ped_out.so /opt/dumbo-mpc/kzg_ped_out.so
  )
fi

# Rebuild Bulletproof shared library on demand if missing in runtime container.
if [[ ! -f /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/libbulletproofs_amcl.so ]]; then
  echo "libbulletproofs_amcl.so missing, rebuilding..."
  mkdir -p /tmp/cargo-home
  (
    cd /opt/dumbo-mpc/bulletproofs-amcl
    CARGO_HOME=/tmp/cargo-home cargo build --release
    cp -f target/release/libbulletproofs_amcl.so /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/libbulletproofs_amcl.so
    cp -f target/release/libbulletproofs_amcl.so /opt/dumbo-mpc/libbulletproofs_amcl.so
  )
fi

cd /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen
python3 scripts/run_key_gen_dyn.py --N "$n" --f "$t" --layers "$layers" --total_cm "$total_cm"

cd /opt/dumbo-mpc
exec ./run_local_network_test.sh "$task" "$n" "$layers" "$total_cm"
