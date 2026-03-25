#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 || $# -gt 5 ]]; then
  echo "Usage: run-dumbo-mpc-local <n> <t> <k> [full|drop-epoch4] [layers]" >&2
  exit 1
fi

n="$1"
t="$2"
k="$3"
mode="${4:-full}"
layers="${5:-10}"

case "$mode" in
  full|drop-epoch4) ;;
  *)
    echo "Invalid mode: ${mode}. Expected one of: full, drop-epoch4" >&2
    exit 1
    ;;
esac

source /opt/venv/continuum/bin/activate
export PYTHONPATH="/opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen:${PYTHONPATH:-}"

cd /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen
python3 scripts/run_key_gen.py --N "$n" --f "$t"

cd /opt/dumbo-mpc
exec ./run_local_network_test.sh asy-triple "$n" "$k" "$mode" "$layers"
