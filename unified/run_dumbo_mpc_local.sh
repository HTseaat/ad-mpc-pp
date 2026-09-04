#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 || $# -gt 5 ]]; then
  echo "Usage: run-dumbo-mpc-local <n> <t> <k> [full|drop-epoch4|fault-accumulation|bgw-direct] [layers]" >&2
  exit 1
fi

n="$1"
t="$2"
k="$3"
mode="${4:-full}"
layers="${5:-10}"

case "$mode" in
  full|drop-epoch4|fault-accumulation|bgw-direct) ;;
  *)
    echo "Invalid mode: ${mode}. Expected one of: full, drop-epoch4, fault-accumulation, bgw-direct" >&2
    exit 1
    ;;
esac

source /opt/venv/continuum/bin/activate
export PYTHONPATH="/opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen:${PYTHONPATH:-}"
export ZMQ_AUTH_MODE=curve

if [[ "$mode" == "fault-accumulation" ]]; then
  unset FAULT_MODE FAULT_TARGET FAULT_COMPUTATION_EPOCH \
    FAULT_BATCHMUL_EPOCH FAULT_DELAY_SOURCE_EPOCH \
    FAULT_AGGTRANS_SOURCE_EPOCH FAULT_BATCHMUL_SOURCE_EPOCH \
    FAULT_DELTA_MS FAULT_ATTACK_INDEX
  export FAULT_ACCUMULATION_MODE=silent
  export FAULT_ACCUMULATION_COUNT="$t"
  export FAULT_ACCUMULATION_START_EPOCH=1
fi

cd /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen
python3 scripts/run_key_gen.py --N "$n" --f "$t"

cd /opt/dumbo-mpc
if [[ "$mode" == "bgw-direct" ]]; then
  exec ./run_local_network_test.sh dumbo-bgw-direct "$n" "$k" "$layers"
fi

exec ./run_local_network_test.sh asy-triple "$n" "$k" "$mode" "$layers"
