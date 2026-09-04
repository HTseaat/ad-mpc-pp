#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 4 || $# -gt 5 ]]; then
  echo "Usage: $0 <n> <t> <layers> <total_cm> [attack_index=0]" >&2
  exit 1
fi

n="$1"
t="$2"
layers="$3"
total_cm="$4"
delay_ms=10000
attack_index="${5:-0}"
if ! [[ "$attack_index" =~ ^[0-9]+$ ]]; then
  echo "Invalid attack_index=${attack_index}; expected a non-negative integer." >&2
  exit 1
fi
if ! [[ "$layers" =~ ^[0-9]+$ ]] || (( layers < 6 )); then
  echo "Figure 10 source epochs E3/E4 require at least 6 total layers." >&2
  exit 1
fi

unset FAULT_ACCUMULATION_MODE FAULT_ACCUMULATION_COUNT \
  FAULT_ACCUMULATION_START_EPOCH FAULT_COMPUTATION_EPOCH
export FAULT_MODE=figure10-attack
export FAULT_TARGET=adtrans
export FAULT_DELAY_SOURCE_EPOCH=3
export FAULT_ADTRANS_SOURCE_EPOCH=4
export FAULT_DELTA_MS="$delay_ms"
export FAULT_ATTACK_INDEX="$attack_index"

exec /opt/unified/run_admpc_local.sh \
  admpc "$n" "$t" "$layers" "$total_cm"
