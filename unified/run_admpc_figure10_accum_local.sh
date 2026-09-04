#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "Usage: $0 <n> <t> <layers> <total_cm>" >&2
  exit 1
fi

n="$1"
t="$2"
layers="$3"
total_cm="$4"

unset FAULT_MODE FAULT_TARGET FAULT_COMPUTATION_EPOCH \
  FAULT_DELAY_SOURCE_EPOCH FAULT_ADTRANS_SOURCE_EPOCH \
  FAULT_DELTA_MS FAULT_ATTACK_INDEX
export FAULT_ACCUMULATION_MODE=silent
export FAULT_ACCUMULATION_COUNT="$t"
export FAULT_ACCUMULATION_START_EPOCH=1

exec /opt/unified/run_admpc_local.sh \
  admpc "$n" "$t" "$layers" "$total_cm"
