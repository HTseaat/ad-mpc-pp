#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 6 ]]; then
  echo "Usage: run_admpc_delay_local.sh <n> <t> <layers> <total_cm> <computation_epoch> <delta_ms>" >&2
  exit 1
fi

n="$1"
t="$2"
layers="$3"
total_cm="$4"
computation_epoch="$5"
delta_ms="$6"

if ! [[ "$computation_epoch" =~ ^[0-9]+$ ]] || (( computation_epoch < 1 )); then
  echo "Invalid computation_epoch=${computation_epoch}; expected a positive integer." >&2
  exit 1
fi

if ! [[ "$delta_ms" =~ ^[0-9]+$ ]] || (( delta_ms <= 0 )); then
  echo "Invalid delta_ms=${delta_ms}; expected a positive integer." >&2
  exit 1
fi

export FAULT_MODE=delay
export FAULT_TARGET=adtrans
export FAULT_COMPUTATION_EPOCH="$computation_epoch"
export FAULT_DELTA_MS="$delta_ms"

exec /opt/unified/run_admpc_local.sh \
  admpc "$n" "$t" "$layers" "$total_cm"
