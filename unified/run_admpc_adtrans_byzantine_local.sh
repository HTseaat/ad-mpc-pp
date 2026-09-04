#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 6 ]]; then
  echo "Usage: run_admpc_adtrans_byzantine_local.sh <n> <t> <layers> <total_cm> <computation_epoch> <attack_index>" >&2
  exit 1
fi

n="$1"
t="$2"
layers="$3"
total_cm="$4"
computation_epoch="$5"
attack_index="$6"

if ! [[ "$computation_epoch" =~ ^[0-9]+$ ]] || (( computation_epoch < 1 )); then
  echo "Invalid computation_epoch=${computation_epoch}; expected a positive integer." >&2
  exit 1
fi

if ! [[ "$attack_index" =~ ^[0-9]+$ ]]; then
  echo "Invalid attack_index=${attack_index}; expected a non-negative integer." >&2
  exit 1
fi

export FAULT_MODE=byzantine
export FAULT_TARGET=adtrans
export FAULT_COMPUTATION_EPOCH="$computation_epoch"
export FAULT_ATTACK_INDEX="$attack_index"

exec /opt/unified/run_admpc_local.sh \
  admpc "$n" "$t" "$layers" "$total_cm"
