#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 7 ]]; then
  echo "Usage: run_continuum_byzantine_local.sh <n> <t> <layers> <total_cm> <aggtrans_epoch> <batchmul_epoch> <attack_index>" >&2
  exit 1
fi

n="$1"
t="$2"
layers="$3"
total_cm="$4"
aggtrans_epoch="$5"
batchmul_epoch="$6"
attack_index="$7"

if ! [[ "$aggtrans_epoch" =~ ^[0-9]+$ ]] || (( aggtrans_epoch < 1 )); then
  echo "Invalid aggtrans_epoch=${aggtrans_epoch}; expected a positive integer." >&2
  exit 1
fi
if ! [[ "$batchmul_epoch" =~ ^[0-9]+$ ]] || (( batchmul_epoch != aggtrans_epoch + 1 )); then
  echo "Invalid batchmul_epoch=${batchmul_epoch}; expected aggtrans_epoch+1." >&2
  exit 1
fi
if ! [[ "$attack_index" =~ ^[0-9]+$ ]]; then
  echo "Invalid attack_index=${attack_index}; expected a non-negative integer." >&2
  exit 1
fi

export FAULT_MODE=byzantine
export FAULT_TARGET=aggtrans+batchmul
export FAULT_COMPUTATION_EPOCH="$aggtrans_epoch"
export FAULT_BATCHMUL_EPOCH="$batchmul_epoch"
export FAULT_ATTACK_INDEX="$attack_index"

required_node_ids=()
for epoch in "$aggtrans_epoch" "$batchmul_epoch"; do
  for ((local_id = n - t; local_id < n; local_id++)); do
    required_node_ids+=("$((epoch * n + local_id))")
  done
done
required_node_ids_csv=$(IFS=,; echo "${required_node_ids[*]}")

export FINISHED_PATTERN='"event": "config"'
export FINAL_LAYER_START="$((n * (layers - 1)))"
export FINAL_LAYER_PATTERN="my_send_id: .* exec_time"
export REQUIRED_NODE_IDS="$required_node_ids_csv"
export REQUIRED_NODE_PATTERN='"component": "(aggtrans|batchmul)".*"event": "byzantine_mutation"|"event": "byzantine_mutation".*"component": "(aggtrans|batchmul)"'

exec /opt/unified/run_continuum_local.sh \
  "$n" "$t" "$layers" "$total_cm" mixed
