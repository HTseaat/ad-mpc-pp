#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 6 ]]; then
  echo "Usage: run_continuum_batchmul_byzantine_local.sh <n> <t> <layers> <total_cm> <computation_epoch> <attack_index>" >&2
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
export FAULT_TARGET=batchmul
export FAULT_COMPUTATION_EPOCH="$computation_epoch"
export FAULT_ATTACK_INDEX="$attack_index"

required_node_ids=()
for ((local_id = n - t; local_id < n; local_id++)); do
  required_node_ids+=("$((computation_epoch * n + local_id))")
done
required_node_ids_csv=$(IFS=,; echo "${required_node_ids[*]}")
# Non-final, non-attacked processes only need to have started with the exact
# fault configuration.  Protocol success is guarded by the stronger attacked
# dealer mutation marker and every output process's top-level completion.
export FINISHED_PATTERN='"event": "config"'
export FINAL_LAYER_START="$((n * (layers - 1)))"
export FINAL_LAYER_PATTERN="my_send_id: .* exec_time"
export REQUIRED_NODE_IDS="$required_node_ids_csv"
export REQUIRED_NODE_PATTERN='"component": "batchmul".*"event": "byzantine_mutation"|"event": "byzantine_mutation".*"component": "batchmul"'

exec /opt/unified/run_continuum_local.sh \
  "$n" "$t" "$layers" "$total_cm" mixed
