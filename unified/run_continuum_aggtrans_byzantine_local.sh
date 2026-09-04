#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 6 ]]; then
  echo "Usage: run_continuum_aggtrans_byzantine_local.sh <n> <t> <layers> <total_cm> <computation_epoch> <attack_index>" >&2
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
export FAULT_TARGET=aggtrans
export FAULT_COMPUTATION_EPOCH="$computation_epoch"
export FAULT_ATTACK_INDEX="$attack_index"
# The generic launcher treats intermediate Transfer/BatchMul "Finished"
# messages as completion.  Require the attacked dealers to emit their mutation
# event and the final physical layer to return from the complete protocol.
required_node_ids=()
for ((local_id = n - t; local_id < n; local_id++)); do
  required_node_ids+=("$((computation_epoch * n + local_id))")
done
required_node_ids_csv=$(IFS=,; echo "${required_node_ids[*]}")
export FINISHED_PATTERN="Finished|my_send_id: .* exec_time"
export FINAL_LAYER_START="$((n * (layers - 1)))"
export FINAL_LAYER_PATTERN="my_send_id: .* exec_time"
export REQUIRED_NODE_IDS="$required_node_ids_csv"
export REQUIRED_NODE_PATTERN='"event": "byzantine_mutation"'

exec /opt/unified/run_continuum_local.sh \
  "$n" "$t" "$layers" "$total_cm" mixed
