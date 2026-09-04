#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 9 ]]; then
  echo "Usage: run_adversarial_stage7_local.sh <n> <t> <layers> <total_cm> <aggtrans_epoch> <batchmul_epoch> <delay_ms> <attack_index> <output_dir>" >&2
  exit 1
fi

n="$1"
t="$2"
layers="$3"
total_cm="$4"
aggtrans_epoch="$5"
batchmul_epoch="$6"
delay_ms="$7"
attack_index="$8"
output_dir="$9"

if (( n < 3 * t + 1 )); then
  echo "Invalid n/t: require n >= 3*t+1." >&2
  exit 1
fi
if ! [[ "$layers" =~ ^[0-9]+$ ]] || (( layers < 3 )); then
  echo "Invalid layers=${layers}." >&2
  exit 1
fi
if ! [[ "$aggtrans_epoch" =~ ^[0-9]+$ ]] || (( aggtrans_epoch < 1 )); then
  echo "Invalid aggtrans_epoch=${aggtrans_epoch}." >&2
  exit 1
fi
if ! [[ "$batchmul_epoch" =~ ^[0-9]+$ ]] || (( batchmul_epoch != aggtrans_epoch + 1 )); then
  echo "Invalid batchmul_epoch=${batchmul_epoch}; expected aggtrans_epoch+1." >&2
  exit 1
fi
if ! [[ "$delay_ms" =~ ^[0-9]+$ ]] || (( delay_ms <= 0 )); then
  echo "Invalid delay_ms=${delay_ms}." >&2
  exit 1
fi
if ! [[ "$attack_index" =~ ^[0-9]+$ ]]; then
  echo "Invalid attack_index=${attack_index}." >&2
  exit 1
fi
if [[ -e "$output_dir" ]]; then
  echo "Refusing to overwrite existing Stage-7 output: ${output_dir}" >&2
  exit 1
fi

mkdir -p "$output_dir"
total_nodes=$((n * layers))
final_layer_start=$((n * (layers - 1)))
selected_source_ids=()
for ((local_id = n - t; local_id < n; local_id++)); do
  selected_source_ids+=("$((aggtrans_epoch * n + local_id))")
done
selected_source_ids_csv=$(IFS=,; echo "${selected_source_ids[*]}")

archive_continuum() {
  local scenario="$1"
  local destination="$output_dir/$scenario"
  mkdir -p "$destination/logs" "$destination/conf"
  for ((global_id = 0; global_id < total_nodes; global_id++)); do
    cp "/opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/log/logs-${global_id}.log" \
      "$destination/logs/"
  done
  cp -a "/opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/conf/admpc_${total_cm}_${layers}_${n}/." \
    "$destination/conf/"
}

archive_admpc() {
  local scenario="$1"
  local destination="$output_dir/$scenario"
  mkdir -p "$destination/logs" "$destination/conf" "$destination/metrics"
  for ((layer = 1; layer <= layers; layer++)); do
    for ((local_id = 0; local_id < n; local_id++)); do
      cp "/opt/admpc/logs/node${local_id}_layer${layer}.log" \
        "$destination/logs/"
    done
  done
  cp -a /opt/admpc/conf/curve_local_admpc_${n}_${layers}/. \
    "$destination/conf/"
  cp /opt/admpc/extracted_times.csv /opt/admpc/summary_times.csv \
    "$destination/metrics/"
}

echo "[Stage 7] 1/4 Continuum-delay"
FINISHED_PATTERN='"event": "config"' \
FINAL_LAYER_START="$final_layer_start" \
FINAL_LAYER_PATTERN='my_send_id: .* exec_time' \
REQUIRED_NODE_IDS="$selected_source_ids_csv" \
REQUIRED_NODE_PATTERN='"event": "delay_released"' \
ZMQ_AUTH_MODE=curve \
ZMQ_CURVE_READY_TIMEOUT=60 \
  /opt/unified/run_continuum_delay_local.sh \
    "$n" "$t" "$layers" "$total_cm" "$aggtrans_epoch" "$delay_ms"
archive_continuum continuum-delay

echo "[Stage 7] 2/4 Continuum-Byzantine"
ZMQ_AUTH_MODE=curve \
ZMQ_CURVE_READY_TIMEOUT=60 \
  /opt/unified/run_continuum_byzantine_local.sh \
    "$n" "$t" "$layers" "$total_cm" \
    "$aggtrans_epoch" "$batchmul_epoch" "$attack_index"
archive_continuum continuum-byzantine

echo "[Stage 7] 3/4 AD-MPC-delay"
ZMQ_AUTH_MODE=curve \
ZMQ_CURVE_READY_TIMEOUT=60 \
  /opt/unified/run_admpc_delay_local.sh \
    "$n" "$t" "$layers" "$total_cm" "$aggtrans_epoch" "$delay_ms"
archive_admpc admpc-delay

echo "[Stage 7] 4/4 AD-MPC-Byzantine"
ZMQ_AUTH_MODE=curve \
ZMQ_CURVE_READY_TIMEOUT=60 \
  /opt/unified/run_admpc_adtrans_byzantine_local.sh \
    "$n" "$t" "$layers" "$total_cm" "$aggtrans_epoch" "$attack_index"
archive_admpc admpc-byzantine

/opt/venv/admpc/bin/python /opt/unified/extract_adversarial_traces.py \
  --n "$n" --t "$t" --layers "$layers" \
  --continuum-delay "$output_dir/continuum-delay/logs" \
  --continuum-byzantine "$output_dir/continuum-byzantine/logs" \
  --admpc-delay "$output_dir/admpc-delay/logs" \
  --admpc-byzantine "$output_dir/admpc-byzantine/logs" \
  --trace-output "$output_dir/layer_trace.tsv" \
  --event-output "$output_dir/fault_events.tsv" \
  --summary-output "$output_dir/scenario_summary.json"
echo "Stage-7 four-scenario campaign complete: $output_dir"
