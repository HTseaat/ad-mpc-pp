#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 6 ]]; then
    echo "Usage: $0 <config-dir> <node-number> <node-count> <layers> <start-time> <timeout>" >&2
    exit 2
fi

conf_dir="$1"
node_number="$2"
node_count="$3"
layers="$4"
start_time="$5"
run_timeout="$6"

for value in "$node_number" "$node_count" "$layers" "$start_time" "$run_timeout"; do
    if ! [[ "$value" =~ ^[1-9][0-9]*$ ]]; then
        echo "numeric arguments must be positive integers" >&2
        exit 2
    fi
done
if (( node_number > node_count )); then
    echo "node-number must not exceed node-count" >&2
    exit 2
fi
: "${MPC_IMAGE:?MPC_IMAGE is required}"

compose_file="${MPC_COMPOSE_FILE:-docker-compose.aws.yml}"
if command -v docker-compose >/dev/null 2>&1; then
    compose=(docker-compose)
elif docker compose version >/dev/null 2>&1; then
    compose=(docker compose)
else
    echo "Neither docker-compose nor docker compose is available." >&2
    exit 127
fi

mkdir -p logs
find logs -maxdepth 1 -type f -name "node${node_number}_cont*.log" -delete

base_port=7000
pids=()
for ((layer_number = 1; layer_number <= layers; layer_number++)); do
    external_port=$((base_port + layer_number))
    file_number=$(((layer_number - 1) * node_count + node_number - 1))
    log_path="logs/node${node_number}_cont${layer_number}.log"
    echo "[node${node_number}_cont${layer_number}] LAUNCHED global_id=${file_number} port=${external_port}"
    (
        MPC_IMAGE="$MPC_IMAGE" timeout --signal=TERM --kill-after=30s "${run_timeout}s" \
            "${compose[@]}" -f "$compose_file" run --rm -w /usr/src/adkg \
            -p "${external_port}:${external_port}" \
            -e "PROTOCOL_OVERHEAD_METRICS=${PROTOCOL_OVERHEAD_METRICS:-0}" \
            -e "ZMQ_AUTH_MODE=${ZMQ_AUTH_MODE:-null}" \
            -e "ZMQ_CURVE_READY_TIMEOUT=${ZMQ_CURVE_READY_TIMEOUT:-420}" \
            -e "FAULT_MODE=${FAULT_MODE:-none}" \
            -e "FAULT_TARGET=${FAULT_TARGET:-}" \
            -e "FAULT_COMPUTATION_EPOCH=${FAULT_COMPUTATION_EPOCH:-}" \
            -e "FAULT_DELTA_MS=${FAULT_DELTA_MS:-}" \
            -e "FAULT_ATTACK_INDEX=${FAULT_ATTACK_INDEX:-}" \
            htadkg_adkg /opt/venv/admpc/bin/python3 -u \
            -m scripts.admpc_dynamic_linear_run -d \
            -f "conf/${conf_dir}/local.${file_number}.json" -time "$start_time" \
            >"$log_path" 2>&1
    ) &
    pids+=("$!")
    sleep 0.05
done

job_failed=0
for index in "${!pids[@]}"; do
    layer_number=$((index + 1))
    if wait "${pids[$index]}"; then
        echo "[node${node_number}_cont${layer_number}] FINISHED"
    else
        echo "[node${node_number}_cont${layer_number}] FAILED" >&2
        job_failed=1
    fi
done
exit "$job_failed"
