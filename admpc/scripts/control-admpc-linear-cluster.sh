#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "Usage: $0 <config-dir> <start-time> <timeout>" >&2
    exit 2
fi

conf_dir="$1"
start_time="$2"
run_timeout="$3"
IFS='_' read -r _ _ layer_offset config_node_count <<<"$conf_dir"
layers=$((layer_offset + 2))

source -- ./config.sh
if (( NODE_NUM != config_node_count )); then
    echo "config node count does not match NODE_NUM" >&2
    exit 2
fi

ssh_options=(
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o LogLevel=ERROR
    -o BatchMode=yes
    -o ConnectTimeout=12
    -o ConnectionAttempts=3
)
if [[ -n "${SSH_IDENTITY_FILE:-}" ]]; then
    ssh_options+=(-i "$SSH_IDENTITY_FILE" -o IdentitiesOnly=yes)
fi

remote_root="/home/${NODE_SSH_USERNAME}/${REMOTE_WORKSPACE_DIR}/admpc"
mkdir -p logs
find logs -maxdepth 1 -type f \( -name 'node*_cont*.log' -o -name 'node*_launcher.log' -o -name 'node*_dispatch.log' \) -delete

pids=()
for node_number in $(seq 1 "$NODE_NUM"); do
    ip="${NODE_IPS[$((node_number - 1))]}"
    host="${NODE_SSH_USERNAME}@${ip}"
    command ssh "${ssh_options[@]}" -T "$host" \
        "cd '$remote_root'; mkdir -p logs; nohup setsid env MPC_IMAGE='${MPC_IMAGE}' MPC_COMPOSE_FILE='${MPC_COMPOSE_FILE:-docker-compose.aws.yml}' PROTOCOL_OVERHEAD_METRICS='${PROTOCOL_OVERHEAD_METRICS:-0}' ZMQ_AUTH_MODE='${ZMQ_AUTH_MODE:-null}' ZMQ_CURVE_READY_TIMEOUT='${ZMQ_CURVE_READY_TIMEOUT:-420}' ./scripts/control-admpc-linear-node.sh '$conf_dir' '$node_number' '$NODE_NUM' '$layers' '$start_time' '$run_timeout' >'logs/node${node_number}_launcher.log' 2>&1 < /dev/null & echo DETACHED_PID=\$!" \
        >"logs/node${node_number}_dispatch.log" 2>&1 &
    pids+=("$!")
    sleep 0.05
done

job_failed=0
for pid in "${pids[@]}"; do
    if ! wait "$pid"; then
        job_failed=1
    fi
done
exit "$job_failed"
