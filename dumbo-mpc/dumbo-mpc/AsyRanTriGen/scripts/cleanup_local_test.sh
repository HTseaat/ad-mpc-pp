#!/bin/bash
set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <num_nodes> [base_port] [port_step]"
    exit 1
fi

NUM_NODES=$1
BASE_PORT=${2:-10001}
PORT_STEP=${3:-200}

if ! [[ "$NUM_NODES" =~ ^[0-9]+$ ]] || [ "$NUM_NODES" -le 0 ]; then
    echo "Invalid num_nodes: ${NUM_NODES}"
    exit 1
fi

if ! [[ "$BASE_PORT" =~ ^[0-9]+$ ]] || [ "$BASE_PORT" -le 0 ]; then
    echo "Invalid base_port: ${BASE_PORT}"
    exit 1
fi

if ! [[ "$PORT_STEP" =~ ^[0-9]+$ ]] || [ "$PORT_STEP" -le 0 ]; then
    echo "Invalid port_step: ${PORT_STEP}"
    exit 1
fi

if ! command -v fuser >/dev/null 2>&1; then
    echo "fuser not found, skip cleanup"
    exit 0
fi

echo "Checking local test ports for stale processes ..."
for ID in $(seq 0 $((NUM_NODES - 1))); do
    PORT=$((BASE_PORT + ID * PORT_STEP))
    PIDS=$(fuser -n tcp "${PORT}" 2>/dev/null || true)
    if [ -n "${PIDS}" ]; then
        echo "Port ${PORT} is in use by PID(s): ${PIDS} -> killing"
        fuser -k -9 -n tcp "${PORT}" >/dev/null 2>&1 || true
    fi
done

echo "Cleanup finished."
