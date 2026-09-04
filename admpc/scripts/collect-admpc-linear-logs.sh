#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <output-directory>" >&2
    exit 2
fi

output_dir="$1"
source -- ./config.sh
mkdir -p "$output_dir/logs"

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
parallelism="${COLLECT_PARALLELISM:-32}"
pids=()
failed=0
for node_number in $(seq 1 "$NODE_NUM"); do
    ip="${NODE_IPS[$((node_number - 1))]}"
    host="${NODE_SSH_USERNAME}@${ip}"
    command scp "${ssh_options[@]}" \
        "${host}:${remote_root}/logs/node${node_number}_*.log" "$output_dir/logs/" &
    pids+=("$!")
    if (( ${#pids[@]} >= parallelism )); then
        for pid in "${pids[@]}"; do
            if ! wait "$pid"; then failed=1; fi
        done
        pids=()
    fi
done
for pid in "${pids[@]}"; do
    if ! wait "$pid"; then failed=1; fi
done

count="$(find "$output_dir/logs" -maxdepth 1 -type f -name 'node*.log' | wc -l)"
echo "collected_logs=$count failed=$failed output=$output_dir/logs"
exit "$failed"
