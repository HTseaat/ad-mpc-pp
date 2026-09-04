#!/usr/bin/env bash
set -euo pipefail

source -- ./config.sh
parallelism="${PROGRESS_PARALLELISM:-32}"
progress_dir="$(mktemp -d /tmp/admpc-progress.XXXXXX)"
cleanup() {
    if [[ "$progress_dir" == /tmp/admpc-progress.* ]]; then
        command rm -rf -- "$progress_dir"
    fi
}
trap cleanup EXIT

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

check_host() {
    local index="$1"
    local node_number=$((index + 1))
    local ip="${NODE_IPS[$index]}"
    local host="${NODE_SSH_USERNAME}@${ip}"
    local base="/home/${NODE_SSH_USERNAME}/${REMOTE_WORKSPACE_DIR}/admpc/logs/node${node_number}"
    local result
    if result="$(command ssh "${ssh_options[@]}" "$host" \
        "t3=0; t4=0; fatal=0; alive=0; grep -q 'layer ID: 2 layer_time' '${base}_cont3.log' 2>/dev/null && t3=1; grep -q 'layer ID: 3 layer_time' '${base}_cont4.log' 2>/dev/null && t4=1; grep -q -e TimeoutError -e MemoryError -e 'No space left' ${base}_cont*.log 2>/dev/null && fatal=1; pgrep -f '[c]ontrol-admpc-linear-node.sh admpc-linear_300_6_128' >/dev/null && alive=1; printf '%s %s %s %s\\n' \"\$t3\" \"\$t4\" \"\$fatal\" \"\$alive\"" 2>/dev/null)"; then
        printf '%s %s %s\n' "$node_number" "$ip" "$result" >"$progress_dir/$node_number"
    else
        printf '%s %s SSHFAIL\n' "$node_number" "$ip" >"$progress_dir/$node_number"
    fi
}

pids=()
for index in "${!NODE_IPS[@]}"; do
    check_host "$index" &
    pids+=("$!")
    if (( ${#pids[@]} >= parallelism )); then
        for pid in "${pids[@]}"; do wait "$pid" || true; done
        pids=()
    fi
done
for pid in "${pids[@]}"; do wait "$pid" || true; done

awk '
    $3 == 1 { third++ }
    $4 == 1 { fourth++ }
    $5 == 1 { fatal++ }
    $6 == 1 { alive++ }
    $3 == "SSHFAIL" { sshfail++ }
    END {
        printf "third_complete_hosts=%d fourth_complete_hosts=%d fatal_hosts=%d launcher_alive_hosts=%d ssh_failures=%d total=%d\n",
            third, fourth, fatal, alive, sshfail, NR
    }
' "$progress_dir"/*

awk '$3 != 1 { print $1 }' "$progress_dir"/* | paste -sd, - | sed 's/^/third_incomplete_nodes=/'
awk '$4 != 1 { print $1 }' "$progress_dir"/* | paste -sd, - | sed 's/^/fourth_incomplete_nodes=/'
