#!/usr/bin/env bash
set -euo pipefail

INVENTORY="${N128_INVENTORY:-/opt/unified/distributed/cluster.aws-public-n128-fig89-followup-20260828.env}"
LOCAL_IPC="${N128_IPC_PATH:-/opt/benchmark-baselines/n128-ipc-compatible-20260828/ipc.py}"
PARALLELISM="${DISTRIBUTE_PARALLELISM:-32}"

# shellcheck disable=SC1090
source "$INVENTORY"

if [[ ${#CLUSTER_IPS[@]} -ne 128 ]]; then
    echo "Expected 128 nodes, found ${#CLUSTER_IPS[@]}" >&2
    exit 1
fi

SSH_OPTIONS=(
    -i "$SSH_IDENTITY_FILE"
    -o IdentitiesOnly=yes
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o LogLevel=ERROR
    -o BatchMode=yes
    -o ConnectTimeout=12
)

REMOTE_ROOT="/home/${NODE_SSH_USERNAME}/${REMOTE_WORKSPACE_DIR}/dumbo-mpc"
REMOTE_IPC="$REMOTE_ROOT/dumbo-mpc/AsyRanTriGen/beaver/ipc.py"
REMOTE_TMP="$REMOTE_ROOT/dumbo-mpc/AsyRanTriGen/beaver/.ipc.py.compatible-n128.tmp"
REMOTE_INCOMPATIBLE_BACKUP="$REMOTE_IPC.incompatible-artifact-state-20260828"
EXPECTED_SHA="$(sha256sum "$LOCAL_IPC" | awk '{print $1}')"

deploy_host() {
    local index="$1"
    local ip="${CLUSTER_IPS[$index]}"
    local host="${NODE_SSH_USERNAME}@${ip}"

    scp "${SSH_OPTIONS[@]}" "$LOCAL_IPC" "$host:$REMOTE_TMP"
    ssh "${SSH_OPTIONS[@]}" "$host" -- \
        "set -e; python3 -c \"import ast; ast.parse(open('$REMOTE_TMP', encoding='utf-8').read())\"; test \"\$(sha256sum '$REMOTE_TMP' | awk '{print \$1}')\" = '$EXPECTED_SHA'; if [ -e '$REMOTE_IPC' ] && [ ! -e '$REMOTE_INCOMPATIBLE_BACKUP' ]; then cp -p '$REMOTE_IPC' '$REMOTE_INCOMPATIBLE_BACKUP'; fi; mv '$REMOTE_TMP' '$REMOTE_IPC'"
}

failed=0
passed=0
workers=()
for index in "${!CLUSTER_IPS[@]}"; do
    deploy_host "$index" &
    workers+=("$!")
    if [[ ${#workers[@]} -ge $PARALLELISM ]]; then
        for pid in "${workers[@]}"; do
            if wait "$pid"; then passed=$((passed + 1)); else failed=$((failed + 1)); fi
        done
        workers=()
    fi
done
for pid in "${workers[@]}"; do
    if wait "$pid"; then passed=$((passed + 1)); else failed=$((failed + 1)); fi
done

echo "Compatible n128 IPC distribution: passed=$passed failed=$failed ipc_sha256=$EXPECTED_SHA"
if [[ $failed -ne 0 || $passed -ne 128 ]]; then
    exit 1
fi
