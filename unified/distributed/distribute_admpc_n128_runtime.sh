#!/usr/bin/env bash
set -euo pipefail

INVENTORY="${N128_INVENTORY:-/opt/unified/distributed/cluster.aws-public-n128-fig89-followup-20260828.env}"
LOCAL_COMPOSE="/opt/admpc/docker-compose.aws.yml"
LOCAL_IPC="/opt/admpc/adkg/ipc.py"
LOCAL_NODE_LAUNCHER="/opt/admpc/scripts/control-admpc-linear-node.sh"
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

REMOTE_ROOT="/home/${NODE_SSH_USERNAME}/${REMOTE_WORKSPACE_DIR}/admpc"
REMOTE_COMPOSE="$REMOTE_ROOT/docker-compose.aws.yml"
REMOTE_IPC="$REMOTE_ROOT/adkg/ipc.py"
REMOTE_NODE_LAUNCHER="$REMOTE_ROOT/scripts/control-admpc-linear-node.sh"
REMOTE_COMPOSE_TMP="$REMOTE_ROOT/.docker-compose.aws.yml.n128.tmp"
REMOTE_IPC_TMP="$REMOTE_ROOT/adkg/.ipc.py.n128.tmp"
REMOTE_NODE_LAUNCHER_TMP="$REMOTE_ROOT/scripts/.control-admpc-linear-node.sh.n128.tmp"
BACKUP_SUFFIX=".pre-n128-socket-20260828"
COMPOSE_SHA="$(sha256sum "$LOCAL_COMPOSE" | awk '{print $1}')"
IPC_SHA="$(sha256sum "$LOCAL_IPC" | awk '{print $1}')"
NODE_LAUNCHER_SHA="$(sha256sum "$LOCAL_NODE_LAUNCHER" | awk '{print $1}')"

deploy_host() {
    local index="$1"
    local ip="${CLUSTER_IPS[$index]}"
    local host="${NODE_SSH_USERNAME}@${ip}"
    scp "${SSH_OPTIONS[@]}" "$LOCAL_COMPOSE" "$host:$REMOTE_COMPOSE_TMP"
    scp "${SSH_OPTIONS[@]}" "$LOCAL_IPC" "$host:$REMOTE_IPC_TMP"
    scp "${SSH_OPTIONS[@]}" "$LOCAL_NODE_LAUNCHER" "$host:$REMOTE_NODE_LAUNCHER_TMP"
    ssh "${SSH_OPTIONS[@]}" "$host" -- \
        "set -e; python3 -c \"import ast; ast.parse(open('$REMOTE_IPC_TMP', encoding='utf-8').read())\"; bash -n '$REMOTE_NODE_LAUNCHER_TMP'; if docker compose version >/dev/null 2>&1; then MPC_IMAGE='$MPC_IMAGE' docker compose -f '$REMOTE_COMPOSE_TMP' config >/dev/null; else MPC_IMAGE='$MPC_IMAGE' docker-compose -f '$REMOTE_COMPOSE_TMP' config >/dev/null; fi; test \"\$(sha256sum '$REMOTE_COMPOSE_TMP' | awk '{print \$1}')\" = '$COMPOSE_SHA'; test \"\$(sha256sum '$REMOTE_IPC_TMP' | awk '{print \$1}')\" = '$IPC_SHA'; test \"\$(sha256sum '$REMOTE_NODE_LAUNCHER_TMP' | awk '{print \$1}')\" = '$NODE_LAUNCHER_SHA'; if [ -e '$REMOTE_COMPOSE' ] && [ ! -e '$REMOTE_COMPOSE$BACKUP_SUFFIX' ]; then cp -p '$REMOTE_COMPOSE' '$REMOTE_COMPOSE$BACKUP_SUFFIX'; fi; if [ -e '$REMOTE_IPC' ] && [ ! -e '$REMOTE_IPC$BACKUP_SUFFIX' ]; then cp -p '$REMOTE_IPC' '$REMOTE_IPC$BACKUP_SUFFIX'; fi; mv '$REMOTE_COMPOSE_TMP' '$REMOTE_COMPOSE'; mv '$REMOTE_IPC_TMP' '$REMOTE_IPC'; mv '$REMOTE_NODE_LAUNCHER_TMP' '$REMOTE_NODE_LAUNCHER'; chmod 0755 '$REMOTE_NODE_LAUNCHER'"
}

passed=0
failed=0
pids=()
for index in "${!CLUSTER_IPS[@]}"; do
    deploy_host "$index" &
    pids+=("$!")
    if [[ ${#pids[@]} -ge $PARALLELISM ]]; then
        for pid in "${pids[@]}"; do
            if wait "$pid"; then passed=$((passed + 1)); else failed=$((failed + 1)); fi
        done
        pids=()
    fi
done
for pid in "${pids[@]}"; do
    if wait "$pid"; then passed=$((passed + 1)); else failed=$((failed + 1)); fi
done

echo "AD-MPC n128 runtime distribution: passed=$passed failed=$failed compose_sha256=$COMPOSE_SHA ipc_sha256=$IPC_SHA"
if [[ $failed -ne 0 || $passed -ne 128 ]]; then
    exit 1
fi
