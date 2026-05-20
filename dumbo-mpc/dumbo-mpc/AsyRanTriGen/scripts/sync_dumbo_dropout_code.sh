#!/usr/bin/env bash
set -euo pipefail

source -- ./common.sh
ensure_script_dir
source -- ./config.sh

REMOTE_WORKSPACE_DIR="${REMOTE_WORKSPACE_DIR:-}"
if [[ -n "$REMOTE_WORKSPACE_DIR" ]]; then
    REMOTE_ROOT="~/${REMOTE_WORKSPACE_DIR}"
else
    REMOTE_ROOT="~"
fi

LOCAL_BEAVER_DIR="$(cd "$(dirname "$0")/../beaver" && pwd)"
REMOTE_BEAVER_DIR="${REMOTE_ROOT}/dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver"

FILES=(
    "dumbo_mpc_dyn.py"
    "dumbo_mpc_dyn_dropout.py"
)

echo "开始同步 Dumbo-MPC 掉线实验相关代码到远端节点..."
echo "远端目录: ${REMOTE_BEAVER_DIR}"

for i in $(seq 1 "$NODE_NUM"); do
    ssh_user_host="${NODE_SSH_USERNAME}@${NODE_IPS[$i - 1]}"
    echo "[node $i/$NODE_NUM] ${ssh_user_host}"

    ssh "$ssh_user_host" -- "mkdir -p ${REMOTE_BEAVER_DIR}"

    for fname in "${FILES[@]}"; do
        echo "  - 同步 ${fname}"
        scp "${LOCAL_BEAVER_DIR}/${fname}" "${ssh_user_host}:${REMOTE_BEAVER_DIR}/${fname}"
    done
done

echo "Dumbo-MPC 掉线实验代码已同步完成。"
