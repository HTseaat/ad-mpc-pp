#!/usr/bin/env bash
set -euo pipefail

INVENTORY="${N128_INVENTORY:-/opt/unified/distributed/cluster.aws-public-n128-fig8-aggtrans-null-20260821.env}"
LOCAL_COMPOSE="/opt/dumbo-mpc/docker-compose.aws.yml"
LOCAL_IPC="/opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/ipc.py"
LOCAL_NOAGG_SO="${N128_NOAGG_AMD64_SO:-/opt/benchmark-baselines/noagg-unbatched-amd64-20260825/kzg_ped_out.so}"
PARALLELISM="${DISTRIBUTE_PARALLELISM:-32}"

# shellcheck disable=SC1090
source "$INVENTORY"

if [[ ${#CLUSTER_IPS[@]} -ne 128 ]]; then
    echo "Expected 128 nodes, found ${#CLUSTER_IPS[@]}" >&2
    exit 1
fi
if ! [[ "$PARALLELISM" =~ ^[1-9][0-9]*$ ]]; then
    echo "DISTRIBUTE_PARALLELISM must be a positive integer" >&2
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
REMOTE_COMPOSE="$REMOTE_ROOT/docker-compose.aws.yml"
REMOTE_TMP="$REMOTE_ROOT/.docker-compose.aws.yml.nofile.tmp"
REMOTE_IPC="$REMOTE_ROOT/dumbo-mpc/AsyRanTriGen/beaver/ipc.py"
REMOTE_IPC_TMP="$REMOTE_ROOT/dumbo-mpc/AsyRanTriGen/beaver/.ipc.py.max-sockets.tmp"
REMOTE_NOAGG_SO="$REMOTE_ROOT/dumbo-mpc/AsyRanTriGen/kzg_ped_out.so"
REMOTE_NOAGG_SO_TMP="$REMOTE_ROOT/dumbo-mpc/AsyRanTriGen/.kzg_ped_out.so.noagg-amd64.tmp"
REMOTE_BACKUP_SUFFIX=".pre-noagg-unbatched-20260828"
EXPECTED_COMPOSE_SHA="$(sha256sum "$LOCAL_COMPOSE" | awk '{print $1}')"
EXPECTED_IPC_SHA="$(sha256sum "$LOCAL_IPC" | awk '{print $1}')"
EXPECTED_NOAGG_SO_SHA="$(sha256sum "$LOCAL_NOAGG_SO" | awk '{print $1}')"

deploy_host() {
    local index="$1"
    local ip="${CLUSTER_IPS[$index]}"
    local host="${NODE_SSH_USERNAME}@${ip}"

    scp "${SSH_OPTIONS[@]}" "$LOCAL_COMPOSE" "$host:$REMOTE_TMP"
    scp "${SSH_OPTIONS[@]}" "$LOCAL_IPC" "$host:$REMOTE_IPC_TMP"
    scp "${SSH_OPTIONS[@]}" "$LOCAL_NOAGG_SO" "$host:$REMOTE_NOAGG_SO_TMP"
    ssh "${SSH_OPTIONS[@]}" "$host" -- \
        "set -e; cd '$REMOTE_ROOT'; test \"\$(uname -m)\" = x86_64; python3 -c \"import ast; ast.parse(open('$REMOTE_IPC_TMP', encoding='utf-8').read())\"; if docker compose version >/dev/null 2>&1; then MPC_IMAGE='$MPC_IMAGE' docker compose -f '$REMOTE_TMP' config >/dev/null; else MPC_IMAGE='$MPC_IMAGE' docker-compose -f '$REMOTE_TMP' config >/dev/null; fi; test \"\$(sha256sum '$REMOTE_TMP' | awk '{print \$1}')\" = '$EXPECTED_COMPOSE_SHA'; test \"\$(sha256sum '$REMOTE_IPC_TMP' | awk '{print \$1}')\" = '$EXPECTED_IPC_SHA'; test \"\$(sha256sum '$REMOTE_NOAGG_SO_TMP' | awk '{print \$1}')\" = '$EXPECTED_NOAGG_SO_SHA'; if [ -e '$REMOTE_COMPOSE' ] && [ ! -e '$REMOTE_COMPOSE$REMOTE_BACKUP_SUFFIX' ]; then cp -p '$REMOTE_COMPOSE' '$REMOTE_COMPOSE$REMOTE_BACKUP_SUFFIX'; fi; if [ -e '$REMOTE_IPC' ] && [ ! -e '$REMOTE_IPC$REMOTE_BACKUP_SUFFIX' ]; then cp -p '$REMOTE_IPC' '$REMOTE_IPC$REMOTE_BACKUP_SUFFIX'; fi; if [ -e '$REMOTE_NOAGG_SO' ] && [ ! -e '$REMOTE_NOAGG_SO$REMOTE_BACKUP_SUFFIX' ]; then cp -p '$REMOTE_NOAGG_SO' '$REMOTE_NOAGG_SO$REMOTE_BACKUP_SUFFIX'; fi; mv '$REMOTE_NOAGG_SO_TMP' '$REMOTE_NOAGG_SO'; mv '$REMOTE_IPC_TMP' '$REMOTE_IPC'; mv '$REMOTE_TMP' '$REMOTE_COMPOSE'; printf 'OK %03d %s\\n' '$((index + 1))' '$ip'"
}

failed=0
passed=0
workers=()
results="$(mktemp -d /tmp/continuum-compose-distribute.XXXXXX)"
cleanup() {
    find "$results" -maxdepth 1 -type f -delete 2>/dev/null || true
    rmdir "$results" 2>/dev/null || true
}
trap cleanup EXIT

for index in "${!CLUSTER_IPS[@]}"; do
    deploy_host "$index" >"$results/$index.out" 2>"$results/$index.err" &
    workers+=("$!:$index")
    if [[ ${#workers[@]} -ge $PARALLELISM ]]; then
        for item in "${workers[@]}"; do
            pid="${item%%:*}"
            idx="${item##*:}"
            if wait "$pid"; then
                passed=$((passed + 1))
            else
                failed=$((failed + 1))
                echo "FAIL $((idx + 1)) ${CLUSTER_IPS[$idx]}: $(<"$results/$idx.err")" >&2
            fi
        done
        workers=()
    fi
done

for item in "${workers[@]}"; do
    pid="${item%%:*}"
    idx="${item##*:}"
    if wait "$pid"; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
        echo "FAIL $((idx + 1)) ${CLUSTER_IPS[$idx]}: $(<"$results/$idx.err")" >&2
    fi
done

echo "NoAgg runtime distribution: passed=$passed failed=$failed compose_sha256=$EXPECTED_COMPOSE_SHA ipc_sha256=$EXPECTED_IPC_SHA noagg_so_sha256=$EXPECTED_NOAGG_SO_SHA"
if [[ $failed -ne 0 || $passed -ne 128 ]]; then
    exit 1
fi
