#!/usr/bin/env bash
set -euo pipefail

INVENTORY="${N128_INVENTORY:-/opt/unified/distributed/cluster.aws-public-n128-fig9-batchmul-null-20260821.env}"
ARCHIVE="${N128_CONFIG_ARCHIVE:-/opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/conf/admpc_600_8_128.tar.xz}"
ARCHIVE_NAME="${N128_ARCHIVE_NAME:-$(basename "$ARCHIVE")}"
CONFIG_NAME="${N128_CONFIG_NAME:-admpc_600_8_128}"
EXPECTED_FILES="${N128_EXPECTED_FILES:-1024}"
PARALLELISM="${DISTRIBUTE_PARALLELISM:-32}"
HTTP_PORT=7010
WEST_SEED_INDEX="${N128_WEST_SEED_INDEX:-0}"
EAST_SEED_INDEX="${N128_EAST_SEED_INDEX:-60}"
WEST_COUNT="${N128_WEST_COUNT:-60}"
REGION_ASSIGNMENT="${N128_REGION_ASSIGNMENT:-legacy-batchmul}"

# shellcheck disable=SC1090
source "$INVENTORY"

if [[ ${#CLUSTER_IPS[@]} -ne 128 ]]; then
    echo "Expected 128 cluster IPs, found ${#CLUSTER_IPS[@]}" >&2
    exit 1
fi
if [[ ! -f "$ARCHIVE" ]]; then
    echo "Missing archive: $ARCHIVE" >&2
    exit 1
fi
if ! [[ "$PARALLELISM" =~ ^[1-9][0-9]*$ ]]; then
    echo "DISTRIBUTE_PARALLELISM must be a positive integer" >&2
    exit 1
fi

SSH_OPTIONS=(
    -i "$SSH_IDENTITY_FILE"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o BatchMode=yes
    -o ConnectTimeout=12
    -o ServerAliveInterval=15
    -o ServerAliveCountMax=3
)

WEST_SEED="${CLUSTER_IPS[$WEST_SEED_INDEX]}"
EAST_SEED="${CLUSTER_IPS[$EAST_SEED_INDEX]}"
REMOTE_ROOT="/home/${NODE_SSH_USERNAME}/${REMOTE_WORKSPACE_DIR}"
REMOTE_CONF="$REMOTE_ROOT/dumbo-mpc/dumbo-mpc/AsyRanTriGen/conf"
REMOTE_CIPHER_DIR="/tmp/continuum-n128-config-cipher"
REMOTE_CIPHER="$REMOTE_CIPHER_DIR/${ARCHIVE_NAME}.enc"
REMOTE_KEY="/tmp/continuum-n128-config.key"
REMOTE_DOWNLOAD="/tmp/${ARCHIVE_NAME}.enc"
REMOTE_ARCHIVE_TMP="$REMOTE_CONF/${ARCHIVE_NAME}.tmp"
REMOTE_HTTP_PID="/tmp/continuum-n128-config-http.pid"
REMOTE_HTTP_LOG="/tmp/continuum-n128-config-http.log"

LOCAL_TMP="$(mktemp -d /tmp/continuum-n128-config.XXXXXX)"
LOCAL_KEY="$LOCAL_TMP/key"
LOCAL_CIPHER="$LOCAL_TMP/${ARCHIVE_NAME}.enc"
PLAIN_SHA="$(sha256sum "$ARCHIVE" | awk '{print $1}')"
CLEANED=0

ssh_host() {
    local ip="$1"
    shift
    ssh "${SSH_OPTIONS[@]}" "${NODE_SSH_USERNAME}@${ip}" -- "$@"
}

cleanup_seeds() {
    local seed
    for seed in "$WEST_SEED" "$EAST_SEED"; do
        ssh_host "$seed" \
            "if test -s '$REMOTE_HTTP_PID'; then pkill -F '$REMOTE_HTTP_PID' 2>/dev/null || true; fi; rm -f '$REMOTE_HTTP_PID' '$REMOTE_HTTP_LOG' '$REMOTE_CIPHER'; rmdir '$REMOTE_CIPHER_DIR' 2>/dev/null || true" \
            >/dev/null 2>&1 &
    done
    wait || true
}

cleanup_remote_secrets() {
    local ip
    local -a pids=()
    for ip in "${CLUSTER_IPS[@]}"; do
        ssh_host "$ip" "rm -f '$REMOTE_KEY' '$REMOTE_DOWNLOAD' '${REMOTE_DOWNLOAD}.part' '$REMOTE_ARCHIVE_TMP'" \
            >/dev/null 2>&1 &
        pids+=("$!")
        if [[ ${#pids[@]} -ge $PARALLELISM ]]; then
            wait "${pids[@]}" 2>/dev/null || true
            pids=()
        fi
    done
    if [[ ${#pids[@]} -gt 0 ]]; then
        wait "${pids[@]}" 2>/dev/null || true
    fi
}

cleanup() {
    local rc=$?
    trap - EXIT INT TERM
    if [[ $CLEANED -eq 0 ]]; then
        cleanup_seeds
        cleanup_remote_secrets
        rm -f "$LOCAL_KEY" "$LOCAL_CIPHER"
        rmdir "$LOCAL_TMP" 2>/dev/null || true
        CLEANED=1
    fi
    exit "$rc"
}
trap cleanup EXIT INT TERM

echo "Encrypting configuration archive..."
openssl rand -hex -out "$LOCAL_KEY" 32
chmod 600 "$LOCAL_KEY"
openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
    -pass "file:$LOCAL_KEY" -in "$ARCHIVE" -out "$LOCAL_CIPHER"

echo "Uploading encrypted archive to regional seeds..."
for seed in "$WEST_SEED" "$EAST_SEED"; do
    ssh_host "$seed" \
        "mkdir -p '$REMOTE_CIPHER_DIR'; if test -s '$REMOTE_HTTP_PID'; then pkill -F '$REMOTE_HTTP_PID' 2>/dev/null || true; fi; rm -f '$REMOTE_HTTP_PID' '$REMOTE_HTTP_LOG' '$REMOTE_CIPHER'"
    scp "${SSH_OPTIONS[@]}" "$LOCAL_CIPHER" \
        "${NODE_SSH_USERNAME}@${seed}:$REMOTE_CIPHER" &
done
wait

echo "Starting ciphertext-only download endpoints..."
for seed in "$WEST_SEED" "$EAST_SEED"; do
    ssh_host "$seed" \
        "nohup python3 -m http.server '$HTTP_PORT' --bind 0.0.0.0 --directory '$REMOTE_CIPHER_DIR' >'$REMOTE_HTTP_LOG' 2>&1 </dev/null & echo \$! >'$REMOTE_HTTP_PID'" &
done
wait

sleep 1
ssh_host "${CLUSTER_IPS[1]}" \
    "curl -fsSI --connect-timeout 5 'http://$WEST_SEED:$HTTP_PORT/${ARCHIVE_NAME}.enc' >/dev/null"
ssh_host "${CLUSTER_IPS[127]}" \
    "curl -fsSI --connect-timeout 5 'http://$EAST_SEED:$HTTP_PORT/${ARCHIVE_NAME}.enc' >/dev/null"

echo "Sending one-time decryption key over SSH..."
key_failed=0
pids=()
for ip in "${CLUSTER_IPS[@]}"; do
    scp "${SSH_OPTIONS[@]}" "$LOCAL_KEY" \
        "${NODE_SSH_USERNAME}@${ip}:$REMOTE_KEY" >/dev/null &
    pids+=("$!")
    if [[ ${#pids[@]} -ge $PARALLELISM ]]; then
        for pid in "${pids[@]}"; do
            if ! wait "$pid"; then key_failed=1; fi
        done
        pids=()
    fi
done
for pid in "${pids[@]}"; do
    if ! wait "$pid"; then key_failed=1; fi
done
if [[ $key_failed -ne 0 ]]; then
    echo "Failed to send the key to one or more nodes" >&2
    exit 1
fi

echo "Downloading, decrypting, verifying, and extracting on 128 nodes..."
deploy_failed=0
pids=()
for index in "${!CLUSTER_IPS[@]}"; do
    ip="${CLUSTER_IPS[$index]}"
    if [[ "$REGION_ASSIGNMENT" == "contiguous" ]] && (( index < WEST_COUNT )); then
        seed="$WEST_SEED"
    elif [[ "$REGION_ASSIGNMENT" == "contiguous" ]]; then
        seed="$EAST_SEED"
    elif (( index < 60 || (index >= 64 && index < 71) )); then
        seed="$WEST_SEED"
    else
        seed="$EAST_SEED"
    fi
    if [[ "$ip" == "$seed" ]]; then
        download_host="127.0.0.1"
    else
        download_host="$seed"
    fi
    remote_command="set -e; chmod 600 '$REMOTE_KEY'; mkdir -p '$REMOTE_CONF'; curl -fsSL --retry 4 --retry-delay 1 --connect-timeout 8 'http://$download_host:$HTTP_PORT/${ARCHIVE_NAME}.enc' -o '${REMOTE_DOWNLOAD}.part'; mv '${REMOTE_DOWNLOAD}.part' '$REMOTE_DOWNLOAD'; openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -pass 'file:$REMOTE_KEY' -in '$REMOTE_DOWNLOAD' -out '$REMOTE_ARCHIVE_TMP'; printf '%s  %s\n' '$PLAIN_SHA' '$REMOTE_ARCHIVE_TMP' | sha256sum -c - >/dev/null; mv '$REMOTE_ARCHIVE_TMP' '$REMOTE_CONF/$ARCHIVE_NAME'; tar -C '$REMOTE_CONF' -xJf '$REMOTE_CONF/$ARCHIVE_NAME'; test \"\$(find '$REMOTE_CONF/$CONFIG_NAME' -maxdepth 1 -type f -name 'local.*.json' | wc -l)\" -eq '$EXPECTED_FILES'; rm -f '$REMOTE_KEY' '$REMOTE_DOWNLOAD'"
    ssh_host "$ip" "$remote_command" >/dev/null &
    pids+=("$!")
    if [[ ${#pids[@]} -ge $PARALLELISM ]]; then
        for pid in "${pids[@]}"; do
            if ! wait "$pid"; then deploy_failed=1; fi
        done
        pids=()
    fi
done
for pid in "${pids[@]}"; do
    if ! wait "$pid"; then deploy_failed=1; fi
done
if [[ $deploy_failed -ne 0 ]]; then
    echo "One or more node deployments failed" >&2
    exit 1
fi

echo "Cleaning ciphertext service and one-time secrets..."
cleanup_seeds
cleanup_remote_secrets
rm -f "$LOCAL_KEY" "$LOCAL_CIPHER"
rmdir "$LOCAL_TMP"
CLEANED=1
trap - EXIT INT TERM

echo "Encrypted distribution complete: 128/128 nodes, $EXPECTED_FILES configs per node."
