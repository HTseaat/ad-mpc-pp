#!/usr/bin/env bash

set -euo pipefail

# Read config directory
if [ $# -lt 1 ]; then
    echo "Usage: $0 <config_dir> [protocol] [start-unix-time] [run-timeout-seconds]"
    exit 1
fi
conf_dir=$1

# Optional protocol override (non-numeric second arg)
if [[ $# -ge 2 && ! "$2" =~ ^[0-9] ]]; then
    protocol_override="$2"
    START_TIME=${3:-$(date +%s)}
    RUN_TIMEOUT=${4:-900}
else
    protocol_override=""
    START_TIME=${2:-$(date +%s)}
    RUN_TIMEOUT=${3:-900}
fi


if ! [[ "$START_TIME" =~ ^[0-9]+$ && "$RUN_TIMEOUT" =~ ^[1-9][0-9]*$ ]]; then
    echo "start-unix-time and run-timeout-seconds must be positive integers" >&2
    exit 1
fi

IFS='_' read -r protocol_from_dir total_cm layer_offset N <<< "$conf_dir"
protocol="$protocol_from_dir"
# Use override if provided
if [ -n "$protocol_override" ]; then
    protocol="$protocol_override"
fi

# Compute how many containers per node: layer_offset + 2
containers_per_node=$(( layer_offset + 2 ))

# Determine which run module to invoke
case "$protocol" in
    admpc)
        run_mod="scripts.admpc_dynamic_run"
        ;;
    admpc-linear)
        run_mod="scripts.admpc_dynamic_linear_run"
        ;;
    admpc-nonlinear)
        run_mod="scripts.admpc_dynamic_nonlinear_run"
        ;;
    admpc-shuffle)
        run_mod="scripts.admpc_dynamic_shuffle_run"
        ;;
    fluid1)
        run_mod="scripts.fluid_mpc_run_1"
        ;;
    fluid2)
        run_mod="scripts.fluid_mpc_run"
        ;;
    hbmpc)
        run_mod="scripts.honeybadgermpc_run"
        ;;
    hbmpc_attack)
        run_mod="scripts.hbmpc_attack_run"
        ;;
    *)
        echo "Unknown protocol: $protocol"
        exit 1
        ;;
esac

# Base directory for JSON files
json_dir="conf/$conf_dir"

mkdir -p logs      # create local log directory
find logs -maxdepth 1 -type f -name 'node*.log' -delete

source -- ./common.sh
ensure_script_dir


source -- ./config.sh

SSH_OPTIONS=(
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o BatchMode=yes
    -o ConnectTimeout=12
    -o ConnectionAttempts=3
)

REMOTE_WORKSPACE_DIR="${REMOTE_WORKSPACE_DIR:-}"
if [ -n "$REMOTE_WORKSPACE_DIR" ]; then
    REMOTE_ROOT="~/${REMOTE_WORKSPACE_DIR}"
else
    REMOTE_ROOT="~"
fi

metrics_enabled="${PROTOCOL_OVERHEAD_METRICS:-0}"
metrics_run_id="${PROTOCOL_OVERHEAD_RUN_ID:-$conf_dir}"
adtrans_alg4_per_item="${ADTRANS_ALG4_PER_ITEM:-0}"
# batch_verify_eval_rs is intentionally fixed to the historical benchmark
# implementation. Keep the environment value pinned for artifact compatibility.
admpc_legacy_eval_verify=1
shuffle_k="${SHUFFLE_K:-128}"
shuffle_mode="${SHUFFLE_MODE:-iterated}"
shuffle_ack_timeout="${SHUFFLE_ACK_TIMEOUT:-600}"
shuffle_ack_threshold="${SHUFFLE_ACK_THRESHOLD:-$NODE_NUM}"
admpc_shuffle_run_id="${ADMPC_SHUFFLE_RUN_ID:-$conf_dir}"
fault_mode="${FAULT_MODE:-none}"
fault_target="${FAULT_TARGET:-}"
fault_computation_epoch="${FAULT_COMPUTATION_EPOCH:-}"
fault_delay_source_epoch="${FAULT_DELAY_SOURCE_EPOCH:-}"
fault_adtrans_source_epoch="${FAULT_ADTRANS_SOURCE_EPOCH:-}"
fault_delta_ms="${FAULT_DELTA_MS:-}"
fault_attack_index="${FAULT_ATTACK_INDEX:-}"
fault_accumulation_mode="${FAULT_ACCUMULATION_MODE:-none}"
fault_accumulation_count="${FAULT_ACCUMULATION_COUNT:-}"
fault_accumulation_start_epoch="${FAULT_ACCUMULATION_START_EPOCH:-}"

if [[ "$adtrans_alg4_per_item" != "0" && "$adtrans_alg4_per_item" != "1" ]]; then
    echo "ADTRANS_ALG4_PER_ITEM must be 0 (aggregate) or 1 (per-item)" >&2
    exit 1
fi

echo "WARNING: AD-MPC batch_verify_eval_rs uses historical inner-proof-only verification; benchmark use only" >&2

case "$fault_accumulation_mode" in
    none)
        if [[ -n "$fault_accumulation_count" || -n "$fault_accumulation_start_epoch" ]]; then
            echo "FAULT_ACCUMULATION_MODE=none cannot be combined with accumulation parameters" >&2
            exit 1
        fi
        ;;
    silent)
        if ! [[ "$fault_accumulation_count" =~ ^[1-9][0-9]*$ ]] || \
           ! [[ "$fault_accumulation_start_epoch" =~ ^[1-9][0-9]*$ ]] || \
           [[ "$fault_mode" != "none" ]]; then
            echo "AD-MPC accumulation requires a positive count/start epoch and FAULT_MODE=none" >&2
            exit 1
        fi
        ;;
    *)
        echo "Unsupported FAULT_ACCUMULATION_MODE for AD-MPC: $fault_accumulation_mode" >&2
        exit 1
        ;;
esac

case "$fault_mode" in
    none)
        if [[ -n "$fault_target" || -n "$fault_computation_epoch" || \
              -n "$fault_delay_source_epoch" || -n "$fault_adtrans_source_epoch" || \
              -n "$fault_delta_ms" || -n "$fault_attack_index" ]]; then
            echo "FAULT_MODE=none cannot be combined with AD-MPC fault parameters" >&2
            exit 1
        fi
        ;;
    delay)
        if [[ "$fault_target" != "adtrans" ]] || \
           ! [[ "$fault_computation_epoch" =~ ^[0-9]+$ ]] || \
           ! [[ "$fault_delta_ms" =~ ^[1-9][0-9]*$ ]] || \
           [[ -n "$fault_attack_index" || -n "$fault_delay_source_epoch" || \
              -n "$fault_adtrans_source_epoch" ]]; then
            echo "AD-MPC delay requires target=adtrans, a non-negative epoch, a positive delta, and no attack index" >&2
            exit 1
        fi
        ;;
    byzantine)
        if [[ "$fault_target" != "adtrans" ]] || \
           ! [[ "$fault_computation_epoch" =~ ^[0-9]+$ ]] || \
           ! [[ "$fault_attack_index" =~ ^[0-9]+$ ]] || \
           [[ -n "$fault_delta_ms" || -n "$fault_delay_source_epoch" || \
              -n "$fault_adtrans_source_epoch" ]]; then
            echo "AD-MPC Byzantine mode requires target=adtrans, a non-negative epoch/index, and no delay" >&2
            exit 1
        fi
        ;;
    figure10-attack)
        if [[ "$fault_target" != "adtrans" ]] || \
           [[ -n "$fault_computation_epoch" ]] || \
           ! [[ "$fault_delay_source_epoch" =~ ^[1-9][0-9]*$ ]] || \
           ! [[ "$fault_adtrans_source_epoch" =~ ^[1-9][0-9]*$ ]] || \
           [[ "$fault_delta_ms" != "10000" ]] || \
           ! [[ "$fault_attack_index" =~ ^[0-9]+$ ]] || \
           (( fault_delay_source_epoch != 3 )) || \
           (( fault_adtrans_source_epoch != 4 )); then
            echo "AD-MPC Figure 10 attack requires source epochs 3/4, delay 10000 ms, and a non-negative attack index" >&2
            exit 1
        fi
        ;;
    *)
        echo "Unsupported FAULT_MODE for AD-MPC: $fault_mode" >&2
        exit 1
        ;;
esac
if [[ "$metrics_enabled" =~ ^(1|true|yes|on)$ ]] && \
   [[ ! "$metrics_run_id" =~ ^[A-Za-z0-9_.-]+$ ]]; then
    echo "Unsafe PROTOCOL_OVERHEAD_RUN_ID: $metrics_run_id" >&2
    exit 1
fi
container_metrics_dir="/opt/admpc/logs/protocol-overhead/${metrics_run_id}"
remote_metrics_dir="${REMOTE_ROOT}/admpc/logs/protocol-overhead/${metrics_run_id}"


base_port=7000  # setting basic port, e.g. 7000
delay_between_ssh_commands="${CONTROL_NODE_SSH_DELAY:-0.1}"
pids=()

# Figure 12 needs 51 containers per physical host. Launch them through one SSH
# session per host so the controller does not hit sshd's concurrent handshake
# limit while preserving one container and one log per logical process.
if [[ "$protocol" == "admpc-shuffle" ]]; then
    for i in $(seq 1 "$NODE_NUM"); do
        ssh_user_host="${NODE_SSH_USERNAME}@${NODE_IPS[$i - 1]}"
        scp "${SSH_OPTIONS[@]}" ./control-admpc-shuffle-node.sh \
            "${ssh_user_host}:${REMOTE_ROOT}/admpc/scripts/control-admpc-shuffle-node.sh"
        ssh "${SSH_OPTIONS[@]}" -T "$ssh_user_host" \
            "chmod 0755 ${REMOTE_ROOT}/admpc/scripts/control-admpc-shuffle-node.sh"
    done

    for i in $(seq 1 "$NODE_NUM"); do
        ssh_user_host="${NODE_SSH_USERNAME}@${NODE_IPS[$i - 1]}"
        ssh "${SSH_OPTIONS[@]}" -T "$ssh_user_host" \
            "cd ${REMOTE_ROOT}/admpc; \
            MPC_IMAGE='${MPC_IMAGE:-}' \
            MPC_COMPOSE_FILE='${MPC_COMPOSE_FILE:-docker-compose.aws.yml}' \
            ZMQ_AUTH_MODE='${ZMQ_AUTH_MODE:-curve}' \
            ZMQ_CURVE_READY_TIMEOUT='${ZMQ_CURVE_READY_TIMEOUT:-180}' \
            SHUFFLE_K='${shuffle_k}' \
            SHUFFLE_MODE='${shuffle_mode}' \
            SHUFFLE_ACK_TIMEOUT='${shuffle_ack_timeout}' \
            SHUFFLE_ACK_THRESHOLD='${shuffle_ack_threshold}' \
            ADMPC_SHUFFLE_RUN_ID='${admpc_shuffle_run_id}' \
            ./scripts/control-admpc-shuffle-node.sh \
              '${conf_dir}' '${i}' '${NODE_NUM}' '${containers_per_node}' \
              '${START_TIME}' '${RUN_TIMEOUT}'" \
            2>&1 | tee "logs/node${i}_launcher.log" &
    done

    job_failed=0
    for job in $(jobs -p); do
        if ! wait "$job"; then
            job_failed=1
        fi
    done
    for i in $(seq 1 "$NODE_NUM"); do
        ssh_user_host="${NODE_SSH_USERNAME}@${NODE_IPS[$i - 1]}"
        if ! scp "${SSH_OPTIONS[@]}" "${ssh_user_host}:${REMOTE_ROOT}/admpc/logs/node${i}_cont*.log" logs/; then
            job_failed=1
        fi
    done
    if [[ "$job_failed" -ne 0 ]]; then
        echo "One or more remote AD-MPC shuffle runs failed. Check logs/ for details." >&2
        exit 1
    fi
    exit 0
fi

if [ "$protocol" = "hbmpc" ] || [ "$protocol" = "hbmpc_attack" ]; then
    # Single loop for hbmpc: one container per node
    for i in $(seq 1 $NODE_NUM); do
        external_port=$((base_port + 1))
        ssh_user_host="${NODE_SSH_USERNAME}@${NODE_IPS[$i - 1]}"
        file_num=$((i - 1))
        ssh "${SSH_OPTIONS[@]}" -T "$ssh_user_host" \
            "set -e; cd ${REMOTE_ROOT}/admpc; \
            if command -v docker-compose >/dev/null 2>&1; then \
                MPC_IMAGE='${MPC_IMAGE:-}' timeout --signal=TERM --kill-after=30s ${RUN_TIMEOUT}s docker-compose -f '${MPC_COMPOSE_FILE:-docker-compose.aws.yml}' run --rm -w /usr/src/adkg -p $external_port:$external_port -e PROTOCOL_OVERHEAD_METRICS=${metrics_enabled} -e PROTOCOL_OVERHEAD_OUTPUT_DIR=${container_metrics_dir} -e PROTOCOL_OVERHEAD_RUN_ID=${metrics_run_id} -e ADTRANS_ALG4_PER_ITEM=${adtrans_alg4_per_item} -e ADMPC_LEGACY_EVAL_VERIFY=${admpc_legacy_eval_verify} -e ZMQ_AUTH_MODE=${ZMQ_AUTH_MODE:-null} -e ZMQ_CURVE_READY_TIMEOUT=${ZMQ_CURVE_READY_TIMEOUT:-60} -e SHUFFLE_K=${shuffle_k} -e SHUFFLE_MODE=${shuffle_mode} -e SHUFFLE_ACK_TIMEOUT=${shuffle_ack_timeout} -e SHUFFLE_ACK_THRESHOLD=${shuffle_ack_threshold} -e ADMPC_SHUFFLE_RUN_ID=${admpc_shuffle_run_id} htadkg_adkg \
                /opt/venv/admpc/bin/python3 -u -m $run_mod -d -f $json_dir/local.${file_num}.json -time $START_TIME; \
            elif docker compose version >/dev/null 2>&1; then \
                MPC_IMAGE='${MPC_IMAGE:-}' timeout --signal=TERM --kill-after=30s ${RUN_TIMEOUT}s docker compose -f '${MPC_COMPOSE_FILE:-docker-compose.aws.yml}' run --rm -w /usr/src/adkg -p $external_port:$external_port -e PROTOCOL_OVERHEAD_METRICS=${metrics_enabled} -e PROTOCOL_OVERHEAD_OUTPUT_DIR=${container_metrics_dir} -e PROTOCOL_OVERHEAD_RUN_ID=${metrics_run_id} -e ADTRANS_ALG4_PER_ITEM=${adtrans_alg4_per_item} -e ADMPC_LEGACY_EVAL_VERIFY=${admpc_legacy_eval_verify} -e ZMQ_AUTH_MODE=${ZMQ_AUTH_MODE:-null} -e ZMQ_CURVE_READY_TIMEOUT=${ZMQ_CURVE_READY_TIMEOUT:-60} -e SHUFFLE_K=${shuffle_k} -e SHUFFLE_MODE=${shuffle_mode} -e SHUFFLE_ACK_TIMEOUT=${shuffle_ack_timeout} -e SHUFFLE_ACK_THRESHOLD=${shuffle_ack_threshold} -e ADMPC_SHUFFLE_RUN_ID=${admpc_shuffle_run_id} htadkg_adkg \
                /opt/venv/admpc/bin/python3 -u -m $run_mod -d -f $json_dir/local.${file_num}.json -time $START_TIME; \
            else \
                echo 'Neither docker-compose nor docker compose is available on this node.' >&2; \
                exit 127; \
            fi" \
            > "logs/node${i}.log" 2>&1 &
        pids+=("$!")
    done
else
    # Two-layer loops for admpc and fluid
    for j in $(seq 1 $containers_per_node); do
        for i in $(seq 1 $NODE_NUM); do
            external_port=$((base_port + j))
            ssh_user_host="${NODE_SSH_USERNAME}@${NODE_IPS[$i - 1]}"
            file_num=$(((j - 1) * NODE_NUM + i - 1))
            ssh "${SSH_OPTIONS[@]}" -T "$ssh_user_host" \
                "set -e; cd ${REMOTE_ROOT}/admpc; \
                if command -v docker-compose >/dev/null 2>&1; then \
                MPC_IMAGE='${MPC_IMAGE:-}' timeout --signal=TERM --kill-after=30s ${RUN_TIMEOUT}s docker-compose -f '${MPC_COMPOSE_FILE:-docker-compose.aws.yml}' run --rm -w /usr/src/adkg -p $external_port:$external_port -e PROTOCOL_OVERHEAD_METRICS=${metrics_enabled} -e PROTOCOL_OVERHEAD_OUTPUT_DIR=${container_metrics_dir} -e PROTOCOL_OVERHEAD_RUN_ID=${metrics_run_id} -e ADTRANS_ALG4_PER_ITEM=${adtrans_alg4_per_item} -e ADMPC_LEGACY_EVAL_VERIFY=${admpc_legacy_eval_verify} -e ZMQ_AUTH_MODE=${ZMQ_AUTH_MODE:-null} -e ZMQ_CURVE_READY_TIMEOUT=${ZMQ_CURVE_READY_TIMEOUT:-60} -e SHUFFLE_K=${shuffle_k} -e SHUFFLE_MODE=${shuffle_mode} -e SHUFFLE_ACK_TIMEOUT=${shuffle_ack_timeout} -e SHUFFLE_ACK_THRESHOLD=${shuffle_ack_threshold} -e ADMPC_SHUFFLE_RUN_ID=${admpc_shuffle_run_id} -e FAULT_ACCUMULATION_MODE=${fault_accumulation_mode} -e FAULT_ACCUMULATION_COUNT=${fault_accumulation_count} -e FAULT_ACCUMULATION_START_EPOCH=${fault_accumulation_start_epoch} -e FAULT_MODE=${fault_mode} -e FAULT_TARGET=${fault_target} -e FAULT_COMPUTATION_EPOCH=${fault_computation_epoch} -e FAULT_DELAY_SOURCE_EPOCH=${fault_delay_source_epoch} -e FAULT_ADTRANS_SOURCE_EPOCH=${fault_adtrans_source_epoch} -e FAULT_DELTA_MS=${fault_delta_ms} -e FAULT_ATTACK_INDEX=${fault_attack_index} htadkg_adkg \
                    /opt/venv/admpc/bin/python3 -u -m $run_mod -d -f $json_dir/local.${file_num}.json -time $START_TIME; \
            elif docker compose version >/dev/null 2>&1; then \
                MPC_IMAGE='${MPC_IMAGE:-}' timeout --signal=TERM --kill-after=30s ${RUN_TIMEOUT}s docker compose -f '${MPC_COMPOSE_FILE:-docker-compose.aws.yml}' run --rm -w /usr/src/adkg -p $external_port:$external_port -e PROTOCOL_OVERHEAD_METRICS=${metrics_enabled} -e PROTOCOL_OVERHEAD_OUTPUT_DIR=${container_metrics_dir} -e PROTOCOL_OVERHEAD_RUN_ID=${metrics_run_id} -e ADTRANS_ALG4_PER_ITEM=${adtrans_alg4_per_item} -e ADMPC_LEGACY_EVAL_VERIFY=${admpc_legacy_eval_verify} -e ZMQ_AUTH_MODE=${ZMQ_AUTH_MODE:-null} -e ZMQ_CURVE_READY_TIMEOUT=${ZMQ_CURVE_READY_TIMEOUT:-60} -e SHUFFLE_K=${shuffle_k} -e SHUFFLE_MODE=${shuffle_mode} -e SHUFFLE_ACK_TIMEOUT=${shuffle_ack_timeout} -e SHUFFLE_ACK_THRESHOLD=${shuffle_ack_threshold} -e ADMPC_SHUFFLE_RUN_ID=${admpc_shuffle_run_id} -e FAULT_ACCUMULATION_MODE=${fault_accumulation_mode} -e FAULT_ACCUMULATION_COUNT=${fault_accumulation_count} -e FAULT_ACCUMULATION_START_EPOCH=${fault_accumulation_start_epoch} -e FAULT_MODE=${fault_mode} -e FAULT_TARGET=${fault_target} -e FAULT_COMPUTATION_EPOCH=${fault_computation_epoch} -e FAULT_DELAY_SOURCE_EPOCH=${fault_delay_source_epoch} -e FAULT_ADTRANS_SOURCE_EPOCH=${fault_adtrans_source_epoch} -e FAULT_DELTA_MS=${fault_delta_ms} -e FAULT_ATTACK_INDEX=${fault_attack_index} htadkg_adkg \
                    /opt/venv/admpc/bin/python3 -u -m $run_mod -d -f $json_dir/local.${file_num}.json -time $START_TIME; \
                else \
                    echo 'Neither docker-compose nor docker compose is available on this node.' >&2; \
                    exit 127; \
                fi" \
                > "logs/node${i}_cont${j}.log" 2>&1 &
            pids+=("$!")
            sleep "$delay_between_ssh_commands"
        done
    done
fi

# waiting SSH commands to finish
job_failed=0
for job in "${pids[@]}"; do
    if ! wait "$job"; then
        job_failed=1
    fi
done

if [ "$job_failed" -ne 0 ]; then
    echo "One or more remote runs failed. Check logs/ for details." >&2
    exit 1
fi

if [[ "$metrics_enabled" =~ ^(1|true|yes|on)$ ]]; then
    local_metrics_dir="logs/protocol-overhead/${metrics_run_id}"
    mkdir -p "$local_metrics_dir"
    for i in $(seq 1 "$NODE_NUM"); do
        ssh_user_host="${NODE_SSH_USERNAME}@${NODE_IPS[$i - 1]}"
        # The production container writes mode-0600 files into the bind mount.
        # Make this run's metrics readable by the SSH collection user.
        ssh "${SSH_OPTIONS[@]}" "$ssh_user_host" \
            "sudo chmod a+r ${remote_metrics_dir}/communication-*.json"
        scp "${SSH_OPTIONS[@]}" "${ssh_user_host}:${remote_metrics_dir}/communication-*.json" \
            "$local_metrics_dir/"
    done
fi
