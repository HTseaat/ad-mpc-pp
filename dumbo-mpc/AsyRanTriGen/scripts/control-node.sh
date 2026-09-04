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

# Compute how many containers per node: layer_offset
containers_per_node=$(( layer_offset ))

# Determine which run module to invoke
case "$protocol" in
    admpc2)
        run_mod="scripts.admpc2_dynamic_run"
        ;;
    admpc2-linear)
        run_mod="scripts.admpc2_dynamic_linear_run"
        ;;
    admpc2-nonlinear)
        run_mod="scripts.admpc2_dynamic_nonlinear_run"
        ;;
    admpc2-bgw-aggtrans)
        run_mod="scripts.admpc2_dynamic_bgw_aggtrans_run"
        ;;
    admpc2-shuffle)
        run_mod="scripts.admpc2_dynamic_shuffle_run"
        ;;
    admpc2-shuffle-bgw-static)
        run_mod="scripts.admpc2_dynamic_shuffle_bgw_static_run"
        ;;
    admpc2-dumbo-shuffle-beaver)
        run_mod="scripts.admpc2_dynamic_dumbo_shuffle_beaver_run"
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
status_dir="logs/.control-node-status.$$"
mkdir -p "$status_dir"

cleanup_status_dir() {
    if [[ -d "$status_dir" ]]; then
        find "$status_dir" -maxdepth 1 -type f -delete
        rmdir "$status_dir" 2>/dev/null || true
    fi
}
trap cleanup_status_dir EXIT

source -- ./common.sh
ensure_script_dir


source -- ./config.sh

SSH_OPTIONS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes)
if [[ -n "${SSH_IDENTITY_FILE:-}" ]]; then
    if [[ ! -r "$SSH_IDENTITY_FILE" ]]; then
        echo "SSH identity file is not readable: $SSH_IDENTITY_FILE" >&2
        exit 1
    fi
    SSH_OPTIONS+=(-i "$SSH_IDENTITY_FILE" -o IdentitiesOnly=yes)
fi

REMOTE_WORKSPACE_DIR="${REMOTE_WORKSPACE_DIR:-}"
if [ -n "$REMOTE_WORKSPACE_DIR" ]; then
    REMOTE_ROOT="~/${REMOTE_WORKSPACE_DIR}"
else
    REMOTE_ROOT="~"
fi

metrics_enabled="${PROTOCOL_OVERHEAD_METRICS:-0}"
metrics_run_id="${PROTOCOL_OVERHEAD_RUN_ID:-$conf_dir}"
metrics_barrier_timeout="${PROTOCOL_OVERHEAD_BARRIER_TIMEOUT_SECONDS:-300}"
remote_log_filter="${REMOTE_LOG_FILTER:-0}"
# REMOTE_LOG_FILTER is intended for large distributed runs where forwarding
# every protocol/debug line (and every benign asyncio shutdown traceback) can
# dominate controller I/O.  Keep benchmark milestones and actionable failures;
# deliberately do not match generic ERROR/WARNING/Traceback lines because the
# processes emit thousands of harmless pending-task warnings during teardown.
remote_log_pattern='FAULT_EVENT|FAULT_ACCUM_EVENT|FIGURE10_PROGRESS_EVENT|ADMPC start time|ZeroMQ auth mode|CURVE channel ready|CURVE authentication failures|layer ID: [0-9]+ .*(_time:| length:|received all shares)|my_send_id: .* exec_time:|Finished|UnpicklingError|ConnectionRefusedError|MemoryError|AssertionError|TimeoutError|ValueError|KeyError|OSError|invalid load key|address already in use|Connection refused|No route to host|timed out|timeout|Killed|Out of memory'
if [[ "$remote_log_filter" != "0" && "$remote_log_filter" != "1" ]]; then
    echo "REMOTE_LOG_FILTER must be 0 or 1" >&2
    exit 1
fi
if [[ "$metrics_enabled" =~ ^(1|true|yes|on)$ ]] && \
   [[ ! "$metrics_run_id" =~ ^[A-Za-z0-9_.-]+$ ]]; then
    echo "Unsafe PROTOCOL_OVERHEAD_RUN_ID: $metrics_run_id" >&2
    exit 1
fi
if [[ "$metrics_enabled" =~ ^(1|true|yes|on)$ ]] && \
   [[ ! "$metrics_barrier_timeout" =~ ^[1-9][0-9]*$ ]]; then
    echo "PROTOCOL_OVERHEAD_BARRIER_TIMEOUT_SECONDS must be a positive integer" >&2
    exit 1
fi
container_metrics_dir="/opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/log/protocol-overhead/${metrics_run_id}"
remote_metrics_dir="${REMOTE_ROOT}/dumbo-mpc/dumbo-mpc/AsyRanTriGen/log/protocol-overhead/${metrics_run_id}"

fault_mode="${FAULT_MODE:-none}"
fault_target="${FAULT_TARGET:-}"
fault_computation_epoch="${FAULT_COMPUTATION_EPOCH:-}"
fault_batchmul_epoch="${FAULT_BATCHMUL_EPOCH:-}"
fault_delay_source_epoch="${FAULT_DELAY_SOURCE_EPOCH:-}"
fault_aggtrans_source_epoch="${FAULT_AGGTRANS_SOURCE_EPOCH:-}"
fault_batchmul_source_epoch="${FAULT_BATCHMUL_SOURCE_EPOCH:-}"
fault_delta_ms="${FAULT_DELTA_MS:-}"
fault_attack_index="${FAULT_ATTACK_INDEX:-}"

case "$fault_mode" in
    none|delay|byzantine|figure10-attack) ;;
    *)
        echo "Unsafe FAULT_MODE: $fault_mode" >&2
        exit 1
        ;;
esac
case "$fault_target" in
    ""|handoff|aggtrans|batchmul|aggtrans+batchmul|handoff+aggtrans+batchmul) ;;
    *)
        echo "Unsafe FAULT_TARGET: $fault_target" >&2
        exit 1
        ;;
esac
for fault_integer in \
    "$fault_computation_epoch" "$fault_batchmul_epoch" \
    "$fault_delay_source_epoch" "$fault_aggtrans_source_epoch" \
    "$fault_batchmul_source_epoch" \
    "$fault_delta_ms" "$fault_attack_index"; do
    if [[ -n "$fault_integer" && ! "$fault_integer" =~ ^[0-9]+$ ]]; then
        echo "Fault epoch, delay, and attack index values must be non-negative integers" >&2
        exit 1
    fi
done
if [[ "$fault_mode" == "figure10-attack" ]]; then
    if [[ "$fault_target" != "handoff+aggtrans+batchmul" ]] || \
       [[ -n "$fault_computation_epoch" || -n "$fault_batchmul_epoch" ]] || \
       ! [[ "$fault_delay_source_epoch" =~ ^[1-9][0-9]*$ ]] || \
       ! [[ "$fault_aggtrans_source_epoch" =~ ^[1-9][0-9]*$ ]] || \
       ! [[ "$fault_batchmul_source_epoch" =~ ^[1-9][0-9]*$ ]] || \
       [[ "$fault_delta_ms" != "10000" ]] || \
       ! [[ "$fault_attack_index" =~ ^[0-9]+$ ]] || \
       (( fault_delay_source_epoch != 3 )) || \
       (( fault_aggtrans_source_epoch != 4 )) || \
       (( fault_batchmul_source_epoch != 5 )); then
        echo "Continuum Figure 10 attack requires source epochs 3/4/5, delay 10000 ms, and a non-negative attack index" >&2
        exit 1
    fi
fi


base_port=7000  # setting basic port, e.g. 7000
delay_between_ssh_commands="${CONTROL_NODE_SSH_DELAY:-0}"

maybe_sleep_between_launches() {
    if [ "$delay_between_ssh_commands" != "0" ] && [ "$delay_between_ssh_commands" != "0.0" ]; then
        sleep "$delay_between_ssh_commands"
    fi
}

if [ "$protocol" = "hbmpc" ] || [ "$protocol" = "hbmpc_attack" ]; then
    # Single loop for hbmpc: one container per node
    for i in $(seq 1 $NODE_NUM); do
        external_port=$((base_port + 1))
        ssh_user_host="${NODE_SSH_USERNAME}@${NODE_IPS[$i - 1]}"
        file_num=$((i - 1))
        (
        set +e
        ssh "${SSH_OPTIONS[@]}" -T "$ssh_user_host" \
            "set -eo pipefail; cd ${REMOTE_ROOT}/admpc; \
            if command -v docker-compose >/dev/null 2>&1; then \
                MPC_IMAGE='${MPC_IMAGE:-}' timeout --signal=TERM --kill-after=30s ${RUN_TIMEOUT}s docker-compose -f '${MPC_COMPOSE_FILE:-docker-compose.aws.yml}' run --rm -p $external_port:$external_port -e PROTOCOL_OVERHEAD_METRICS=${metrics_enabled} -e PROTOCOL_OVERHEAD_OUTPUT_DIR=${container_metrics_dir} -e PROTOCOL_OVERHEAD_RUN_ID=${metrics_run_id} -e ZMQ_AUTH_MODE=${ZMQ_AUTH_MODE:-null} -e ZMQ_CURVE_READY_TIMEOUT=${ZMQ_CURVE_READY_TIMEOUT:-60} htadkg_adkg \
                python3 -u -m $run_mod -d -f $json_dir/local.${file_num}.json -time $START_TIME; \
            elif docker compose version >/dev/null 2>&1; then \
                MPC_IMAGE='${MPC_IMAGE:-}' timeout --signal=TERM --kill-after=30s ${RUN_TIMEOUT}s docker compose -f '${MPC_COMPOSE_FILE:-docker-compose.aws.yml}' run --rm -p $external_port:$external_port -e PROTOCOL_OVERHEAD_METRICS=${metrics_enabled} -e PROTOCOL_OVERHEAD_OUTPUT_DIR=${container_metrics_dir} -e PROTOCOL_OVERHEAD_RUN_ID=${metrics_run_id} -e ZMQ_AUTH_MODE=${ZMQ_AUTH_MODE:-null} -e ZMQ_CURVE_READY_TIMEOUT=${ZMQ_CURVE_READY_TIMEOUT:-60} htadkg_adkg \
                python3 -u -m $run_mod -d -f $json_dir/local.${file_num}.json -time $START_TIME; \
            else \
                echo 'Neither docker-compose nor docker compose is available on this node.' >&2; \
                exit 127; \
            fi" \
            > "logs/node${i}.log" 2>&1
        rc=$?
        printf '%s\n' "$rc" > "$status_dir/node${i}.status"
        exit "$rc"
        ) &
        maybe_sleep_between_launches
    done
else
    # Two-layer loops for admpc and fluid
    for j in $(seq 1 $containers_per_node); do
        for i in $(seq 1 $NODE_NUM); do
            external_port=$((base_port + j))
            ssh_user_host="${NODE_SSH_USERNAME}@${NODE_IPS[$i - 1]}"
            file_num=$(((j - 1) * NODE_NUM + i - 1))
            # ssh -T "$ssh_user_host" \
            #     "cd ~/dumbo-mpc && docker-compose run -p $external_port:$external_port dumbo-mpc \
            #     python -u -m $run_mod -d -f $json_dir/local.${file_num}.json -time $TIMEOUT" \
            #     > "logs/node${i}_cont${j}.log" 2>&1 &
            # ssh -T "$ssh_user_host" \
            #     "cd ~/dumbo-mpc && docker-compose run -p $external_port:$external_port dumbo-mpc \
            #     python -u dumbo-mpc/AsyRanTriGen/scripts/admpc2_dynamic_run.py \
            #         -d -f dumbo-mpc/AsyRanTriGen/conf/$conf_dir/local.${file_num}.json -time $TIMEOUT" \
            #     > "logs/node${i}_cont${j}.log" 2>&1 &
            (
            set +e
            ssh "${SSH_OPTIONS[@]}" -T "$ssh_user_host" \
                "set -eo pipefail; cd ${REMOTE_ROOT}/dumbo-mpc; \
                if command -v docker-compose >/dev/null 2>&1; then \
                    MPC_IMAGE='${MPC_IMAGE:-}' timeout --signal=TERM --kill-after=30s ${RUN_TIMEOUT}s docker-compose -f '${MPC_COMPOSE_FILE:-docker-compose.aws.yml}' run --rm -p $external_port:$external_port \
                    -e PROTOCOL_OVERHEAD_METRICS=${metrics_enabled} \
                    -e PROTOCOL_OVERHEAD_OUTPUT_DIR=${container_metrics_dir} \
                    -e PROTOCOL_OVERHEAD_RUN_ID=${metrics_run_id} \
                    -e PROTOCOL_OVERHEAD_BARRIER_TIMEOUT_SECONDS=${metrics_barrier_timeout} \
                    -e CIRCUIT_WIDTH=${CIRCUIT_WIDTH:-100} \
                    -e DISABLE_RLC=${DISABLE_RLC:-} \
                    -e DISABLE_AGG_PROTO=${DISABLE_AGG_PROTO:-} \
                    -e AGG_KZG_V2=${AGG_KZG_V2:-1} \
                    -e BGW_UNBATCHED_VERIFY=${BGW_UNBATCHED_VERIFY:-} \
                    -e BGW_UNBATCHED_BATCH_ALL_VERIFY=${BGW_UNBATCHED_BATCH_ALL_VERIFY:-} \
                    -e BGW_UNBATCHED_BATCH_SHARE_VERIFY=${BGW_UNBATCHED_BATCH_SHARE_VERIFY:-} \
                    -e BGW_UNBATCHED_BATCH_HIDDEN_VERIFY=${BGW_UNBATCHED_BATCH_HIDDEN_VERIFY:-} \
                    -e BGW_UNBATCHED_BATCH_ZERO_VERIFY=${BGW_UNBATCHED_BATCH_ZERO_VERIFY:-} \
                    -e BGW_UNBATCHED_BATCH_PROD_VERIFY=${BGW_UNBATCHED_BATCH_PROD_VERIFY:-} \
                    -e BGW_BATCH_UNBATCHED_PROD_VERIFY=${BGW_BATCH_UNBATCHED_PROD_VERIFY:-} \
                    -e SHUFFLE_MODE=${SHUFFLE_MODE:-} \
                    -e SHUFFLE_HANDOFF_INTERVAL=${SHUFFLE_HANDOFF_INTERVAL:-} \
                    -e SHUFFLE_HANDOFF_GRACE_SECONDS=${SHUFFLE_HANDOFF_GRACE_SECONDS:-} \
                    -e ZMQ_AUTH_MODE=${ZMQ_AUTH_MODE:-null} \
                    -e ZMQ_CURVE_READY_TIMEOUT=${ZMQ_CURVE_READY_TIMEOUT:-60} \
                    -e COMMITTEE_ELECTION_MODE=${COMMITTEE_ELECTION_MODE:-off} \
                    -e COMMITTEE_ELECTION_CANDIDATES=${COMMITTEE_ELECTION_CANDIDATES:-4} \
                    -e COMMITTEE_ELECTION_TIMEOUT_SECONDS=${COMMITTEE_ELECTION_TIMEOUT_SECONDS:-30} \
                    -e FAULT_ACCUMULATION_MODE=${FAULT_ACCUMULATION_MODE:-none} \
                    -e FAULT_ACCUMULATION_COUNT=${FAULT_ACCUMULATION_COUNT:-} \
                    -e FAULT_ACCUMULATION_START_EPOCH=${FAULT_ACCUMULATION_START_EPOCH:-} \
                    -e FAULT_MODE=${fault_mode} \
                    -e FAULT_TARGET=${fault_target} \
                    -e FAULT_COMPUTATION_EPOCH=${fault_computation_epoch} \
                    -e FAULT_BATCHMUL_EPOCH=${fault_batchmul_epoch} \
                    -e FAULT_DELAY_SOURCE_EPOCH=${fault_delay_source_epoch} \
                    -e FAULT_AGGTRANS_SOURCE_EPOCH=${fault_aggtrans_source_epoch} \
                    -e FAULT_BATCHMUL_SOURCE_EPOCH=${fault_batchmul_source_epoch} \
                    -e FAULT_DELTA_MS=${fault_delta_ms} \
                    -e FAULT_ATTACK_INDEX=${fault_attack_index} \
                    -w /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen \
                    dumbo-mpc \
                    /opt/venv/continuum/bin/python3 -u -m $run_mod -d -f $json_dir/local.${file_num}.json --time $START_TIME 2>&1 | \
                    if [ '${remote_log_filter}' = '1' ]; then \
                        grep --line-buffered -E '${remote_log_pattern}'; \
                    else \
                        cat; \
                    fi; \
                elif docker compose version >/dev/null 2>&1; then \
                    MPC_IMAGE='${MPC_IMAGE:-}' timeout --signal=TERM --kill-after=30s ${RUN_TIMEOUT}s docker compose -f '${MPC_COMPOSE_FILE:-docker-compose.aws.yml}' run --rm -p $external_port:$external_port \
                    -e PROTOCOL_OVERHEAD_METRICS=${metrics_enabled} \
                    -e PROTOCOL_OVERHEAD_OUTPUT_DIR=${container_metrics_dir} \
                    -e PROTOCOL_OVERHEAD_RUN_ID=${metrics_run_id} \
                    -e PROTOCOL_OVERHEAD_BARRIER_TIMEOUT_SECONDS=${metrics_barrier_timeout} \
                    -e CIRCUIT_WIDTH=${CIRCUIT_WIDTH:-100} \
                    -e DISABLE_RLC=${DISABLE_RLC:-} \
                    -e DISABLE_AGG_PROTO=${DISABLE_AGG_PROTO:-} \
                    -e AGG_KZG_V2=${AGG_KZG_V2:-1} \
                    -e BGW_UNBATCHED_VERIFY=${BGW_UNBATCHED_VERIFY:-} \
                    -e BGW_UNBATCHED_BATCH_ALL_VERIFY=${BGW_UNBATCHED_BATCH_ALL_VERIFY:-} \
                    -e BGW_UNBATCHED_BATCH_SHARE_VERIFY=${BGW_UNBATCHED_BATCH_SHARE_VERIFY:-} \
                    -e BGW_UNBATCHED_BATCH_HIDDEN_VERIFY=${BGW_UNBATCHED_BATCH_HIDDEN_VERIFY:-} \
                    -e BGW_UNBATCHED_BATCH_ZERO_VERIFY=${BGW_UNBATCHED_BATCH_ZERO_VERIFY:-} \
                    -e BGW_UNBATCHED_BATCH_PROD_VERIFY=${BGW_UNBATCHED_BATCH_PROD_VERIFY:-} \
                    -e BGW_BATCH_UNBATCHED_PROD_VERIFY=${BGW_BATCH_UNBATCHED_PROD_VERIFY:-} \
                    -e SHUFFLE_MODE=${SHUFFLE_MODE:-} \
                    -e SHUFFLE_HANDOFF_INTERVAL=${SHUFFLE_HANDOFF_INTERVAL:-} \
                    -e SHUFFLE_HANDOFF_GRACE_SECONDS=${SHUFFLE_HANDOFF_GRACE_SECONDS:-} \
                    -e ZMQ_AUTH_MODE=${ZMQ_AUTH_MODE:-null} \
                    -e ZMQ_CURVE_READY_TIMEOUT=${ZMQ_CURVE_READY_TIMEOUT:-60} \
                    -e COMMITTEE_ELECTION_MODE=${COMMITTEE_ELECTION_MODE:-off} \
                    -e COMMITTEE_ELECTION_CANDIDATES=${COMMITTEE_ELECTION_CANDIDATES:-4} \
                    -e COMMITTEE_ELECTION_TIMEOUT_SECONDS=${COMMITTEE_ELECTION_TIMEOUT_SECONDS:-30} \
                    -e FAULT_ACCUMULATION_MODE=${FAULT_ACCUMULATION_MODE:-none} \
                    -e FAULT_ACCUMULATION_COUNT=${FAULT_ACCUMULATION_COUNT:-} \
                    -e FAULT_ACCUMULATION_START_EPOCH=${FAULT_ACCUMULATION_START_EPOCH:-} \
                    -e FAULT_MODE=${fault_mode} \
                    -e FAULT_TARGET=${fault_target} \
                    -e FAULT_COMPUTATION_EPOCH=${fault_computation_epoch} \
                    -e FAULT_BATCHMUL_EPOCH=${fault_batchmul_epoch} \
                    -e FAULT_DELAY_SOURCE_EPOCH=${fault_delay_source_epoch} \
                    -e FAULT_AGGTRANS_SOURCE_EPOCH=${fault_aggtrans_source_epoch} \
                    -e FAULT_BATCHMUL_SOURCE_EPOCH=${fault_batchmul_source_epoch} \
                    -e FAULT_DELTA_MS=${fault_delta_ms} \
                    -e FAULT_ATTACK_INDEX=${fault_attack_index} \
                    -w /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen \
                    dumbo-mpc \
                    /opt/venv/continuum/bin/python3 -u -m $run_mod -d -f $json_dir/local.${file_num}.json --time $START_TIME 2>&1 | \
                    if [ '${remote_log_filter}' = '1' ]; then \
                        grep --line-buffered -E '${remote_log_pattern}'; \
                    else \
                        cat; \
                    fi; \
                else \
                    echo 'Neither docker-compose nor docker compose is available on this node.' >&2; \
                    exit 127; \
                fi" \
                > "logs/node${i}_cont${j}.log" 2>&1
            rc=$?
            printf '%s\n' "$rc" > "$status_dir/node${i}_cont${j}.status"
            exit "$rc"
            ) &
            maybe_sleep_between_launches
        done
    done
fi

# waiting SSH commands to finish
wait
job_failed=0
expected_jobs=$((NODE_NUM * containers_per_node))
if [[ "$protocol" = "hbmpc" || "$protocol" = "hbmpc_attack" ]]; then
    expected_jobs=$NODE_NUM
fi
status_count=$(find "$status_dir" -maxdepth 1 -type f -name '*.status' | wc -l)
if [[ "$status_count" -ne "$expected_jobs" ]]; then
    echo "Expected $expected_jobs remote statuses, found $status_count." >&2
    job_failed=1
fi
while IFS= read -r status_file; do
    if [[ "$(<"$status_file")" -ne 0 ]]; then
        job_failed=1
    fi
done < <(find "$status_dir" -maxdepth 1 -type f -name '*.status' -print)

if [[ "$metrics_enabled" =~ ^(1|true|yes|on)$ ]]; then
    local_metrics_dir="logs/protocol-overhead/${metrics_run_id}"
    mkdir -p "$local_metrics_dir"
    for i in $(seq 1 "$NODE_NUM"); do
        ssh_user_host="${NODE_SSH_USERNAME}@${NODE_IPS[$i - 1]}"
        # The production container runs as root and creates mode-0600 metric
        # artifacts in the bind-mounted host directory. Make this run's JSON
        # readable by the SSH collection user before copying it back.
        if ssh "$ssh_user_host" \
            "set -- ${remote_metrics_dir}/communication-*.json; \
             [ -e \"\$1\" ] || exit 3; sudo chmod a+r \"\$@\""; then
            if ! scp \
                "${ssh_user_host}:${remote_metrics_dir}/communication-*.json" \
                "$local_metrics_dir/"; then
                echo "Warning: failed to collect metrics from ${ssh_user_host}" >&2
            fi
        else
            echo "Warning: no readable metrics checkpoint on ${ssh_user_host}" >&2
        fi
    done
    collected_metrics=$(find "$local_metrics_dir" -maxdepth 1 -type f \
        -name 'communication-*.json' | wc -l)
    {
        echo "run_id=${metrics_run_id}"
        echo "expected_processes=${expected_jobs}"
        echo "collected_processes=${collected_metrics}"
        echo "complete=$([[ "$collected_metrics" -eq "$expected_jobs" ]] && echo 1 || echo 0)"
    } > "${local_metrics_dir}/collection-status.env"
    echo "Collected ${collected_metrics}/${expected_jobs} protocol-overhead artifacts."
fi

if [ "$job_failed" -ne 0 ]; then
    echo "One or more remote runs failed. Partial metrics were retained when available." >&2
    exit 1
fi
