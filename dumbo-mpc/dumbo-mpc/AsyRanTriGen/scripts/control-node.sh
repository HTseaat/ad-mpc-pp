#!/usr/bin/env bash

set -euo pipefail

# Read config directory
if [ $# -lt 1 ]; then
    echo "Usage: $0 <config_dir> [protocol] [timeout]"
    exit 1
fi
conf_dir=$1

# Optional protocol override (non-numeric second arg)
if [[ $# -ge 2 && ! "$2" =~ ^[0-9] ]]; then
    protocol_override="$2"
    TIMEOUT=${3:-12}
else
    protocol_override=""
    TIMEOUT=${2:-12}
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

source -- ./common.sh
ensure_script_dir


source -- ./config.sh

REMOTE_WORKSPACE_DIR="${REMOTE_WORKSPACE_DIR:-}"
if [ -n "$REMOTE_WORKSPACE_DIR" ]; then
    REMOTE_ROOT="~/${REMOTE_WORKSPACE_DIR}"
else
    REMOTE_ROOT="~"
fi


base_port=7000  # setting basic port, e.g. 7000
delay_between_ssh_commands=0.1

if [ "$protocol" = "hbmpc" ] || [ "$protocol" = "hbmpc_attack" ]; then
    # Single loop for hbmpc: one container per node
    for i in $(seq 1 $NODE_NUM); do
        external_port=$((base_port + 1))
        ssh_user_host="${NODE_SSH_USERNAME}@${NODE_IPS[$i - 1]}"
        file_num=$((i - 1))
        ssh -T "$ssh_user_host" \
            "set -e; cd ${REMOTE_ROOT}/admpc; \
            if command -v docker-compose >/dev/null 2>&1; then \
                MPC_IMAGE='${MPC_IMAGE:-}' docker-compose run -p $external_port:$external_port htadkg_adkg \
                python3 -u -m $run_mod -d -f $json_dir/local.${file_num}.json -time $TIMEOUT; \
            elif docker compose version >/dev/null 2>&1; then \
                MPC_IMAGE='${MPC_IMAGE:-}' docker compose run -p $external_port:$external_port htadkg_adkg \
                python3 -u -m $run_mod -d -f $json_dir/local.${file_num}.json -time $TIMEOUT; \
            else \
                echo 'Neither docker-compose nor docker compose is available on this node.' >&2; \
                exit 127; \
            fi" \
            > "logs/node${i}.log" 2>&1 &
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
            ssh -T "$ssh_user_host" \
                "set -e; cd ${REMOTE_ROOT}/dumbo-mpc; \
                if command -v docker-compose >/dev/null 2>&1; then \
                    MPC_IMAGE='${MPC_IMAGE:-}' docker-compose run -p $external_port:$external_port \
                    -w /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen \
                    dumbo-mpc \
                    /opt/venv/continuum/bin/python3 -u -m $run_mod -d -f $json_dir/local.${file_num}.json --time $TIMEOUT; \
                elif docker compose version >/dev/null 2>&1; then \
                    MPC_IMAGE='${MPC_IMAGE:-}' docker compose run -p $external_port:$external_port \
                    -w /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen \
                    dumbo-mpc \
                    /opt/venv/continuum/bin/python3 -u -m $run_mod -d -f $json_dir/local.${file_num}.json --time $TIMEOUT; \
                else \
                    echo 'Neither docker-compose nor docker compose is available on this node.' >&2; \
                    exit 127; \
                fi" \
                > "logs/node${i}_cont${j}.log" 2>&1 &
        done
    done
fi

# waiting SSH commands to finish
job_failed=0
for job in $(jobs -p); do
    if ! wait "$job"; then
        job_failed=1
    fi
done

if [ "$job_failed" -ne 0 ]; then
    echo "One or more remote runs failed. Check logs/ for details." >&2
    exit 1
fi
