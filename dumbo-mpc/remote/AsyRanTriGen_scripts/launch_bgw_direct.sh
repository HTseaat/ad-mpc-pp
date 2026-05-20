#!/bin/bash
# Usage: ./launch_bgw_direct.sh <N_nodes> <batch_size> [layers] [full|drop-epoch4]
# Launch Dumbo-BGW direct multiplication evaluation across servers.

set -uo pipefail

if [ $# -lt 2 ]; then
  echo "Usage: $0 <N_nodes> <batch_size> [layers] [full|drop-epoch4]" >&2
  exit 1
fi

NODES_NUM="$1"
BATCH_SIZE="$2"
LAYERS="${3:-10}"
DUMBO_MODE="${4:-full}"

case "$DUMBO_MODE" in
  full|drop-epoch4) ;;
  *)
    echo "[ERROR] Invalid dumbo mode: ${DUMBO_MODE}. Expected full|drop-epoch4" >&2
    exit 1
    ;;
esac

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

source -- ../config.sh

REMOTE_WORKSPACE_DIR="${REMOTE_WORKSPACE_DIR:-}"
if [[ -n "$REMOTE_WORKSPACE_DIR" ]]; then
  REMOTE_ROOT="~/${REMOTE_WORKSPACE_DIR}"
else
  REMOTE_ROOT="~"
fi

IP_FILE="../ip.txt"
IPS_LIST=()
if [[ -f "$IP_FILE" && -s "$IP_FILE" ]]; then
    mapfile -t IPS_LIST < <(sed -e 's/\r$//' -e '/^\s*#/d' -e '/^\s*$/d' "$IP_FILE")
else
  IPS_LIST=("${NODE_IPS[@]}")
fi

echo "[DEBUG] bgw-direct NODES_NUM=${NODES_NUM}"
echo "[DEBUG] bgw-direct BATCH_SIZE=${BATCH_SIZE}"
echo "[DEBUG] bgw-direct LAYERS=${LAYERS}"
echo "[DEBUG] bgw-direct DUMBO_MODE=${DUMBO_MODE}"
echo "[DEBUG] IP count=${#IPS_LIST[@]}"
echo "[DEBUG] IP list: ${IPS_LIST[*]}"

mkdir -p logs

PIDS=()
terminate_children() {
  echo "[INTERRUPT] Stopping ${#PIDS[@]} background launch jobs..." >&2
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  exit 130
}
trap terminate_children INT TERM

if [[ ${#IPS_LIST[@]} -eq 0 ]]; then
  echo "[ERROR] No available IPs. Configure ../config.sh or ../ip.txt." >&2
  exit 1
fi

if [[ ${#IPS_LIST[@]} -lt $NODES_NUM ]]; then
  echo "[WARN] Available IP count (${#IPS_LIST[@]}) is less than NODES_NUM (${NODES_NUM}); launching first ${#IPS_LIST[@]} nodes." >&2
  NODES_NUM=${#IPS_LIST[@]}
fi

id=0
for (( idx=0; idx< NODES_NUM; idx++ )); do
    ip="${IPS_LIST[$idx]}"
    ssh_user_host="${NODE_SSH_USERNAME}@${ip}"

    (
        peer_port=7001
        echo "[DEBUG] Node ID ${id} will use peer_port=${peer_port}"
        ssh -n -T -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 "$ssh_user_host" \
    "set -e; cd ${REMOTE_ROOT}/dumbo-mpc && \
        if command -v docker-compose >/dev/null 2>&1; then \
          MPC_IMAGE='${MPC_IMAGE:-}' docker-compose run --rm -p ${peer_port}:${peer_port} \
            -e BGW_UNBATCHED_VERIFY=${BGW_UNBATCHED_VERIFY:-} \
            -e BGW_UNBATCHED_BATCH_ALL_VERIFY=${BGW_UNBATCHED_BATCH_ALL_VERIFY:-} \
            -e BGW_UNBATCHED_BATCH_SHARE_VERIFY=${BGW_UNBATCHED_BATCH_SHARE_VERIFY:-} \
            -e BGW_UNBATCHED_BATCH_HIDDEN_VERIFY=${BGW_UNBATCHED_BATCH_HIDDEN_VERIFY:-} \
            -e BGW_UNBATCHED_BATCH_ZERO_VERIFY=${BGW_UNBATCHED_BATCH_ZERO_VERIFY:-} \
            -e BGW_UNBATCHED_BATCH_PROD_VERIFY=${BGW_UNBATCHED_BATCH_PROD_VERIFY:-} \
            -e BGW_BATCH_UNBATCHED_PROD_VERIFY=${BGW_BATCH_UNBATCHED_PROD_VERIFY:-} \
            -w /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen \
            dumbo-mpc \
            bash -lc 'PY_EXEC=/opt/venv/continuum/bin/python3; \
                      if [ ! -x \"\$PY_EXEC\" ]; then echo \"Missing continuum python: \$PY_EXEC\" >&2; exit 127; fi; \
                      \"\$PY_EXEC\" scripts/init_batchsize_layer_ip.py --N $NODES_NUM --k $BATCH_SIZE --layers $LAYERS --dumbo_mode $DUMBO_MODE && \
                      \"\$PY_EXEC\" -u -m scripts.run_dumbo_bgw_direct -d -f conf/mpc_$NODES_NUM/local.${id}.json -time 0'; \
        elif docker compose version >/dev/null 2>&1; then \
          MPC_IMAGE='${MPC_IMAGE:-}' docker compose run --rm -p ${peer_port}:${peer_port} \
            -e BGW_UNBATCHED_VERIFY=${BGW_UNBATCHED_VERIFY:-} \
            -e BGW_UNBATCHED_BATCH_ALL_VERIFY=${BGW_UNBATCHED_BATCH_ALL_VERIFY:-} \
            -e BGW_UNBATCHED_BATCH_SHARE_VERIFY=${BGW_UNBATCHED_BATCH_SHARE_VERIFY:-} \
            -e BGW_UNBATCHED_BATCH_HIDDEN_VERIFY=${BGW_UNBATCHED_BATCH_HIDDEN_VERIFY:-} \
            -e BGW_UNBATCHED_BATCH_ZERO_VERIFY=${BGW_UNBATCHED_BATCH_ZERO_VERIFY:-} \
            -e BGW_UNBATCHED_BATCH_PROD_VERIFY=${BGW_UNBATCHED_BATCH_PROD_VERIFY:-} \
            -e BGW_BATCH_UNBATCHED_PROD_VERIFY=${BGW_BATCH_UNBATCHED_PROD_VERIFY:-} \
            -w /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen \
            dumbo-mpc \
            bash -lc 'PY_EXEC=/opt/venv/continuum/bin/python3; \
                      if [ ! -x \"\$PY_EXEC\" ]; then echo \"Missing continuum python: \$PY_EXEC\" >&2; exit 127; fi; \
                      \"\$PY_EXEC\" scripts/init_batchsize_layer_ip.py --N $NODES_NUM --k $BATCH_SIZE --layers $LAYERS --dumbo_mode $DUMBO_MODE && \
                      \"\$PY_EXEC\" -u -m scripts.run_dumbo_bgw_direct -d -f conf/mpc_$NODES_NUM/local.${id}.json -time 0'; \
        else \
          echo 'Neither docker-compose nor docker compose is available on this node.' >&2; \
          exit 127; \
        fi"
    ) > "logs/node${idx}.log" 2>&1 &
    PIDS+=("$!")
    (( id++ ))
done

wait_rc=0
for pid in "${PIDS[@]}"; do
    wait "$pid" || wait_rc=$?
done

echo "Dumbo-BGW direct launch completed on ${NODES_NUM} nodes."
exit "$wait_rc"
