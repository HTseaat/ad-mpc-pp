#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

usage() {
  cat <<USAGE
Usage: $0 [options]

Run independent real committee elections and add their protocol latencies as
the sequential election overhead for epochs 2..(depth+1).

Options:
  --cluster-env <path>    Cluster env file
  --results-root <path>   Results root (default: /opt/benchmark-distributed)
  --session-dir <path>    Exact output directory (overrides --results-root)
  --n <N>                 Number of election parties (default: 4)
  --t <t>                 Byzantine threshold (default: floor((N-1)/3))
  --depth <d>             Number of consecutive elections (default: 6)
  --base-port <port>      Election port on every server (default: 12000)
  --protocol-timeout <s>  Election share timeout inside the protocol (default: 30)
  --timeout <s>           Hard timeout for each container (default: 90)
  --candidates <K>        Number of predefined candidate committees (default: 4)
  --skip-preflight        Skip the full image/clock preflight
  --setup-ssh-keys        Explicitly install the manager public key first
USAGE
}

RESULTS_ROOT="$RESULTS_ROOT_DEFAULT"
SESSION_DIR_OVERRIDE=""
BASE_PORT=12000
PROTOCOL_TIMEOUT=30
RUN_TIMEOUT=90
CANDIDATES=4
SETUP_SSH_KEYS=0
N=4
T=""
ELECTION_COUNT=6
SKIP_PREFLIGHT=0
CONTINUUM_PYTHON="${CONTINUUM_PYTHON:-/opt/venv/continuum/bin/python3}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cluster-env)
      CLUSTER_ENV="$2"
      export CLUSTER_ENV
      shift 2
      ;;
    --results-root)
      RESULTS_ROOT="$2"
      shift 2
      ;;
    --session-dir)
      SESSION_DIR_OVERRIDE="$2"
      shift 2
      ;;
    --n)
      N="$2"
      shift 2
      ;;
    --t)
      T="$2"
      shift 2
      ;;
    --depth)
      ELECTION_COUNT="$2"
      shift 2
      ;;
    --base-port)
      BASE_PORT="$2"
      shift 2
      ;;
    --protocol-timeout)
      PROTOCOL_TIMEOUT="$2"
      shift 2
      ;;
    --timeout)
      RUN_TIMEOUT="$2"
      shift 2
      ;;
    --candidates)
      CANDIDATES="$2"
      shift 2
      ;;
    --skip-preflight)
      SKIP_PREFLIGHT=1
      shift
      ;;
    --setup-ssh-keys)
      SETUP_SSH_KEYS=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

for value_name in N BASE_PORT RUN_TIMEOUT CANDIDATES ELECTION_COUNT; do
  value="${!value_name}"
  if ! [[ "$value" =~ ^[1-9][0-9]*$ ]]; then
    echo "${value_name} must be a positive integer" >&2
    exit 1
  fi
done
if [[ -z "$T" ]]; then
  T=$(( (N - 1) / 3 ))
fi
if ! [[ "$T" =~ ^[0-9]+$ ]]; then
  echo "T must be a non-negative integer" >&2
  exit 1
fi
if (( N < 3 * T + 1 )); then
  echo "N=${N}, T=${T} violates N >= 3*T+1" >&2
  exit 1
fi
if ! [[ "$PROTOCOL_TIMEOUT" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
  echo "PROTOCOL_TIMEOUT must be a non-negative number" >&2
  exit 1
fi
if (( BASE_PORT < 1024 || BASE_PORT + ELECTION_COUNT - 1 > 65000 )); then
  echo "BASE_PORT is outside the allowed benchmark range" >&2
  exit 1
fi

load_cluster_env
require_immutable_image
select_cluster_ips "$N"
require_tools bash python3 ssh scp tar timeout pkill
if [[ ! -x "$CONTINUUM_PYTHON" ]]; then
  echo "Continuum python not found: ${CONTINUUM_PYTHON}" >&2
  exit 1
fi

if [[ "$SKIP_PREFLIGHT" -eq 0 ]]; then
  if [[ -n "${CLUSTER_ENV:-}" ]]; then
    "${SCRIPT_DIR}/preflight_fig89_n4.sh" --cluster-env "$CLUSTER_ENV" --n "$N"
  else
    "${SCRIPT_DIR}/preflight_fig89_n4.sh" --n "$N"
  fi
fi

if [[ "$SETUP_SSH_KEYS" -eq 1 ]]; then
  "${ASY_SCRIPTS_DIR}/setup_ssh_keys.sh" "$N"
fi

run_tag="$(timestamp_utc)"
session_dir="${SESSION_DIR_OVERRIDE:-${RESULTS_ROOT}/${run_tag}_committee-election_n${N}}"
mkdir -p "$session_dir"

peer_ip_file="${session_dir}/peer_ips.txt"
printf '%s\n' "${SELECTED_PEER_IPS[@]}" > "$peer_ip_file"

SSH_OPTIONS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o BatchMode=yes -o ConnectTimeout=10 -o ConnectionAttempts=1)
if [[ -n "${SSH_IDENTITY_FILE:-}" ]]; then
  if [[ ! -r "$SSH_IDENTITY_FILE" ]]; then
    echo "SSH identity file is not readable: ${SSH_IDENTITY_FILE}" >&2
    exit 1
  fi
  SSH_OPTIONS+=(-i "$SSH_IDENTITY_FILE" -o IdentitiesOnly=yes)
fi

if [[ -n "$REMOTE_WORKSPACE_DIR" ]]; then
  remote_root="~/${REMOTE_WORKSPACE_DIR}"
else
  remote_root="~"
fi

echo "Election session: ${session_dir}"
echo "Image: ${MPC_IMAGE}; compose: ${MPC_COMPOSE_FILE}"
echo "Parameters: N=${N}; t=${T}; depth=${ELECTION_COUNT}; candidates=${CANDIDATES}"

cleanup_succeeded=0
for cleanup_attempt in 1 2 3; do
  if [[ -n "${CLUSTER_ENV:-}" ]]; then
    if CLUSTER_ENV="$CLUSTER_ENV" "${SCRIPT_DIR}/cleanup_remote_ports.sh" \
      --protocol continuum --n "$N"; then
      cleanup_succeeded=1
      break
    fi
  elif "${SCRIPT_DIR}/cleanup_remote_ports.sh" --protocol continuum --n "$N"; then
    cleanup_succeeded=1
    break
  fi
  echo "Transient initial cleanup failure; retrying attempt $((cleanup_attempt + 1))/3" >&2
  sleep 2
done
if [[ "$cleanup_succeeded" -ne 1 ]]; then
  echo "Initial remote cleanup failed after three attempts." >&2
  exit 1
fi

last_epoch=$((ELECTION_COUNT + 1))

# Generate and distribute every independent configuration before the measured
# sequence. This keeps the gap between charged epochs to analysis + container
# startup, rather than key generation and 16-way config distribution.
for charged_epoch in $(seq 2 "$last_epoch"); do
  epoch_dir="${session_dir}/epoch-${charged_epoch}"
  epoch_port=$((BASE_PORT + charged_epoch - 2))
  config_name="committee-election-${run_tag}-e${charged_epoch}"
  config_dir="${ASY_DIR}/conf/${config_name}"
  mkdir -p "$epoch_dir"

  if [[ -s "${epoch_dir}/summary.json" ]]; then
    continue
  fi

  echo "[setup] generating config charged to epoch ${charged_epoch}"
  if [[ -n "${CLUSTER_ENV:-}" ]]; then
    CLUSTER_ENV="$CLUSTER_ENV" "${SCRIPT_DIR}/generate_committee_election_config_remote.sh" \
      "$config_name" "$N" "$T" "$CANDIDATES" "$epoch_port"
  else
    "${SCRIPT_DIR}/generate_committee_election_config_remote.sh" \
      "$config_name" "$N" "$T" "$CANDIDATES" "$epoch_port"
  fi

  "$CONTINUUM_PYTHON" "${SCRIPT_DIR}/validate_mpc_config.py" \
    --config-dir "$config_dir" --n "$N" --layers 1 \
    --ip-file "$peer_ip_file" --base-port "$epoch_port" \
    --port-layout shared --auth-mode curve

  echo "[setup] distributing config for epoch ${charged_epoch}"
  distribute_pids=()
  for node_id in $(seq 0 "$((N - 1))"); do
    host="${NODE_SSH_USERNAME}@${SELECTED_IPS[$node_id]}"
    (
      scp "${SSH_OPTIONS[@]}" -r "$config_dir" \
        "${host}:${remote_root}/dumbo-mpc/dumbo-mpc/AsyRanTriGen/conf/"
    ) > "${epoch_dir}/distribute-node-${node_id}.log" 2>&1 &
    distribute_pids+=("$!")
  done
  distribute_failed=0
  for pid in "${distribute_pids[@]}"; do
    if ! wait "$pid"; then
      distribute_failed=1
    fi
  done
  if [[ "$distribute_failed" -ne 0 ]]; then
    echo "Config distribution for epoch ${charged_epoch} failed; see ${epoch_dir}/distribute-node-*.log" >&2
    exit 1
  fi
done

echo "[setup] all election configs are ready; starting the low-gap sequence"

for charged_epoch in $(seq 2 "$last_epoch"); do
  epoch_dir="${session_dir}/epoch-${charged_epoch}"
  log_dir="${epoch_dir}/logs"
  epoch_port=$((BASE_PORT + charged_epoch - 2))
  config_name="committee-election-${run_tag}-e${charged_epoch}"
  mkdir -p "$log_dir"

  if [[ -s "${epoch_dir}/summary.json" ]]; then
    echo "[election] reusing completed epoch ${charged_epoch}: ${epoch_dir}/summary.json"
    continue
  fi

  echo "[election] measurement charged to epoch ${charged_epoch} on port ${epoch_port}"
  launch_started_utc="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"

  pids=()
  for node_id in $(seq 0 "$((N - 1))"); do
    host="${NODE_SSH_USERNAME}@${SELECTED_IPS[$node_id]}"
    remote_config="conf/${config_name}/local.${node_id}.json"
    (
    for attempt in 1 2 3; do
      attempt_started="$(date +%s)"
      if ssh "${SSH_OPTIONS[@]}" -T "$host" \
      "set -e; cd ${remote_root}/dumbo-mpc; \
       if command -v docker-compose >/dev/null 2>&1; then \
         MPC_IMAGE='${MPC_IMAGE}' timeout --signal=TERM --kill-after=15s ${RUN_TIMEOUT}s \
           docker-compose -f '${MPC_COMPOSE_FILE}' run --rm -p ${epoch_port}:${epoch_port} \
           -e ZMQ_AUTH_MODE=curve -e ZMQ_CURVE_READY_TIMEOUT=60 \
           -e COMMITTEE_ELECTION_TIMEOUT_SECONDS=${PROTOCOL_TIMEOUT} \
           -w /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen dumbo-mpc \
           /opt/venv/continuum/bin/python3 -u -m scripts.run_committee_election \
           -d -f ${remote_config}; \
       elif docker compose version >/dev/null 2>&1; then \
         MPC_IMAGE='${MPC_IMAGE}' timeout --signal=TERM --kill-after=15s ${RUN_TIMEOUT}s \
           docker compose -f '${MPC_COMPOSE_FILE}' run --rm -p ${epoch_port}:${epoch_port} \
           -e ZMQ_AUTH_MODE=curve -e ZMQ_CURVE_READY_TIMEOUT=60 \
           -e COMMITTEE_ELECTION_TIMEOUT_SECONDS=${PROTOCOL_TIMEOUT} \
           -w /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen dumbo-mpc \
           /opt/venv/continuum/bin/python3 -u -m scripts.run_committee_election \
           -d -f ${remote_config}; \
       else \
         echo 'Neither docker-compose nor docker compose is available.' >&2; exit 127; \
       fi"; then
        exit 0
      else
        status="$?"
      fi
      elapsed=$(( $(date +%s) - attempt_started ))
      if [[ "$attempt" -ge 3 || "$elapsed" -ge 15 ]]; then
        exit "$status"
      fi
      echo "Transient SSH launch failure for node ${node_id}; retrying attempt $((attempt + 1))/3" >&2
      sleep 2
    done
    ) > "${log_dir}/node-${node_id}.log" 2>&1 &
    pids+=("$!")
  done

  # A few Docker Compose versions can linger after the benchmark process has
  # emitted its authenticated completion record. Once all N records exist,
  # release those local SSH waits immediately. Each epoch has a distinct port,
  # so remote Compose cleanup cannot block the next election.
  while :; do
    completed_logs=0
    live_workers=0
    for node_id in $(seq 0 "$((N - 1))"); do
      if grep -q '^COMMITTEE_ELECTION_FINISHED$' "${log_dir}/node-${node_id}.log" 2>/dev/null; then
        completed_logs=$((completed_logs + 1))
      fi
    done
    for pid in "${pids[@]}"; do
      if kill -0 "$pid" 2>/dev/null; then
        live_workers=$((live_workers + 1))
      fi
    done
    if [[ "$completed_logs" -eq "$N" ]]; then
      for pid in "${pids[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
          pkill -TERM -P "$pid" 2>/dev/null || true
          kill -TERM "$pid" 2>/dev/null || true
        fi
      done
      break
    fi
    if [[ "$live_workers" -eq 0 ]]; then
      break
    fi
    sleep 0.1
  done

  failed=0
  for pid in "${pids[@]}"; do
    if ! wait "$pid"; then
      failed=1
    fi
  done
  if [[ "$failed" -ne 0 ]]; then
    completed_logs=0
    for node_id in $(seq 0 "$((N - 1))"); do
      if grep -q '^COMMITTEE_ELECTION_FINISHED$' "${log_dir}/node-${node_id}.log"; then
        completed_logs=$((completed_logs + 1))
      fi
    done
    if [[ "$completed_logs" -ne "$N" ]]; then
      echo "Election charged to epoch ${charged_epoch} failed; see ${log_dir}" >&2
      exit 1
    fi
    echo "All ${N} election nodes finished; ignoring a post-protocol SSH/container cleanup status." >&2
  fi

  (
    cd "$ASY_DIR"
    PYTHONPATH="${ASY_DIR}:${PYTHONPATH:-}" "$CONTINUUM_PYTHON" \
      -m scripts.analyze_committee_election \
      --log-dir "$log_dir" --expected-n "$N" --output "${epoch_dir}/summary.json"
  )
  finished_utc="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
  printf 'charged_target_epoch=%s\nprotocol_target_epoch=2\nport=%s\nlaunch_started_utc=%s\nfinished_utc=%s\n' \
    "$charged_epoch" "$epoch_port" "$launch_started_utc" "$finished_utc" \
    > "${epoch_dir}/metadata.env"
done

python3 "${SCRIPT_DIR}/aggregate_committee_elections.py" --session-dir "$session_dir" \
  --count "$ELECTION_COUNT" --expected-n "$N" --expected-t "$T"
echo "ELECTION_SESSION_DIR=${session_dir}"
echo "ELECTION_SUMMARY=${session_dir}/election_summary.json"
