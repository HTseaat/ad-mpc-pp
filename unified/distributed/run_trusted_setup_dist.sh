#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

usage() {
  cat <<USAGE
Usage: $0 [options]

Run one authenticated trusted-setup party on each physical server.

Options:
  --cluster-env <path>    Cluster env file
  --results-root <path>   Results root (default: /opt/benchmark-distributed)
  --n <N>                 Number of setup parties (default: 4)
  --t <T>                 Fault threshold (default: 1)
  --powers <Q>            Requested G1 powers (default: 2)
  --base-port <port>      Same host port on every server (default: 7001)
  --protocol-timeout <s>  Per protocol-phase timeout (default: 300)
  --readiness-timeout <s> CURVE readiness timeout (default: 120)
  --timeout <s>           Hard container timeout (default: 600)
  --skip-preflight        Skip the remote image/environment preflight
USAGE
}

RESULTS_ROOT="$RESULTS_ROOT_DEFAULT"
POWERS=2
BASE_PORT=7001
PROTOCOL_TIMEOUT=300
READINESS_TIMEOUT=120
RUN_TIMEOUT=600
N=4
T=1
SKIP_PREFLIGHT=0
CONTINUUM_PYTHON="${CONTINUUM_PYTHON:-/opt/venv/continuum/bin/python3}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cluster-env) CLUSTER_ENV="$2"; export CLUSTER_ENV; shift 2 ;;
    --results-root) RESULTS_ROOT="$2"; shift 2 ;;
    --n) N="$2"; shift 2 ;;
    --t) T="$2"; shift 2 ;;
    --powers) POWERS="$2"; shift 2 ;;
    --base-port) BASE_PORT="$2"; shift 2 ;;
    --protocol-timeout) PROTOCOL_TIMEOUT="$2"; shift 2 ;;
    --readiness-timeout) READINESS_TIMEOUT="$2"; shift 2 ;;
    --timeout) RUN_TIMEOUT="$2"; shift 2 ;;
    --skip-preflight) SKIP_PREFLIGHT=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

for value_name in N T POWERS BASE_PORT PROTOCOL_TIMEOUT READINESS_TIMEOUT RUN_TIMEOUT; do
  value="${!value_name}"
  if ! [[ "$value" =~ ^[1-9][0-9]*$ ]]; then
    echo "${value_name} must be a positive integer" >&2
    exit 1
  fi
done
if (( N < 3 * T + 1 )); then
  echo "N must satisfy N >= 3*T + 1" >&2
  exit 1
fi
if (( (N & (N - 1)) != 0 )); then
  echo "N must be a power of two for the current trusted-setup NTT path" >&2
  exit 1
fi
if (( POWERS < T + 1 )); then
  echo "POWERS must be at least T + 1" >&2
  exit 1
fi
if (( BASE_PORT < 1024 || BASE_PORT > 65535 )); then
  echo "BASE_PORT is outside the allowed benchmark range" >&2
  exit 1
fi

load_cluster_env
require_immutable_image
select_cluster_ips "$N"
require_tools bash python3 ssh scp timeout
if [[ ! -x "$CONTINUUM_PYTHON" ]]; then
  echo "Continuum Python not found: ${CONTINUUM_PYTHON}" >&2
  exit 1
fi

SSH_OPTIONS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes)
if [[ -n "${SSH_IDENTITY_FILE:-}" ]]; then
  if [[ ! -r "$SSH_IDENTITY_FILE" ]]; then
    echo "SSH identity file is not readable: ${SSH_IDENTITY_FILE}" >&2
    exit 1
  fi
  SSH_OPTIONS+=(-i "$SSH_IDENTITY_FILE" -o IdentitiesOnly=yes)
fi

if [[ "$SKIP_PREFLIGHT" -eq 0 ]]; then
  if [[ -n "${CLUSTER_ENV:-}" ]]; then
    "${SCRIPT_DIR}/preflight_fig89_n4.sh" --cluster-env "$CLUSTER_ENV" --n "$N"
  else
    "${SCRIPT_DIR}/preflight_fig89_n4.sh" --n "$N"
  fi
fi

run_tag="$(timestamp_utc)"
run_id="trusted-setup-n${N}-q${POWERS}-${run_tag}"
session_dir="${RESULTS_ROOT}/trusted-setup-n${N}-q${POWERS}/${run_tag}"
config_dir="${session_dir}/config"
artifact_dir="${session_dir}/artifacts"
log_dir="${session_dir}/logs"
mkdir -p "$config_dir" "$artifact_dir" "$log_dir"
cat >"${session_dir}/metadata.env" <<EOF
timestamp_utc=${run_tag}
protocol=trusted-setup
n=${N}
t=${T}
requested_powers=${POWERS}
base_port=${BASE_PORT}
protocol_timeout=${PROTOCOL_TIMEOUT}
readiness_timeout=${READINESS_TIMEOUT}
run_timeout=${RUN_TIMEOUT}
auth_mode=curve
cluster_env=${CLUSTER_ENV:-${CLUSTER_ENV_DEFAULT}}
mpc_image=${MPC_IMAGE}
mpc_image_id=${MPC_IMAGE_ID}
mpc_image_patch_ref=${MPC_IMAGE_PATCH_REF}
EOF

peer_args=()
for peer_ip in "${SELECTED_PEER_IPS[@]}"; do
  peer_args+=(--peer "${peer_ip}:${BASE_PORT}")
done
PYTHONPATH="${ASY_DIR}:${PYTHONPATH:-}" "$CONTINUUM_PYTHON" \
  -m trusted_setup.generate_distributed_config \
  --n "$N" --t "$T" --powers "$POWERS" --run-id "$run_id" \
  --output-dir "$config_dir" "${peer_args[@]}"

if [[ -n "$REMOTE_WORKSPACE_DIR" ]]; then
  remote_root="~/${REMOTE_WORKSPACE_DIR}"
else
  remote_root="~"
fi
remote_config_name="$run_id"

cleanup() {
  if [[ -n "${CLUSTER_ENV:-}" ]]; then
    CLUSTER_ENV="$CLUSTER_ENV" "${SCRIPT_DIR}/cleanup_remote_ports.sh" \
      --protocol continuum --n "$N" >/dev/null 2>&1 || true
  else
    "${SCRIPT_DIR}/cleanup_remote_ports.sh" \
      --protocol continuum --n "$N" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM
cleanup

copy_pids=()
for node_id in $(seq 0 "$((N - 1))"); do
  host="${NODE_SSH_USERNAME}@${SELECTED_IPS[$node_id]}"
  (
    ssh "${SSH_OPTIONS[@]}" -T "$host" \
      "mkdir -p ${remote_root}/dumbo-mpc/dumbo-mpc/AsyRanTriGen/conf/${remote_config_name}"
    scp -q "${SSH_OPTIONS[@]}" \
      "${config_dir}/local.${node_id}.json" \
      "${host}:${remote_root}/dumbo-mpc/dumbo-mpc/AsyRanTriGen/conf/${remote_config_name}/local.${node_id}.json"
  ) &
  copy_pids+=("$!")
done
for pid in "${copy_pids[@]}"; do
  wait "$pid"
done

pids=()
for node_id in $(seq 0 "$((N - 1))"); do
  host="${NODE_SSH_USERNAME}@${SELECTED_IPS[$node_id]}"
  remote_config="conf/${remote_config_name}/local.${node_id}.json"
  remote_srs="conf/${remote_config_name}/node-${node_id}.srs.json"
  remote_metrics="conf/${remote_config_name}/node-${node_id}.metrics.json"
  kzg_flag=""
  if [[ "$node_id" -eq 0 ]]; then
    kzg_flag="--kzg-smoke"
  fi
  (
    ssh "${SSH_OPTIONS[@]}" -o ConnectTimeout=10 -T "$host" \
      "set -e; cd ${remote_root}/dumbo-mpc; \
       MPC_IMAGE='${MPC_IMAGE}' timeout --signal=TERM --kill-after=15s ${RUN_TIMEOUT}s \
       docker compose -f '${MPC_COMPOSE_FILE}' run --rm -p ${BASE_PORT}:${BASE_PORT} \
       -w /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen dumbo-mpc \
       /opt/venv/continuum/bin/python3 -u -m trusted_setup.run_node \
       --config '${remote_config}' --timeout '${PROTOCOL_TIMEOUT}' \
       --readiness-timeout '${READINESS_TIMEOUT}' --output-srs '${remote_srs}' \
       --metrics-output '${remote_metrics}' ${kzg_flag}"
  ) >"${log_dir}/node-${node_id}.log" 2>&1 &
  pids+=("$!")
done

failed=0
for pid in "${pids[@]}"; do
  if ! wait "$pid"; then
    failed=1
  fi
done

collection_pids=()
for node_id in $(seq 0 "$((N - 1))"); do
  host="${NODE_SSH_USERNAME}@${SELECTED_IPS[$node_id]}"
  remote_dir="${remote_root}/dumbo-mpc/dumbo-mpc/AsyRanTriGen/conf/${remote_config_name}"
  (
    # Production containers write these files as root. Make only this run's
    # public artifacts readable by the SSH account before collecting them.
    ssh "${SSH_OPTIONS[@]}" -T "$host" \
      "sudo chmod 0644 ${remote_dir}/node-${node_id}.metrics.json ${remote_dir}/node-${node_id}.srs.json"
    scp -q "${SSH_OPTIONS[@]}" \
      "${host}:${remote_dir}/node-${node_id}.metrics.json" \
      "${artifact_dir}/node-${node_id}.metrics.json"
    scp -q "${SSH_OPTIONS[@]}" \
      "${host}:${remote_dir}/node-${node_id}.srs.json" \
      "${artifact_dir}/node-${node_id}.srs.json"
  ) &
  collection_pids+=("$!")
done
for pid in "${collection_pids[@]}"; do
  if ! wait "$pid"; then
    failed=1
  fi
done

if [[ "$failed" -ne 0 ]]; then
  echo "Trusted-setup distributed execution failed; see ${log_dir}" >&2
  echo "TRUSTED_SETUP_SESSION_DIR=${session_dir}" >&2
  exit 1
fi

python3 "${SCRIPT_DIR}/analyze_trusted_setup.py" \
  --input-dir "$artifact_dir" --expected-n "$N" \
  --output "${session_dir}/summary.json"
echo "TRUSTED_SETUP_SESSION_DIR=${session_dir}"
echo "TRUSTED_SETUP_SUMMARY=${session_dir}/summary.json"
