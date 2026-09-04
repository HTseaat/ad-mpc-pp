#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ADMPC_DIR="/opt/admpc"
CONTINUUM_DIR="/opt/dumbo-mpc"
ASY_DIR="${CONTINUUM_DIR}/dumbo-mpc/AsyRanTriGen"
ASY_SCRIPTS_DIR="${ASY_DIR}/scripts"
REMOTE_DIR="${CONTINUUM_DIR}/remote"
REMOTE_ASY_SCRIPTS_DIR="${REMOTE_DIR}/AsyRanTriGen_scripts"
RESULTS_ROOT_DEFAULT="/opt/benchmark-distributed"
MPC_IMAGE_DEFAULT="continuum-aws-amd64:20260817-7b503d9c5fd1-r3"
MPC_IMAGE_ID_DEFAULT="sha256:6c9b45c8f134489765ba75f920052dcc27caaa214fed7454e13c9618a67ecb5f"
MPC_COMPOSE_FILE_DEFAULT="docker-compose.aws.yml"

CLUSTER_ENV_DEFAULT="${SCRIPT_DIR}/cluster.env"

NODE_SSH_USERNAME=""
MPC_IMAGE=""
MPC_IMAGE_ID=""
MPC_IMAGE_PATCH_REF=""
REMOTE_WORKSPACE_DIR=""
MPC_COMPOSE_FILE=""
CLUSTER_IPS=()
CLUSTER_PEER_IPS=()

load_cluster_env() {
  local env_file="${CLUSTER_ENV:-$CLUSTER_ENV_DEFAULT}"
  if [[ ! -f "$env_file" ]]; then
    echo "Cluster config not found: $env_file" >&2
    echo "Create it from: ${SCRIPT_DIR}/cluster.env.example" >&2
    exit 1
  fi

  # shellcheck disable=SC1090
  source "$env_file"

  NODE_SSH_USERNAME="${NODE_SSH_USERNAME:-root}"
  # Keep a stable default image tag even if remote repositories are on mixed versions.
  # This avoids accidentally falling back to outdated compose defaults on remote hosts.
  MPC_IMAGE="${MPC_IMAGE:-$MPC_IMAGE_DEFAULT}"
  MPC_IMAGE_ID="${MPC_IMAGE_ID:-$MPC_IMAGE_ID_DEFAULT}"
  MPC_IMAGE_PATCH_REF="${MPC_IMAGE_PATCH_REF:-}"
  MPC_COMPOSE_FILE="${MPC_COMPOSE_FILE:-$MPC_COMPOSE_FILE_DEFAULT}"
  REMOTE_WORKSPACE_DIR="${REMOTE_WORKSPACE_DIR:-}"

  if [[ ${#CLUSTER_IPS[@]} -eq 0 ]]; then
    echo "CLUSTER_IPS is empty in $env_file" >&2
    exit 1
  fi
  if [[ ${#CLUSTER_PEER_IPS[@]} -eq 0 ]]; then
    CLUSTER_PEER_IPS=("${CLUSTER_IPS[@]}")
  fi
  if [[ ${#CLUSTER_PEER_IPS[@]} -ne ${#CLUSTER_IPS[@]} ]]; then
    echo "CLUSTER_PEER_IPS must be empty or match CLUSTER_IPS length." >&2
    exit 1
  fi
}

require_immutable_image() {
  if [[ -z "$MPC_IMAGE" ]]; then
    echo "MPC_IMAGE must identify the preloaded experiment image." >&2
    exit 1
  fi
  if [[ "$MPC_IMAGE" == *":latest" && "${ALLOW_MUTABLE_MPC_IMAGE:-0}" != "1" ]]; then
    echo "Refusing mutable MPC_IMAGE=${MPC_IMAGE}. Pin the r3 tag/digest in cluster.env." >&2
    echo "Set ALLOW_MUTABLE_MPC_IMAGE=1 only for an intentional development run." >&2
    exit 1
  fi
  if [[ "$MPC_COMPOSE_FILE" != "docker-compose.aws.yml" && "${ALLOW_SOURCE_MOUNT_COMPOSE:-0}" != "1" ]]; then
    echo "Refusing non-production MPC_COMPOSE_FILE=${MPC_COMPOSE_FILE}." >&2
    echo "The experiment must not bind-mount host source over the r3 image." >&2
    exit 1
  fi
}

require_tools() {
  local missing=0
  local tool
  for tool in "$@"; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      echo "Missing required command: $tool" >&2
      missing=1
    fi
  done
  if [[ $missing -ne 0 ]]; then
    exit 1
  fi
}

select_cluster_ips() {
  local n="$1"
  if ! [[ "$n" =~ ^[0-9]+$ ]] || [[ "$n" -le 0 ]]; then
    echo "Invalid node count: $n" >&2
    exit 1
  fi

  if [[ "$n" -gt "${#CLUSTER_IPS[@]}" ]]; then
    echo "Requested N=$n, but only ${#CLUSTER_IPS[@]} IPs configured." >&2
    exit 1
  fi

  SELECTED_IPS=("${CLUSTER_IPS[@]:0:$n}")
  SELECTED_PEER_IPS=("${CLUSTER_PEER_IPS[@]:0:$n}")
}

write_config_sh() {
  local target_file="$1"
  local node_num="$2"

  {
    echo "# worker nodes config"
    echo "NODE_NUM=${node_num}"
    echo "NODE_IPS=("
    local ip
    for ip in "${SELECTED_IPS[@]}"; do
      echo "    \"${ip}\""
    done
    echo ")"
    echo "PEER_IPS=("
    for ip in "${SELECTED_PEER_IPS[@]}"; do
      echo "    \"${ip}\""
    done
    echo ")"
    echo "NODE_SSH_USERNAME=\"${NODE_SSH_USERNAME}\""
    echo "SSH_IDENTITY_FILE=\"${SSH_IDENTITY_FILE:-}\""
    echo "MPC_IMAGE=\"${MPC_IMAGE}\""
    echo "MPC_IMAGE_ID=\"${MPC_IMAGE_ID}\""
    echo "MPC_IMAGE_PATCH_REF=\"${MPC_IMAGE_PATCH_REF}\""
    echo "MPC_COMPOSE_FILE=\"${MPC_COMPOSE_FILE}\""
    echo "REMOTE_WORKSPACE_DIR=\"${REMOTE_WORKSPACE_DIR}\""
    echo
    echo "# ethermint config"
    echo "# CHAINID=\"ethermint_9000-1\""
    echo "# MONIKER=\"mytestnet\""
    echo "# KEYALGO=\"eth_secp256k1\""
  } > "$target_file"
}

write_ip_txt() {
  local target_file="$1"
  shift
  local ips=("$@")
  : > "$target_file"
  local ip
  for ip in "${ips[@]}"; do
    echo "$ip" >> "$target_file"
  done
}

timestamp_utc() {
  date -u +%Y%m%dT%H%M%SZ
}

save_metadata() {
  local outdir="$1"
  local protocol="$2"
  local exp_id="$3"
  local n="$4"
  local t="$5"
  local d="$6"
  local layers_total="$7"
  local total_cm="$8"
  local dumbo_mode="${9:-}"

  mkdir -p "$outdir"
  {
    echo "timestamp_utc=$(timestamp_utc)"
    echo "protocol=${protocol}"
    echo "experiment=${exp_id}"
    echo "n=${n}"
    echo "t=${t}"
    echo "d=${d}"
    echo "layers_total=${layers_total}"
    echo "total_cm=${total_cm}"
    echo "zmq_auth_mode=${ZMQ_AUTH_MODE:-null}"
    echo "zmq_curve_ready_timeout=${ZMQ_CURVE_READY_TIMEOUT:-60}"
    echo "mpc_image=${MPC_IMAGE}"
    echo "mpc_image_id=${MPC_IMAGE_ID}"
    echo "mpc_image_patch_ref=${MPC_IMAGE_PATCH_REF:-}"
    echo "mpc_compose_file=${MPC_COMPOSE_FILE}"
    echo "agg_kzg_v2=${AGG_KZG_V2:-1}"
    echo "disable_agg_proto=${DISABLE_AGG_PROTO:-0}"
    echo "protocol_overhead=${PROTOCOL_OVERHEAD:-0}"
    echo "protocol_overhead_barrier_timeout_seconds=${PROTOCOL_OVERHEAD_BARRIER_TIMEOUT_SECONDS:-300}"
    echo "bgw_unbatched_verify=${BGW_UNBATCHED_VERIFY:-0}"
    echo "bgw_unbatched_batch_all_verify=${BGW_UNBATCHED_BATCH_ALL_VERIFY:-0}"
    echo "bgw_unbatched_batch_share_verify=${BGW_UNBATCHED_BATCH_SHARE_VERIFY:-0}"
    echo "bgw_unbatched_batch_hidden_verify=${BGW_UNBATCHED_BATCH_HIDDEN_VERIFY:-0}"
    echo "bgw_unbatched_batch_zero_verify=${BGW_UNBATCHED_BATCH_ZERO_VERIFY:-0}"
    echo "bgw_unbatched_batch_prod_verify=${BGW_UNBATCHED_BATCH_PROD_VERIFY:-0}"
    echo "admpc_legacy_eval_verify=1"
    echo "admpc_evaluation_verifier_mode=legacy-inner-proof-only"
    echo "start_delay_seconds=${START_DELAY:-30}"
    echo "process_timeout_seconds=${RUN_TIMEOUT:-900}"
    echo "continuum_config_generator=${CONTINUUM_CONFIG_GENERATOR:-local}"
    if [[ -n "$dumbo_mode" ]]; then
      echo "dumbo_mode=${dumbo_mode}"
    fi
  } > "${outdir}/metadata.env"
}
