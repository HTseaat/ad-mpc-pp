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

CLUSTER_ENV_DEFAULT="${SCRIPT_DIR}/cluster.env"

NODE_SSH_USERNAME=""
MPC_IMAGE=""
REMOTE_WORKSPACE_DIR=""
CLUSTER_IPS=()

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
  MPC_IMAGE="${MPC_IMAGE:-continuum:latest}"
  REMOTE_WORKSPACE_DIR="${REMOTE_WORKSPACE_DIR:-}"

  if [[ ${#CLUSTER_IPS[@]} -eq 0 ]]; then
    echo "CLUSTER_IPS is empty in $env_file" >&2
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
}

write_config_sh() {
  local target_file="$1"
  local node_num="$2"
  shift 2
  local ips=("$@")

  {
    echo "# worker nodes config"
    echo "NODE_NUM=${node_num}"
    echo "NODE_IPS=("
    local ip
    for ip in "${ips[@]}"; do
      echo "    \"${ip}\""
    done
    echo ")"
    echo "NODE_SSH_USERNAME=\"${NODE_SSH_USERNAME}\""
    echo "MPC_IMAGE=\"${MPC_IMAGE}\""
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
    if [[ -n "$dumbo_mode" ]]; then
      echo "dumbo_mode=${dumbo_mode}"
    fi
  } > "${outdir}/metadata.env"
}
