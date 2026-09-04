#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

usage() {
  cat <<USAGE
Usage: $0 [options]

Options:
  --protocol <admpc|continuum|dumbo|all>   Which compose project(s) to clean (default: all)
  --n <N>                                   Number of nodes from CLUSTER_IPS head (default: all configured)
  --cluster-env <path>                      Cluster env file (default: distributed/cluster.env)
  --dry-run                                 Print targets only, do not execute cleanup
USAGE
}

TARGET_PROTOCOL="all"
TARGET_N=""
DRY_RUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --protocol)
      TARGET_PROTOCOL="$2"
      shift 2
      ;;
    --n)
      TARGET_N="$2"
      shift 2
      ;;
    --cluster-env)
      CLUSTER_ENV="$2"
      export CLUSTER_ENV
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
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

case "$TARGET_PROTOCOL" in
  admpc|continuum|dumbo|all) ;;
  *)
    echo "Invalid --protocol: ${TARGET_PROTOCOL}" >&2
    usage
    exit 1
    ;;
esac

load_cluster_env
require_tools ssh

SSH_OPTIONS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes)
if [[ -n "${SSH_IDENTITY_FILE:-}" ]]; then
  if [[ ! -r "$SSH_IDENTITY_FILE" ]]; then
    echo "SSH identity file is not readable: ${SSH_IDENTITY_FILE}" >&2
    exit 1
  fi
  SSH_OPTIONS+=(-i "$SSH_IDENTITY_FILE" -o IdentitiesOnly=yes)
fi

if [[ -z "$TARGET_N" ]]; then
  TARGET_N="${#CLUSTER_IPS[@]}"
fi

if ! [[ "$TARGET_N" =~ ^[0-9]+$ ]] || [[ "$TARGET_N" -le 0 ]]; then
  echo "Invalid --n: ${TARGET_N}" >&2
  exit 1
fi

select_cluster_ips "$TARGET_N"

PROJECTS=()
case "$TARGET_PROTOCOL" in
  admpc)
    PROJECTS=("admpc")
    ;;
  continuum|dumbo)
    PROJECTS=("dumbo-mpc")
    ;;
  all)
    PROJECTS=("admpc" "dumbo-mpc")
    ;;
esac

echo "Cleanup target protocol=${TARGET_PROTOCOL}, N=${TARGET_N}"
echo "Projects: ${PROJECTS[*]}"
echo "Hosts: ${SELECTED_IPS[*]}"

parallelism="${CLEANUP_PARALLELISM:-8}"
if ! [[ "$parallelism" =~ ^[1-9][0-9]*$ ]]; then
  echo "CLEANUP_PARALLELISM must be a positive integer" >&2
  exit 1
fi

cleanup_host() {
  local ip="$1"
  local host="${NODE_SSH_USERNAME}@${ip}"
  echo "[cleanup] ${host}"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    return 0
  fi

  ssh "${SSH_OPTIONS[@]}" "$host" bash -s -- "${PROJECTS[@]}" <<'EOF'
set -euo pipefail

projects=("$@")
for project in "${projects[@]}"; do
  ids="$(docker ps -aq --filter "label=com.docker.compose.project=${project}" || true)"
  if [[ -n "$ids" ]]; then
    docker rm -f $ids >/dev/null 2>&1 || true
  fi
done

# Print residual listeners in expected benchmark range for diagnostics.
docker ps --format '{{.Names}} {{.Ports}}' | grep -E '(:700[1-9]|:7010)->' || true
EOF
}

pids=()
failed=0
for ip in "${SELECTED_IPS[@]}"; do
  cleanup_host "$ip" &
  pids+=("$!")
  if [[ "${#pids[@]}" -ge "$parallelism" ]]; then
    for pid in "${pids[@]}"; do
      if ! wait "$pid"; then
        failed=1
      fi
    done
    pids=()
  fi
done

for pid in "${pids[@]}"; do
  if ! wait "$pid"; then
    failed=1
  fi
done

if [[ "$failed" -ne 0 ]]; then
  echo "One or more remote cleanups failed" >&2
  exit 1
fi

echo "Remote cleanup completed."
