#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

usage() {
  cat <<USAGE
Usage: $0 [options]

Clean docker compose containers left by distributed experiments.

Options:
  --protocol <all|admpc|continuum|dumbo>  Compose project(s) to clean (default: all)
  --n <N>                                 Clean first N hosts from CLUSTER_IPS (default: all)
  --host <ip>                             Clean one extra host/IP, can be repeated
  --cluster-env <path>                    Cluster env file (default: distributed/cluster.env)
  --prune                                 Also run docker container prune -f
  --dry-run                               Print commands only, do not execute
  -h, --help                              Show this help

Examples:
  $0
  $0 --protocol dumbo --n 4
  $0 --host 110.42.130.226
  $0 --host 110.42.130.226 --protocol all --prune
USAGE
}

TARGET_PROTOCOL="all"
TARGET_N=""
DRY_RUN=0
DO_PRUNE=0
EXTRA_HOSTS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --protocol)
      TARGET_PROTOCOL="${2:?missing value for --protocol}"
      shift 2
      ;;
    --n)
      TARGET_N="${2:?missing value for --n}"
      shift 2
      ;;
    --host)
      EXTRA_HOSTS+=("${2:?missing value for --host}")
      shift 2
      ;;
    --cluster-env)
      CLUSTER_ENV="${2:?missing value for --cluster-env}"
      export CLUSTER_ENV
      shift 2
      ;;
    --prune)
      DO_PRUNE=1
      shift
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
  all|admpc|continuum|dumbo) ;;
  *)
    echo "Invalid --protocol: ${TARGET_PROTOCOL}" >&2
    usage
    exit 1
    ;;
esac

load_cluster_env
require_tools ssh

if [[ -z "$TARGET_N" ]]; then
  TARGET_N="${#CLUSTER_IPS[@]}"
fi

select_cluster_ips "$TARGET_N"

TARGET_HOSTS=("${SELECTED_IPS[@]}")
if [[ "${#EXTRA_HOSTS[@]}" -gt 0 ]]; then
  TARGET_HOSTS+=("${EXTRA_HOSTS[@]}")
fi

REMOTE_ROOT="~"
if [[ -n "${REMOTE_WORKSPACE_DIR:-}" ]]; then
  REMOTE_ROOT="~/${REMOTE_WORKSPACE_DIR}"
fi

REMOTE_PROJECT_DIRS=()
LABEL_PROJECTS=()
case "$TARGET_PROTOCOL" in
  all)
    REMOTE_PROJECT_DIRS=("admpc" "dumbo-mpc")
    LABEL_PROJECTS=("admpc" "dumbo-mpc")
    ;;
  admpc)
    REMOTE_PROJECT_DIRS=("admpc")
    LABEL_PROJECTS=("admpc")
    ;;
  continuum|dumbo)
    REMOTE_PROJECT_DIRS=("dumbo-mpc")
    LABEL_PROJECTS=("dumbo-mpc")
    ;;
esac

echo "Cleanup protocol: ${TARGET_PROTOCOL}"
echo "Remote root: ${REMOTE_ROOT}"
echo "Project dirs: ${REMOTE_PROJECT_DIRS[*]}"
echo "Compose labels: ${LABEL_PROJECTS[*]}"
echo "Hosts: ${TARGET_HOSTS[*]}"

for ip in "${TARGET_HOSTS[@]}"; do
  host="${NODE_SSH_USERNAME}@${ip}"
  echo
  echo "[cleanup] ${host}"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "ssh ${host} 'cd ${REMOTE_ROOT}/{${REMOTE_PROJECT_DIRS[*]}} && docker compose down --remove-orphans'"
    continue
  fi

  ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$host" \
    bash -s -- "$REMOTE_ROOT" "$DO_PRUNE" "${#REMOTE_PROJECT_DIRS[@]}" "${REMOTE_PROJECT_DIRS[@]}" "${LABEL_PROJECTS[@]}" <<'EOF'
set -euo pipefail

remote_root="$1"
do_prune="$2"
dir_count="$3"
shift 3

project_dirs=("${@:1:dir_count}")
shift "$dir_count"
label_projects=("$@")

compose_down() {
  local project_dir="$1"
  local full_dir="${remote_root}/${project_dir}"

  if [[ ! -d "$full_dir" ]]; then
    echo "[skip] Missing directory: ${full_dir}"
    return
  fi

  if [[ ! -f "${full_dir}/docker-compose.yml" && ! -f "${full_dir}/compose.yml" ]]; then
    echo "[skip] No compose file in: ${full_dir}"
    return
  fi

  echo "[down] ${full_dir}"
  cd "$full_dir"
  if docker compose version >/dev/null 2>&1; then
    docker compose down --remove-orphans || true
  elif command -v docker-compose >/dev/null 2>&1; then
    docker-compose down --remove-orphans || true
  else
    echo "[warn] docker compose is not available on this host"
  fi
}

for project_dir in "${project_dirs[@]}"; do
  compose_down "$project_dir"
done

# Compose run containers sometimes survive under the project label if the
# launcher is interrupted. Remove them by label as a second pass.
for project in "${label_projects[@]}"; do
  ids="$(docker ps -aq --filter "label=com.docker.compose.project=${project}" || true)"
  if [[ -n "$ids" ]]; then
    echo "[rm] containers with compose project label: ${project}"
    docker rm -f $ids >/dev/null 2>&1 || true
  fi
done

if [[ "$do_prune" == "1" ]]; then
  echo "[prune] docker container prune -f"
  docker container prune -f >/dev/null 2>&1 || true
fi

echo "[remaining]"
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' || true
EOF
done

echo
echo "Remote docker cleanup completed."
