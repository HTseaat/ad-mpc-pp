#!/usr/bin/env bash
# Sync the Dumbo shuffle Beaver baseline plus the recent distributed-script
# updates to remote servers. This patch set only touches shell/python/docs, so
# it intentionally does not rebuild the Go KZG shared library.
#
# Typical usage:
#   ./sync_dumbo_shuffle_beaver_code.sh
#   ./sync_dumbo_shuffle_beaver_code.sh --only-n 4
#   ./sync_dumbo_shuffle_beaver_code.sh --host 110.42.130.226
#   ./sync_dumbo_shuffle_beaver_code.sh --seed-only
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

CLUSTER_ENV_FILE="${CLUSTER_ENV:-${SCRIPT_DIR}/cluster.env}"
if [[ -f "$CLUSTER_ENV_FILE" ]]; then
  CLUSTER_ENV="$CLUSTER_ENV_FILE" load_cluster_env
else
  NODE_SSH_USERNAME="${NODE_SSH_USERNAME:-root}"
  MPC_IMAGE="${MPC_IMAGE:-continuum:latest}"
  REMOTE_WORKSPACE_DIR="${REMOTE_WORKSPACE_DIR:-Continuum}"
fi

SEED_IP="${SEED_IP:-110.42.130.226}"
TARGET_USER="${TARGET_USER:-${NODE_SSH_USERNAME:-root}}"
DRY_RUN=0
ONLY_N=""
INCLUDE_SEED=0
SEED_ONLY=0
INCLUDE_CLUSTER=1
SSH_CONNECT_TIMEOUT="${SSH_CONNECT_TIMEOUT:-10}"
SSH_VERBOSE=0
EXPLICIT_HOSTS=()

if [[ -n "${REMOTE_ROOT:-}" ]]; then
  REMOTE_ROOT_VALUE="$REMOTE_ROOT"
elif [[ -n "${REMOTE_WORKSPACE_DIR:-}" ]]; then
  REMOTE_ROOT_VALUE="~/${REMOTE_WORKSPACE_DIR}"
else
  REMOTE_ROOT_VALUE="~"
fi

# Keep this list explicit: it is the combined patch set from the recent cloud
# runner updates, the shuffle sign-selector path, the dumbo-shuffle-beaver path,
# and BGW-direct dropout wiring. No Go sources are included here, so no remote
# rebuild is needed.
SYNC_FILES=(
  "README.md"
  "admpc/scripts/batch_create_json.sh"
  "unified/run_continuum_local.sh"
  "unified/distributed/README.md"
  "unified/distributed/run_admpc_dist.sh"
  "unified/distributed/run_continuum_dist.sh"
  "unified/distributed/run_dumbo_dist.sh"
  "unified/distributed/run_dumbo_bgw_direct_dist.sh"
  "unified/distributed/run_suite.sh"
  "unified/distributed/sync_seed_server_code.sh"
  "unified/distributed/sync_bgw_unbatched_code.sh"
  "unified/distributed/sync_dumbo_shuffle_beaver_code.sh"
  "dumbo-mpc/run_local_network_test.sh"
  "dumbo-mpc/remote/AsyRanTriGen_scripts/launch_asyrantrigen.sh"
  "dumbo-mpc/remote/AsyRanTriGen_scripts/launch_bgw_direct.sh"
  "dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/hbacss.py"
  "dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/batch_rand_bit.py"
  "dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/admpc2_dynamic_shuffle.py"
  "dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/admpc2_dynamic_shuffle_bgw_static.py"
  "dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/admpc2_dynamic_dumbo_shuffle_beaver.py"
  "dumbo-mpc/dumbo-mpc/AsyRanTriGen/scripts/run_dumbo_bgw_direct.py"
  "dumbo-mpc/dumbo-mpc/AsyRanTriGen/scripts/admpc2_dynamic_dumbo_shuffle_beaver_run.py"
  "dumbo-mpc/dumbo-mpc/AsyRanTriGen/scripts/control-node.sh"
)

usage() {
  cat <<USAGE
Usage: $0 [options]

Options:
  --only-n <n>          Sync only the first n CLUSTER_IPS from cluster.env.
  --host <ip>           Sync to an explicit host IP. Can be repeated.
                        If any --host is supplied, cluster.env hosts are not
                        used unless --include-cluster is also supplied.
  --include-cluster     Use cluster.env hosts together with explicit --host IPs.
  --include-seed        Also sync to SEED_IP (default: ${SEED_IP}).
  --seed-only           Sync only to SEED_IP (default: ${SEED_IP}).
  --seed-ip <ip>        Override seed IP.
  --user <user>         SSH user (default: ${TARGET_USER}).
  --remote-root <path>  Remote workspace root (default: ${REMOTE_ROOT_VALUE}).
  --connect-timeout <s> SSH/SCP connect timeout in seconds
                        (default: ${SSH_CONNECT_TIMEOUT}).
  --ssh-verbose         Pass -v to ssh/scp for connection debugging.
  --dry-run             Print target/file list without copying.
  -h, --help            Show this help.

Synced files:
$(printf '  %s\n' "${SYNC_FILES[@]}")
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --only-n)
      ONLY_N="${2:?missing value for --only-n}"
      shift 2
      ;;
    --host)
      EXPLICIT_HOSTS+=("${2:?missing value for --host}")
      INCLUDE_CLUSTER=0
      shift 2
      ;;
    --include-cluster)
      INCLUDE_CLUSTER=1
      shift
      ;;
    --include-seed)
      INCLUDE_SEED=1
      shift
      ;;
    --seed-only)
      SEED_ONLY=1
      INCLUDE_CLUSTER=0
      shift
      ;;
    --seed-ip)
      SEED_IP="${2:?missing value for --seed-ip}"
      shift 2
      ;;
    --user)
      TARGET_USER="${2:?missing value for --user}"
      shift 2
      ;;
    --remote-root)
      REMOTE_ROOT_VALUE="${2:?missing value for --remote-root}"
      shift 2
      ;;
    --connect-timeout)
      SSH_CONNECT_TIMEOUT="${2:?missing value for --connect-timeout}"
      shift 2
      ;;
    --ssh-verbose)
      SSH_VERBOSE=1
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

require_tools bash tar scp ssh

SSH_OPTS=(
  -o "ConnectTimeout=${SSH_CONNECT_TIMEOUT}"
  -o "ServerAliveInterval=15"
  -o "ServerAliveCountMax=2"
)
if [[ "$SSH_VERBOSE" -eq 1 ]]; then
  SSH_OPTS=(-v "${SSH_OPTS[@]}")
fi

TARGET_IPS=()
if [[ "$SEED_ONLY" -eq 1 ]]; then
  TARGET_IPS+=("$SEED_IP")
else
  if [[ "$INCLUDE_CLUSTER" -eq 1 ]]; then
    if [[ ${#CLUSTER_IPS[@]} -eq 0 ]]; then
      echo "No CLUSTER_IPS loaded. Use --host <ip> or provide cluster.env." >&2
      exit 1
    fi
    if [[ -n "$ONLY_N" ]]; then
      select_cluster_ips "$ONLY_N"
      TARGET_IPS+=("${SELECTED_IPS[@]}")
    else
      TARGET_IPS+=("${CLUSTER_IPS[@]}")
    fi
  fi
  TARGET_IPS+=("${EXPLICIT_HOSTS[@]}")
  if [[ "$INCLUDE_SEED" -eq 1 ]]; then
    TARGET_IPS+=("$SEED_IP")
  fi
fi

if [[ ${#TARGET_IPS[@]} -eq 0 ]]; then
  echo "No target hosts selected." >&2
  exit 1
fi

deduped=()
for ip in "${TARGET_IPS[@]}"; do
  seen=0
  for existing in "${deduped[@]}"; do
    if [[ "$existing" == "$ip" ]]; then
      seen=1
      break
    fi
  done
  if [[ "$seen" -eq 0 ]]; then
    deduped+=("$ip")
  fi
done
TARGET_IPS=("${deduped[@]}")

echo "Targets (${#TARGET_IPS[@]}): ${TARGET_IPS[*]}"
echo "SSH user: ${TARGET_USER}"
echo "Remote workspace root: ${REMOTE_ROOT_VALUE}"
echo "Go rebuild: no"
echo "SSH connect timeout: ${SSH_CONNECT_TIMEOUT}s"
echo ""
echo "Files to sync:"
for rel in "${SYNC_FILES[@]}"; do
  if [[ ! -f "/opt/${rel}" ]]; then
    echo "Missing local file: /opt/${rel}" >&2
    exit 1
  fi
  echo "  ${rel}"
done

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo ""
  echo "Dry run only; no files copied."
  exit 0
fi

archive="$(mktemp -t continuum-dumbo-shuffle-beaver-code.XXXXXX.tar.gz)"
archive_name="$(basename "$archive")"
trap 'rm -f "$archive"' EXIT

tar -C /opt -czf "$archive" "${SYNC_FILES[@]}"

for ip in "${TARGET_IPS[@]}"; do
  host="${TARGET_USER}@${ip}"
  remote_archive="/tmp/${archive_name}"
  echo ""
  echo "Syncing ${host}"
  echo "  Uploading archive to ${host}:${remote_archive}"
  scp "${SSH_OPTS[@]}" "$archive" "${host}:${remote_archive}"
  echo "  Extracting archive under ${REMOTE_ROOT_VALUE}"
  ssh "${SSH_OPTS[@]}" "$host" "set -e; mkdir -p ${REMOTE_ROOT_VALUE}; tar -xzf ${remote_archive} -C ${REMOTE_ROOT_VALUE}; rm -f ${remote_archive}"
done

echo ""
echo "Sync complete. No Go rebuild was run."
