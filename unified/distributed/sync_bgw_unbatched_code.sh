#!/usr/bin/env bash
# Sync the BGW degree-reduction unbatched verification patch and BGW-direct
# dropout experiment wiring to remote servers. By default this also rebuilds
# kzg_ped_out.so on each server inside the Docker container.
#
# Default target set:
#   all CLUSTER_IPS from unified/distributed/cluster.env
#
# Typical usage:
#   ./sync_bgw_unbatched_code.sh
#   ./sync_bgw_unbatched_code.sh --only-n 4
#   ./sync_bgw_unbatched_code.sh --include-seed
#   ./sync_bgw_unbatched_code.sh --seed-only
#   ./sync_bgw_unbatched_code.sh --host 110.42.130.226
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
MPC_IMAGE="${MPC_IMAGE:-continuum:latest}"
DO_BUILD=1
DRY_RUN=0
ONLY_N=""
INCLUDE_SEED=0
SEED_ONLY=0
EXPLICIT_HOSTS=()

if [[ -n "${REMOTE_ROOT:-}" ]]; then
  REMOTE_ROOT_VALUE="$REMOTE_ROOT"
elif [[ -n "${REMOTE_WORKSPACE_DIR:-}" ]]; then
  REMOTE_ROOT_VALUE="~/${REMOTE_WORKSPACE_DIR}"
else
  REMOTE_ROOT_VALUE="~"
fi

if [[ -n "${GO_PROXY:-}" ]]; then
  GO_PROXIES="$GO_PROXY"
else
  GO_PROXIES="${GO_PROXIES:-https://mirrors.aliyun.com/goproxy/,direct https://goproxy.cn,direct https://goproxy.io,direct direct}"
fi

LOCAL_KZG_DIR="${CONTINUUM_DIR}/gnark-crypto/kzg_ped_bls12-381"

SYNC_FILES=(
  "unified/distributed/run_suite.sh"
  "dumbo-mpc/gnark-crypto/kzg_ped_bls12-381/kzg_ped_out.go"
  "dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/hbacss.py"
  "dumbo-mpc/dumbo-mpc/AsyRanTriGen/scripts/control-node.sh"
  "dumbo-mpc/dumbo-mpc/AsyRanTriGen/scripts/run_dumbo_bgw_direct.py"
  "dumbo-mpc/run_local_network_test.sh"
  "dumbo-mpc/remote/AsyRanTriGen_scripts/launch_asyrantrigen.sh"
  "dumbo-mpc/remote/AsyRanTriGen_scripts/launch_bgw_direct.sh"
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
  --mpc-image <image>   Docker compose image override (default: ${MPC_IMAGE}).
  --go-proxies <list>   Space-separated GOPROXY retry list used only when
                        preparing the local offline vendor bundle.
  --no-build            Only sync files; skip remote KZG rebuild.
  --dry-run             Print target/file list without copying.
  -h, --help            Show this help.

Synced files:
$(printf '  %s\n' "${SYNC_FILES[@]}")
USAGE
}

INCLUDE_CLUSTER=1
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
    --mpc-image)
      MPC_IMAGE="${2:?missing value for --mpc-image}"
      shift 2
      ;;
    --go-proxies)
      GO_PROXIES="${2:?missing value for --go-proxies}"
      shift 2
      ;;
    --no-build)
      DO_BUILD=0
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
echo "MPC image: ${MPC_IMAGE}"
echo "Build remote kzg_ped_out.so: ${DO_BUILD}"
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

archive="$(mktemp -t continuum-bgw-unbatched-code.XXXXXX.tar.gz)"
vendor_tmp=""
vendor_archive=""
trap 'rm -f "$archive" "$vendor_archive"; if [[ -n "$vendor_tmp" ]]; then rm -rf "$vendor_tmp"; fi' EXIT

tar -C /opt -czf "$archive" "${SYNC_FILES[@]}"

vendor_ok() {
  local root="$1"
  [[ -d "${root}/vendor/github.com/bits-and-blooms/bitset" ]] &&
  [[ -d "${root}/vendor/github.com/consensys/bavard" ]] &&
  [[ -d "${root}/vendor/github.com/mmcloughlin/addchain" ]] &&
  [[ -d "${root}/vendor/golang.org/x/sys" ]] &&
  [[ -d "${root}/vendor/rsc.io/tmplfunc" ]]
}

prepare_vendor_bundle() {
  require_tools go

  vendor_tmp="$(mktemp -d -t continuum-kzg-vendor.XXXXXX)"
  local gocache_tmp
  gocache_tmp="$(mktemp -d -t continuum-go-build-cache.XXXXXX)"
  local rc=1

  echo ""
  echo "Preparing offline Go vendor bundle..."
  if (cd "$LOCAL_KZG_DIR" && GOCACHE="$gocache_tmp" GOPROXY=off GOSUMDB=off go mod vendor -o "${vendor_tmp}/vendor"); then
    if vendor_ok "$vendor_tmp"; then
      rc=0
    fi
  fi

  if [[ "$rc" -ne 0 ]]; then
    for proxy in $GO_PROXIES; do
      echo "Preparing vendor with GOPROXY=${proxy}"
      rm -rf "${vendor_tmp}/vendor"
      if (cd "$LOCAL_KZG_DIR" && GOCACHE="$gocache_tmp" GOPROXY="$proxy" GOSUMDB=off go mod vendor -o "${vendor_tmp}/vendor"); then
        if vendor_ok "$vendor_tmp"; then
          rc=0
          break
        fi
      fi
    done
  fi

  rm -rf "$gocache_tmp"
  if [[ "$rc" -ne 0 ]]; then
    echo "Failed to prepare Go vendor bundle. Check local Go module cache/network." >&2
    exit 1
  fi

  vendor_archive="$(mktemp -t continuum-kzg-vendor.XXXXXX.tar.gz)"
  tar -C "$vendor_tmp" -czf "$vendor_archive" vendor
}

if [[ "$DO_BUILD" -eq 1 ]]; then
  prepare_vendor_bundle
fi

remote_build_cmd=$(cat <<'REMOTE'
set -euo pipefail
case "${REMOTE_ROOT_VALUE}" in
  "~")
    remote_root="${HOME}"
    ;;
  "~/"*)
    remote_root="${HOME}${REMOTE_ROOT_VALUE#\~}"
    ;;
  *)
    remote_root="${REMOTE_ROOT_VALUE}"
    ;;
esac
cd "${remote_root}/dumbo-mpc"
if command -v docker-compose >/dev/null 2>&1; then
  compose_cmd=(docker-compose)
elif docker compose version >/dev/null 2>&1; then
  compose_cmd=(docker compose)
else
  echo "Neither docker-compose nor docker compose is available." >&2
  exit 127
fi
MPC_IMAGE="${MPC_IMAGE}" "${compose_cmd[@]}" run --rm --no-deps dumbo-mpc bash -lc \
  'cd gnark-crypto/kzg_ped_bls12-381 && GOCACHE=/tmp/go-build-cache GOPROXY=off GOSUMDB=off GOFLAGS=-mod=vendor bash build_shared_library.sh && cp -f kzg_ped_out.so /opt/dumbo-mpc/kzg_ped_out.so'
REMOTE
)

for ip in "${TARGET_IPS[@]}"; do
  host="${TARGET_USER}@${ip}"
  remote_archive="/tmp/$(basename "$archive")"

  echo ""
  echo "=== ${host} ==="
  echo "Uploading code archive..."
  scp "$archive" "${host}:${remote_archive}"

  echo "Extracting code archive..."
  ssh "$host" "set -e; mkdir -p ${REMOTE_ROOT_VALUE}; tar -xzf ${remote_archive} -C ${REMOTE_ROOT_VALUE}; rm -f ${remote_archive}"

  if [[ "$DO_BUILD" -eq 1 ]]; then
    remote_vendor_archive="/tmp/$(basename "$vendor_archive")"

    echo "Uploading offline Go vendor bundle..."
    scp "$vendor_archive" "${host}:${remote_vendor_archive}"

    echo "Installing vendor bundle..."
    ssh "$host" "set -e; cd ${REMOTE_ROOT_VALUE}/dumbo-mpc/gnark-crypto/kzg_ped_bls12-381; rm -rf vendor; tar -xzf ${remote_vendor_archive}; rm -f ${remote_vendor_archive}"

    echo "Rebuilding kzg_ped_out.so inside Docker..."
    ssh "$host" "REMOTE_ROOT_VALUE='${REMOTE_ROOT_VALUE}' MPC_IMAGE='${MPC_IMAGE}' bash -lc $(printf '%q' "$remote_build_cmd")"
  fi

  echo "Done: ${host}"
done

echo ""
echo "BGW unbatched code sync complete for ${#TARGET_IPS[@]} server(s)."
