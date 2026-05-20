#!/usr/bin/env bash
# Sync the current Continuum experiment code to one seed server, then rebuild
# the KZG shared library there so the server can be used as an image source.
#
# Default target:
#   root@110.42.130.226
#
# Usage:
#   ./sync_seed_server_code.sh
#   TARGET_IP=110.42.130.226 TARGET_USER=root ./sync_seed_server_code.sh
#   ./sync_seed_server_code.sh --target-ip 110.42.130.226 --user root
#   ./sync_seed_server_code.sh --no-build
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

CLUSTER_ENV_FILE="${CLUSTER_ENV:-${SCRIPT_DIR}/cluster.env}"
if [[ -f "$CLUSTER_ENV_FILE" ]]; then
  CLUSTER_ENV="$CLUSTER_ENV_FILE" load_cluster_env
fi

TARGET_IP="${TARGET_IP:-110.42.130.226}"
TARGET_USER="${TARGET_USER:-${NODE_SSH_USERNAME:-root}}"
MPC_IMAGE="${MPC_IMAGE:-continuum:latest}"
if [[ -n "${GO_PROXY:-}" ]]; then
  GO_PROXIES="$GO_PROXY"
else
  GO_PROXIES="${GO_PROXIES:-https://mirrors.aliyun.com/goproxy/,direct https://goproxy.cn,direct https://goproxy.io,direct direct}"
fi
DO_BUILD=1
DRY_RUN=0
KZG_DIR="/opt/dumbo-mpc/gnark-crypto/kzg_ped_bls12-381"

if [[ -n "${REMOTE_ROOT:-}" ]]; then
  REMOTE_ROOT_VALUE="$REMOTE_ROOT"
elif [[ -n "${REMOTE_WORKSPACE_DIR:-}" ]]; then
  REMOTE_ROOT_VALUE="~/${REMOTE_WORKSPACE_DIR}"
else
  REMOTE_ROOT_VALUE="~"
fi

usage() {
  cat <<USAGE
Usage: $0 [options]

Options:
  --target-ip <ip>       Seed server IP (default: ${TARGET_IP})
  --user <user>          SSH user (default: ${TARGET_USER})
  --remote-root <path>   Remote workspace root (default: ${REMOTE_ROOT_VALUE})
  --mpc-image <image>    Docker compose image override (default: ${MPC_IMAGE})
  --go-proxy <proxy>     Single GOPROXY value used while rebuilding KZG
  --go-proxies <list>    Space-separated GOPROXY values used only to prepare
                         a local vendor bundle if local cache is incomplete
                         (default: ${GO_PROXIES})
  --no-build             Only sync files; skip KZG rebuild
  --dry-run              Print file list and commands without copying
  -h, --help             Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target-ip)
      TARGET_IP="$2"
      shift 2
      ;;
    --user)
      TARGET_USER="$2"
      shift 2
      ;;
    --remote-root)
      REMOTE_ROOT_VALUE="$2"
      shift 2
      ;;
    --mpc-image)
      MPC_IMAGE="$2"
      shift 2
      ;;
    --go-proxy)
      GO_PROXIES="$2"
      shift 2
      ;;
    --go-proxies)
      GO_PROXIES="$2"
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

TARGET_HOST="${TARGET_USER}@${TARGET_IP}"

# Keep this list explicit: it is the current experiment patch set, without
# generated configs, logs, pycache, or benchmark outputs.
SYNC_FILES=(
  "README.md"
  "papers/shuffle_mixing_network_implementation_plan.md"
  "unified/run_continuum_local.sh"
  "unified/run_dumbo_mpc_local.sh"
  "unified/distributed/README.md"
  "unified/distributed/cleanup_remote_containers.sh"
  "unified/distributed/run_suite.sh"
  "unified/distributed/run_dumbo_bgw_direct_dist.sh"
  "unified/distributed/sync_ablation_code.sh"
  "unified/distributed/sync_seed_server_code.sh"
  "dumbo-mpc/run_local_network_test.sh"
  "dumbo-mpc/remote/AsyRanTriGen_scripts/launch_bgw_direct.sh"
  "dumbo-mpc/gnark-crypto/kzg_ped_bls12-381/kzg_ped_out.go"
  "dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/hbacss.py"
  "dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/bgw_multiplication.py"
  "dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/bgw_multiplication_static.py"
  "dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/batch_multiplication_local.py"
  "dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/admpc2_dynamic_bgw_aggtrans.py"
  "dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/shuffle_network.py"
  "dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/batch_rand_bit.py"
  "dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/admpc2_dynamic_shuffle.py"
  "dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/admpc2_dynamic_shuffle_bgw_static.py"
  "dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/admpc2_dynamic_dumbo_shuffle_beaver.py"
  "dumbo-mpc/dumbo-mpc/AsyRanTriGen/scripts/admpc2_dynamic_bgw_aggtrans_run.py"
  "dumbo-mpc/dumbo-mpc/AsyRanTriGen/scripts/init_batchsize_ip.py"
  "dumbo-mpc/dumbo-mpc/AsyRanTriGen/scripts/run_dumbo_bgw_direct.py"
  "dumbo-mpc/dumbo-mpc/AsyRanTriGen/scripts/admpc2_dynamic_shuffle_run.py"
  "dumbo-mpc/dumbo-mpc/AsyRanTriGen/scripts/admpc2_dynamic_shuffle_bgw_static_run.py"
  "dumbo-mpc/dumbo-mpc/AsyRanTriGen/scripts/admpc2_dynamic_dumbo_shuffle_beaver_run.py"
  "dumbo-mpc/dumbo-mpc/AsyRanTriGen/scripts/control-node.sh"
  "dumbo-mpc/dumbo-mpc/AsyRanTriGen/scripts/local_admpc_test.sh"
)

echo "Target seed server: ${TARGET_HOST}"
echo "Remote workspace root: ${REMOTE_ROOT_VALUE}"
echo "MPC image: ${MPC_IMAGE}"
echo "GOPROXY retry list: ${GO_PROXIES}"
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

archive="$(mktemp -t continuum-seed-code.XXXXXX.tar.gz)"
archive_name="$(basename "$archive")"
remote_archive="/tmp/${archive_name}"
vendor_tmp=""
vendor_archive=""
trap 'rm -f "$archive" "$vendor_archive"; if [[ -n "$vendor_tmp" ]]; then rm -rf "$vendor_tmp"; fi' EXIT

echo ""
echo "Creating archive: ${archive}"
tar -C /opt -czf "$archive" "${SYNC_FILES[@]}"

echo "Uploading archive to ${TARGET_HOST}:${remote_archive}"
scp "$archive" "${TARGET_HOST}:${remote_archive}"

echo "Extracting archive under ${REMOTE_ROOT_VALUE}"
ssh "$TARGET_HOST" "set -e; mkdir -p ${REMOTE_ROOT_VALUE}; tar -xzf ${remote_archive} -C ${REMOTE_ROOT_VALUE}; rm -f ${remote_archive}"

if [[ "$DO_BUILD" -eq 0 ]]; then
  echo "Skipping KZG rebuild (--no-build)."
  echo "Sync complete."
  exit 0
fi

vendor_ok() {
  local root="$1"
  [[ -d "${root}/vendor/github.com/bits-and-blooms/bitset" ]] &&
  [[ -d "${root}/vendor/github.com/consensys/bavard" ]] &&
  [[ -d "${root}/vendor/github.com/mmcloughlin/addchain" ]] &&
  [[ -d "${root}/vendor/golang.org/x/sys" ]] &&
  [[ -d "${root}/vendor/rsc.io/tmplfunc" ]]
}

prepare_vendor_bundle() {
  if ! command -v go >/dev/null 2>&1; then
    echo "Local 'go' command is required to prepare the offline vendor bundle." >&2
    exit 1
  fi

  vendor_tmp="$(mktemp -d -t continuum-kzg-vendor.XXXXXX)"
  local gocache_tmp
  gocache_tmp="$(mktemp -d -t continuum-go-build-cache.XXXXXX)"
  local rc=1

  echo "Preparing offline Go vendor bundle..."
  if (cd "$KZG_DIR" && GOCACHE="$gocache_tmp" GOPROXY=off GOSUMDB=off go mod vendor -o "${vendor_tmp}/vendor"); then
    if vendor_ok "$vendor_tmp"; then
      rc=0
    fi
  fi

  if [[ "$rc" -ne 0 ]]; then
    for proxy in $GO_PROXIES; do
      echo "Preparing vendor with GOPROXY=${proxy}"
      rm -rf "${vendor_tmp}/vendor"
      if (cd "$KZG_DIR" && GOCACHE="$gocache_tmp" GOPROXY="$proxy" GOSUMDB=off go mod vendor -o "${vendor_tmp}/vendor"); then
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

prepare_vendor_bundle
remote_vendor_archive="/tmp/$(basename "$vendor_archive")"
echo "Uploading offline Go vendor bundle to ${TARGET_HOST}:${remote_vendor_archive}"
scp "$vendor_archive" "${TARGET_HOST}:${remote_vendor_archive}"

echo "Extracting vendor bundle on seed server"
ssh "$TARGET_HOST" "set -e; cd ${REMOTE_ROOT_VALUE}/dumbo-mpc/gnark-crypto/kzg_ped_bls12-381; rm -rf vendor; tar -xzf ${remote_vendor_archive}; rm -f ${remote_vendor_archive}"

echo "Rebuilding kzg_ped_out.so on seed server inside Docker using offline vendor..."
ssh "$TARGET_HOST" "set -e; cd ${REMOTE_ROOT_VALUE}/dumbo-mpc; \
  if command -v docker-compose >/dev/null 2>&1; then \
    compose_cmd='docker-compose'; \
  elif docker compose version >/dev/null 2>&1; then \
    compose_cmd='docker compose'; \
  else \
    echo 'Neither docker-compose nor docker compose is available on the seed server.' >&2; \
    exit 127; \
  fi; \
  MPC_IMAGE='${MPC_IMAGE}' \$compose_cmd run --rm --no-deps dumbo-mpc bash -lc \
    'cd gnark-crypto/kzg_ped_bls12-381 && GOCACHE=/tmp/go-build-cache GOPROXY=off GOSUMDB=off GOFLAGS=-mod=vendor bash build_shared_library.sh && cp -f kzg_ped_out.so /opt/dumbo-mpc/kzg_ped_out.so'"

echo ""
echo "Seed server code sync complete."
