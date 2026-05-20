#!/usr/bin/env bash
# Sync ablation experiment code changes to all cluster nodes and recompile the Go .so.
#
# Changed files:
#   - beaver/hbacss.py         (DISABLE_AGG_PROTO knob)
#   - kzg_ped_bls12-381/kzg_ped_out.go  (DISABLE_RLC knob + BatchVerifyTest)
#
# Usage: ./sync_ablation_code.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"
load_cluster_env

if [[ -n "${GO_PROXY:-}" ]]; then
    GO_PROXIES="$GO_PROXY"
else
    GO_PROXIES="${GO_PROXIES:-https://mirrors.aliyun.com/goproxy/,direct https://goproxy.cn,direct https://goproxy.io,direct direct}"
fi

REMOTE_ROOT="~"
if [[ -n "${REMOTE_WORKSPACE_DIR:-}" ]]; then
    REMOTE_ROOT="~/${REMOTE_WORKSPACE_DIR}"
fi

LOCAL_HBACSS="${ASY_DIR}/beaver/hbacss.py"
LOCAL_KZG_GO="${CONTINUUM_DIR}/gnark-crypto/kzg_ped_bls12-381/kzg_ped_out.go"
LOCAL_KZG_DIR="${CONTINUUM_DIR}/gnark-crypto/kzg_ped_bls12-381"

REMOTE_DUMBO="${REMOTE_ROOT}/dumbo-mpc"
REMOTE_BEAVER="${REMOTE_ROOT}/dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver"
REMOTE_KZG="${REMOTE_ROOT}/dumbo-mpc/gnark-crypto/kzg_ped_bls12-381"

N=${#CLUSTER_IPS[@]}
VENDOR_TMP=""
VENDOR_ARCHIVE=""
trap 'rm -f "$VENDOR_ARCHIVE"; if [[ -n "$VENDOR_TMP" ]]; then rm -rf "$VENDOR_TMP"; fi' EXIT

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

    VENDOR_TMP="$(mktemp -d -t continuum-kzg-vendor.XXXXXX)"
    local gocache_tmp
    gocache_tmp="$(mktemp -d -t continuum-go-build-cache.XXXXXX)"
    local rc=1

    echo "Preparing offline Go vendor bundle..."
    if (cd "$LOCAL_KZG_DIR" && GOCACHE="$gocache_tmp" GOPROXY=off GOSUMDB=off go mod vendor -o "${VENDOR_TMP}/vendor"); then
        if vendor_ok "$VENDOR_TMP"; then
            rc=0
        fi
    fi

    if [[ "$rc" -ne 0 ]]; then
        for proxy in $GO_PROXIES; do
            echo "Preparing vendor with GOPROXY=${proxy}"
            rm -rf "${VENDOR_TMP}/vendor"
            if (cd "$LOCAL_KZG_DIR" && GOCACHE="$gocache_tmp" GOPROXY="$proxy" GOSUMDB=off go mod vendor -o "${VENDOR_TMP}/vendor"); then
                if vendor_ok "$VENDOR_TMP"; then
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

    VENDOR_ARCHIVE="$(mktemp -t continuum-kzg-vendor.XXXXXX.tar.gz)"
    tar -C "$VENDOR_TMP" -czf "$VENDOR_ARCHIVE" vendor
}

echo "Syncing ablation code to ${N} nodes..."
echo "GOPROXY retry list for local vendor preparation: ${GO_PROXIES}"
prepare_vendor_bundle

for i in $(seq 1 "$N"); do
    host="${NODE_SSH_USERNAME}@${CLUSTER_IPS[$i-1]}"
    echo ""
    echo "=== Node ${i}: ${host} ==="

    echo "  Copying hbacss.py..."
    scp "$LOCAL_HBACSS" "${host}:${REMOTE_BEAVER}/hbacss.py"

    echo "  Copying kzg_ped_out.go..."
    scp "$LOCAL_KZG_GO" "${host}:${REMOTE_KZG}/kzg_ped_out.go"

    remote_vendor_archive="/tmp/$(basename "$VENDOR_ARCHIVE")"
    echo "  Copying offline Go vendor bundle..."
    scp "$VENDOR_ARCHIVE" "${host}:${remote_vendor_archive}"
    ssh "$host" "set -e; cd ${REMOTE_KZG}; rm -rf vendor; tar -xzf ${remote_vendor_archive}; rm -f ${remote_vendor_archive}"

    # Build inside the Docker container so the .so is linked against the
    # container's glibc (Ubuntu 20.04), not the host OS.  The volume mount
    # (./:/opt/dumbo-mpc) writes the result back to disk automatically.
    echo "  Compiling kzg_ped_out.so inside Docker container using offline vendor..."
    ssh "$host" "cd ${REMOTE_DUMBO} && MPC_IMAGE=${MPC_IMAGE:-continuum:latest} docker compose run --rm --no-deps dumbo-mpc bash -lc 'cd gnark-crypto/kzg_ped_bls12-381 && GOCACHE=/tmp/go-build-cache GOPROXY=off GOSUMDB=off GOFLAGS=-mod=vendor bash build_shared_library.sh && cp -f kzg_ped_out.so /opt/dumbo-mpc/kzg_ped_out.so'"

    echo "  Done."
done

echo ""
echo "All ${N} nodes updated and compiled."
