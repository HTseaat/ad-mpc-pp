#!/usr/bin/env bash
set -e

source -- ./common.sh
ensure_script_dir

source -- ./config.sh

SSH_OPTIONS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes)

REMOTE_WORKSPACE_DIR="${REMOTE_WORKSPACE_DIR:-}"
if [ -n "$REMOTE_WORKSPACE_DIR" ]; then
    REMOTE_ROOT="~/${REMOTE_WORKSPACE_DIR}"
else
    REMOTE_ROOT="~"
fi

if [ $# -lt 1 ]; then
    echo "Usage: $0 <config_dir>"
    exit 1
fi

conf_dir="$1"
archive_name="${conf_dir}.tar.xz"
parallelism="${DISTRIBUTE_PARALLELISM:-8}"

if ! [[ "$parallelism" =~ ^[1-9][0-9]*$ ]]; then
    echo "DISTRIBUTE_PARALLELISM must be a positive integer" >&2
    exit 1
fi

# trick: these nodes must:
# 1. have permission to run docker (i.e., user has been added to the docker group)
# 2. have the same username
# 3. be accessible via SSH (port 22) using the controller's private key
# 4. the user's default shell interprets character "~" as the home directory (which should be by default)

# check each node has access to docker; will fail if not


# 压缩文件
cd ../
cd conf
if [ ! -d "$conf_dir" ]; then
    echo "Config directory not found: $(pwd)/$conf_dir"
    exit 1
fi
tar Jcf "$archive_name" "$conf_dir"


# Copy and extract on multiple independent nodes concurrently. Each worker
# still receives exactly one archive; the limit avoids opening an unbounded
# number of public SSH connections on larger clusters.
deploy_node() {
    i="$1"
    ssh_user_host="${NODE_SSH_USERNAME}@${NODE_IPS[$i - 1]}"
    # ssh "$ssh_user_host" -- "cd htadkg/conf && rm -rf admpc_4_cloud"
    # ssh "$ssh_user_host" -- "cd htadkg/conf && rm -rf admpc_4.tar.xz && rm -rf admpc_4"
    scp "${SSH_OPTIONS[@]}" "$archive_name" "$ssh_user_host:${REMOTE_ROOT}/dumbo-mpc/dumbo-mpc/AsyRanTriGen/conf"
    ssh "${SSH_OPTIONS[@]}" "$ssh_user_host" -- "cd ${REMOTE_ROOT}/dumbo-mpc/dumbo-mpc/AsyRanTriGen/conf && tar Jxf $archive_name"
    # scp "./dist/sdumoe-chain-ethermint.docker.image.tar.xz" "$ssh_user_host:~/sdumoe-docker/sdumoe-chain-ethermint.docker.image.tar.xz"
    # scp "./dist/sdumoe-chain-backend.docker.image.tar.xz" "$ssh_user_host:~/sdumoe-docker/sdumoe-chain-backend.docker.image.tar.xz"
}

pids=()
failed=0
for i in $(seq 1 "$NODE_NUM"); do
    deploy_node "$i" &
    pids+=("$!")

    if [ "${#pids[@]}" -ge "$parallelism" ]; then
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

if [ "$failed" -ne 0 ]; then
    echo "One or more config distributions failed" >&2
    exit 1
fi


echo "All done."
