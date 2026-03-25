#!/usr/bin/env bash
set -e

source -- ./common.sh
ensure_script_dir

source -- ./config.sh

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

# trick: these nodes must:
# 1. have permission to run docker (i.e., user has been added to the docker group)
# 2. have the same username
# 3. be accessible via SSH (port 22) using the controller's private key
# 4. the user's default shell interprets character "~" as the home directory (which should be by default)

# check each node has access to docker; will fail if not


# 压缩文件
cd ..
cd conf
if [ ! -d "$conf_dir" ]; then
    echo "Config directory not found: $(pwd)/$conf_dir"
    exit 1
fi
tar Jcf "$archive_name" "$conf_dir"

# copy these files to each node
for i in $(seq 1 $NODE_NUM); do
    ssh_user_host="${NODE_SSH_USERNAME}@${NODE_IPS[$i - 1]}"
    # ssh "$ssh_user_host" -- "cd htadkg/conf && rm -rf admpc_4_cloud"
    # ssh "$ssh_user_host" -- "cd htadkg/conf && rm -rf admpc_4.tar.xz && rm -rf admpc_4"
    scp "$archive_name" "$ssh_user_host:${REMOTE_ROOT}/admpc/conf"
    ssh "$ssh_user_host" -- "cd ${REMOTE_ROOT}/admpc/conf && tar Jxf $archive_name"
    # scp "./dist/sdumoe-chain-ethermint.docker.image.tar.xz" "$ssh_user_host:~/sdumoe-docker/sdumoe-chain-ethermint.docker.image.tar.xz"
    # scp "./dist/sdumoe-chain-backend.docker.image.tar.xz" "$ssh_user_host:~/sdumoe-docker/sdumoe-chain-backend.docker.image.tar.xz"
done



echo "All done."
