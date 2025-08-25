#!/usr/bin/env bash
set -e

source -- ./common.sh
ensure_script_dir

source -- ./config.sh

# trick: these nodes must:
# 1. have permission to run docker (i.e., user has been added to the docker group)
# 2. have the same username
# 3. be accessible via SSH (port 22) using the controller's private key
# 4. the user's default shell interprets character "~" as the home directory (which should be by default)

# check each node has access to docker; will fail if not


# 压缩文件
cd ../
cd conf
# rm -rf admpc_4.tar.xz
# tar Jcf hbmpc_300_4_16.tar.xz hbmpc_300_4_16
tar Jcf admpc_0_8_16.tar.xz admpc_0_8_16


# copy these files to each node
for i in $(seq 1 $NODE_NUM); do
    ssh_user_host="${NODE_SSH_USERNAME}@${NODE_IPS[$i - 1]}"
    # ssh "$ssh_user_host" -- "cd htadkg/conf && rm -rf admpc_4_cloud"
    # ssh "$ssh_user_host" -- "cd htadkg/conf && rm -rf admpc_4.tar.xz && rm -rf admpc_4"
    scp "admpc_0_8_16.tar.xz" "$ssh_user_host:~/dumbo-mpc/dumbo-mpc/AsyRanTriGen/conf"
    ssh "$ssh_user_host" -- "cd dumbo-mpc/dumbo-mpc/AsyRanTriGen/conf && tar Jxf admpc_0_8_16.tar.xz"
    # scp "./dist/sdumoe-chain-ethermint.docker.image.tar.xz" "$ssh_user_host:~/sdumoe-docker/sdumoe-chain-ethermint.docker.image.tar.xz"
    # scp "./dist/sdumoe-chain-backend.docker.image.tar.xz" "$ssh_user_host:~/sdumoe-docker/sdumoe-chain-backend.docker.image.tar.xz"
done



echo "All done."