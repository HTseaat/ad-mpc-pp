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



for i in $(seq 1 $NODE_NUM); do
    ssh_user_host="${NODE_SSH_USERNAME}@${NODE_IPS[$i - 1]}"
    ssh "$ssh_user_host" -- "docker version"
done


cd ../../../..

tar Jcf dumbo-mpc.tar.xz dumbo-mpc

# copy these files to each node
for i in $(seq 1 $NODE_NUM); do
    ssh_user_host="${NODE_SSH_USERNAME}@${NODE_IPS[$i - 1]}"


    scp "dumbo-mpc.tar.xz" "$ssh_user_host:${REMOTE_ROOT}/dumbo-mpc.tar.xz"

done


for i in $(seq 1 $NODE_NUM); do
    ssh_user_host="${NODE_SSH_USERNAME}@${NODE_IPS[$i - 1]}"
    ssh "$ssh_user_host" -- "mkdir -p ${REMOTE_ROOT} && cd ${REMOTE_ROOT} && tar Jxf dumbo-mpc.tar.xz"

done



echo "All done."
