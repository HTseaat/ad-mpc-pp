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
# cd ../../..
# cd adkg
# rm -rf admpc_4.tar.xz

# copy these files to each node
for i in $(seq 1 $NODE_NUM); do
    ssh_user_host="${NODE_SSH_USERNAME}@${NODE_IPS[$i - 1]}"
    # ssh "$ssh_user_host" -- "cd dumbo-mpc/dumbo-mpc/AsyRanTriGen/scripts && rm -rf ip.txt"
    ssh "$ssh_user_host" -- "cd dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver && rm -rf admpc2_dynamic.py"
    # ssh "$ssh_user_host" -- "cd dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver && rm -rf hbacss.py"

    # scp "ip.txt" "$ssh_user_host:~/dumbo-mpc/dumbo-mpc/AsyRanTriGen/scripts"
    # scp "$(dirname "$0")/../beaver/hbacss.py" "$ssh_user_host:~/dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/"
    scp "$(dirname "$0")/../beaver/admpc2_dynamic.py" "$ssh_user_host:~/dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/"
done



echo "All done."