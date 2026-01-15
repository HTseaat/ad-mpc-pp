#!/bin/bash
# Usage: ./launch_asyrantrigen.sh <N_nodes> <batch_size>
# 将 AsyRanTriGen 跨服务器启动，依赖 config.sh 中的 NODE_SSH_USERNAME / NODE_IPS
# 若存在 ../ip.txt 且非空，则优先使用该文件中的 IP 列表（每行一个 IP）。

set -uo pipefail

if [ $# -lt 2 ]; then
  echo "Usage: $0 <N_nodes> <batch_size>" >&2
  exit 1
fi

NODES_NUM="$1"
BATCH_SIZE="$2"
LAYERS="${3:-10}"


# 读取统一的节点配置，与 control-node.sh 保持一致
# 要求当前脚本位于 remote/AsyRanTriGen_scripts/ 目录
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# 引入 config.sh（提供 NODE_SSH_USERNAME / NODE_IPS）
source -- ../config.sh

# 优先从 ../ip.txt 读取 IP；如果没有或为空，则使用 NODE_IPS 数组
IP_FILE="../ip.txt"
IPS_LIST=()
if [[ -f "$IP_FILE" ]] && [[ -s "$IP_FILE" ]]; then
    # 兼容 CRLF，去掉注释与空行
    mapfile -t IPS_LIST < <(sed -e 's/\r$//' -e '/^\s*#/d' -e '/^\s*$/d' "$IP_FILE")
else
  # 使用 config.sh 中的 NODE_IPS 数组
  IPS_LIST=("${NODE_IPS[@]}")
fi

echo "[DEBUG] 期望节点数(NODES_NUM) = $NODES_NUM"
echo "[DEBUG] batch_size(BATCH_SIZE) = $BATCH_SIZE"
echo "[DEBUG] layers(LAYERS) = $LAYERS"
echo "[DEBUG] 实际读取到的 IP 数量 = ${#IPS_LIST[@]}"
echo "[DEBUG] IP 列表: ${IPS_LIST[*]}"

mkdir -p logs

# 基础健壮性检查
if [[ ${#IPS_LIST[@]} -eq 0 ]]; then
  echo "[ERROR] 没有可用的 IP。请在 ../config.sh 配置 NODE_IPS，或在 ../ip.txt 中填写 IP 列表。" >&2
  exit 1
fi

if [[ ${#IPS_LIST[@]} -lt $NODES_NUM ]]; then
  echo "[WARN] 可用 IP 数量(${#IPS_LIST[@]}) 少于期望节点数($NODES_NUM)，仅对前 ${#IPS_LIST[@]} 台机器发起启动。" >&2
  NODES_NUM=${#IPS_LIST[@]}
fi

# 按顺序在每台机器启动一个节点进程：对应 conf/mpc_<N>/local.<id>.json
id=0
for (( idx=0; idx< NODES_NUM; idx++ )); do
    ip="${IPS_LIST[$idx]}"
    ssh_user_host="${NODE_SSH_USERNAME}@${ip}"

    (
        peer_port=$((7001))
        echo "[DEBUG] Node ID $id will use peer_port=$peer_port"
        ssh -n -T -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 "$ssh_user_host" \
    "cd ~/dumbo-mpc && \
        docker-compose run -p ${peer_port}:${peer_port} \
        -w /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen \
        dumbo-mpc \
        bash -lc 'python3 scripts/init_batchsize_layer_ip.py --N $NODES_NUM --k $BATCH_SIZE --layers $LAYERS && \
                    python3 -u -m scripts.run_beaver_triple -d -f conf/mpc_$NODES_NUM/local.${id}.json -time 0'"
    ) > "logs/node${idx}.log" 2>&1 &
    (( id++ ))
done

# 等待所有后台 ssh 结束
wait

echo "✅ 已向 $NODES_NUM 台服务器下发 AsyRanTriGen 进程启动命令。查看各机 ~/dumbo-mpc/dumbo-mpc/AsyRanTriGen/log/ 下的 logs-<id>.log。"