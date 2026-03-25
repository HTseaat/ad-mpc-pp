#!/bin/bash
set -euo pipefail

# Parse command-line arguments
if [ $# -lt 5 ]; then
    echo "Usage: $0 <protocol> <N> <t> <layers> <total_cm>"
    exit 1
fi

PROTOCOL=$1
N=$2
t=$3
layers=$4
total_cm=$5

script_dir="$(cd "$(dirname "$0")" && pwd)"
source "${script_dir}/config.sh"

## N=16
## layers=8
## total_cm=300
layer_offset=$((layers - 2))

# 定义Python代码
PYTHON_CODE=$(cat << 'PYCODE'
import json
import os

N = int(os.environ["N"])
layers = int(os.environ["LAYERS"])
total_cm = int(os.environ["TOTAL_CM"])
output_dir = os.environ["OUTPUT_DIR"]
os.makedirs(output_dir, exist_ok=True)

protocol = os.environ["PROTOCOL"].lower()
need_layer_split = (protocol != "hbmpc")
effective_layers = layers if need_layer_split else 1

# 基础端口号
base_port = 7001

# 从环境变量读取 t 的值
t = int(os.environ["T"])
# 文件数量和 peers 数量，根据协议决定是否按 layer 拆分
num_files = N * effective_layers

# IP地址列表
ips = json.loads(os.environ["NODE_IPS_JSON"])
if N > len(ips):
    raise ValueError(f"N={N} exceeds NODE_IPS length ({len(ips)})")

# 构建peers列表
peers = []
# 若协议不拆分层，则只有一组节点
for layer in range(effective_layers):
    for idx, ip in enumerate(ips[:N]):
        port = base_port + layer  # 计算端口号
        peers.append(f"{ip}:{port}")

data = {
    "N": N,
    "t": t,
    "k": t,
    "my_id": 0,
    "my_send_id": 0,
    "layers": layers,
    "total_cm": total_cm,
    "peers": peers
}

def create_json_files(data, num_files):
    for i in range(num_files):
        data["my_id"] = i % N  # my_id循环从0到N-1
        data["my_send_id"] = i
        file_name = os.path.join(output_dir, f"local.{i}.json")
        with open(file_name, 'w') as json_file:
            json.dump(data, json_file, indent=4)
        print(f"{file_name} 已成功创建。")

create_json_files(data, num_files)
PYCODE
)

output_dir="${script_dir}/../conf/${PROTOCOL}_${total_cm}_${layer_offset}_${N}"
mkdir -p "${output_dir}"

NODE_IPS_JSON=$(printf '%s\n' "${NODE_IPS[@]}" | python3 -c 'import json,sys; print(json.dumps([line.strip() for line in sys.stdin if line.strip()]))')

N=$N LAYERS=$layers TOTAL_CM=$total_cm T=$t OUTPUT_DIR=${output_dir} PROTOCOL=${PROTOCOL} NODE_IPS_JSON="$NODE_IPS_JSON" python3 -c "$PYTHON_CODE"
