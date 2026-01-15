#!/usr/bin/env bash
set -e

# === 修改这里：你的远程服务器信息 ===
NODE_SSH_USERNAME="root"

# === 从 ip.txt 读取 IP 列表，并可选只使用前 N 个 ===
# 用法：
#   ./setup_ssh_keys.sh        # 对 ip.txt 中所有 IP 配置免密
#   ./setup_ssh_keys.sh 8      # 只对 ip.txt 中前 8 个 IP 配置免密

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IP_FILE="$SCRIPT_DIR/ip.txt"

if [ ! -f "$IP_FILE" ]; then
    echo "❌ 找不到 IP 列表文件: $IP_FILE"
    exit 1
fi

# 读取非空行，去掉行尾空白
mapfile -t ALL_IPS < <(grep -v '^[[:space:]]*$' "$IP_FILE" | sed 's/[[:space:]]*$//')

if [ "${#ALL_IPS[@]}" -eq 0 ]; then
    echo "❌ $IP_FILE 中没有任何有效 IP 行"
    exit 1
fi

if [ -n "$1" ]; then
    NUM_NODES="$1"
    if ! [[ "$NUM_NODES" =~ ^[0-9]+$ ]]; then
        echo "❌ 参数必须是正整数，例如: ./setup_ssh_keys.sh 8"
        exit 1
    fi
    if [ "$NUM_NODES" -le 0 ]; then
        echo "❌ 节点数量必须 > 0"
        exit 1
    fi
    if [ "$NUM_NODES" -gt "${#ALL_IPS[@]}" ]; then
        echo "❌ 请求的节点数量 $NUM_NODES 超过 ip.txt 中的 IP 数量 ${#ALL_IPS[@]}"
        exit 1
    fi
else
    NUM_NODES="${#ALL_IPS[@]}"
fi

NODE_IPS=("${ALL_IPS[@]:0:$NUM_NODES}")

echo "📌 将为前 $NUM_NODES 个节点配置免密登录："
printf '  - %s\n' "${NODE_IPS[@]}"

# === 第一步：在本地生成 SSH 密钥对（如果没有） ===
KEY_PATH="$HOME/.ssh/id_ed25519"
if [ ! -f "$KEY_PATH" ]; then
    echo "📌 未检测到 SSH 密钥对，正在生成..."
    ssh-keygen -t ed25519 -f "$KEY_PATH" -N ""
else
    echo "✅ 已检测到 SSH 密钥：$KEY_PATH"
fi

# === 第二步：将公钥分发到每个远程主机 ===
PUB_KEY_CONTENT=$(cat "$KEY_PATH.pub")
for ip in "${NODE_IPS[@]}"; do
    echo "🚀 正在配置 $NODE_SSH_USERNAME@$ip 的免密登录..."
    
    ssh "$NODE_SSH_USERNAME@$ip" "mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
    
    # 检查是否已存在相同公钥，若没有再追加
    ssh "$NODE_SSH_USERNAME@$ip" "grep -qxF '$PUB_KEY_CONTENT' ~/.ssh/authorized_keys || echo '$PUB_KEY_CONTENT' >> ~/.ssh/authorized_keys"

    echo "✅ $ip 配置完成。"
done

echo "🎉 所有节点免密登录配置完成。你现在可以直接 ssh 登录任意节点而无需密码。"