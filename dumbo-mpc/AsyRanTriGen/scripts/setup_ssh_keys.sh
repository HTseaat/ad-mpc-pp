#!/usr/bin/env bash
set -e

# === 修改这里：你的远程服务器信息 ===
NODE_SSH_USERNAME="root"
NODE_IPS=("150.158.35.81"
    "124.220.16.71"
    "101.43.22.70"
	"111.229.197.238"
    "124.222.6.165"
    "1.116.108.22"
    "1.15.15.230"
	"111.229.40.140"
    "203.195.208.93"
    "106.53.26.38"
    "42.193.192.137"
	"43.139.185.179"
    "43.136.183.52"
    "148.70.214.61"
    "139.155.173.17"
	"1.14.63.87"
	)

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