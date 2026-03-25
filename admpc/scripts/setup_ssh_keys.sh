#!/usr/bin/env bash
set -e

# Usage:
#   ./setup_ssh_keys.sh        # configure all NODE_IPS from config.sh
#   ./setup_ssh_keys.sh 8      # configure only first 8 NODE_IPS

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
source -- ./config.sh

ALL_IPS=("${NODE_IPS[@]}")
if [ "${#ALL_IPS[@]}" -eq 0 ]; then
    echo "No NODE_IPS found in scripts/config.sh"
    exit 1
fi

if [ -n "${1:-}" ]; then
    NUM_NODES="$1"
    if ! [[ "$NUM_NODES" =~ ^[0-9]+$ ]]; then
        echo "Invalid node count: $NUM_NODES"
        exit 1
    fi
    if [ "$NUM_NODES" -le 0 ]; then
        echo "Node count must be > 0"
        exit 1
    fi
    if [ "$NUM_NODES" -gt "${#ALL_IPS[@]}" ]; then
        echo "Requested nodes $NUM_NODES exceed NODE_IPS length ${#ALL_IPS[@]}"
        exit 1
    fi
else
    NUM_NODES="${#ALL_IPS[@]}"
fi

TARGET_IPS=("${ALL_IPS[@]:0:$NUM_NODES}")

KEY_PATH="$HOME/.ssh/id_ed25519"
if [ ! -f "$KEY_PATH" ]; then
    echo "SSH key not found, generating at $KEY_PATH"
    ssh-keygen -t ed25519 -f "$KEY_PATH" -N ""
else
    echo "Detected SSH key: $KEY_PATH"
fi

PUB_KEY_CONTENT=$(cat "$KEY_PATH.pub")
for ip in "${TARGET_IPS[@]}"; do
    echo "Configuring passwordless SSH for $NODE_SSH_USERNAME@$ip ..."
    ssh "$NODE_SSH_USERNAME@$ip" "mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
    ssh "$NODE_SSH_USERNAME@$ip" "grep -qxF '$PUB_KEY_CONTENT' ~/.ssh/authorized_keys || echo '$PUB_KEY_CONTENT' >> ~/.ssh/authorized_keys"
    echo "Done: $ip"
done

echo "Passwordless SSH setup completed for $NUM_NODES node(s)."
