#!/usr/bin/env bash
# Install Go 1.21 on all cluster nodes.
# Safe to re-run; skips install if go 1.21 is already present.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"
load_cluster_env

GO_VERSION="1.21.13"
GO_TAR="go${GO_VERSION}.linux-amd64.tar.gz"
GO_URL="https://go.dev/dl/${GO_TAR}"

N=${#CLUSTER_IPS[@]}
echo "Installing Go ${GO_VERSION} on ${N} nodes..."

for i in $(seq 1 "$N"); do
    host="${NODE_SSH_USERNAME}@${CLUSTER_IPS[$i-1]}"
    echo ""
    echo "=== Node ${i}: ${host} ==="

    ssh "$host" bash <<EOF
set -euo pipefail
if /usr/local/go/bin/go version 2>/dev/null | grep -q "go${GO_VERSION}"; then
    echo "  Go ${GO_VERSION} already installed, skipping."
    exit 0
fi
echo "  Downloading Go ${GO_VERSION}..."
curl -fsSL "${GO_URL}" -o /tmp/${GO_TAR}
echo "  Installing to /usr/local/go..."
rm -rf /usr/local/go
tar -C /usr/local -xzf /tmp/${GO_TAR}
rm /tmp/${GO_TAR}
echo "  Installed: \$(/usr/local/go/bin/go version)"
EOF

    echo "  Done."
done

echo ""
echo "All ${N} nodes have Go ${GO_VERSION} at /usr/local/go/bin/go"
echo "Run ./sync_ablation_code.sh to compile the .so on each node."
