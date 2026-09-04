#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

usage() {
  echo "Usage: $0 <N>"
  echo "Example: $0 8"
}

if [[ $# -ne 1 ]]; then
  usage
  exit 1
fi

N="$1"

load_cluster_env
select_cluster_ips "$N"

write_config_sh "${ADMPC_DIR}/scripts/config.sh" "$N"
write_config_sh "${ASY_SCRIPTS_DIR}/config.sh" "$N"
write_config_sh "${REMOTE_DIR}/config.sh" "$N"

write_ip_txt "${ASY_SCRIPTS_DIR}/ip.txt" "${SELECTED_PEER_IPS[@]}"
write_ip_txt "${REMOTE_DIR}/ip.txt" "${SELECTED_PEER_IPS[@]}"

echo "Cluster config synced for N=${N}"
echo "Username: ${NODE_SSH_USERNAME}"
echo "SSH IPs: ${SELECTED_IPS[*]}"
echo "Protocol peer IPs: ${SELECTED_PEER_IPS[*]}"
