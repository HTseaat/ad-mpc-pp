#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 <n> <t> <Q> <new-output-directory>" >&2
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi
if [[ $# -ne 4 ]]; then
  usage
  exit 1
fi

exec /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/trusted_setup/scripts/run_distributed_local.sh \
  "$1" "$2" "$3" "$4"
