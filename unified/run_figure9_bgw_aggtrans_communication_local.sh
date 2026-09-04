#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 <n> <t> <d> <w> <new-output-directory>" >&2
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi
if [[ $# -ne 5 ]]; then
  usage
  exit 1
fi

exec /opt/unified/run_figure9_communication_case.sh bgw-aggtrans "$@"
