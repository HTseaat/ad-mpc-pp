#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 <n> <t> <d> <w>" >&2
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi
if [[ $# -ne 4 ]]; then
  usage
  exit 1
fi

exec /opt/unified/run_figure8_local_case.sh continuum-aggtrans "$@"
