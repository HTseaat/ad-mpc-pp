#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 <n> <t> <d>" >&2
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi
if [[ $# -ne 3 ]]; then
  usage
  exit 2
fi

exec /opt/unified/run_figure14_local_case.sh continuum "$@"
