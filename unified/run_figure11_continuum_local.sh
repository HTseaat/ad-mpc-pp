#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 <n> <t>" >&2
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi
if [[ $# -ne 2 ]]; then
  usage
  exit 2
fi

exec /opt/unified/run_figure11_local_case.sh continuum "$@"
