#!/usr/bin/env bash
set -euo pipefail

source /opt/venv/admpc/bin/activate
export PYTHONPATH="/opt/admpc:${PYTHONPATH:-}"
cd /opt/admpc

if [[ $# -lt 4 || $# -gt 5 ]]; then
  echo "Usage: run-admpc-local [admpc|admpc-linear|admpc-nonlinear|fluid1|fluid2|hbmpc|hbmpc_attack] <n> <t> <layers> <total_cm>" >&2
  exit 1
fi

exec ./local_admpc_run.sh "$@"
