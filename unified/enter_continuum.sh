#!/usr/bin/env bash
set -euo pipefail

source /opt/venv/continuum/bin/activate
export PYTHONPATH="/opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen:${PYTHONPATH:-}"
cd /opt/dumbo-mpc

if [[ $# -eq 0 ]]; then
  exec /bin/bash
fi

exec "$@"
