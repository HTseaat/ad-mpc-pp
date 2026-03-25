#!/usr/bin/env bash
set -euo pipefail

source /opt/venv/admpc/bin/activate
export PYTHONPATH="/opt/admpc:${PYTHONPATH:-}"
cd /opt/admpc

if [[ $# -eq 0 ]]; then
  exec /bin/bash
fi

exec "$@"
