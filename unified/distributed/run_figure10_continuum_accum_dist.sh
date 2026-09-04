#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export CIRCUIT_WIDTH=100
export AGG_KZG_V2=1
export DISABLE_AGG_PROTO=0
unset BGW_UNBATCHED_VERIFY DISABLE_RLC

exec "${SCRIPT_DIR}/run_suite.sh" continuum exp4 "$@" \
  --fault-profile accumulation --auth-mode curve \
  --config-generator remote-image
