#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export AGG_KZG_V2=1
export DISABLE_AGG_PROTO=0
export CIRCUIT_WIDTH=100
unset BGW_UNBATCHED_VERIFY DISABLE_RLC

exec "${SCRIPT_DIR}/run_suite.sh" continuum exp2 "$@" \
  --auth-mode curve --config-generator remote-image
