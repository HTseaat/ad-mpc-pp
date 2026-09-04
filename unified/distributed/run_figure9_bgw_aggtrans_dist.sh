#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export AGG_KZG_V2=1
export DISABLE_AGG_PROTO=0
export CIRCUIT_WIDTH=100
export BGW_UNBATCHED_VERIFY=1
export BGW_UNBATCHED_BATCH_ALL_VERIFY=0
export BGW_UNBATCHED_BATCH_SHARE_VERIFY=0
export BGW_UNBATCHED_BATCH_HIDDEN_VERIFY=0
export BGW_UNBATCHED_BATCH_ZERO_VERIFY=0
export BGW_UNBATCHED_BATCH_PROD_VERIFY=0
unset DISABLE_RLC

exec "${SCRIPT_DIR}/run_suite.sh" bgw-aggtrans exp2 "$@" \
  --auth-mode curve --config-generator remote-image
