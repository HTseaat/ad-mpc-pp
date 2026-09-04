#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export SHUFFLE_K=128
export SHUFFLE_MODE=iterated
export SHUFFLE_HANDOFF_INTERVAL=static
export COMMITTEE_ELECTION_MODE=off
export BGW_UNBATCHED_VERIFY=0
export BGW_BATCH_UNBATCHED_PROD_VERIFY=1
export BGW_UNBATCHED_BATCH_ALL_VERIFY=0
export BGW_UNBATCHED_BATCH_SHARE_VERIFY=0
export BGW_UNBATCHED_BATCH_HIDDEN_VERIFY=0
export BGW_UNBATCHED_BATCH_ZERO_VERIFY=0
export BGW_UNBATCHED_BATCH_PROD_VERIFY=0
unset DISABLE_AGG_PROTO DISABLE_RLC

exec "${SCRIPT_DIR}/run_paper_scale_suite.sh" \
  shuffle-bgw-static exp-shuffle "4,10,16" "$@" \
  --auth-mode curve --config-generator remote-image
