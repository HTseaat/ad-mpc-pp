#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export SHUFFLE_K=128
export SHUFFLE_MODE=iterated
export SHUFFLE_HANDOFF_INTERVAL=1
export SHUFFLE_HANDOFF_GRACE_SECONDS=3
export AGG_KZG_V2=1
export DISABLE_AGG_PROTO=0
export COMMITTEE_ELECTION_MODE=off
unset BGW_UNBATCHED_VERIFY DISABLE_RLC

exec "${SCRIPT_DIR}/run_paper_scale_suite.sh" \
  shuffle exp-shuffle "4,10,16" "$@" \
  --auth-mode curve --config-generator remote-image
