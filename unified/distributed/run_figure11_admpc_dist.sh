#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export SHUFFLE_K=128
export SHUFFLE_MODE=iterated
export SHUFFLE_HANDOFF_INTERVAL=1
export ADTRANS_ALG4_PER_ITEM=0
export COMMITTEE_ELECTION_MODE=off

exec "${SCRIPT_DIR}/run_paper_scale_suite.sh" \
  admpc-shuffle exp-shuffle "4,10,16" "$@" --auth-mode curve
