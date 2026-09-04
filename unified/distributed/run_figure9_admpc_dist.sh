#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export ADTRANS_ALG4_PER_ITEM=0
export CIRCUIT_WIDTH=100

exec "${SCRIPT_DIR}/run_paper_scale_suite.sh" admpc exp2 "4,10,16,22" \
  "$@" --auth-mode curve
