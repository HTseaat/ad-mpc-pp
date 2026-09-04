#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export CIRCUIT_WIDTH=100
export ADTRANS_ALG4_PER_ITEM=0

exec "${SCRIPT_DIR}/run_suite.sh" admpc exp4 "$@" \
  --fault-profile attack --auth-mode curve
