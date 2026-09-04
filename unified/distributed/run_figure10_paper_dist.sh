#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  echo "Usage: $0 [common run_suite options]" >&2
  echo "Runs each Figure 10 curve once: AD-MPC-Accum, Continuum-Accum, Dumbo-MPC, Continuum-Attack, and AD-MPC-Attack." >&2
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

"${SCRIPT_DIR}/run_admpc_dist.sh" exp4 --fault-profile accumulation "$@"
"${SCRIPT_DIR}/run_continuum_dist.sh" exp4 --fault-profile accumulation "$@"
"${SCRIPT_DIR}/run_dumbo_dist.sh" exp4 --fault-profile accumulation "$@"
"${SCRIPT_DIR}/run_continuum_dist.sh" exp4 --fault-profile attack "$@"
"${SCRIPT_DIR}/run_admpc_dist.sh" exp4 --fault-profile attack "$@"
