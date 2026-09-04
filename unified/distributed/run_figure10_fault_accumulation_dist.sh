#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  echo "Usage: $0 [common run_suite options]" >&2
  echo "Runs AD-MPC (t silent/committee), Continuum (t silent/committee), then Dumbo-MPC (t new silent/epoch)." >&2
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

"${SCRIPT_DIR}/run_admpc_dist.sh" exp4 --fault-profile accumulation "$@"
"${SCRIPT_DIR}/run_continuum_dist.sh" exp4 --fault-profile accumulation "$@"
"${SCRIPT_DIR}/run_dumbo_dist.sh" exp4 --fault-profile accumulation "$@"
