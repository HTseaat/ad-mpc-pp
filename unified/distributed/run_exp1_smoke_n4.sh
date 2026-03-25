#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<USAGE
Usage: $0 [run_suite options]

Run exp1 smoke test for both protocols with n=4 only:
  1) admpc exp1
  2) continuum exp1

All arguments are forwarded to run_suite.sh, for example:
  $0 --cluster-env ./cluster.env --timeout 20
USAGE
}

if [[ $# -gt 0 ]]; then
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
  esac
fi

echo "[smoke] Running AD-MPC exp1 with n=4 ..."
"${SCRIPT_DIR}/run_suite.sh" admpc exp1 --only-n 4 --sleep-between-case 0 "$@"

echo "[smoke] Running continuum exp1 with n=4 ..."
"${SCRIPT_DIR}/run_suite.sh" continuum exp1 --only-n 4 --sleep-between-case 0 "$@"

echo "[smoke] Done."
