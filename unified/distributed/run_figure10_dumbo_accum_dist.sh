#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

exec "${SCRIPT_DIR}/run_suite.sh" dumbo exp4 --dumbo-timeout 900 "$@" \
  --fault-profile accumulation --auth-mode curve
