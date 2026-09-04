#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

exec "${SCRIPT_DIR}/run_suite.sh" dumbo exp3 --dumbo-timeout 900 "$@" \
  --auth-mode curve
