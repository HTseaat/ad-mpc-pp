#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <exp1|exp2|exp3|exp4> [options]"
  exit 1
fi

exec "${SCRIPT_DIR}/run_suite.sh" admpc "$@"
