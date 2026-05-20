#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <exp2|exp3|exp4> [options]"
  echo "Example: $0 exp3 --only-d 6"
  exit 1
fi

exec "${SCRIPT_DIR}/run_suite.sh" dumbo-bgw-direct "$@"
