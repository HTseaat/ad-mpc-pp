#!/usr/bin/env bash
set -euo pipefail

trusted_setup_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Backward-compatible entry point.  The current suite includes stage 5.
exec bash "${trusted_setup_root}/scripts/test_stages_1_5.sh"
