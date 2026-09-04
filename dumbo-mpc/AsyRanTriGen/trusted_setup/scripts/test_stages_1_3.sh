#!/usr/bin/env bash
set -euo pipefail

trusted_setup_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Backward-compatible entry point.  Stage 4 extends the same adapter, so the
# current regression command intentionally includes its checks as well.
exec bash "${trusted_setup_root}/scripts/test_stages_1_4.sh"
