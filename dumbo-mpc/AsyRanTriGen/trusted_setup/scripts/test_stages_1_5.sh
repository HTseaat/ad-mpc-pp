#!/usr/bin/env bash
set -euo pipefail

trusted_setup_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Backward-compatible entry point. Stage 7 is intentionally deferred; the
# current suite additionally covers stages 6, 8, and 9.
exec bash "${trusted_setup_root}/scripts/test_stages_1_9.sh"
