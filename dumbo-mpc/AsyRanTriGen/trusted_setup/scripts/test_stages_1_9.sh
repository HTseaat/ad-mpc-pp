#!/usr/bin/env bash
set -euo pipefail

trusted_setup_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
asyran_root="$(cd "${trusted_setup_root}/.." && pwd)"
python_bin="${TRUSTED_SETUP_PYTHON:-/opt/venv/admpc/bin/python}"

cd "${asyran_root}"
"${python_bin}" -m unittest \
  trusted_setup.tests.test_params \
  trusted_setup.tests.test_stage4 \
  trusted_setup.tests.test_stage5 \
  trusted_setup.tests.test_stages_6_8_9 \
  trusted_setup.tests.test_stages_1_3 \
  trusted_setup.tests.test_distributed \
  -v
"${python_bin}" "${trusted_setup_root}/scripts/verify_stage0.py"
