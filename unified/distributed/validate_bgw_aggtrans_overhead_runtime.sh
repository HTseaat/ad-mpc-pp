#!/usr/bin/env bash
set -euo pipefail

WORKSPACE_ROOT="${1:-${HOME}/Continuum}"
MPC_IMAGE_VALUE="${2:-644843666939.dkr.ecr.us-west-2.amazonaws.com/continuum@sha256:a30f3c25bc71e21f2d610c6c12d6b23bdefe2b6a0a6d2650f616afc3e3eb7907}"
COMPOSE_ROOT="${WORKSPACE_ROOT}/dumbo-mpc"

cd "$COMPOSE_ROOT"
MPC_IMAGE="$MPC_IMAGE_VALUE" \
  docker compose -f docker-compose.aws.yml config --quiet >/dev/null

MPC_IMAGE="$MPC_IMAGE_VALUE" \
  docker compose -f docker-compose.aws.yml run --rm --no-deps \
    -e BGW_UNBATCHED_VERIFY=1 \
    -e AGG_KZG_V2=1 \
    -e DISABLE_AGG_PROTO=0 \
    dumbo-mpc /opt/venv/continuum/bin/python3 -c '
import hashlib
import os
import platform
from ctypes import CDLL
from pathlib import Path

expected = {
    "beaver/ipc.py": "8c15ad0adbcdf4698d6f481f4e1550488f7e4fb6339a668ed0e0eea0b56b7149",
    "beaver/hbacss.py": "dee07ad43f3c84d75dac96bcd9c7362cbfef0f5904867f73a96bf93a4d6dad74",
    "beaver/communication_metrics.py": "bde55b948f8569d98977dc206795546768edaa1717623c46a4d2f80ea99c72f2",
    "beaver/protocol_metrics.py": "3074111bf2f0b6bab8bf85c31d18766980184fe25d33aad78b6d3e9eeec4a034",
    "beaver/bgw_multiplication.py": "6edef36733cfbc594e759249357cefc2e9ebdf31c10d0b14d55a040f7bf8d471",
    "beaver/admpc2_dynamic_bgw_aggtrans.py": "4e7ac93d7fe5a708f6e189fc19613fcb4cf11083aa75df1066a654fb4f19e50e",
    "scripts/admpc2_dynamic_bgw_aggtrans_run.py": "a7e4ea6fc634da5f521ac397d7849e596adf1fbea77185d8345f3187779263a2",
    "kzg_ped_out.so": "e9f24330ddd60f3c3c6b9a0938a5603d7d53d3e48dbd01de24581212154b6337",
}
assert platform.machine() == "x86_64"
assert os.environ["BGW_UNBATCHED_VERIFY"] == "1"
for relative_path, expected_hash in expected.items():
    actual_hash = hashlib.sha256(Path(relative_path).read_bytes()).hexdigest()
    assert actual_hash == expected_hash, (relative_path, actual_hash)

library = CDLL("./kzg_ped_out.so")
for symbol in (
    "pyParseRandomUnbatched",
    "pyBatchVerifyUnbatched",
    "pyBatchhiddenverifyUnbatched",
    "pyBatchhiddenzeroverifyUnbatched",
    "pyProdverifyUnbatched",
):
    getattr(library, symbol)

import inspect

from beaver import (
    admpc2_dynamic_bgw_aggtrans,
    bgw_multiplication,
    communication_metrics,
    hbacss,
    ipc,
    protocol_metrics,
)
import scripts.admpc2_dynamic_bgw_aggtrans_run

assert hasattr(communication_metrics.CommunicationMetricsArtifact, "record_payload_calibration")
assert hasattr(ipc.NodeCommunicator, "write_metrics_checkpoint")
assert protocol_metrics.bgw_effective_batch_size(22, 100) == 100
assert "self.acss.mpc_instance = self.mpc_instance" in inspect.getsource(
    bgw_multiplication.BGWReduction.acss_step
)
bgw_run_source = inspect.getsource(bgw_multiplication.BGWReduction.run_multiply)
assert "await self.acss_task" not in bgw_run_source
assert "LOCAL_BGW_ACSS_BARRIER" not in bgw_run_source
wrapper_source = inspect.getsource(
    admpc2_dynamic_bgw_aggtrans.ADMPC_Dynamic._run_bgw_reduction
)
assert "self._retained_bgw_reductions.append(bgw)" in wrapper_source
assert admpc2_dynamic_bgw_aggtrans.ADMPC_Dynamic._run_bgw_reduction
print("PASS bgw-aggtrans runtime overlay imports/symbols")
'

residual="$({ docker ps -a --filter name=dumbo-mpc-run --format '{{.Names}}' || true; } | wc -l)"
if [[ "$residual" -ne 0 ]]; then
  echo "Residual dumbo-mpc-run containers: ${residual}" >&2
  exit 1
fi

echo "PASS production Compose validation; residual_run_containers=0"
