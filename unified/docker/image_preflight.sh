#!/usr/bin/env bash
set -euo pipefail

mode="${1:-}"
if [[ -n "$mode" && "$mode" != "--build-check" && "$mode" != "--runtime-check" ]]; then
  echo "Usage: $0 [--build-check|--runtime-check]" >&2
  exit 2
fi

expected_arch="${MPC_EXPECTED_ARCH:-x86_64}"
actual_arch="$(uname -m)"
if [[ "$actual_arch" != "$expected_arch" ]]; then
  echo "architecture mismatch: expected=${expected_arch}, actual=${actual_arch}" >&2
  exit 1
fi

continuum_root="/opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen"
continuum_python="/opt/venv/continuum/bin/python3"
admpc_python="/opt/venv/admpc/bin/python3"
kzg_lib="${continuum_root}/kzg_ped_out.so"
bulletproof_lib="${continuum_root}/libbulletproofs_amcl.so"

required_paths=(
  "$continuum_python"
  "$admpc_python"
  "$kzg_lib"
  "$bulletproof_lib"
  "$continuum_root/beaver/aggregation_interfaces.py"
  "$continuum_root/beaver/protocol_metrics.py"
  "$continuum_root/beaver/fault_accumulation.py"
  "$continuum_root/committee_election/protocol.py"
  "$continuum_root/scripts/__init__.py"
  "$continuum_root/scripts/admpc2_dynamic_run.py"
  "$continuum_root/trusted_setup/run_local.py"
  "$continuum_root/trusted_setup/continuum_kzg_smoke"
  "$continuum_root/trusted_setup/build/qsdh-py/pairing/pypairing/pypairing.so"
  "/opt/unified/distributed/run_suite.sh"
  "/opt/unified/run_trusted_setup_local.sh"
  "/opt/unified/run_committee_election_local.sh"
)

for path in "${required_paths[@]}"; do
  if [[ ! -e "$path" ]]; then
    echo "missing required image path: $path" >&2
    exit 1
  fi
done

required_entrypoints=(
  "enter-admpc=/opt/unified/enter_admpc.sh"
  "enter-continuum=/opt/unified/enter_continuum.sh"
  "run-admpc-local=/opt/unified/run_admpc_local.sh"
  "run-continuum-local=/opt/unified/run_continuum_local.sh"
  "run-dumbo-mpc-local=/opt/unified/run_dumbo_mpc_local.sh"
)
for entrypoint in "${required_entrypoints[@]}"; do
  command_name="${entrypoint%%=*}"
  expected_target="${entrypoint#*=}"
  command_path="/usr/local/bin/${command_name}"
  if [[ ! -L "$command_path" ]]; then
    echo "missing command symlink: $command_path" >&2
    exit 1
  fi
  if [[ "$(readlink "$command_path")" != "$expected_target" ]]; then
    echo "wrong command symlink target: ${command_path} -> $(readlink "$command_path")" >&2
    exit 1
  fi
  if [[ ! -x "$expected_target" ]]; then
    echo "command target is not executable: $expected_target" >&2
    exit 1
  fi
done

"$admpc_python" \
  "$continuum_root/trusted_setup/scripts/verify_stage0.py" --source-only

(
  cd "$continuum_root"
  PYTHONPATH="$continuum_root" "$admpc_python" - <<'PY'
from trusted_setup.protocol.bootstrap import activate_upstream

activate_upstream()
from adkg.ntl import vandermonde_batch_evaluate
from pypairing import G1, G2, ZR, pair

g, g2, alpha = G1.rand(b"check-g"), G2.rand(b"checkg2"), ZR(7)
assert pair(g ** alpha, g2) == pair(g, g2 ** alpha)
print("PASS trusted-setup locked snapshot/native build")
PY
)

case "$expected_arch" in
  x86_64) file_pattern='x86-64' ;;
  aarch64|arm64) file_pattern='ARM aarch64' ;;
  *) echo "unsupported MPC_EXPECTED_ARCH=${expected_arch}" >&2; exit 2 ;;
esac

continuum_ntl="$(
  cd "$continuum_root"
  PYTHONPATH="$continuum_root" "$continuum_python" - <<'PY'
from optimizedhbmpc.ntl import _hbmpc_ntl_helpers
print(_hbmpc_ntl_helpers.__file__)
PY
)"
admpc_ntl="$(
  cd /opt/admpc
  PYTHONPATH=/opt/admpc "$admpc_python" - <<'PY'
from adkg.ntl import _hbmpc_ntl_helpers
print(_hbmpc_ntl_helpers.__file__)
PY
)"

native_libraries=("$kzg_lib" "$bulletproof_lib" "$continuum_ntl" "$admpc_ntl")

for library in "${native_libraries[@]}"; do
  description="$(file "$library")"
  echo "$description"
  if [[ "$description" != *"$file_pattern"* ]]; then
    echo "wrong native-library architecture: $library" >&2
    exit 1
  fi
  ldd_output="$(ldd "$library" 2>&1)"
  if [[ "$ldd_output" == *"not found"* ]]; then
    echo "unresolved shared-library dependency: $library" >&2
    echo "$ldd_output" >&2
    exit 1
  fi
done

required_kzg_symbols=(
  pyAggPubProEvalBatch2
  pyAggPubVerEvalBatch2
  pyAggPedVerEvalBatch3
  pyBatchVerifyPubCombined
  pyCircuitLinearComb
)
for symbol in "${required_kzg_symbols[@]}"; do
  if ! nm -D "$kzg_lib" | awk -v required="$symbol" \
      '$NF == required { found = 1 } END { exit !found }'; then
    echo "missing KZG export: ${symbol}" >&2
    exit 1
  fi
done

(
  cd "$continuum_root"
  PYTHONPATH="$continuum_root" "$continuum_python" - <<'PY'
from ctypes import CDLL
from pathlib import Path

import charm
import pypairing
import zmq
from optimizedhbmpc.ntl import vandermonde_batch_evaluate
from beaver import aggregation_interfaces, fault_accumulation, ipc, protocol_metrics
from committee_election import protocol as committee_protocol
from scripts import admpc2_dynamic_run

root = Path.cwd()
CDLL(str(root / "kzg_ped_out.so"))
CDLL(str(root / "libbulletproofs_amcl.so"))
assert zmq.has("curve"), "PyZMQ/libzmq was built without CURVE"
assert pypairing.ZR(1) == pypairing.ZR(1)
print("PASS continuum imports/native libraries/CURVE")
PY
)

(
  cd /opt/admpc
  PYTHONPATH=/opt/admpc "$admpc_python" - <<'PY'
import pypairing
import zmq
from adkg import ipc
from adkg.ntl import vandermonde_batch_evaluate

assert zmq.has("curve"), "AD-MPC PyZMQ/libzmq was built without CURVE"
assert pypairing.ZR(1) == pypairing.ZR(1)
print("PASS AD-MPC imports/native libraries/CURVE")
PY
)

echo "PASS unified image preflight (${actual_arch})"
