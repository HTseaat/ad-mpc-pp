#!/usr/bin/env bash
set -euo pipefail

trusted_setup_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_root="${trusted_setup_root}/upstream/qsdh-py"
build_root="${trusted_setup_root}/build/qsdh-py"
python_bin="${TRUSTED_SETUP_PYTHON:-/opt/venv/admpc/bin/python}"
cargo_home="${TRUSTED_SETUP_CARGO_HOME:-/root/.cargo}"
cargo_offline="${TRUSTED_SETUP_CARGO_OFFLINE:-1}"
pairing_lock_sha256="320d30537b4f32758025ad9107335d6a3546a22cb1e9cd18757cacee91982e7f"

case "${cargo_offline}" in
  1|true) cargo_network_args=(--offline) ;;
  0|false) cargo_network_args=() ;;
  *)
    echo "TRUSTED_SETUP_CARGO_OFFLINE must be 0/1/false/true" >&2
    exit 2
    ;;
esac

if [[ "${1:-}" == "--clean" ]]; then
  case "${build_root}" in
    "${trusted_setup_root}/build/qsdh-py") rm -rf "${build_root}" ;;
    *) echo "refusing to clean unexpected path: ${build_root}" >&2; exit 1 ;;
  esac
elif [[ $# -ne 0 ]]; then
  echo "Usage: $0 [--clean]" >&2
  exit 1
fi

"${python_bin}" "${trusted_setup_root}/scripts/verify_stage0.py" --source-only

if [[ ! -d "${build_root}" ]]; then
  mkdir -p "${trusted_setup_root}/build"
  cp -a "${source_root}" "${build_root}"
fi

# The immutable snapshot uses -march=native.  Change only the disposable build
# copy so an x86_64 image remains portable across different server CPUs.
sed -i 's/-march=native/-march=x86-64/g' "${build_root}/setup.py"

(
  cd "${build_root}"
  "${python_bin}" setup.py build_ext --inplace
)

(
  cd "${build_root}/pairing"
  if [[ ! -f Cargo.lock ]]; then
    CARGO_HOME="${cargo_home}" cargo generate-lockfile "${cargo_network_args[@]}"
  fi
  actual_lock_sha256="$(sha256sum Cargo.lock | awk '{print $1}')"
  if [[ "${actual_lock_sha256}" != "${pairing_lock_sha256}" ]]; then
    echo "unexpected pairing Cargo.lock digest: ${actual_lock_sha256}" >&2
    exit 1
  fi
  CARGO_HOME="${cargo_home}" cargo build --release --locked \
    "${cargo_network_args[@]}"
  cp target/release/libpypairing.so pypairing/pypairing.so
)

(
  cd "${build_root}"
  PYTHONPATH="${build_root}:${build_root}/pairing" "${python_bin}" - <<'PY'
import sys
import types
sys.modules["pytest"] = types.ModuleType("pytest")
from adkg.ntl import vandermonde_batch_evaluate
from pypairing import G1, G2, ZR, pair
g, g2, alpha = G1.rand(b"build-g"), G2.rand(b"buildg2"), ZR(7)
assert pair(g ** alpha, g2) == pair(g, g2 ** alpha)
print("PASS isolated qsdh-py native build")
PY
)
