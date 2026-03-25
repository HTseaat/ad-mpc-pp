#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

usage() {
  cat <<USAGE
Usage: $0 [options]

Run a dumbo-MPC smoke test with a small 4-node case.
Default case:
  n=4, t=1, width=100, depth=6, k=300, mode=full

Options:
  --cluster-env <path>     Cluster env file (default: distributed/cluster.env)
  --results-root <path>    Results root (default: /opt/benchmark-distributed)
  --n <int>                Node count (default: 4)
  --t <int>                Fault threshold (default: 1)
  --width <int>            Circuit width (default: 100)
  --depth <int>            Circuit depth (default: 6)
  --k <int>                Dumbo batch size (default: width*depth/2)
  --mode <full|drop-epoch4>
                           Dumbo run mode (default: full)
  --dumbo-timeout <sec>    Launch timeout (default: 600, 0 means no timeout)
  --sync-code              Also run code distribution before launch
  --skip-remote-cleanup    Skip remote container cleanup before launch
  -h, --help               Show this help

Examples:
  $0
  $0 --sync-code
  $0 --n 4 --t 1 --depth 6 --width 100
USAGE
}

N=4
T=1
WIDTH=100
DEPTH=6
K=""
MODE="full"
DUMBO_TIMEOUT=600
SYNC_CODE=0
REMOTE_CLEANUP=1
RESULTS_ROOT="$RESULTS_ROOT_DEFAULT"
CONTINUUM_PYTHON="${CONTINUUM_PYTHON:-/opt/venv/continuum/bin/python3}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cluster-env)
      CLUSTER_ENV="$2"
      export CLUSTER_ENV
      shift 2
      ;;
    --results-root)
      RESULTS_ROOT="$2"
      shift 2
      ;;
    --n)
      N="$2"
      shift 2
      ;;
    --t)
      T="$2"
      shift 2
      ;;
    --width)
      WIDTH="$2"
      shift 2
      ;;
    --depth)
      DEPTH="$2"
      shift 2
      ;;
    --k)
      K="$2"
      shift 2
      ;;
    --mode)
      MODE="$2"
      shift 2
      ;;
    --dumbo-timeout)
      DUMBO_TIMEOUT="$2"
      shift 2
      ;;
    --sync-code)
      SYNC_CODE=1
      shift
      ;;
    --skip-remote-cleanup)
      REMOTE_CLEANUP=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

for vname in N T WIDTH DEPTH DUMBO_TIMEOUT; do
  val="${!vname}"
  if ! [[ "$val" =~ ^[0-9]+$ ]]; then
    echo "Invalid value for ${vname}: ${val}" >&2
    exit 1
  fi
done

if [[ -n "$K" ]] && ! [[ "$K" =~ ^[0-9]+$ ]]; then
  echo "Invalid value for K: ${K}" >&2
  exit 1
fi

case "$MODE" in
  full|drop-epoch4) ;;
  *)
    echo "Invalid --mode: ${MODE} (expected full|drop-epoch4)" >&2
    exit 1
    ;;
esac

if [[ -z "$K" ]]; then
  K=$(( (WIDTH * DEPTH) / 2 ))
fi

if (( N < 3 * T + 1 )); then
  echo "Invalid (n,t): must satisfy n >= 3t + 1, got n=${N}, t=${T}" >&2
  exit 1
fi

load_cluster_env
select_cluster_ips "$N"
require_tools bash python3 ssh scp tar timeout

if [[ ! -x "$CONTINUUM_PYTHON" ]]; then
  echo "Continuum python not found or not executable: ${CONTINUUM_PYTHON}" >&2
  exit 1
fi
if ! "$CONTINUUM_PYTHON" -c "import charm" >/dev/null 2>&1; then
  echo "Continuum python cannot import 'charm': ${CONTINUUM_PYTHON}" >&2
  exit 1
fi

RUN_TAG="$(timestamp_utc)"
SESSION_DIR="${RESULTS_ROOT}/${RUN_TAG}_dumbo_smoke"
CASE_NAME="n${N}_t${T}_d${DEPTH}"
OUTDIR="${SESSION_DIR}/${CASE_NAME}"
mkdir -p "$OUTDIR"

echo "Run session: ${SESSION_DIR}"
echo "[dumbo-smoke] case=${CASE_NAME}, mode=${MODE}, width=${WIDTH}, depth=${DEPTH}, k=${K}"

if [[ -n "${CLUSTER_ENV:-}" ]]; then
  CLUSTER_ENV="$CLUSTER_ENV" "${SCRIPT_DIR}/sync_cluster_config.sh" "$N"
else
  "${SCRIPT_DIR}/sync_cluster_config.sh" "$N"
fi

echo "Configuring passwordless SSH for N=${N}"
"${ASY_SCRIPTS_DIR}/setup_ssh_keys.sh" "$N"

if [[ "$REMOTE_CLEANUP" -eq 1 ]]; then
  echo "Cleaning remote leftover containers for protocol=dumbo, N=${N}"
  if [[ -n "${CLUSTER_ENV:-}" ]]; then
    CLUSTER_ENV="$CLUSTER_ENV" "${SCRIPT_DIR}/cleanup_remote_ports.sh" --protocol dumbo --n "$N"
  else
    "${SCRIPT_DIR}/cleanup_remote_ports.sh" --protocol dumbo --n "$N"
  fi
fi

(
  cd "${ASY_DIR}"
  PYTHONPATH="${ASY_DIR}:${PYTHONPATH:-}" \
    "$CONTINUUM_PYTHON" scripts/run_key_gen_dumbo_dyn.py \
      --N "$N" \
      --f "$T" \
      --k "$K" \
      --layers "$DEPTH" \
      --ip-file scripts/ip.txt \
      --port 7001

  cd "${ASY_SCRIPTS_DIR}"
  ./distribute-admpc.sh
  if [[ "$SYNC_CODE" -eq 1 ]]; then
    ./distribute-docker.sh
  fi
  ./distribute-file.sh "mpc_${N}"

  cd "${REMOTE_ASY_SCRIPTS_DIR}"
  if [[ "$DUMBO_TIMEOUT" -gt 0 ]]; then
    set +e
    timeout "${DUMBO_TIMEOUT}s" ./launch_asyrantrigen.sh "$N" "$K" "$DEPTH" "$MODE"
    rc=$?
    set -e
    if [[ "$rc" -ne 0 && "$rc" -ne 124 ]]; then
      echo "Dumbo launch failed with rc=${rc}" >&2
      exit "$rc"
    fi
    if [[ "$rc" -eq 124 ]]; then
      echo "Dumbo launch hit timeout (${DUMBO_TIMEOUT}s)."
    fi
  else
    ./launch_asyrantrigen.sh "$N" "$K" "$DEPTH" "$MODE"
  fi
)

LAYERS_TOTAL=$((DEPTH + 2))
save_metadata "$OUTDIR" "dumbo" "smoke" "$N" "$T" "$DEPTH" "$LAYERS_TOTAL" "$K" "$MODE"
cp -r "${REMOTE_ASY_SCRIPTS_DIR}/logs" "${OUTDIR}/remote_logs" 2>/dev/null || true
cp -r "${ASY_DIR}/conf/mpc_${N}" "${OUTDIR}/conf" 2>/dev/null || true
cat > "${OUTDIR}/COLLECT_METRICS_TODO.txt" <<'TXT'
Raw logs have been copied for this case.
Metric extraction is intentionally left as TODO (per current request).
TXT

echo "Done. Session output: ${SESSION_DIR}"
