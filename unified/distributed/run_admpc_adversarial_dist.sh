#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

usage() {
  cat <<USAGE
Usage: $0 [options]

Run distributed AD-MPC delay and/or Byzantine cases.

Options:
  --cluster-env <path>       Cluster file (default: distributed/cluster.env)
  --results-root <path>      Archive root (default: /opt/benchmark-distributed)
  --n <N>                    Committee size: 4, 10, 16, or 22 (default: 4)
  --scenario <name>          both (default), delay, or byzantine
  --delay-ms <ms>            ADtrans delay injected at C3 (default: 2000)
  --attack-index <index>     Forked outgoing-share element (default: 0)
  --start-delay <sec>        Shared future start offset (default: 30)
  --timeout <sec>            Per-process hard timeout (default: 900)
  --sleep-between-case <sec> Pause between cases (default: 15)
  --reuse-config             Reuse an existing local/remote configuration
  --skip-remote-cleanup      Do not remove leftover AD-MPC containers
USAGE
}

RESULTS_ROOT="$RESULTS_ROOT_DEFAULT"
SCENARIO="both"
DELAY_MS=2000
ATTACK_INDEX=0
START_DELAY=30
RUN_TIMEOUT=900
SLEEP_BETWEEN_CASE=15
REMOTE_CLEANUP=1
REUSE_CONFIG=0

N=4
D=6
LAYERS_TOTAL=8
TOTAL_CM=300
COMPUTATION_EPOCH=3
AUTH_MODE=curve
CURVE_VALIDATION_PYTHON="${CURVE_VALIDATION_PYTHON:-/opt/venv/continuum/bin/python3}"

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
    --scenario)
      SCENARIO="$2"
      shift 2
      ;;
    --delay-ms)
      DELAY_MS="$2"
      shift 2
      ;;
    --attack-index)
      ATTACK_INDEX="$2"
      shift 2
      ;;
    --start-delay)
      START_DELAY="$2"
      shift 2
      ;;
    --timeout)
      RUN_TIMEOUT="$2"
      shift 2
      ;;
    --sleep-between-case)
      SLEEP_BETWEEN_CASE="$2"
      shift 2
      ;;
    --reuse-config)
      REUSE_CONFIG=1
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
      usage >&2
      exit 1
      ;;
  esac
done

case "$SCENARIO" in
  both|delay|byzantine) ;;
  *) echo "Invalid --scenario: $SCENARIO" >&2; exit 1 ;;
esac
case "$N" in
  4) T=1 ;;
  10) T=3 ;;
  16) T=5 ;;
  22) T=7 ;;
  *) echo "Unsupported --n: ${N}. Expected 4, 10, 16, or 22." >&2; exit 1 ;;
esac
for value_name in DELAY_MS START_DELAY RUN_TIMEOUT SLEEP_BETWEEN_CASE ATTACK_INDEX; do
  value="${!value_name}"
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "${value_name} must be a non-negative integer" >&2
    exit 1
  fi
done
if [[ "$DELAY_MS" -le 0 || "$RUN_TIMEOUT" -le 0 ]]; then
  echo "DELAY_MS and RUN_TIMEOUT must be positive" >&2
  exit 1
fi

load_cluster_env
require_immutable_image
select_cluster_ips "$N"
require_tools bash python3 ssh scp tar timeout sha256sum

if [[ ! -x "$CURVE_VALIDATION_PYTHON" ]] || \
   ! "$CURVE_VALIDATION_PYTHON" -c "import zmq" >/dev/null 2>&1; then
  echo "CURVE validation Python cannot import pyzmq: $CURVE_VALIDATION_PYTHON" >&2
  exit 1
fi

export ZMQ_AUTH_MODE="$AUTH_MODE"
export ZMQ_CURVE_READY_TIMEOUT="${ZMQ_CURVE_READY_TIMEOUT:-180}"
export CONTROL_NODE_SSH_DELAY="${CONTROL_NODE_SSH_DELAY:-0.1}"

if [[ -n "${CLUSTER_ENV:-}" ]]; then
  CLUSTER_ENV="$CLUSTER_ENV" "${SCRIPT_DIR}/sync_cluster_config.sh" "$N"
else
  "${SCRIPT_DIR}/sync_cluster_config.sh" "$N"
fi

RUN_TAG="$(timestamp_utc)"
SESSION_DIR="${RESULTS_ROOT}/${RUN_TAG}_admpc_adversarial_n${N}"
mkdir -p "$SESSION_DIR"

echo "AD-MPC adversarial session: $SESSION_DIR"
echo "Cluster: ${SELECTED_IPS[*]}"
echo "Image: $MPC_IMAGE"

protocol_start_epoch() {
  echo $(( $(date +%s) + START_DELAY ))
}

cleanup_remote() {
  if [[ "$REMOTE_CLEANUP" -eq 0 ]]; then
    return
  fi
  if [[ -n "${CLUSTER_ENV:-}" ]]; then
    CLUSTER_ENV="$CLUSTER_ENV" "${SCRIPT_DIR}/cleanup_remote_ports.sh" \
      --protocol admpc --n "$N"
  else
    "${SCRIPT_DIR}/cleanup_remote_ports.sh" --protocol admpc --n "$N"
  fi
}

validate_generated_config() {
  local config_dir="$1"
  "$CURVE_VALIDATION_PYTHON" "${SCRIPT_DIR}/validate_mpc_config.py" \
    --config-dir "$config_dir" --n "$N" --layers "$LAYERS_TOTAL" \
    --ip-file "${ASY_SCRIPTS_DIR}/ip.txt" --auth-mode curve
}

write_source_manifest() {
  local outdir="$1"
  local paths=(
    "${ADMPC_DIR}/adkg/adversarial_faults.py"
    "${ADMPC_DIR}/adkg/adtrans_byzantine.py"
    "${ADMPC_DIR}/adkg/robust_reconstruction.py"
    "${ADMPC_DIR}/adkg/admpc_dynamic.py"
    "${ADMPC_DIR}/adkg/trans.py"
    "${ADMPC_DIR}/adkg/acss.py"
    "${ADMPC_DIR}/scripts/control-node.sh"
    "${ADMPC_DIR}/scripts/distribute-file.sh"
    "${SCRIPT_DIR}/run_admpc_adversarial_dist.sh"
    "${SCRIPT_DIR}/analyze_admpc_adversarial_case.py"
    "${SCRIPT_DIR}/../extract_adversarial_traces.py"
  )
  sha256sum "${paths[@]}" > "${outdir}/source-sha256.txt"
}

run_case() {
  local scenario="$1"
  local case_name="admpc-${scenario}"
  local outdir="${SESSION_DIR}/${case_name}"
  local conf_dir="admpc_${TOTAL_CM}_${D}_${N}"
  local launch_rc=0
  local analysis_rc=0

  echo "[${case_name}] cleaning and launching ${N}x${LAYERS_TOTAL} processes"
  cleanup_remote

  set +e
  (
    set -e
    cd "${ADMPC_DIR}/scripts"
    if [[ "$REUSE_CONFIG" -eq 1 ]]; then
      if [[ ! -d "${ADMPC_DIR}/conf/${conf_dir}" ]]; then
        echo "Cannot reuse missing AD-MPC adversarial config: ${ADMPC_DIR}/conf/${conf_dir}" >&2
        exit 1
      fi
      validate_generated_config "${ADMPC_DIR}/conf/${conf_dir}"
      echo "Reusing existing AD-MPC adversarial config ${conf_dir}"
    else
      ./create_json_files.sh admpc "$N" "$T" "$LAYERS_TOTAL" "$TOTAL_CM"
      validate_generated_config "${ADMPC_DIR}/conf/${conf_dir}"
      ./distribute-file.sh "$conf_dir"
    fi

    export FAULT_TARGET=adtrans
    export FAULT_COMPUTATION_EPOCH="$COMPUTATION_EPOCH"
    if [[ "$scenario" == "delay" ]]; then
      export FAULT_MODE=delay
      export FAULT_DELTA_MS="$DELAY_MS"
      unset FAULT_ATTACK_INDEX
    else
      export FAULT_MODE=byzantine
      export FAULT_ATTACK_INDEX="$ATTACK_INDEX"
      unset FAULT_DELTA_MS
    fi
    ./control-node.sh "$conf_dir" admpc "$(protocol_start_epoch)" "$RUN_TIMEOUT"
  )
  launch_rc=$?
  set -e

  mkdir -p "$outdir"
  save_metadata \
    "$outdir" admpc "$case_name" "$N" "$T" "$D" \
    "$LAYERS_TOTAL" "$TOTAL_CM"
  {
    echo "scenario=${case_name}"
    echo "fault_mode=${scenario}"
    echo "fault_target=adtrans"
    echo "fault_computation_epoch=${COMPUTATION_EPOCH}"
    echo "fault_delta_ms=$([[ "$scenario" == delay ]] && echo "$DELAY_MS")"
    echo "fault_attack_index=$([[ "$scenario" == byzantine ]] && echo "$ATTACK_INDEX")"
    echo "cluster_ips=$(IFS=,; echo "${SELECTED_IPS[*]}")"
    echo "reuse_config=${REUSE_CONFIG}"
    echo "launcher_exit_code=${launch_rc}"
  } >> "${outdir}/metadata.env"
  cp -a "${ADMPC_DIR}/scripts/logs" "${outdir}/logs" 2>/dev/null || true
  cp -a "${ADMPC_DIR}/conf/${conf_dir}" "${outdir}/conf" 2>/dev/null || true
  write_source_manifest "$outdir"

  analyzer_args=(
    --case-dir "$outdir"
    --scenario "$case_name"
    --n "$N" --t "$T" --layers "$LAYERS_TOTAL"
    --computation-epoch "$COMPUTATION_EPOCH"
  )
  if [[ "$scenario" == "delay" ]]; then
    analyzer_args+=(--delay-ms "$DELAY_MS")
  else
    analyzer_args+=(--attack-index "$ATTACK_INDEX")
  fi

  set +e
  python3 "${SCRIPT_DIR}/analyze_admpc_adversarial_case.py" "${analyzer_args[@]}"
  analysis_rc=$?
  set -e
  {
    echo "analysis_exit_code=${analysis_rc}"
    echo "completed_utc=$(timestamp_utc)"
  } >> "${outdir}/metadata.env"

  if [[ "$launch_rc" -ne 0 || "$analysis_rc" -ne 0 ]]; then
    echo "[${case_name}] FAILED launch_rc=${launch_rc} analysis_rc=${analysis_rc}" >&2
    return 1
  fi
  echo "[${case_name}] PASS"
}

cases=()
case "$SCENARIO" in
  both) cases=(delay byzantine) ;;
  delay) cases=(delay) ;;
  byzantine) cases=(byzantine) ;;
esac

campaign_rc=0
for index in "${!cases[@]}"; do
  if ! run_case "${cases[$index]}"; then
    campaign_rc=1
  fi
  if (( index + 1 < ${#cases[@]} && SLEEP_BETWEEN_CASE > 0 )); then
    echo "Pausing ${SLEEP_BETWEEN_CASE}s before the next case"
    sleep "$SLEEP_BETWEEN_CASE"
  fi
done

cleanup_remote || campaign_rc=1
echo "Session archived at: $SESSION_DIR"
exit "$campaign_rc"
