#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

usage() {
  cat <<USAGE
Usage: $0 <protocol> <experiment> [options]

Protocols:
  admpc | continuum | dumbo

Experiments:
  exp1 | exp2 | exp3 | exp4

Options:
  --cluster-env <path>    Cluster env file (default: distributed/cluster.env)
  --results-root <path>   Results root (default: /opt/benchmark-distributed)
  --timeout <seconds>     control-node timeout for admpc/continuum (default: 12)
  --dumbo-timeout <sec>   launch timeout for dumbo runs (default: 600)
  --only-n <n>            Only run cases with this N (exp1/exp2 use-case filter)
  --skip-remote-cleanup   Skip automatic remote container cleanup before each case
  --sleep-between-case <seconds>
                           Pause between cases to collect data (default: 30)
  --sync-code             Also run code distribution step before each case

Examples:
  $0 admpc exp1
  $0 continuum exp2 --timeout 20
  $0 dumbo exp4 --dumbo-timeout 900
USAGE
}

if [[ $# -lt 2 ]]; then
  usage
  exit 1
fi

PROTOCOL="$1"
EXP_ID="$2"
shift 2

TIMEOUT=12
DUMBO_TIMEOUT=600
SLEEP_BETWEEN_CASE=30
SYNC_CODE=0
RESULTS_ROOT="$RESULTS_ROOT_DEFAULT"
ONLY_N=""
REMOTE_CLEANUP=1
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
    --timeout)
      TIMEOUT="$2"
      shift 2
      ;;
    --dumbo-timeout)
      DUMBO_TIMEOUT="$2"
      shift 2
      ;;
    --only-n)
      ONLY_N="$2"
      shift 2
      ;;
    --skip-remote-cleanup)
      REMOTE_CLEANUP=0
      shift
      ;;
    --sleep-between-case)
      SLEEP_BETWEEN_CASE="$2"
      shift 2
      ;;
    --sync-code)
      SYNC_CODE=1
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

case "$PROTOCOL" in
  admpc|continuum|dumbo) ;;
  *)
    echo "Invalid protocol: $PROTOCOL" >&2
    usage
    exit 1
    ;;
esac

case "$EXP_ID" in
  exp1|exp2|exp3|exp4) ;;
  *)
    echo "Invalid experiment: $EXP_ID" >&2
    usage
    exit 1
    ;;
esac

if ! [[ "$SLEEP_BETWEEN_CASE" =~ ^[0-9]+$ ]]; then
  echo "Invalid --sleep-between-case: ${SLEEP_BETWEEN_CASE}" >&2
  exit 1
fi

if [[ -n "$ONLY_N" ]] && ! [[ "$ONLY_N" =~ ^[0-9]+$ ]]; then
  echo "Invalid --only-n: ${ONLY_N}" >&2
  exit 1
fi

if [[ -n "$ONLY_N" ]] && [[ "$EXP_ID" == "exp3" || "$EXP_ID" == "exp4" ]] && [[ "$ONLY_N" != "16" ]]; then
  echo "--only-n=${ONLY_N} does not match ${EXP_ID} preset (fixed n=16)." >&2
  exit 1
fi

if [[ "$PROTOCOL" == "dumbo" ]] && [[ "$EXP_ID" == "exp1" || "$EXP_ID" == "exp2" ]]; then
  echo "Dumbo is not part of ${EXP_ID}. Supported: exp3, exp4" >&2
  exit 1
fi

load_cluster_env
require_tools bash python3 ssh ssh-keygen scp tar timeout

if [[ "$PROTOCOL" == "continuum" || "$PROTOCOL" == "dumbo" ]]; then
  if [[ ! -x "$CONTINUUM_PYTHON" ]]; then
    echo "Continuum python not found or not executable: ${CONTINUUM_PYTHON}" >&2
    echo "Set CONTINUUM_PYTHON env or ensure /opt/venv/continuum exists." >&2
    exit 1
  fi
  if ! "$CONTINUUM_PYTHON" -c "import charm" >/dev/null 2>&1; then
    echo "Continuum python cannot import 'charm': ${CONTINUUM_PYTHON}" >&2
    echo "Please check continuum virtualenv dependencies." >&2
    exit 1
  fi
fi

RUN_TAG="$(timestamp_utc)"
SESSION_DIR="${RESULTS_ROOT}/${RUN_TAG}_${PROTOCOL}_${EXP_ID}"
mkdir -p "$SESSION_DIR"

echo "Run session: $SESSION_DIR"
if [[ -n "$ONLY_N" ]]; then
  echo "Case filter enabled: n=${ONLY_N}"
fi

SSH_SETUP_DONE_NS=()

total_cm_for_gate() {
  local gate_mode="$1"
  local width="$2"
  local d="$3"
  case "$gate_mode" in
    linear|mixed)
      echo $(( (width * d) / 2 ))
      ;;
    nonlinear)
      echo $(( width * d ))
      ;;
    *)
      echo "Unknown gate mode: $gate_mode" >&2
      exit 1
      ;;
  esac
}

admpc_protocol_name() {
  local gate_mode="$1"
  case "$gate_mode" in
    mixed) echo "admpc" ;;
    linear) echo "admpc-linear" ;;
    nonlinear) echo "admpc-nonlinear" ;;
    *)
      echo "Unknown gate mode: $gate_mode" >&2
      exit 1
      ;;
  esac
}

continuum_protocol_name() {
  local gate_mode="$1"
  case "$gate_mode" in
    mixed) echo "admpc2" ;;
    linear) echo "admpc2-linear" ;;
    nonlinear) echo "admpc2-nonlinear" ;;
    *)
      echo "Unknown gate mode: $gate_mode" >&2
      exit 1
      ;;
  esac
}

sync_cluster_for_n() {
  local n="$1"
  if [[ -n "${CLUSTER_ENV:-}" ]]; then
    CLUSTER_ENV="$CLUSTER_ENV" "${SCRIPT_DIR}/sync_cluster_config.sh" "$n"
  else
    "${SCRIPT_DIR}/sync_cluster_config.sh" "$n"
  fi
}

collect_raw_logs_placeholder() {
  local outdir="$1"
  mkdir -p "$outdir"
  cat > "${outdir}/COLLECT_METRICS_TODO.txt" <<'TXT'
Raw logs have been copied for this case.
Metric extraction is intentionally left as TODO (per current request).
TXT
}

ensure_ssh_setup_for_n() {
  local n="$1"
  local done_n
  for done_n in "${SSH_SETUP_DONE_NS[@]}"; do
    if [[ "$done_n" == "$n" ]]; then
      return
    fi
  done

  local setup_script
  case "$PROTOCOL" in
    admpc)
      setup_script="${ADMPC_DIR}/scripts/setup_ssh_keys.sh"
      ;;
    continuum|dumbo)
      setup_script="${ASY_SCRIPTS_DIR}/setup_ssh_keys.sh"
      ;;
    *)
      echo "Unsupported protocol for ssh setup: ${PROTOCOL}" >&2
      exit 1
      ;;
  esac

  if [[ ! -x "$setup_script" ]]; then
    echo "SSH setup script is missing or not executable: ${setup_script}" >&2
    exit 1
  fi

  echo "Configuring passwordless SSH for N=${n} via ${setup_script}"
  "$setup_script" "$n"
  SSH_SETUP_DONE_NS+=("$n")
}

cleanup_remote_before_case() {
  local n="$1"
  if [[ "$REMOTE_CLEANUP" -eq 0 ]]; then
    return
  fi

  local cleanup_script="${SCRIPT_DIR}/cleanup_remote_ports.sh"
  if [[ ! -x "$cleanup_script" ]]; then
    echo "Cleanup script is missing or not executable: ${cleanup_script}" >&2
    exit 1
  fi

  echo "Cleaning remote leftover containers for protocol=${PROTOCOL}, N=${n}"
  if [[ -n "${CLUSTER_ENV:-}" ]]; then
    CLUSTER_ENV="$CLUSTER_ENV" "$cleanup_script" --protocol "$PROTOCOL" --n "$n"
  else
    "$cleanup_script" --protocol "$PROTOCOL" --n "$n"
  fi
}

pause_between_cases_if_needed() {
  local idx="$1"
  local total="$2"
  if [[ "$SLEEP_BETWEEN_CASE" -le 0 ]]; then
    return
  fi
  if (( idx + 1 < total )); then
    echo "Pausing ${SLEEP_BETWEEN_CASE}s before next case..."
    sleep "$SLEEP_BETWEEN_CASE"
  fi
}

run_admpc_case() {
  local case_name="$1"
  local gate_mode="$2"
  local n="$3"
  local t="$4"
  local d="$5"
  local total_cm="$6"

  local layers_total=$((d + 2))
  local protocol_name
  protocol_name="$(admpc_protocol_name "$gate_mode")"
  local conf_dir="${protocol_name}_${total_cm}_${d}_${n}"
  local outdir="${SESSION_DIR}/${case_name}"

  echo "[AD-MPC] ${case_name}: mode=${gate_mode}, n=${n}, t=${t}, d=${d}, layers=${layers_total}, total_cm=${total_cm}"
  sync_cluster_for_n "$n"
  ensure_ssh_setup_for_n "$n"
  cleanup_remote_before_case "$n"

  (
    cd "${ADMPC_DIR}/scripts"
    if [[ "$SYNC_CODE" -eq 1 ]]; then
      ./distribute-docker.sh
    fi
    ./create_json_files.sh "$protocol_name" "$n" "$t" "$layers_total" "$total_cm"
    ./distribute-file.sh "$conf_dir"
    ./control-node.sh "$conf_dir" "$protocol_name" "$TIMEOUT"
  )

  mkdir -p "$outdir"
  save_metadata "$outdir" "admpc" "$EXP_ID" "$n" "$t" "$d" "$layers_total" "$total_cm"
  cp -r "${ADMPC_DIR}/scripts/logs" "${outdir}/logs" 2>/dev/null || true
  cp -r "${ADMPC_DIR}/conf/${conf_dir}" "${outdir}/conf" 2>/dev/null || true
  collect_raw_logs_placeholder "$outdir"
}

run_continuum_case() {
  local case_name="$1"
  local gate_mode="$2"
  local n="$3"
  local t="$4"
  local d="$5"
  local total_cm="$6"

  local layers_total=$((d + 2))
  local protocol_override
  protocol_override="$(continuum_protocol_name "$gate_mode")"
  local conf_dir="admpc_${total_cm}_${layers_total}_${n}"
  local outdir="${SESSION_DIR}/${case_name}"

  echo "[continuum] ${case_name}: mode=${gate_mode}, n=${n}, t=${t}, d=${d}, layers=${layers_total}, total_cm=${total_cm}"
  sync_cluster_for_n "$n"
  ensure_ssh_setup_for_n "$n"
  cleanup_remote_before_case "$n"

  (
    cd "${ASY_DIR}"
    PYTHONPATH="${ASY_DIR}:${PYTHONPATH:-}" \
      "$CONTINUUM_PYTHON" scripts/create_json_files.py admpc "$n" "$t" "$layers_total" "$total_cm"

    cd "${ASY_SCRIPTS_DIR}"
    ./distribute-admpc.sh
    if [[ "$SYNC_CODE" -eq 1 ]]; then
      ./distribute-docker.sh
    fi
    ./distribute-file.sh "$conf_dir"
    ./control-node.sh "$conf_dir" "$protocol_override" "$TIMEOUT"
  )

  mkdir -p "$outdir"
  save_metadata "$outdir" "continuum" "$EXP_ID" "$n" "$t" "$d" "$layers_total" "$total_cm"
  cp -r "${ASY_SCRIPTS_DIR}/logs" "${outdir}/logs" 2>/dev/null || true
  cp -r "${ASY_DIR}/conf/${conf_dir}" "${outdir}/conf" 2>/dev/null || true
  collect_raw_logs_placeholder "$outdir"
}

run_dumbo_case() {
  local case_name="$1"
  local n="$2"
  local t="$3"
  local d="$4"
  local k="$5"
  local dumbo_mode="$6"

  local layers_total=$((d + 2))
  local conf_dir="mpc_${n}"
  local outdir="${SESSION_DIR}/${case_name}"

  echo "[dumbo] ${case_name}: mode=${dumbo_mode}, n=${n}, t=${t}, d=${d}, k=${k}"
  sync_cluster_for_n "$n"
  ensure_ssh_setup_for_n "$n"
  cleanup_remote_before_case "$n"

  (
    cd "${ASY_DIR}"
    PYTHONPATH="${ASY_DIR}:${PYTHONPATH:-}" \
      "$CONTINUUM_PYTHON" scripts/run_key_gen_dumbo_dyn.py --N "$n" --f "$t" --k "$k" --layers "$d" --ip-file scripts/ip.txt --port 7001

    cd "${ASY_SCRIPTS_DIR}"
    ./distribute-admpc.sh
    if [[ "$SYNC_CODE" -eq 1 ]]; then
      ./distribute-docker.sh
    fi
    ./distribute-file.sh "$conf_dir"

    cd "${REMOTE_ASY_SCRIPTS_DIR}"
    if [[ "$DUMBO_TIMEOUT" -gt 0 ]]; then
      set +e
      timeout "${DUMBO_TIMEOUT}s" ./launch_asyrantrigen.sh "$n" "$k" "$d" "$dumbo_mode"
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
      ./launch_asyrantrigen.sh "$n" "$k" "$d" "$dumbo_mode"
    fi
  )

  mkdir -p "$outdir"
  save_metadata "$outdir" "dumbo" "$EXP_ID" "$n" "$t" "$d" "$layers_total" "$k" "$dumbo_mode"
  cp -r "${REMOTE_ASY_SCRIPTS_DIR}/logs" "${outdir}/remote_logs" 2>/dev/null || true
  cp -r "${ASY_DIR}/conf/${conf_dir}" "${outdir}/conf" 2>/dev/null || true
  collect_raw_logs_placeholder "$outdir"
}

WIDTH=100

case "$EXP_ID" in
  exp1)
    GATE_MODE="linear"
    D=6
    NS=(4 8 12 16)
    TS=(1 2 3 5)
    selected_indices=()
    for idx in "${!NS[@]}"; do
      n="${NS[$idx]}"
      if [[ -n "$ONLY_N" ]] && [[ "$n" != "$ONLY_N" ]]; then
        continue
      fi
      selected_indices+=("$idx")
    done
    if [[ "${#selected_indices[@]}" -eq 0 ]]; then
      echo "No exp1 cases selected with --only-n=${ONLY_N}" >&2
      exit 1
    fi

    for run_idx in "${!selected_indices[@]}"; do
      idx="${selected_indices[$run_idx]}"
      n="${NS[$idx]}"
      t="${TS[$idx]}"
      total_cm="$(total_cm_for_gate "$GATE_MODE" "$WIDTH" "$D")"
      case_name="n${n}_t${t}_d${D}"
      if [[ "$PROTOCOL" == "admpc" ]]; then
        run_admpc_case "$case_name" "$GATE_MODE" "$n" "$t" "$D" "$total_cm"
      else
        run_continuum_case "$case_name" "$GATE_MODE" "$n" "$t" "$D" "$total_cm"
      fi
      pause_between_cases_if_needed "$run_idx" "${#selected_indices[@]}"
    done
    ;;

  exp2)
    GATE_MODE="nonlinear"
    D=6
    NS=(4 8 12 16)
    TS=(1 2 3 5)
    selected_indices=()
    for idx in "${!NS[@]}"; do
      n="${NS[$idx]}"
      if [[ -n "$ONLY_N" ]] && [[ "$n" != "$ONLY_N" ]]; then
        continue
      fi
      selected_indices+=("$idx")
    done
    if [[ "${#selected_indices[@]}" -eq 0 ]]; then
      echo "No exp2 cases selected with --only-n=${ONLY_N}" >&2
      exit 1
    fi

    for run_idx in "${!selected_indices[@]}"; do
      idx="${selected_indices[$run_idx]}"
      n="${NS[$idx]}"
      t="${TS[$idx]}"
      total_cm="$(total_cm_for_gate "$GATE_MODE" "$WIDTH" "$D")"
      case_name="n${n}_t${t}_d${D}"
      if [[ "$PROTOCOL" == "admpc" ]]; then
        run_admpc_case "$case_name" "$GATE_MODE" "$n" "$t" "$D" "$total_cm"
      else
        run_continuum_case "$case_name" "$GATE_MODE" "$n" "$t" "$D" "$total_cm"
      fi
      pause_between_cases_if_needed "$run_idx" "${#selected_indices[@]}"
    done
    ;;

  exp3)
    GATE_MODE="mixed"
    N=16
    T=5
    DS=(2 4 6 8 10)
    for idx in "${!DS[@]}"; do
      d="${DS[$idx]}"
      total_cm="$(total_cm_for_gate "$GATE_MODE" "$WIDTH" "$d")"
      case_name="n${N}_t${T}_d${d}"
      if [[ "$PROTOCOL" == "admpc" ]]; then
        run_admpc_case "$case_name" "$GATE_MODE" "$N" "$T" "$d" "$total_cm"
      elif [[ "$PROTOCOL" == "continuum" ]]; then
        run_continuum_case "$case_name" "$GATE_MODE" "$N" "$T" "$d" "$total_cm"
      else
        run_dumbo_case "$case_name" "$N" "$T" "$d" "$total_cm" "full"
      fi
      pause_between_cases_if_needed "$idx" "${#DS[@]}"
    done
    ;;

  exp4)
    GATE_MODE="mixed"
    N=16
    T=5
    D=6
    total_cm="$(total_cm_for_gate "$GATE_MODE" "$WIDTH" "$D")"
    case_name="n${N}_t${T}_d${D}"

    if [[ "$PROTOCOL" == "admpc" ]]; then
      run_admpc_case "$case_name" "$GATE_MODE" "$N" "$T" "$D" "$total_cm"
    elif [[ "$PROTOCOL" == "continuum" ]]; then
      run_continuum_case "$case_name" "$GATE_MODE" "$N" "$T" "$D" "$total_cm"
    else
      run_dumbo_case "${case_name}_drop-epoch4" "$N" "$T" "$D" "$total_cm" "drop-epoch4"
    fi
    ;;
esac

echo "Done. Session output: ${SESSION_DIR}"
