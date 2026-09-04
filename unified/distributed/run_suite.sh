#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

usage() {
  cat <<USAGE
Usage: $0 <protocol> <experiment> [options]

Protocols:
  admpc | admpc-shuffle | continuum | bgw-aggtrans | shuffle | shuffle-bgw-static | dumbo-shuffle-beaver | dumbo | dumbo-bgw-direct

Experiments:
  exp1 | exp2 | exp3 | exp4 | exp-shuffle

Options:
  --cluster-env <path>    Cluster env file (default: distributed/cluster.env)
  --results-root <path>   Results root (default: /opt/benchmark-distributed)
  --start-delay <sec>     Shared future start time offset (default: 30)
  --timeout <seconds>     Hard timeout for each remote MPC process (default: 900)
  --dumbo-timeout <sec>   launch timeout for dumbo runs (default: 600)
  --auth-mode <mode>      ZeroMQ transport: curve (default) or null
  --config-generator <mode>
                           Continuum config generator: remote-image (default) or local
  --only-n <n>            Only run cases with this N (exp1/exp2 use-case filter)
  --only-d <d>            Only run exp3 cases with this circuit depth d
  --fault-profile <name>  exp4 profile: accumulation (default), attack, or legacy-drop
  --skip-remote-cleanup   Skip automatic remote container cleanup before each case
  --skip-ssh-setup        Assume controller SSH keys are already installed
  --sleep-between-case <seconds>
                           Pause between cases to collect data (default: 30)
  --sync-code             Also run code distribution step before each case
  --reuse-config          Reuse the existing local/remote JSON config for an identical case
  --protocol-overhead     Record, collect, and analyze communication + local crypto overhead

Examples:
  $0 admpc exp1
  SHUFFLE_MODE=iterated SHUFFLE_K=128 $0 admpc-shuffle exp-shuffle --only-n 4
  $0 continuum exp2 --only-n 4 --start-delay 30 --timeout 900
  BGW_UNBATCHED_VERIFY=1 $0 bgw-aggtrans exp2 --only-n 4 --start-delay 30 --timeout 900
  $0 shuffle exp-shuffle --timeout 900
  $0 shuffle-bgw-static exp-shuffle --timeout 900
  $0 dumbo-shuffle-beaver exp-shuffle --timeout 900
  $0 dumbo exp4 --dumbo-timeout 900
  $0 continuum exp4 --fault-profile accumulation
  $0 dumbo-bgw-direct exp2 --dumbo-timeout 900
USAGE
}

if [[ $# -lt 2 ]]; then
  usage
  exit 1
fi

PROTOCOL="$1"
EXP_ID="$2"
shift 2

START_DELAY=30
RUN_TIMEOUT=900
DUMBO_TIMEOUT=600
SLEEP_BETWEEN_CASE=30
SYNC_CODE=0
REUSE_CONFIG=0
PROTOCOL_OVERHEAD=0
RESULTS_ROOT="$RESULTS_ROOT_DEFAULT"
ONLY_N=""
ONLY_D=""
REMOTE_CLEANUP=1
SKIP_SSH_SETUP=0
CONTINUUM_PYTHON="${CONTINUUM_PYTHON:-/opt/venv/continuum/bin/python3}"
CURVE_VALIDATION_PYTHON="${CURVE_VALIDATION_PYTHON:-/opt/venv/continuum/bin/python3}"
AUTH_MODE="${ZMQ_AUTH_MODE:-curve}"
CONTINUUM_CONFIG_GENERATOR="${CONTINUUM_CONFIG_GENERATOR:-remote-image}"
FAULT_PROFILE=""

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
      RUN_TIMEOUT="$2"
      shift 2
      ;;
    --start-delay)
      START_DELAY="$2"
      shift 2
      ;;
    --dumbo-timeout)
      DUMBO_TIMEOUT="$2"
      shift 2
      ;;
    --auth-mode)
      AUTH_MODE="$2"
      shift 2
      ;;
    --config-generator)
      CONTINUUM_CONFIG_GENERATOR="$2"
      shift 2
      ;;
    --only-n)
      ONLY_N="$2"
      shift 2
      ;;
    --only-d)
      ONLY_D="$2"
      shift 2
      ;;
    --fault-profile)
      FAULT_PROFILE="$2"
      shift 2
      ;;
    --skip-remote-cleanup)
      REMOTE_CLEANUP=0
      shift
      ;;
    --skip-ssh-setup)
      SKIP_SSH_SETUP=1
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
    --reuse-config)
      REUSE_CONFIG=1
      shift
      ;;
    --protocol-overhead)
      PROTOCOL_OVERHEAD=1
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
  admpc|admpc-shuffle|continuum|bgw-aggtrans|shuffle|shuffle-bgw-static|dumbo-shuffle-beaver|dumbo|dumbo-bgw-direct) ;;
  *)
    echo "Invalid protocol: $PROTOCOL" >&2
    usage
    exit 1
    ;;
esac

case "$AUTH_MODE" in
  curve|null) ;;
  *)
    echo "Invalid --auth-mode: ${AUTH_MODE}. Expected curve or null." >&2
    exit 1
    ;;
esac
export ZMQ_AUTH_MODE="$AUTH_MODE"

case "$CONTINUUM_CONFIG_GENERATOR" in
  remote-image|local) ;;
  *)
    echo "Invalid --config-generator: ${CONTINUUM_CONFIG_GENERATOR}. Expected remote-image or local." >&2
    exit 1
    ;;
esac

case "$EXP_ID" in
  exp1|exp2|exp3|exp4|exp-shuffle) ;;
  *)
    echo "Invalid experiment: $EXP_ID" >&2
    usage
    exit 1
    ;;
esac

if [[ "$PROTOCOL_OVERHEAD" -eq 1 ]]; then
  if [[ "$EXP_ID" != "exp1" && "$EXP_ID" != "exp2" ]]; then
    echo "--protocol-overhead currently supports exp1/exp2 (Figure 8/9) only." >&2
    exit 1
  fi
  if [[ "$PROTOCOL" != "admpc" && "$PROTOCOL" != "continuum" && "$PROTOCOL" != "bgw-aggtrans" ]]; then
    echo "--protocol-overhead currently supports protocol=admpc, continuum, or bgw-aggtrans." >&2
    exit 1
  fi
  if [[ "$PROTOCOL" == "bgw-aggtrans" ]]; then
    if [[ "${BGW_UNBATCHED_VERIFY:-0}" != "1" ]]; then
      echo "BGW-AggTrans computation overhead requires BGW_UNBATCHED_VERIFY=1." >&2
      exit 1
    fi
    if [[ "${AGG_KZG_V2:-1}" != "1" || "${DISABLE_AGG_PROTO:-0}" == "1" ]]; then
      echo "BGW-AggTrans computation overhead requires AGG_KZG_V2=1 and DISABLE_AGG_PROTO=0." >&2
      exit 1
    fi
    for mixed_flag in \
      BGW_UNBATCHED_BATCH_ALL_VERIFY \
      BGW_UNBATCHED_BATCH_SHARE_VERIFY \
      BGW_UNBATCHED_BATCH_HIDDEN_VERIFY \
      BGW_UNBATCHED_BATCH_ZERO_VERIFY \
      BGW_UNBATCHED_BATCH_PROD_VERIFY; do
      if [[ "${!mixed_flag:-0}" == "1" ]]; then
        echo "BGW-AggTrans unbatched overhead rejects ${mixed_flag}=1; all four verifier relations must use their unbatched path." >&2
        exit 1
      fi
    done
  fi
fi

if [[ -n "$FAULT_PROFILE" && "$EXP_ID" != "exp4" ]]; then
  echo "--fault-profile is only supported for exp4." >&2
  exit 1
fi
if [[ "$EXP_ID" == "exp4" ]]; then
  if [[ -z "$FAULT_PROFILE" ]]; then
    case "$PROTOCOL" in
      admpc|continuum|dumbo) FAULT_PROFILE="accumulation" ;;
      *) FAULT_PROFILE="legacy-drop" ;;
    esac
  fi
  case "$FAULT_PROFILE" in
    accumulation|attack|legacy-drop) ;;
    *)
      echo "Invalid --fault-profile: ${FAULT_PROFILE}. Expected accumulation, attack, or legacy-drop." >&2
      exit 1
      ;;
  esac
  if [[ "$FAULT_PROFILE" == "accumulation" && "$PROTOCOL" != "admpc" && "$PROTOCOL" != "continuum" && "$PROTOCOL" != "dumbo" ]]; then
    echo "The exp4 accumulation profile supports admpc, continuum, and dumbo." >&2
    exit 1
  fi
  if [[ "$FAULT_PROFILE" == "attack" && "$PROTOCOL" != "admpc" && "$PROTOCOL" != "continuum" ]]; then
    echo "The exp4 attack profile supports admpc and continuum." >&2
    exit 1
  fi
fi

if ! [[ "$SLEEP_BETWEEN_CASE" =~ ^[0-9]+$ ]]; then
  echo "Invalid --sleep-between-case: ${SLEEP_BETWEEN_CASE}" >&2
  exit 1
fi

if ! [[ "$START_DELAY" =~ ^[0-9]+$ ]]; then
  echo "Invalid --start-delay: ${START_DELAY}" >&2
  exit 1
fi

if ! [[ "$RUN_TIMEOUT" =~ ^[1-9][0-9]*$ ]]; then
  echo "Invalid --timeout: ${RUN_TIMEOUT}" >&2
  exit 1
fi

if [[ -n "$ONLY_N" ]] && ! [[ "$ONLY_N" =~ ^[0-9]+$ ]]; then
  echo "Invalid --only-n: ${ONLY_N}" >&2
  exit 1
fi

if [[ -n "$ONLY_D" ]] && ! [[ "$ONLY_D" =~ ^[0-9]+$ ]]; then
  echo "Invalid --only-d: ${ONLY_D}" >&2
  exit 1
fi

if [[ -n "$ONLY_N" ]] && [[ "$EXP_ID" == "exp3" || "$EXP_ID" == "exp4" ]] && [[ "$ONLY_N" != "16" ]]; then
  echo "--only-n=${ONLY_N} does not match ${EXP_ID} preset (fixed n=16)." >&2
  exit 1
fi

if [[ -n "$ONLY_D" && "$EXP_ID" != "exp3" ]]; then
  echo "--only-d is only supported for exp3." >&2
  exit 1
fi

if [[ "$PROTOCOL" == "dumbo" ]] && [[ "$EXP_ID" == "exp1" || "$EXP_ID" == "exp2" ]]; then
  echo "Dumbo is not part of ${EXP_ID}. Supported: exp3, exp4" >&2
  exit 1
fi

if [[ "$PROTOCOL" == "dumbo-bgw-direct" ]] && [[ "$EXP_ID" == "exp1" ]]; then
  echo "dumbo-bgw-direct evaluates multiplication layers; supported: exp2, exp3, exp4" >&2
  exit 1
fi

if [[ ( "$PROTOCOL" == "admpc-shuffle" || "$PROTOCOL" == "shuffle" || "$PROTOCOL" == "shuffle-bgw-static" || "$PROTOCOL" == "dumbo-shuffle-beaver" ) && "$EXP_ID" != "exp-shuffle" ]]; then
  echo "Shuffle protocol uses exp-shuffle." >&2
  exit 1
fi

if [[ "$PROTOCOL" != "admpc-shuffle" && "$PROTOCOL" != "shuffle" && "$PROTOCOL" != "shuffle-bgw-static" && "$PROTOCOL" != "dumbo-shuffle-beaver" && "$EXP_ID" == "exp-shuffle" ]]; then
  echo "exp-shuffle is only supported with protocol=admpc-shuffle, shuffle, shuffle-bgw-static, or dumbo-shuffle-beaver." >&2
  exit 1
fi

load_cluster_env
require_immutable_image
require_tools bash python3 ssh ssh-keygen scp tar timeout

export AGG_KZG_V2="${AGG_KZG_V2:-1}"
export ZMQ_CURVE_READY_TIMEOUT="${ZMQ_CURVE_READY_TIMEOUT:-60}"

if [[ "$AUTH_MODE" == "curve" ]]; then
  if [[ ! -x "$CURVE_VALIDATION_PYTHON" ]] || \
     ! "$CURVE_VALIDATION_PYTHON" -c "import zmq" >/dev/null 2>&1; then
    echo "CURVE validation Python cannot import pyzmq: ${CURVE_VALIDATION_PYTHON}" >&2
    exit 1
  fi
fi

if [[ "$PROTOCOL" == "continuum" || "$PROTOCOL" == "bgw-aggtrans" || "$PROTOCOL" == "shuffle" || "$PROTOCOL" == "shuffle-bgw-static" || "$PROTOCOL" == "dumbo-shuffle-beaver" || "$PROTOCOL" == "dumbo" || "$PROTOCOL" == "dumbo-bgw-direct" ]]; then
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
echo "Image: $MPC_IMAGE"
echo "Compose: $MPC_COMPOSE_FILE"
echo "Start delay: ${START_DELAY}s; per-process hard timeout: ${RUN_TIMEOUT}s"
if [[ -n "$FAULT_PROFILE" ]]; then
  echo "Fault profile: $FAULT_PROFILE"
fi
if [[ -n "$ONLY_N" ]]; then
  echo "Case filter enabled: n=${ONLY_N}"
fi
if [[ -n "$ONLY_D" ]]; then
  echo "Case filter enabled: d=${ONLY_D}"
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

protocol_start_epoch() {
  echo $(( $(date +%s) + START_DELAY ))
}

validate_generated_config() {
  local config_dir="$1"
  local n="$2"
  local layers="$3"
  local ip_file="$4"
  "$CURVE_VALIDATION_PYTHON" "${SCRIPT_DIR}/validate_mpc_config.py" \
    --config-dir "$config_dir" --n "$n" --layers "$layers" \
    --ip-file "$ip_file" --auth-mode "$AUTH_MODE"
}

generate_continuum_config() {
  local n="$1"
  local t="$2"
  local layers="$3"
  local total_cm="$4"

  if [[ "$CONTINUUM_CONFIG_GENERATOR" == "remote-image" ]]; then
    "${SCRIPT_DIR}/generate_continuum_config_remote.sh" \
      "$n" "$t" "$layers" "$total_cm"
    return
  fi

  (
    cd "${ASY_DIR}"
    PYTHONPATH="${ASY_DIR}:${PYTHONPATH:-}" \
      "$CONTINUUM_PYTHON" scripts/create_json_files.py \
        admpc "$n" "$t" "$layers" "$total_cm"
  )
}

generate_dumbo_config() {
  local n="$1"
  local t="$2"
  local k="$3"
  local layers="$4"

  REUSE_EXISTING_CONFIG="$REUSE_CONFIG" \
    "${SCRIPT_DIR}/generate_dumbo_config_remote.sh" \
      "$n" "$t" "$k" "$layers"
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
  if [[ ( "$EXP_ID" == "exp1" || "$EXP_ID" == "exp2" ) && -f "${outdir}/metadata.env" ]] && \
     [[ "$(awk -F= '$1 == "n" {print $2}' "${outdir}/metadata.env")" == "4" ]]; then
    analyzer_args=(--case-dir "$outdir")
    if [[ -n "${ELECTION_SUMMARY:-}" ]]; then
      analyzer_args+=(--election-summary "$ELECTION_SUMMARY")
    fi
    python3 "${SCRIPT_DIR}/analyze_fig89_case.py" "${analyzer_args[@]}"
  else
    printf '%s\n' 'Raw logs copied; the strict analyzer currently targets Figure 8/9 n=4 only.' \
      > "${outdir}/RAW_LOGS_ONLY.txt"
  fi
  if [[ "$PROTOCOL_OVERHEAD" -eq 1 ]]; then
    local case_name metrics_input metrics_output
    case_name="$(basename "$outdir")"
    metrics_input="${outdir}/logs/protocol-overhead/${RUN_TAG}_${case_name}"
    metrics_output="${outdir}/protocol-overhead-summary"
    if [[ ! -d "$metrics_input" ]]; then
      echo "Missing collected protocol-overhead artifacts: $metrics_input" >&2
      exit 1
    fi
    python3 "${SCRIPT_DIR}/../analyze_protocol_overhead.py" \
      "$metrics_input" --output-dir "$metrics_output" \
      --allow-incomplete
  fi
}

ensure_ssh_setup_for_n() {
  local n="$1"
  if [[ "$SKIP_SSH_SETUP" -eq 1 ]]; then
    return
  fi
  local done_n
  for done_n in "${SSH_SETUP_DONE_NS[@]}"; do
    if [[ "$done_n" == "$n" ]]; then
      return
    fi
  done

  local setup_script
  case "$PROTOCOL" in
    admpc|admpc-shuffle)
      setup_script="${ADMPC_DIR}/scripts/setup_ssh_keys.sh"
      ;;
    continuum|bgw-aggtrans|shuffle|shuffle-bgw-static|dumbo-shuffle-beaver|dumbo|dumbo-bgw-direct)
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
  local cleanup_protocol="$PROTOCOL"
  if [[ "$cleanup_protocol" == "admpc-shuffle" ]]; then
    cleanup_protocol="admpc"
  elif [[ "$cleanup_protocol" == "bgw-aggtrans" ]]; then
    cleanup_protocol="continuum"
  elif [[ "$cleanup_protocol" == "shuffle" || "$cleanup_protocol" == "shuffle-bgw-static" || "$cleanup_protocol" == "dumbo-shuffle-beaver" ]]; then
    cleanup_protocol="continuum"
  elif [[ "$cleanup_protocol" == "dumbo-bgw-direct" ]]; then
    cleanup_protocol="dumbo"
  fi

  local cleanup_script="${SCRIPT_DIR}/cleanup_remote_ports.sh"
  if [[ ! -x "$cleanup_script" ]]; then
    echo "Cleanup script is missing or not executable: ${cleanup_script}" >&2
    exit 1
  fi

  echo "Cleaning remote leftover containers for protocol=${cleanup_protocol}, N=${n}"
  if [[ -n "${CLUSTER_ENV:-}" ]]; then
    CLUSTER_ENV="$CLUSTER_ENV" "$cleanup_script" --protocol "$cleanup_protocol" --n "$n"
  else
    "$cleanup_script" --protocol "$cleanup_protocol" --n "$n"
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

append_fault_metadata() {
  local outdir="$1"
  local role="$2"
  local count="${3:-}"
  if [[ "$EXP_ID" != "exp4" ]]; then
    return
  fi
  {
    echo "fault_profile=${FAULT_PROFILE}"
    echo "fault_role=${role}"
    if [[ "$FAULT_PROFILE" == "accumulation" ]]; then
      echo "fault_accumulation_count=${count}"
      echo "fault_accumulation_start_epoch=1"
      if [[ "$role" == "static-cumulative-t-new-per-epoch" ]]; then
        echo "observation_timeout_seconds=${DUMBO_TIMEOUT}"
      fi
    elif [[ "$FAULT_PROFILE" == "attack" ]]; then
      echo "fault_delay_source_epoch=3"
      echo "fault_delay_ms=10000"
      echo "fault_attack_source_epoch=4"
      if [[ "$role" == "continuum-figure10-source-epochs" ]]; then
        echo "fault_batchmul_source_epoch=5"
      fi
      echo "fault_attack_index=0"
    fi
  } >> "${outdir}/metadata.env"
}

verify_fault_trace_if_needed() {
  local outdir="$1"
  local protocol="$2"
  local count="$3"
  if [[ "$EXP_ID" != "exp4" || "$FAULT_PROFILE" != "accumulation" ]]; then
    return
  fi
  python3 "${SCRIPT_DIR}/verify_figure10_fault_trace.py" \
    --case-dir "$outdir" --protocol "$protocol" --n 16 --t 5 --d 6 --count "$count"
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
    export PROTOCOL_OVERHEAD_METRICS="$PROTOCOL_OVERHEAD"
    export PROTOCOL_OVERHEAD_RUN_ID="${RUN_TAG}_${case_name}"
    cd "${ADMPC_DIR}/scripts"
    if [[ "$SYNC_CODE" -eq 1 ]]; then
      ./distribute-docker.sh
    fi
    if [[ "$REUSE_CONFIG" -eq 1 ]]; then
      if [[ ! -d "${ADMPC_DIR}/conf/${conf_dir}" ]]; then
        echo "Cannot reuse missing AD-MPC config: ${ADMPC_DIR}/conf/${conf_dir}" >&2
        exit 1
      fi
      echo "Reusing existing AD-MPC config ${conf_dir}; skipping JSON generation and distribution"
    else
      ./create_json_files.sh "$protocol_name" "$n" "$t" "$layers_total" "$total_cm"
      validate_generated_config "${ADMPC_DIR}/conf/${conf_dir}" "$n" "$layers_total" "${ASY_SCRIPTS_DIR}/ip.txt"
      ./distribute-file.sh "$conf_dir"
    fi
    if [[ "$EXP_ID" == "exp4" && "$FAULT_PROFILE" == "accumulation" ]]; then
      env -u FAULT_MODE \
          -u FAULT_TARGET \
          -u FAULT_COMPUTATION_EPOCH \
          -u FAULT_DELAY_SOURCE_EPOCH \
          -u FAULT_ADTRANS_SOURCE_EPOCH \
          -u FAULT_DELTA_MS \
          -u FAULT_ATTACK_INDEX \
          FAULT_ACCUMULATION_MODE=silent \
          FAULT_ACCUMULATION_COUNT="$t" \
          FAULT_ACCUMULATION_START_EPOCH=1 \
          ./control-node.sh "$conf_dir" "$protocol_name" "$(protocol_start_epoch)" "$RUN_TIMEOUT"
    elif [[ "$EXP_ID" == "exp4" && "$FAULT_PROFILE" == "attack" ]]; then
      env -u FAULT_ACCUMULATION_MODE \
          -u FAULT_ACCUMULATION_COUNT \
          -u FAULT_ACCUMULATION_START_EPOCH \
          -u FAULT_COMPUTATION_EPOCH \
          FAULT_MODE=figure10-attack \
          FAULT_TARGET=adtrans \
          FAULT_DELAY_SOURCE_EPOCH=3 \
          FAULT_ADTRANS_SOURCE_EPOCH=4 \
          FAULT_DELTA_MS=10000 \
          FAULT_ATTACK_INDEX=0 \
          ./control-node.sh "$conf_dir" "$protocol_name" "$(protocol_start_epoch)" "$RUN_TIMEOUT"
    else
      env -u FAULT_ACCUMULATION_MODE \
          -u FAULT_ACCUMULATION_COUNT \
          -u FAULT_ACCUMULATION_START_EPOCH \
          -u FAULT_MODE \
          -u FAULT_TARGET \
          -u FAULT_COMPUTATION_EPOCH \
          -u FAULT_DELAY_SOURCE_EPOCH \
          -u FAULT_ADTRANS_SOURCE_EPOCH \
          -u FAULT_DELTA_MS \
          -u FAULT_ATTACK_INDEX \
          ./control-node.sh "$conf_dir" "$protocol_name" "$(protocol_start_epoch)" "$RUN_TIMEOUT"
    fi
  )

  mkdir -p "$outdir"
  save_metadata "$outdir" "admpc" "$EXP_ID" "$n" "$t" "$d" "$layers_total" "$total_cm"
  echo "reuse_config=${REUSE_CONFIG}" >> "${outdir}/metadata.env"
  if [[ "$EXP_ID" == "exp4" && "$FAULT_PROFILE" == "accumulation" ]]; then
    append_fault_metadata "$outdir" "dynamic-t-silent-per-computation-committee" "$t"
  elif [[ "$EXP_ID" == "exp4" && "$FAULT_PROFILE" == "attack" ]]; then
    append_fault_metadata "$outdir" "admpc-figure10-source-epochs" "$t"
  else
    append_fault_metadata "$outdir" "no-fault" "$t"
  fi
  cp -r "${ADMPC_DIR}/scripts/logs" "${outdir}/logs" 2>/dev/null || true
  cp -r "${ADMPC_DIR}/conf/${conf_dir}" "${outdir}/conf" 2>/dev/null || true
  collect_raw_logs_placeholder "$outdir"
  verify_fault_trace_if_needed "$outdir" "admpc" "$t"
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
  if [[ "$PROTOCOL" == "bgw-aggtrans" ]]; then
    protocol_override="admpc2-bgw-aggtrans"
  else
    protocol_override="$(continuum_protocol_name "$gate_mode")"
  fi
  local conf_dir="admpc_${total_cm}_${layers_total}_${n}"
  local outdir="${SESSION_DIR}/${case_name}"
  local run_status=0

  echo "[${PROTOCOL}] ${case_name}: mode=${gate_mode}, n=${n}, t=${t}, d=${d}, layers=${layers_total}, total_cm=${total_cm}"
  sync_cluster_for_n "$n"
  ensure_ssh_setup_for_n "$n"
  cleanup_remote_before_case "$n"

  if (
    export PROTOCOL_OVERHEAD_METRICS="$PROTOCOL_OVERHEAD"
    export PROTOCOL_OVERHEAD_RUN_ID="${RUN_TAG}_${case_name}"
    if [[ "$REUSE_CONFIG" -eq 1 ]]; then
      if [[ ! -d "${ASY_DIR}/conf/${conf_dir}" ]]; then
        echo "Cannot reuse missing Continuum config: ${ASY_DIR}/conf/${conf_dir}" >&2
        exit 1
      fi
      echo "Reusing existing Continuum config ${conf_dir}; skipping JSON generation and distribution"
    else
      generate_continuum_config "$n" "$t" "$layers_total" "$total_cm"
      validate_generated_config "${ASY_DIR}/conf/${conf_dir}" "$n" "$layers_total" "${ASY_SCRIPTS_DIR}/ip.txt"
    fi

    cd "${ASY_SCRIPTS_DIR}"
    ./distribute-admpc.sh
    if [[ "$SYNC_CODE" -eq 1 ]]; then
      ./distribute-docker.sh
    fi
    if [[ "$REUSE_CONFIG" -eq 0 ]]; then
      ./distribute-file.sh "$conf_dir"
    fi
    if [[ "$EXP_ID" == "exp4" && "$FAULT_PROFILE" == "accumulation" && "$PROTOCOL" == "continuum" ]]; then
      env -u FAULT_MODE \
          -u FAULT_TARGET \
          -u FAULT_COMPUTATION_EPOCH \
          -u FAULT_BATCHMUL_EPOCH \
          -u FAULT_DELAY_SOURCE_EPOCH \
          -u FAULT_AGGTRANS_SOURCE_EPOCH \
          -u FAULT_BATCHMUL_SOURCE_EPOCH \
          -u FAULT_DELTA_MS \
          -u FAULT_ATTACK_INDEX \
          FAULT_ACCUMULATION_MODE=silent \
          FAULT_ACCUMULATION_COUNT="$t" \
          FAULT_ACCUMULATION_START_EPOCH=1 \
          ./control-node.sh "$conf_dir" "$protocol_override" "$(protocol_start_epoch)" "$RUN_TIMEOUT"
    elif [[ "$EXP_ID" == "exp4" && "$FAULT_PROFILE" == "attack" && "$PROTOCOL" == "continuum" ]]; then
      env -u FAULT_ACCUMULATION_MODE \
          -u FAULT_ACCUMULATION_COUNT \
          -u FAULT_ACCUMULATION_START_EPOCH \
          -u FAULT_COMPUTATION_EPOCH \
          -u FAULT_BATCHMUL_EPOCH \
          FAULT_MODE=figure10-attack \
          FAULT_TARGET=handoff+aggtrans+batchmul \
          FAULT_DELAY_SOURCE_EPOCH=3 \
          FAULT_AGGTRANS_SOURCE_EPOCH=4 \
          FAULT_BATCHMUL_SOURCE_EPOCH=5 \
          FAULT_DELTA_MS=10000 \
          FAULT_ATTACK_INDEX=0 \
          ./control-node.sh "$conf_dir" "$protocol_override" "$(protocol_start_epoch)" "$RUN_TIMEOUT"
    else
      env -u FAULT_ACCUMULATION_MODE \
          -u FAULT_ACCUMULATION_COUNT \
          -u FAULT_ACCUMULATION_START_EPOCH \
          -u FAULT_MODE \
          -u FAULT_TARGET \
          -u FAULT_COMPUTATION_EPOCH \
          -u FAULT_BATCHMUL_EPOCH \
          -u FAULT_DELAY_SOURCE_EPOCH \
          -u FAULT_AGGTRANS_SOURCE_EPOCH \
          -u FAULT_BATCHMUL_SOURCE_EPOCH \
          -u FAULT_DELTA_MS \
          -u FAULT_ATTACK_INDEX \
          ./control-node.sh "$conf_dir" "$protocol_override" "$(protocol_start_epoch)" "$RUN_TIMEOUT"
    fi
  ); then
    run_status=0
  else
    run_status=$?
    echo "Continuum case exited with status ${run_status}; archiving partial logs and metrics." >&2
  fi

  mkdir -p "$outdir"
  save_metadata "$outdir" "$PROTOCOL" "$EXP_ID" "$n" "$t" "$d" "$layers_total" "$total_cm"
  echo "reuse_config=${REUSE_CONFIG}" >> "${outdir}/metadata.env"
  echo "process_run_exit_status=${run_status}" >> "${outdir}/metadata.env"
  if [[ "$EXP_ID" == "exp4" && "$FAULT_PROFILE" == "accumulation" ]]; then
    append_fault_metadata "$outdir" "dynamic-t-silent-per-computation-committee" "$t"
  elif [[ "$EXP_ID" == "exp4" && "$FAULT_PROFILE" == "attack" ]]; then
    append_fault_metadata "$outdir" "continuum-figure10-source-epochs" "$t"
  else
    append_fault_metadata "$outdir" "no-fault" "$t"
  fi
  cp -r "${ASY_SCRIPTS_DIR}/logs" "${outdir}/logs" 2>/dev/null || true
  cp -r "${ASY_DIR}/conf/${conf_dir}" "${outdir}/conf" 2>/dev/null || true
  collect_raw_logs_placeholder "$outdir"
  verify_fault_trace_if_needed "$outdir" "continuum" "$t"
  if [[ "$run_status" -ne 0 ]]; then
    return "$run_status"
  fi
}

shuffle_switch_layers() {
  local k="$1"
  local mode="${2:-single}"
  local rounds=0
  local value="$k"
  while (( value > 1 )); do
    if (( value % 2 != 0 )); then
      echo "shuffle k must be a power of two: ${k}" >&2
      exit 1
    fi
    value=$(( value / 2 ))
    rounds=$(( rounds + 1 ))
  done
  case "$mode" in
    single) echo "$rounds" ;;
    iterated) echo $(( rounds * rounds )) ;;
    *)
      echo "Invalid SHUFFLE_MODE=${mode}; expected single or iterated" >&2
      exit 1
      ;;
  esac
}

shuffle_handoff_interval() {
  local switch_layers="$1"
  local raw="${SHUFFLE_HANDOFF_INTERVAL:-1}"
  raw="$(printf '%s' "$raw" | tr '[:upper:]' '[:lower:]')"
  case "$raw" in
    static|none|no-handoff|nohandoff|inf|infinity)
      echo "$switch_layers"
      ;;
    *)
      if ! [[ "$raw" =~ ^[0-9]+$ ]]; then
        echo "Invalid SHUFFLE_HANDOFF_INTERVAL=${SHUFFLE_HANDOFF_INTERVAL:-}" >&2
        exit 1
      fi
      if (( raw <= 0 )); then
        echo "Invalid SHUFFLE_HANDOFF_INTERVAL=${SHUFFLE_HANDOFF_INTERVAL:-}" >&2
        exit 1
      fi
      if (( raw > switch_layers )); then
        echo "$switch_layers"
      else
        echo "$raw"
      fi
      ;;
  esac
}

shuffle_compute_blocks() {
  local switch_layers="$1"
  local handoff_interval="$2"
  echo $(( (switch_layers + handoff_interval - 1) / handoff_interval ))
}

run_admpc_shuffle_case() {
  local case_name="$1"
  local n="$2"
  local t="$3"
  local k="$4"
  local mode="${5:-iterated}"

  local switch_layers
  switch_layers="$(shuffle_switch_layers "$k" "$mode")"
  local layers_total=$((switch_layers + 2))
  local conf_dir="admpc-shuffle_${k}_${switch_layers}_${n}"
  local outdir="${SESSION_DIR}/${case_name}"
  local shuffle_run_id="${RUN_TAG}_${case_name}"
  local launch_rc=0
  local analysis_rc=0

  echo "[admpc-shuffle] ${case_name}: mode=${mode}, n=${n}, t=${t}, k=${k}, switch_layers=${switch_layers}, layers=${layers_total}"
  sync_cluster_for_n "$n"
  ensure_ssh_setup_for_n "$n"
  cleanup_remote_before_case "$n"

  set +e
  (
    set -e
    cd "${ADMPC_DIR}/scripts"
    if [[ "$REUSE_CONFIG" -eq 1 ]]; then
      if [[ ! -d "${ADMPC_DIR}/conf/${conf_dir}" ]]; then
        echo "Cannot reuse missing AD-MPC shuffle config: ${ADMPC_DIR}/conf/${conf_dir}" >&2
        exit 1
      fi
      echo "Reusing existing AD-MPC shuffle config ${conf_dir}; skipping JSON generation"
    else
      ./create_json_files.sh admpc-shuffle "$n" "$t" "$layers_total" "$k"
    fi
    validate_generated_config "${ADMPC_DIR}/conf/${conf_dir}" "$n" "$layers_total" "${ASY_SCRIPTS_DIR}/ip.txt"
    # AD-MPC shuffle logs run on the remote hosts, so a reused local config is
    # still distributed explicitly before launch. This also makes one command
    # sufficient after preparing the 510 CURVE-enabled files locally.
    ./distribute-file.sh "$conf_dir"
    SHUFFLE_K="$k" \
    SHUFFLE_MODE="$mode" \
    SHUFFLE_ACK_TIMEOUT="${SHUFFLE_ACK_TIMEOUT:-600}" \
    SHUFFLE_ACK_THRESHOLD="${SHUFFLE_ACK_THRESHOLD:-$n}" \
    ADMPC_SHUFFLE_RUN_ID="$shuffle_run_id" \
      ./control-node.sh "$conf_dir" admpc-shuffle "$(protocol_start_epoch)" "$RUN_TIMEOUT"
  )
  launch_rc=$?
  set -e

  mkdir -p "$outdir"
  save_metadata "$outdir" admpc-shuffle "$EXP_ID" "$n" "$t" "$switch_layers" "$layers_total" "$k"
  {
    echo "shuffle_mode=${mode}"
    echo "shuffle_switch_layers=${switch_layers}"
    echo "shuffle_ack_timeout_seconds=${SHUFFLE_ACK_TIMEOUT:-600}"
    echo "shuffle_ack_threshold=${SHUFFLE_ACK_THRESHOLD:-$n}"
    echo "admpc_shuffle_run_id=${shuffle_run_id}"
    echo "reuse_config=${REUSE_CONFIG}"
    echo "live_progress_logs=node<N>_launcher.log"
    echo "launcher_exit_code=${launch_rc}"
  } >> "${outdir}/metadata.env"
  cp -r "${ADMPC_DIR}/scripts/logs" "${outdir}/logs" 2>/dev/null || true
  cp -r "${ADMPC_DIR}/conf/${conf_dir}" "${outdir}/conf" 2>/dev/null || true

  set +e
  python3 "${SCRIPT_DIR}/../analyze_admpc_shuffle.py" \
    "${outdir}/logs" --output-dir "$outdir"
  analysis_rc=$?
  set -e
  echo "analysis_exit_code=${analysis_rc}" >> "${outdir}/metadata.env"

  if [[ "$launch_rc" -ne 0 || "$analysis_rc" -ne 0 ]]; then
    echo "AD-MPC shuffle case failed: launcher_rc=${launch_rc}, analysis_rc=${analysis_rc}; archived at ${outdir}" >&2
    return 1
  fi
}

bgw_batch_verify_flag() {
  local env_name="$1"
  local env_value="${!env_name-}"
  if [[ "${BGW_UNBATCHED_BATCH_ALL_VERIFY:-}" == "1" || "$env_value" == "1" ]]; then
    echo 1
  else
    echo 0
  fi
}

bgw_batch_verify_summary() {
  printf 'all=%s,share=%s,hidden=%s,zero=%s,prod=%s,batch_path_unbatched_prod=%s' \
    "${BGW_UNBATCHED_BATCH_ALL_VERIFY:-0}" \
    "$(bgw_batch_verify_flag BGW_UNBATCHED_BATCH_SHARE_VERIFY)" \
    "$(bgw_batch_verify_flag BGW_UNBATCHED_BATCH_HIDDEN_VERIFY)" \
    "$(bgw_batch_verify_flag BGW_UNBATCHED_BATCH_ZERO_VERIFY)" \
    "$(bgw_batch_verify_flag BGW_UNBATCHED_BATCH_PROD_VERIFY)" \
    "${BGW_BATCH_UNBATCHED_PROD_VERIFY:-0}"
}

dumbo_beaver_mix_suffix() {
  if [[ "${BGW_UNBATCHED_BATCH_ALL_VERIFY:-}" == "1" ]]; then
    echo "_mixed_all_batch"
    return
  fi

  local suffix=""
  if [[ "${BGW_UNBATCHED_BATCH_SHARE_VERIFY:-}" == "1" ]]; then
    suffix="${suffix}_share"
  fi
  if [[ "${BGW_UNBATCHED_BATCH_HIDDEN_VERIFY:-}" == "1" ]]; then
    suffix="${suffix}_hidden"
  fi
  if [[ "${BGW_UNBATCHED_BATCH_ZERO_VERIFY:-}" == "1" ]]; then
    suffix="${suffix}_zero"
  fi
  if [[ "${BGW_UNBATCHED_BATCH_PROD_VERIFY:-}" == "1" ]]; then
    suffix="${suffix}_prod"
  fi

  if [[ -n "$suffix" ]]; then
    echo "_mixed${suffix}_batch"
  fi
}

batch_path_mix_suffix() {
  if [[ "${BGW_BATCH_UNBATCHED_PROD_VERIFY:-}" == "1" ]]; then
    echo "_batch_prod_unbatched"
  fi
}

run_shuffle_case() {
  local case_name="$1"
  local n="$2"
  local t="$3"
  local k="$4"
  local mode="${5:-single}"

  local switch_layers
  switch_layers="$(shuffle_switch_layers "$k" "$mode")"
  local handoff_interval
  handoff_interval="$(shuffle_handoff_interval "$switch_layers")"
  local compute_blocks
  compute_blocks="$(shuffle_compute_blocks "$switch_layers" "$handoff_interval")"
  local layers_total=$((compute_blocks + 2))
  local conf_dir="admpc_${k}_${layers_total}_${n}"
  local outdir="${SESSION_DIR}/${case_name}"

  echo "[shuffle] ${case_name}: mode=${mode}, h=${handoff_interval}, n=${n}, t=${t}, k=${k}, switch_layers=${switch_layers}, compute_blocks=${compute_blocks}, layers=${layers_total}"
  sync_cluster_for_n "$n"
  ensure_ssh_setup_for_n "$n"
  cleanup_remote_before_case "$n"

  (
    if [[ "$REUSE_CONFIG" -eq 1 ]]; then
      if [[ ! -d "${ASY_DIR}/conf/${conf_dir}" ]]; then
        echo "Cannot reuse missing Continuum shuffle config: ${ASY_DIR}/conf/${conf_dir}" >&2
        exit 1
      fi
      echo "Reusing existing Continuum shuffle config ${conf_dir}; skipping JSON generation and distribution"
    else
      generate_continuum_config "$n" "$t" "$layers_total" "$k"
    fi
    validate_generated_config "${ASY_DIR}/conf/${conf_dir}" "$n" "$layers_total" "${ASY_SCRIPTS_DIR}/ip.txt"

    cd "${ASY_SCRIPTS_DIR}"
    ./distribute-admpc.sh
    if [[ "$SYNC_CODE" -eq 1 ]]; then
      ./distribute-docker.sh
    fi
    if [[ "$REUSE_CONFIG" -eq 0 ]]; then
      ./distribute-file.sh "$conf_dir"
    fi
    SHUFFLE_MODE="$mode" SHUFFLE_HANDOFF_INTERVAL="$handoff_interval" ./control-node.sh "$conf_dir" "admpc2-shuffle" "$(protocol_start_epoch)" "$RUN_TIMEOUT"
  )

  mkdir -p "$outdir"
  save_metadata "$outdir" "shuffle" "$EXP_ID" "$n" "$t" "$switch_layers" "$layers_total" "$k"
  echo "reuse_config=${REUSE_CONFIG}" >> "${outdir}/metadata.env"
  cp -r "${ASY_SCRIPTS_DIR}/logs" "${outdir}/logs" 2>/dev/null || true
  cp -r "${ASY_DIR}/conf/${conf_dir}" "${outdir}/conf" 2>/dev/null || true
  collect_raw_logs_placeholder "$outdir"
}

run_shuffle_bgw_static_case() {
  local case_name="$1"
  local n="$2"
  local t="$3"
  local k="$4"
  local mode="${5:-single}"

  local switch_layers
  switch_layers="$(shuffle_switch_layers "$k" "$mode")"
  local layers_total=3
  local conf_dir="admpc_${k}_${layers_total}_${n}"
  local outdir="${SESSION_DIR}/${case_name}"

  echo "[shuffle-bgw-static] ${case_name}: mode=${mode}, n=${n}, t=${t}, k=${k}, switch_layers=${switch_layers}, layers=${layers_total}"
  sync_cluster_for_n "$n"
  ensure_ssh_setup_for_n "$n"
  cleanup_remote_before_case "$n"

  (
    if [[ "$REUSE_CONFIG" -eq 1 ]]; then
      if [[ ! -d "${ASY_DIR}/conf/${conf_dir}" ]]; then
        echo "Cannot reuse missing BGW-AMPC shuffle config: ${ASY_DIR}/conf/${conf_dir}" >&2
        exit 1
      fi
      echo "Reusing existing BGW-AMPC shuffle config ${conf_dir}; skipping JSON generation and distribution"
    else
      generate_continuum_config "$n" "$t" "$layers_total" "$k"
    fi
    validate_generated_config "${ASY_DIR}/conf/${conf_dir}" "$n" "$layers_total" "${ASY_SCRIPTS_DIR}/ip.txt"

    cd "${ASY_SCRIPTS_DIR}"
    ./distribute-admpc.sh
    if [[ "$SYNC_CODE" -eq 1 ]]; then
      ./distribute-docker.sh
    fi
    if [[ "$REUSE_CONFIG" -eq 0 ]]; then
      ./distribute-file.sh "$conf_dir"
    fi
    SHUFFLE_MODE="$mode" ./control-node.sh "$conf_dir" "admpc2-shuffle-bgw-static" "$(protocol_start_epoch)" "$RUN_TIMEOUT"
  )

  mkdir -p "$outdir"
  save_metadata "$outdir" "shuffle-bgw-static" "$EXP_ID" "$n" "$t" "$switch_layers" "$layers_total" "$k"
  echo "reuse_config=${REUSE_CONFIG}" >> "${outdir}/metadata.env"
  cp -r "${ASY_SCRIPTS_DIR}/logs" "${outdir}/logs" 2>/dev/null || true
  cp -r "${ASY_DIR}/conf/${conf_dir}" "${outdir}/conf" 2>/dev/null || true
  collect_raw_logs_placeholder "$outdir"
}

run_dumbo_shuffle_beaver_case() {
  local case_name="$1"
  local n="$2"
  local t="$3"
  local k="$4"
  local mode="${5:-single}"

  local switch_layers
  switch_layers="$(shuffle_switch_layers "$k" "$mode")"
  local layers_total=3
  local conf_dir="admpc_${k}_${layers_total}_${n}"
  local outdir="${SESSION_DIR}/${case_name}"
  local triples_needed=$(( (k / 2) * switch_layers ))

  echo "[dumbo-shuffle-beaver] ${case_name}: mode=${mode}, n=${n}, t=${t}, k=${k}, switch_layers=${switch_layers}, triples=${triples_needed}, layers=${layers_total}, mixed_batch_verify={$(bgw_batch_verify_summary)}"
  sync_cluster_for_n "$n"
  ensure_ssh_setup_for_n "$n"
  cleanup_remote_before_case "$n"

  (
    generate_continuum_config "$n" "$t" "$layers_total" "$k"
    validate_generated_config "${ASY_DIR}/conf/${conf_dir}" "$n" "$layers_total" "${ASY_SCRIPTS_DIR}/ip.txt"

    cd "${ASY_SCRIPTS_DIR}"
    ./distribute-admpc.sh
    if [[ "$SYNC_CODE" -eq 1 ]]; then
      ./distribute-docker.sh
    fi
    ./distribute-file.sh "$conf_dir"
    SHUFFLE_MODE="$mode" ./control-node.sh "$conf_dir" "admpc2-dumbo-shuffle-beaver" "$(protocol_start_epoch)" "$RUN_TIMEOUT"
  )

  mkdir -p "$outdir"
  save_metadata "$outdir" "dumbo-shuffle-beaver" "$EXP_ID" "$n" "$t" "$switch_layers" "$layers_total" "$k" "$triples_needed"
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
    generate_dumbo_config "$n" "$t" "$k" "$d"

    cd "${ASY_SCRIPTS_DIR}"
    ./distribute-admpc.sh
    if [[ "$SYNC_CODE" -eq 1 ]]; then
      ./distribute-docker.sh
    fi
    ./distribute-file.sh "$conf_dir"

    cd "${REMOTE_ASY_SCRIPTS_DIR}"
    if [[ "$DUMBO_TIMEOUT" -gt 0 ]]; then
      set +e
      if [[ "$dumbo_mode" == "fault-accumulation" ]]; then
        FAULT_ACCUMULATION_MODE=silent \
        FAULT_ACCUMULATION_COUNT="$t" \
        FAULT_ACCUMULATION_START_EPOCH=1 \
          timeout "${DUMBO_TIMEOUT}s" ./launch_asyrantrigen.sh "$n" "$k" "$d" "$dumbo_mode"
      else
        env -u FAULT_ACCUMULATION_MODE \
            -u FAULT_ACCUMULATION_COUNT \
            -u FAULT_ACCUMULATION_START_EPOCH \
            timeout "${DUMBO_TIMEOUT}s" ./launch_asyrantrigen.sh "$n" "$k" "$d" "$dumbo_mode"
      fi
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
      if [[ "$dumbo_mode" == "fault-accumulation" ]]; then
        FAULT_ACCUMULATION_MODE=silent \
        FAULT_ACCUMULATION_COUNT="$t" \
        FAULT_ACCUMULATION_START_EPOCH=1 \
          ./launch_asyrantrigen.sh "$n" "$k" "$d" "$dumbo_mode"
      else
        env -u FAULT_ACCUMULATION_MODE \
            -u FAULT_ACCUMULATION_COUNT \
            -u FAULT_ACCUMULATION_START_EPOCH \
            ./launch_asyrantrigen.sh "$n" "$k" "$d" "$dumbo_mode"
      fi
    fi
  )

  mkdir -p "$outdir"
  save_metadata "$outdir" "dumbo" "$EXP_ID" "$n" "$t" "$d" "$layers_total" "$k" "$dumbo_mode"
  if [[ "$dumbo_mode" == "fault-accumulation" ]]; then
    append_fault_metadata "$outdir" "static-cumulative-t-new-per-epoch" "$t"
  else
    append_fault_metadata "$outdir" "legacy-drop-epoch4" "$t"
  fi
  cp -r "${REMOTE_ASY_SCRIPTS_DIR}/logs" "${outdir}/remote_logs" 2>/dev/null || true
  cp -r "${ASY_DIR}/conf/${conf_dir}" "${outdir}/conf" 2>/dev/null || true
  collect_raw_logs_placeholder "$outdir"
  verify_fault_trace_if_needed "$outdir" "dumbo" "$t"
}

run_dumbo_bgw_direct_case() {
  local case_name="$1"
  local n="$2"
  local t="$3"
  local d="$4"
  local k="$5"
  local dumbo_mode="${6:-full}"

  local layers_total=$((d + 2))
  local conf_dir="mpc_${n}"
  local outdir="${SESSION_DIR}/${case_name}"

  echo "[dumbo-bgw-direct] ${case_name}: mode=${dumbo_mode}, n=${n}, t=${t}, d=${d}, k=${k}"
  sync_cluster_for_n "$n"
  ensure_ssh_setup_for_n "$n"
  cleanup_remote_before_case "$n"

  (
    generate_dumbo_config "$n" "$t" "$k" "$d"

    cd "${ASY_SCRIPTS_DIR}"
    ./distribute-admpc.sh
    if [[ "$SYNC_CODE" -eq 1 ]]; then
      ./distribute-docker.sh
    fi
    ./distribute-file.sh "$conf_dir"

    cd "${REMOTE_ASY_SCRIPTS_DIR}"
    if [[ "$DUMBO_TIMEOUT" -gt 0 ]]; then
      set +e
      timeout "${DUMBO_TIMEOUT}s" ./launch_bgw_direct.sh "$n" "$k" "$d" "$dumbo_mode"
      rc=$?
      set -e
      if [[ "$rc" -ne 0 && "$rc" -ne 124 ]]; then
        echo "Dumbo-BGW direct launch failed with rc=${rc}" >&2
        exit "$rc"
      fi
      if [[ "$rc" -eq 124 ]]; then
        echo "Dumbo-BGW direct launch hit timeout (${DUMBO_TIMEOUT}s)."
      fi
    else
      ./launch_bgw_direct.sh "$n" "$k" "$d" "$dumbo_mode"
    fi
  )

  mkdir -p "$outdir"
  save_metadata "$outdir" "dumbo-bgw-direct" "$EXP_ID" "$n" "$t" "$d" "$layers_total" "$k" "$dumbo_mode"
  cp -r "${REMOTE_ASY_SCRIPTS_DIR}/logs" "${outdir}/remote_logs" 2>/dev/null || true
  cp -r "${ASY_DIR}/conf/${conf_dir}" "${outdir}/conf" 2>/dev/null || true
  collect_raw_logs_placeholder "$outdir"
}

WIDTH=100
EXP_SCALE_NS=(4 10 16 22 128)
EXP_SCALE_TS=(1 3 5 7 42)

case "$EXP_ID" in
  exp-shuffle)
    SHUFFLE_K="${SHUFFLE_K:-128}"
    SHUFFLE_MODE_VALUE="${SHUFFLE_MODE:-single}"
    NS=("${EXP_SCALE_NS[@]}")
    TS=("${EXP_SCALE_TS[@]}")
    selected_indices=()
    for idx in "${!NS[@]}"; do
      n="${NS[$idx]}"
      if [[ -n "$ONLY_N" ]] && [[ "$n" != "$ONLY_N" ]]; then
        continue
      fi
      selected_indices+=("$idx")
    done
    if [[ "${#selected_indices[@]}" -eq 0 ]]; then
      echo "No exp-shuffle cases selected with --only-n=${ONLY_N}" >&2
      exit 1
    fi

    for run_idx in "${!selected_indices[@]}"; do
      idx="${selected_indices[$run_idx]}"
      n="${NS[$idx]}"
      t="${TS[$idx]}"
      if [[ "$PROTOCOL" == "admpc-shuffle" ]]; then
        case_name="n${n}_t${t}_k${SHUFFLE_K}_${SHUFFLE_MODE_VALUE}_admpc"
        run_admpc_shuffle_case "$case_name" "$n" "$t" "$SHUFFLE_K" "$SHUFFLE_MODE_VALUE"
      elif [[ "$PROTOCOL" == "shuffle" ]]; then
        switch_layers="$(shuffle_switch_layers "$SHUFFLE_K" "$SHUFFLE_MODE_VALUE")"
        handoff_interval="$(shuffle_handoff_interval "$switch_layers")"
        case_name="n${n}_t${t}_k${SHUFFLE_K}_${SHUFFLE_MODE_VALUE}_h${handoff_interval}"
        run_shuffle_case "$case_name" "$n" "$t" "$SHUFFLE_K" "$SHUFFLE_MODE_VALUE"
      elif [[ "$PROTOCOL" == "shuffle-bgw-static" ]]; then
        case_name="n${n}_t${t}_k${SHUFFLE_K}_${SHUFFLE_MODE_VALUE}_bgw_static"
        run_shuffle_bgw_static_case "$case_name" "$n" "$t" "$SHUFFLE_K" "$SHUFFLE_MODE_VALUE"
      else
        case_name="n${n}_t${t}_k${SHUFFLE_K}_${SHUFFLE_MODE_VALUE}_dumbo_beaver"
        case_name="${case_name}$(dumbo_beaver_mix_suffix)$(batch_path_mix_suffix)"
        run_dumbo_shuffle_beaver_case "$case_name" "$n" "$t" "$SHUFFLE_K" "$SHUFFLE_MODE_VALUE"
      fi
      pause_between_cases_if_needed "$run_idx" "${#selected_indices[@]}"
    done
    ;;

  exp1)
    GATE_MODE="linear"
    D=6
    NS=("${EXP_SCALE_NS[@]}")
    TS=("${EXP_SCALE_TS[@]}")
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
      elif [[ "$PROTOCOL" == "continuum" || "$PROTOCOL" == "bgw-aggtrans" ]]; then
        run_continuum_case "$case_name" "$GATE_MODE" "$n" "$t" "$D" "$total_cm"
      else
        run_dumbo_bgw_direct_case "$case_name" "$n" "$t" "$D" "$total_cm"
      fi
      pause_between_cases_if_needed "$run_idx" "${#selected_indices[@]}"
    done
    ;;

  exp2)
    GATE_MODE="nonlinear"
    D=6
    NS=("${EXP_SCALE_NS[@]}")
    TS=("${EXP_SCALE_TS[@]}")
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
      elif [[ "$PROTOCOL" == "continuum" || "$PROTOCOL" == "bgw-aggtrans" ]]; then
        run_continuum_case "$case_name" "$GATE_MODE" "$n" "$t" "$D" "$total_cm"
      else
        run_dumbo_bgw_direct_case "$case_name" "$n" "$t" "$D" "$total_cm"
      fi
      pause_between_cases_if_needed "$run_idx" "${#selected_indices[@]}"
    done
    ;;

  exp3)
    GATE_MODE="mixed"
    N=16
    T=5
    DS=(2 4 6 8 10)
    selected_ds=()
    for d in "${DS[@]}"; do
      if [[ -n "$ONLY_D" && "$d" != "$ONLY_D" ]]; then
        continue
      fi
      selected_ds+=("$d")
    done
    if [[ "${#selected_ds[@]}" -eq 0 ]]; then
      echo "No exp3 cases selected with --only-d=${ONLY_D}. Supported d values: ${DS[*]}" >&2
      exit 1
    fi

    for run_idx in "${!selected_ds[@]}"; do
      d="${selected_ds[$run_idx]}"
      total_cm="$(total_cm_for_gate "$GATE_MODE" "$WIDTH" "$d")"
      case_name="n${N}_t${T}_d${d}"
      if [[ "$PROTOCOL" == "admpc" ]]; then
        run_admpc_case "$case_name" "$GATE_MODE" "$N" "$T" "$d" "$total_cm"
      elif [[ "$PROTOCOL" == "continuum" || "$PROTOCOL" == "bgw-aggtrans" ]]; then
        run_continuum_case "$case_name" "$GATE_MODE" "$N" "$T" "$d" "$total_cm"
      elif [[ "$PROTOCOL" == "dumbo-bgw-direct" ]]; then
        run_dumbo_bgw_direct_case "$case_name" "$N" "$T" "$d" "$total_cm"
      else
        run_dumbo_case "$case_name" "$N" "$T" "$d" "$total_cm" "full"
      fi
      pause_between_cases_if_needed "$run_idx" "${#selected_ds[@]}"
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
      if [[ "$FAULT_PROFILE" == "accumulation" ]]; then
        run_admpc_case "${case_name}_t-silent" "$GATE_MODE" "$N" "$T" "$D" "$total_cm"
      elif [[ "$FAULT_PROFILE" == "attack" ]]; then
        run_admpc_case "${case_name}_attack-e3-e4" "$GATE_MODE" "$N" "$T" "$D" "$total_cm"
      else
        run_admpc_case "$case_name" "$GATE_MODE" "$N" "$T" "$D" "$total_cm"
      fi
    elif [[ "$PROTOCOL" == "continuum" || "$PROTOCOL" == "bgw-aggtrans" ]]; then
      if [[ "$FAULT_PROFILE" == "accumulation" ]]; then
        run_continuum_case "${case_name}_t-silent" "$GATE_MODE" "$N" "$T" "$D" "$total_cm"
      elif [[ "$FAULT_PROFILE" == "attack" ]]; then
        run_continuum_case "${case_name}_attack-e3-e4-e5" "$GATE_MODE" "$N" "$T" "$D" "$total_cm"
      else
        run_continuum_case "$case_name" "$GATE_MODE" "$N" "$T" "$D" "$total_cm"
      fi
    elif [[ "$PROTOCOL" == "dumbo-bgw-direct" ]]; then
      run_dumbo_bgw_direct_case "${case_name}_drop-epoch4" "$N" "$T" "$D" "$total_cm" "drop-epoch4"
    else
      if [[ "$FAULT_PROFILE" == "accumulation" ]]; then
        run_dumbo_case "${case_name}_accumulate-t-silent" "$N" "$T" "$D" "$total_cm" "fault-accumulation"
      else
        run_dumbo_case "${case_name}_drop-epoch4" "$N" "$T" "$D" "$total_cm" "drop-epoch4"
      fi
    fi
    ;;
esac

echo "Done. Session output: ${SESSION_DIR}"
