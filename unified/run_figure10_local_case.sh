#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <admpc-accum|continuum-accum|dumbo-accum|admpc-attack|continuum-attack>" >&2
  exit 2
fi

case_name="$1"
case "$case_name" in
  admpc-accum|continuum-accum|dumbo-accum|admpc-attack|continuum-attack) ;;
  *)
    echo "Unknown Figure 10 case: $case_name" >&2
    exit 2
    ;;
esac

# Figure 10 uses one fixed paper configuration.
n=16
t=5
depth=6
width=100
layers=$((depth + 2))
total_cm=$((depth * width / 2))
dumbo_observation_timeout=600
results_root="/opt/benchmark-local/figure10"

mkdir -p -- "$results_root"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
case_root="$(mktemp -d "${results_root}/${case_name}-${timestamp}-XXXXXX")"
controller_log="$case_root/controller.log"
start_marker="$case_root/run-start.marker"
touch "$start_marker"

protocol=""
fault_profile=""
fault_role=""
log_family=""
observation_timeout=""
case "$case_name" in
  admpc-accum)
    protocol="admpc"
    fault_profile="accumulation"
    fault_role="dynamic-t-new-per-computation-committee"
    log_family="admpc"
    command=(/opt/unified/run_admpc_figure10_accum_local.sh \
      "$n" "$t" "$layers" "$total_cm")
    ;;
  continuum-accum)
    protocol="continuum"
    fault_profile="accumulation"
    fault_role="dynamic-t-new-per-computation-committee"
    log_family="continuum"
    command=(/opt/unified/run_continuum_figure10_accum_local.sh \
      "$n" "$t" "$layers" "$total_cm")
    ;;
  dumbo-accum)
    protocol="dumbo"
    fault_profile="accumulation"
    fault_role="static-cumulative-t-new-per-epoch"
    log_family="dumbo"
    observation_timeout="$dumbo_observation_timeout"
    command=(timeout --signal=TERM --kill-after=30s \
      "${dumbo_observation_timeout}s" \
      /opt/unified/run_dumbo_mpc_local.sh \
      "$n" "$t" "$total_cm" fault-accumulation "$depth")
    ;;
  admpc-attack)
    protocol="admpc"
    fault_profile="attack"
    fault_role="admpc-figure10-source-epochs"
    log_family="admpc"
    command=(/opt/unified/run_admpc_figure10_attack_local.sh \
      "$n" "$t" "$layers" "$total_cm")
    ;;
  continuum-attack)
    protocol="continuum"
    fault_profile="attack"
    fault_role="continuum-figure10-source-epochs"
    log_family="continuum"
    command=(/opt/unified/run_continuum_figure10_attack_local.sh \
      "$n" "$t" "$layers" "$total_cm")
    ;;
esac

start_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
{
  echo "schema=figure10-local-run-v1"
  echo "case=${case_name}"
  echo "protocol=${protocol}"
  echo "fault_profile=${fault_profile}"
  echo "fault_role=${fault_role}"
  echo "n=${n}"
  echo "t=${t}"
  echo "d=${depth}"
  echo "w=${width}"
  echo "layers=${layers}"
  echo "total_cm=${total_cm}"
  echo "zmq_auth_mode=curve"
  echo "start_utc=${start_utc}"
  if [[ -n "$observation_timeout" ]]; then
    echo "observation_timeout_seconds=${observation_timeout}"
  fi
  if [[ "$fault_profile" == "accumulation" ]]; then
    echo "fault_accumulation_count=${t}"
    echo "fault_accumulation_start_epoch=1"
  else
    echo "fault_delay_source_epoch=3"
    echo "fault_delay_ms=10000"
    echo "fault_attack_source_epoch=4"
    if [[ "$protocol" == "continuum" ]]; then
      echo "fault_batchmul_source_epoch=5"
    fi
    echo "fault_attack_index=0"
  fi
} > "$case_root/metadata.env"

export ZMQ_AUTH_MODE=curve
export AGG_KZG_V2=1
export ADTRANS_ALG4_PER_ITEM=0
export CIRCUIT_WIDTH="$width"
unset COMMITTEE_ELECTION_MODE PROTOCOL_OVERHEAD_METRICS \
  PROTOCOL_OVERHEAD_OUTPUT_DIR PROTOCOL_OVERHEAD_RUN_ID \
  BGW_UNBATCHED_VERIFY DISABLE_AGG_PROTO DISABLE_RLC

printf 'FIGURE10_LOCAL_START case=%s output=%s\n' "$case_name" "$case_root"
set +e
"${command[@]}" 2>&1 | tee "$controller_log"
run_status="${PIPESTATUS[0]}"
set -e

if [[ "$log_family" == "dumbo" ]]; then
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/scripts/cleanup_local_test.sh \
    "$n" >/dev/null 2>&1 || true
fi

logs_dir="$case_root/logs"
config_dir="$case_root/config"
mkdir -p -- "$logs_dir" "$config_dir"
archived_logs=0
if [[ "$log_family" == "admpc" ]]; then
  for ((layer = 1; layer <= layers; layer++)); do
    for ((party = 0; party < n; party++)); do
      source_log="/opt/admpc/logs/node${party}_layer${layer}.log"
      if [[ -f "$source_log" && "$source_log" -nt "$start_marker" ]]; then
        cp -- "$source_log" "$logs_dir/"
        archived_logs=$((archived_logs + 1))
      fi
    done
  done
  source_config="/opt/admpc/conf/curve_local_admpc_${n}_${layers}"
elif [[ "$log_family" == "continuum" ]]; then
  for ((sid = 0; sid < n * layers; sid++)); do
    source_log="/opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/log/logs-${sid}.log"
    if [[ -f "$source_log" && "$source_log" -nt "$start_marker" ]]; then
      cp -- "$source_log" "$logs_dir/"
      archived_logs=$((archived_logs + 1))
    fi
  done
  source_config="/opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/conf/admpc_${total_cm}_${layers}_${n}"
else
  for ((party = 0; party < n; party++)); do
    source_log="/opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/log/logs-${party}.log"
    if [[ -f "$source_log" && "$source_log" -nt "$start_marker" ]]; then
      cp -- "$source_log" "$logs_dir/"
      archived_logs=$((archived_logs + 1))
    fi
  done
  source_config="/opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/conf/mpc_${n}"
fi

if [[ -d "$source_config" ]]; then
  cp -a -- "$source_config/." "$config_dir/"
fi

end_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
{
  echo "end_utc=${end_utc}"
  echo "command_exit_status=${run_status}"
  echo "archived_log_count=${archived_logs}"
} >> "$case_root/metadata.env"

expected_logs=$((n * layers))
if [[ "$log_family" == "dumbo" ]]; then
  expected_logs="$n"
fi
if (( archived_logs != expected_logs )); then
  echo "Expected ${expected_logs} fresh logs, archived ${archived_logs}." >&2
  echo "Partial results: $case_root" >&2
  exit 1
fi

validation_status=0
if [[ "$fault_profile" == "accumulation" ]]; then
  set +e
  /opt/venv/continuum/bin/python \
    /opt/unified/distributed/verify_figure10_fault_trace.py \
    --case-dir "$case_root" --protocol "$protocol" \
    --n "$n" --t "$t" --d "$depth" --count "$t" \
    2>&1 | tee -a "$controller_log"
  validation_status="${PIPESTATUS[0]}"
  set -e
fi
echo "trace_validation_exit_status=${validation_status}" >> "$case_root/metadata.env"

if [[ "$case_name" == "dumbo-accum" ]]; then
  if (( run_status != 124 )); then
    echo "Dumbo-MPC should reach the observation timeout; got status ${run_status}." >&2
    echo "Results: $case_root" >&2
    exit 1
  fi
elif (( run_status != 0 )); then
  echo "Figure 10 case failed with status ${run_status}." >&2
  echo "Results: $case_root" >&2
  exit "$run_status"
fi

if (( validation_status != 0 )); then
  echo "Figure 10 fault trace validation failed." >&2
  echo "Results: $case_root" >&2
  exit "$validation_status"
fi

printf 'FIGURE10_LOCAL_COMPLETE case=%s output=%s\n' "$case_name" "$case_root"
