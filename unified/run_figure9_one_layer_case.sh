#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 5 ]]; then
  echo "Usage: $0 <case> <n> <t> <w> <case-output-directory>" >&2
  exit 2
fi

case_name="$1"
n="$2"
t="$3"
width="$4"
case_root="$5"

case "$case_name" in
  admpc-nonlinear|continuum-batchmul|bgw-aggtrans) ;;
  *)
    echo "Unknown Figure 9 case: $case_name" >&2
    exit 2
    ;;
esac
for value_name in n t width; do
  value="${!value_name}"
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "${value_name} must be a non-negative integer" >&2
    exit 2
  fi
done
if (( n < 3 * t + 1 )); then
  echo "n must satisfy n >= 3*t + 1" >&2
  exit 2
fi
if (( width < 1 )); then
  echo "w must be positive" >&2
  exit 2
fi

raw_dir="$case_root/raw"
analysis_dir="$case_root/analysis"
if [[ -e "$case_root" ]] && find "$case_root" -mindepth 1 -print -quit | grep -q .; then
  echo "Refusing to mix artifacts in non-empty case directory: $case_root" >&2
  exit 2
fi
mkdir -p -- "$raw_dir"

layers=3
total_cm="$width"

export CIRCUIT_WIDTH="$width"
export GOMAXPROCS="${GOMAXPROCS:-1}"
export MALLOC_ARENA_MAX="${MALLOC_ARENA_MAX:-2}"
export OPENBLAS_NUM_THREADS="${OPENBLAS_NUM_THREADS:-1}"
export OMP_NUM_THREADS="${OMP_NUM_THREADS:-1}"
export MKL_NUM_THREADS="${MKL_NUM_THREADS:-1}"
export NUMEXPR_NUM_THREADS="${NUMEXPR_NUM_THREADS:-1}"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-1}"
export ZMQ_AUTH_MODE=curve
export ZMQ_IO_THREADS="${ZMQ_IO_THREADS:-1}"
export ZMQ_MAX_SOCKETS="${ZMQ_MAX_SOCKETS:-4096}"
export PROTOCOL_OVERHEAD_METRICS=1
export PROTOCOL_OVERHEAD_OUTPUT_DIR="$raw_dir"
export AGG_KZG_V2=1
export ADTRANS_ALG4_PER_ITEM=1
unset BGW_UNBATCHED_VERIFY DISABLE_AGG_PROTO DISABLE_RLC

cd /opt
case "$case_name" in
  admpc-nonlinear)
    export PROTOCOL_OVERHEAD_RUN_ID="fig9_one_layer_n${n}_t${t}_admpc"
    export POST_EXEC_SLEEP_SECONDS=1
    ./unified/run_admpc_local.sh \
      admpc-nonlinear "$n" "$t" "$layers" "$total_cm"
    ;;
  continuum-batchmul)
    export PROTOCOL_OVERHEAD_RUN_ID="fig9_one_layer_n${n}_t${t}_batchmul"
    export POST_EXEC_SLEEP_SECONDS=1
    export POST_FINISH_GRACE_SECONDS=5
    ./unified/run_continuum_local.sh \
      "$n" "$t" "$layers" "$total_cm" nonlinear
    ;;
  bgw-aggtrans)
    export PROTOCOL_OVERHEAD_RUN_ID="fig9_one_layer_n${n}_t${t}_bgw_aggtrans"
    export POST_EXEC_SLEEP_SECONDS=1
    export POST_FINISH_GRACE_SECONDS=5
    export BGW_UNBATCHED_VERIFY=1
    ./unified/run_continuum_local.sh \
      "$n" "$t" "$layers" "$total_cm" bgw-aggtrans
    ;;
esac

expected_processes=$((3 * n))
artifact_count="$(find "$raw_dir" -maxdepth 1 -type f -name 'communication-*.json' | wc -l)"
if (( artifact_count != expected_processes )); then
  echo "Expected ${expected_processes} communication artifacts, got ${artifact_count}" >&2
  exit 1
fi

logs_dir="$case_root/logs"
mkdir -p -- "$logs_dir"
case "$case_name" in
  admpc-nonlinear)
    for ((sid = 0; sid < expected_processes; sid++)); do
      local_party=$((sid % n))
      layer=$((sid / n + 1))
      cp "/opt/admpc/logs/node${local_party}_layer${layer}.log" "$logs_dir/"
    done
    ;;
  continuum-batchmul|bgw-aggtrans)
    for ((sid = 0; sid < expected_processes; sid++)); do
      cp "/opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/log/logs-${sid}.log" \
        "$logs_dir/"
    done
    ;;
esac

/opt/venv/continuum/bin/python unified/analyze_protocol_overhead.py \
  "$raw_dir" --output-dir "$analysis_dir"
printf 'CASE_COMPLETE case=%s n=%s t=%s w=%s artifacts=%s\n' \
  "$case_name" "$n" "$t" "$width" "$artifact_count"
