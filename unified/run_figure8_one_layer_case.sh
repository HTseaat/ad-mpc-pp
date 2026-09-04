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

if ! [[ "$n" =~ ^[0-9]+$ && "$t" =~ ^[0-9]+$ && "$width" =~ ^[0-9]+$ ]]; then
  echo "n, t, and w must be non-negative integers" >&2
  exit 2
fi
if (( n < 3 * t + 1 )); then
  echo "invalid threshold: n=${n}, t=${t}" >&2
  exit 2
fi
if (( width < 2 || width % 2 != 0 )); then
  echo "w must be a positive even integer" >&2
  exit 2
fi

raw_dir="$case_root/raw"
analysis_dir="$case_root/analysis"
if [[ -e "$case_root" ]] && find "$case_root" -mindepth 1 -print -quit | grep -q .; then
  echo "refusing non-empty case output directory: $case_root" >&2
  exit 2
fi
mkdir -p "$raw_dir"

# One computation layer is represented by input/computation/output committees.
# Metrics select only the computation handoff, so input distribution and final
# reconstruction are excluded. In an all-linear circuit, B equals w and
# total_cm=w/2 gives the matching AD-MPC linear-driver width.
layers=3
total_cm=$((width / 2))

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
unset DISABLE_AGG_PROTO DISABLE_RLC

cd /opt
case "$case_name" in
  continuum-aggtrans)
    export PROTOCOL_OVERHEAD_RUN_ID="fig8_one_layer_n${n}_t${t}_aggtrans"
    export POST_EXEC_SLEEP_SECONDS=5
    export POST_FINISH_GRACE_SECONDS=10
    ./unified/run_continuum_local.sh "$n" "$t" "$layers" "$total_cm" linear
    expected_processes=$((3 * n))
    ;;
  continuum-noagg)
    export PROTOCOL_OVERHEAD_RUN_ID="fig8_one_layer_n${n}_t${t}_noagg"
    export POST_EXEC_SLEEP_SECONDS=5
    export POST_FINISH_GRACE_SECONDS=10
    export DISABLE_AGG_PROTO=1
    ./unified/run_continuum_local.sh "$n" "$t" "$layers" "$total_cm" linear
    expected_processes=$((3 * n))
    ;;
  admpc-linear)
    export PROTOCOL_OVERHEAD_RUN_ID="fig8_one_layer_n${n}_t${t}_admpc"
    export POST_EXEC_SLEEP_SECONDS=1
    ./unified/run_admpc_local.sh admpc-linear "$n" "$t" "$layers" "$total_cm"
    expected_processes=$((3 * n))
    ;;
  *)
    echo "unknown Figure 8 case: $case_name" >&2
    exit 2
    ;;
esac

artifact_count="$(find "$raw_dir" -maxdepth 1 -type f -name 'communication-*.json' | wc -l)"
if (( artifact_count != expected_processes )); then
  echo "expected ${expected_processes} communication artifacts, got ${artifact_count}" >&2
  exit 1
fi

python3 unified/analyze_protocol_overhead.py "$raw_dir" --output-dir "$analysis_dir"
printf 'CASE_COMPLETE case=%s n=%s t=%s artifacts=%s\n' \
  "$case_name" "$n" "$t" "$artifact_count"
