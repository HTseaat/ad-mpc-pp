#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 5 ]]; then
  echo "Usage: $0 <case> <n> <t> <d> <w>" >&2
  exit 2
fi

case_name="$1"
n="$2"
t="$3"
depth="$4"
width="$5"

case "$case_name" in
  admpc-linear|continuum-aggtrans|continuum-noagg) ;;
  *)
    echo "Unknown Figure 8 case: $case_name" >&2
    exit 2
    ;;
esac
for value_name in n t depth width; do
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
if (( depth < 1 )); then
  echo "d must be positive" >&2
  exit 2
fi
if (( width < 2 || width % 2 != 0 )); then
  echo "w must be a positive even integer" >&2
  exit 2
fi

layers=$((depth + 2))
total_cm=$((depth * width / 2))

export ZMQ_AUTH_MODE=curve
export CIRCUIT_WIDTH="$width"
export AGG_KZG_V2=1
export ADTRANS_ALG4_PER_ITEM=0
unset DISABLE_AGG_PROTO DISABLE_RLC
unset PROTOCOL_OVERHEAD_METRICS PROTOCOL_OVERHEAD_OUTPUT_DIR
unset PROTOCOL_OVERHEAD_RUN_ID

case "$case_name" in
  admpc-linear)
    exec /opt/unified/run_admpc_local.sh \
      admpc-linear "$n" "$t" "$layers" "$total_cm"
    ;;
  continuum-aggtrans)
    exec /opt/unified/run_continuum_local.sh \
      "$n" "$t" "$layers" "$total_cm" linear
    ;;
  continuum-noagg)
    export DISABLE_AGG_PROTO=1
    exec /opt/unified/run_continuum_local.sh \
      "$n" "$t" "$layers" "$total_cm" linear
    ;;
esac
