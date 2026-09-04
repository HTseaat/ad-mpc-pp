#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "Usage: $0 <admpc|continuum|dumbo-mpc> <n> <t> <d>" >&2
  exit 2
fi

case_name="$1"
n="$2"
t="$3"
depth="$4"

case "$case_name" in
  admpc|continuum|dumbo-mpc) ;;
  *)
    echo "Unknown Figure 14 case: $case_name" >&2
    exit 2
    ;;
esac
for value_name in n t depth; do
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

width=100
layers=$((depth + 2))
total_cm=$((depth * width / 2))

export ZMQ_AUTH_MODE=curve
export CIRCUIT_WIDTH="$width"
export AGG_KZG_V2=1
export ADTRANS_ALG4_PER_ITEM=0
export COMMITTEE_ELECTION_MODE=off
unset PROTOCOL_OVERHEAD_METRICS PROTOCOL_OVERHEAD_OUTPUT_DIR \
  PROTOCOL_OVERHEAD_RUN_ID SHUFFLE_K SHUFFLE_MODE \
  SHUFFLE_HANDOFF_INTERVAL SHUFFLE_HANDOFF_GRACE_SECONDS \
  FAULT_MODE FAULT_TARGET FAULT_ACCUMULATION_MODE \
  FAULT_ACCUMULATION_COUNT FAULT_ACCUMULATION_START_EPOCH \
  FAULT_COMPUTATION_EPOCH FAULT_BATCHMUL_EPOCH \
  FAULT_DELAY_SOURCE_EPOCH FAULT_ADTRANS_SOURCE_EPOCH \
  FAULT_AGGTRANS_SOURCE_EPOCH FAULT_BATCHMUL_SOURCE_EPOCH \
  FAULT_DELTA_MS FAULT_ATTACK_INDEX BGW_UNBATCHED_VERIFY \
  BGW_BATCH_UNBATCHED_PROD_VERIFY BGW_UNBATCHED_BATCH_ALL_VERIFY \
  BGW_UNBATCHED_BATCH_SHARE_VERIFY BGW_UNBATCHED_BATCH_HIDDEN_VERIFY \
  BGW_UNBATCHED_BATCH_ZERO_VERIFY BGW_UNBATCHED_BATCH_PROD_VERIFY \
  DISABLE_AGG_PROTO DISABLE_RLC

case "$case_name" in
  admpc)
    exec /opt/unified/run_admpc_local.sh \
      admpc "$n" "$t" "$layers" "$total_cm"
    ;;
  continuum)
    exec /opt/unified/run_continuum_local.sh \
      "$n" "$t" "$layers" "$total_cm" mixed
    ;;
  dumbo-mpc)
    exec /opt/unified/run_dumbo_mpc_local.sh \
      "$n" "$t" "$total_cm" full "$depth"
    ;;
esac
