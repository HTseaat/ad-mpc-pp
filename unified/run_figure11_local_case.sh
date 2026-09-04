#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "Usage: $0 <admpc|continuum|continuum-coarse|continuum-static|bgw-ampc> <n> <t>" >&2
  exit 2
fi

case_name="$1"
n="$2"
t="$3"

case "$case_name" in
  admpc|continuum|continuum-coarse|continuum-static|bgw-ampc) ;;
  *)
    echo "Unknown Figure 11 case: $case_name" >&2
    exit 2
    ;;
esac
for value_name in n t; do
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

shuffle_k=128
switch_layers=49

export ZMQ_AUTH_MODE=curve
export SHUFFLE_K="$shuffle_k"
export SHUFFLE_MODE=iterated
export SHUFFLE_HANDOFF_GRACE_SECONDS=3
export AGG_KZG_V2=1
export ADTRANS_ALG4_PER_ITEM=0
export COMMITTEE_ELECTION_MODE=off
unset PROTOCOL_OVERHEAD_METRICS PROTOCOL_OVERHEAD_OUTPUT_DIR \
  PROTOCOL_OVERHEAD_RUN_ID FAULT_MODE FAULT_TARGET \
  FAULT_ACCUMULATION_MODE FAULT_ACCUMULATION_COUNT \
  FAULT_ACCUMULATION_START_EPOCH FAULT_COMPUTATION_EPOCH \
  FAULT_BATCHMUL_EPOCH FAULT_DELAY_SOURCE_EPOCH \
  FAULT_ADTRANS_SOURCE_EPOCH FAULT_AGGTRANS_SOURCE_EPOCH \
  FAULT_BATCHMUL_SOURCE_EPOCH FAULT_DELTA_MS FAULT_ATTACK_INDEX \
  DISABLE_AGG_PROTO DISABLE_RLC \
  BGW_UNBATCHED_VERIFY BGW_BATCH_UNBATCHED_PROD_VERIFY \
  BGW_UNBATCHED_BATCH_ALL_VERIFY BGW_UNBATCHED_BATCH_SHARE_VERIFY \
  BGW_UNBATCHED_BATCH_HIDDEN_VERIFY BGW_UNBATCHED_BATCH_ZERO_VERIFY \
  BGW_UNBATCHED_BATCH_PROD_VERIFY

case "$case_name" in
  admpc)
    export SHUFFLE_HANDOFF_INTERVAL=1
    export ADMPC_SHUFFLE_RUN_ID="figure11_admpc_n${n}_t${t}"
    exec /opt/unified/run_admpc_local.sh \
      admpc-shuffle "$n" "$t" "$((switch_layers + 2))" "$shuffle_k"
    ;;
  continuum)
    export SHUFFLE_HANDOFF_INTERVAL=1
    exec /opt/unified/run_continuum_local.sh \
      "$n" "$t" "$shuffle_k" shuffle
    ;;
  continuum-coarse)
    export SHUFFLE_HANDOFF_INTERVAL=5
    exec /opt/unified/run_continuum_local.sh \
      "$n" "$t" "$shuffle_k" shuffle
    ;;
  continuum-static)
    export SHUFFLE_HANDOFF_INTERVAL=static
    exec /opt/unified/run_continuum_local.sh \
      "$n" "$t" "$shuffle_k" shuffle
    ;;
  bgw-ampc)
    export SHUFFLE_HANDOFF_INTERVAL=static
    export BGW_UNBATCHED_VERIFY=0
    export BGW_BATCH_UNBATCHED_PROD_VERIFY=1
    exec /opt/unified/run_continuum_local.sh \
      "$n" "$t" "$shuffle_k" shuffle-bgw-static
    ;;
esac
