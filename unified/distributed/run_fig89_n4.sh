#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<USAGE
Usage: $0 [options]

Runs the six n=4 variants for paper Figures 8 and 9. By default it performs
one warm-up and three measured repetitions after six authenticated election
measurements.

Options:
  --cluster-env <path>       Cluster env file
  --results-root <path>      Parent output directory
  --warmups <count>          Warm-ups per variant (default: 1)
  --repetitions <count>      Measured runs per variant (default: 3)
  --start-delay <seconds>    Shared protocol start offset (default: 30)
  --timeout <seconds>        Hard timeout per MPC process (default: 900)
  --skip-election            Reuse --election-summary
  --election-summary <path>  Existing six-election aggregate
USAGE
}

CLUSTER_ENV_ARG=""
RESULTS_ROOT="/opt/benchmark-distributed"
WARMUPS=1
REPETITIONS=3
START_DELAY=30
RUN_TIMEOUT=900
SKIP_ELECTION=0
ELECTION_SUMMARY_ARG=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cluster-env)
      CLUSTER_ENV_ARG="$2"
      shift 2
      ;;
    --results-root)
      RESULTS_ROOT="$2"
      shift 2
      ;;
    --warmups)
      WARMUPS="$2"
      shift 2
      ;;
    --repetitions)
      REPETITIONS="$2"
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
    --skip-election)
      SKIP_ELECTION=1
      shift
      ;;
    --election-summary)
      ELECTION_SUMMARY_ARG="$2"
      shift 2
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

for value_name in WARMUPS REPETITIONS START_DELAY; do
  value="${!value_name}"
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "${value_name} must be a non-negative integer" >&2
    exit 1
  fi
done
if ! [[ "$RUN_TIMEOUT" =~ ^[1-9][0-9]*$ ]] || [[ "$REPETITIONS" -eq 0 ]]; then
  echo "RUN_TIMEOUT and REPETITIONS must be positive integers" >&2
  exit 1
fi
if [[ "$SKIP_ELECTION" -eq 1 && -z "$ELECTION_SUMMARY_ARG" ]]; then
  echo "--skip-election requires --election-summary" >&2
  exit 1
fi

run_tag="$(date -u +%Y%m%dT%H%M%SZ)"
root="${RESULTS_ROOT}/fig89_n4_${run_tag}"
mkdir -p "$root"

cluster_args=()
if [[ -n "$CLUSTER_ENV_ARG" ]]; then
  cluster_args=(--cluster-env "$CLUSTER_ENV_ARG")
fi

if [[ "$SKIP_ELECTION" -eq 0 ]]; then
  election_dir="${root}/committee-election"
  "${SCRIPT_DIR}/run_committee_election_dist.sh" \
    "${cluster_args[@]}" --session-dir "$election_dir"
  election_summary="${election_dir}/election_summary.json"
else
  election_summary="$ELECTION_SUMMARY_ARG"
  "${SCRIPT_DIR}/preflight_fig89_n4.sh" "${cluster_args[@]}"
fi

if [[ ! -f "$election_summary" ]]; then
  echo "Election summary not found: ${election_summary}" >&2
  exit 1
fi

run_variant() {
  local output_root="$1"
  local variant="$2"
  common_args=(
    "${cluster_args[@]}"
    --results-root "$output_root"
    --only-n 4
    --auth-mode curve
    --start-delay "$START_DELAY"
    --timeout "$RUN_TIMEOUT"
    --sleep-between-case 0
    --skip-ssh-setup
  )
  case "$variant" in
    fig8-admpc)
      AGG_KZG_V2=1 DISABLE_AGG_PROTO=0 ELECTION_SUMMARY="$election_summary" \
        "${SCRIPT_DIR}/run_suite.sh" admpc exp1 "${common_args[@]}"
      ;;
    fig8-noagg)
      AGG_KZG_V2=1 DISABLE_AGG_PROTO=1 ELECTION_SUMMARY="$election_summary" \
        "${SCRIPT_DIR}/run_suite.sh" continuum exp1 "${common_args[@]}"
      ;;
    fig8-aggtrans)
      AGG_KZG_V2=1 DISABLE_AGG_PROTO=0 ELECTION_SUMMARY="$election_summary" \
        "${SCRIPT_DIR}/run_suite.sh" continuum exp1 "${common_args[@]}"
      ;;
    fig9-admpc)
      AGG_KZG_V2=1 DISABLE_AGG_PROTO=0 ELECTION_SUMMARY="$election_summary" \
        "${SCRIPT_DIR}/run_suite.sh" admpc exp2 "${common_args[@]}"
      ;;
    fig9-bgw-aggtrans)
      BGW_UNBATCHED_VERIFY=1 AGG_KZG_V2=1 DISABLE_AGG_PROTO=0 ELECTION_SUMMARY="$election_summary" \
        "${SCRIPT_DIR}/run_suite.sh" bgw-aggtrans exp2 "${common_args[@]}"
      ;;
    fig9-batchmul)
      AGG_KZG_V2=1 DISABLE_AGG_PROTO=0 ELECTION_SUMMARY="$election_summary" \
        "${SCRIPT_DIR}/run_suite.sh" continuum exp2 "${common_args[@]}"
      ;;
    *)
      echo "Unknown variant: ${variant}" >&2
      exit 1
      ;;
  esac
}

variants=(
  fig8-admpc fig8-noagg fig8-aggtrans
  fig9-admpc fig9-bgw-aggtrans fig9-batchmul
)

for warmup in $(seq 1 "$WARMUPS"); do
  for variant in "${variants[@]}"; do
    echo "[warm-up ${warmup}/${WARMUPS}] ${variant}"
    run_variant "${root}/warmup/round-${warmup}" "$variant"
  done
done

for repetition in $(seq 1 "$REPETITIONS"); do
  for variant in "${variants[@]}"; do
    echo "[measured ${repetition}/${REPETITIONS}] ${variant}"
    run_variant "${root}/measured/round-${repetition}" "$variant"
  done
done

python3 "${SCRIPT_DIR}/aggregate_fig89_n4.py" \
  --root "$root" --repetitions "$REPETITIONS"
echo "FIG89_SESSION_DIR=${root}"
