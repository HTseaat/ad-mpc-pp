#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 <n> <t> <K> <new-output-directory>" >&2
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi
if [[ $# -ne 4 ]]; then
  usage
  exit 1
fi

n="$1"
t="$2"
candidate_count="$3"
output_dir="$4"

for value_name in n t candidate_count; do
  value="${!value_name}"
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "${value_name} must be a non-negative integer" >&2
    exit 1
  fi
done
if (( n < 3 * t + 1 )); then
  echo "n must satisfy n >= 3*t + 1" >&2
  exit 1
fi
if (( candidate_count < 1 )); then
  echo "K must be positive" >&2
  exit 1
fi
if [[ "$output_dir" == -* ]]; then
  echo "Output directory must not begin with '-': $output_dir" >&2
  exit 1
fi
if [[ -e "$output_dir" && ! -d "$output_dir" ]]; then
  echo "Output path exists and is not a directory: $output_dir" >&2
  exit 1
fi
if [[ -e "$output_dir" ]] && find "$output_dir" -mindepth 1 -print -quit | grep -q .; then
  echo "Refusing to mix artifacts in non-empty output directory: $output_dir" >&2
  exit 1
fi
mkdir -p -- "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

unset COMMITTEE_ELECTION_OMIT_LOCAL_ID
cd /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen
exec ./scripts/run_committee_election_local.sh \
  "$n" "$t" "$candidate_count" "$output_dir" "" 12000 120
