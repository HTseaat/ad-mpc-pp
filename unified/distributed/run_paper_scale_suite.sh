#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $# -lt 3 ]]; then
  echo "Usage: $0 <protocol> <experiment> <comma-separated-n-values> [run_suite options]" >&2
  exit 2
fi

protocol="$1"
experiment="$2"
allowed_csv="$3"
shift 3

requested_n=""
args=("$@")
for ((index = 0; index < ${#args[@]}; index++)); do
  case "${args[$index]}" in
    -h|--help)
      exec "${SCRIPT_DIR}/run_suite.sh" "$protocol" "$experiment" "${args[@]}"
      ;;
    --only-n)
      if (( index + 1 >= ${#args[@]} )); then
        echo "--only-n requires a value" >&2
        exit 2
      fi
      requested_n="${args[$((index + 1))]}"
      ;;
  esac
done

IFS=',' read -r -a allowed_ns <<< "$allowed_csv"

if [[ -n "$requested_n" ]]; then
  allowed=0
  for n in "${allowed_ns[@]}"; do
    if [[ "$requested_n" == "$n" ]]; then
      allowed=1
      break
    fi
  done
  if [[ "$allowed" -ne 1 ]]; then
    echo "n=${requested_n} is not evaluated by this paper wrapper; expected one of: ${allowed_ns[*]}" >&2
    exit 2
  fi
  exec "${SCRIPT_DIR}/run_suite.sh" "$protocol" "$experiment" "${args[@]}"
fi

for n in "${allowed_ns[@]}"; do
  "${SCRIPT_DIR}/run_suite.sh" "$protocol" "$experiment" "${args[@]}" --only-n "$n"
done
