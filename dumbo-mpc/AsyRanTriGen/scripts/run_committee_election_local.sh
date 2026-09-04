#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 4 || $# -gt 7 ]]; then
  echo "Usage: $0 <n> <t> <K> <output-dir> [omitted-local-id] [base-port] [protocol-timeout]" >&2
  exit 1
fi

n="$1"
t="$2"
candidate_count="$3"
output_dir="$4"
omitted="${5:-}"
base_port="${6:-12000}"
protocol_timeout="${7:-30}"

args=(
  --N "$n"
  --t "$t"
  --K "$candidate_count"
  --base-port "$base_port"
  --output-dir "$output_dir"
  --timeout "$protocol_timeout"
)
if [[ -n "$omitted" ]]; then
  args+=(--omit "$omitted")
fi

exec /opt/venv/continuum/bin/python -m scripts.run_committee_election_local "${args[@]}"
