#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 <n> <t> <Q> <new-output-directory>" >&2
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
powers="$3"
output_dir="$4"

for value_name in n t powers; do
  value="${!value_name}"
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "${value_name} must be a non-negative integer" >&2
    exit 1
  fi
done
if (( t < 1 )); then
  echo "t must be at least 1" >&2
  exit 1
fi
if (( n < 3 * t + 1 )); then
  echo "n must satisfy n >= 3*t + 1" >&2
  exit 1
fi
if (( n < 1 || (n & (n - 1)) != 0 )); then
  echo "n must be a power of two for the trusted-setup NTT path" >&2
  exit 1
fi
if (( powers < t + 1 )); then
  echo "Q must be at least t + 1" >&2
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

trusted_setup_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
asyran_root="$(cd "${trusted_setup_root}/.." && pwd)"
python_bin="${TRUSTED_SETUP_PYTHON:-/opt/venv/admpc/bin/python}"
analyzer="${TRUSTED_SETUP_ANALYZER:-/opt/unified/distributed/analyze_trusted_setup.py}"
base_port="${TRUSTED_SETUP_BASE_PORT:-17000}"
protocol_timeout=300
readiness_timeout=120
run_id="local-distributed-n${n}-q${powers}-$(date -u +%Y%m%dT%H%M%SZ)"

if ! [[ "$base_port" =~ ^[0-9]+$ ]] || \
    (( base_port < 1024 || base_port + n - 1 > 65535 )); then
  echo "Invalid trusted-setup local base port: $base_port" >&2
  exit 1
fi

mkdir -p "${output_dir}/config" "${output_dir}/artifacts" "${output_dir}/logs"
output_dir="$(cd "$output_dir" && pwd)"
peer_args=()
for ((node_id = 0; node_id < n; node_id++)); do
  peer_args+=(--peer "127.0.0.1:$((base_port + node_id))")
done

cd "$asyran_root"
"$python_bin" -m trusted_setup.generate_distributed_config \
  --n "$n" --t "$t" --powers "$powers" --run-id "$run_id" \
  --output-dir "${output_dir}/config" "${peer_args[@]}"

pids=()
cleanup_children() {
  for pid in "${pids[@]:-}"; do
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
    fi
  done
  for pid in "${pids[@]:-}"; do
    wait "$pid" 2>/dev/null || true
  done
}
trap cleanup_children EXIT

for ((node_id = 0; node_id < n; node_id++)); do
  kzg_flag=()
  if [[ "$node_id" -eq 0 ]]; then
    kzg_flag=(--kzg-smoke)
  fi
  "$python_bin" -u -m trusted_setup.run_node \
    --config "${output_dir}/config/local.${node_id}.json" \
    --timeout "$protocol_timeout" --readiness-timeout "$readiness_timeout" \
    --output-srs "${output_dir}/artifacts/node-${node_id}.srs.json" \
    --metrics-output "${output_dir}/artifacts/node-${node_id}.metrics.json" \
    "${kzg_flag[@]}" >"${output_dir}/logs/node-${node_id}.log" 2>&1 &
  pids+=("$!")
done

failed=0
for pid in "${pids[@]}"; do
  if ! wait "$pid"; then
    failed=1
  fi
done
if [[ "$failed" -ne 0 ]]; then
  echo "Local distributed setup failed; see ${output_dir}/logs" >&2
  exit 1
fi

"$python_bin" "$analyzer" \
  --input-dir "${output_dir}/artifacts" --expected-n "$n" \
  --output "${output_dir}/summary.json"
echo "TRUSTED_SETUP_LOCAL_SESSION=${output_dir}"
