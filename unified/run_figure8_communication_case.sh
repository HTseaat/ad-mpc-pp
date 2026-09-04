#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 6 ]]; then
  echo "Usage: $0 <case> <n> <t> <d> <w> <new-output-directory>" >&2
  exit 2
fi

case_name="$1"
n="$2"
t="$3"
depth="$4"
width="$5"
output_root="$6"

case "$case_name" in
  admpc-linear) summary_protocol="admpc" ;;
  continuum-aggtrans) summary_protocol="continuum_aggtrans" ;;
  continuum-noagg) summary_protocol="continuum_noagg" ;;
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
  echo "d must be a positive integer" >&2
  exit 2
fi
if (( width < 2 || width % 2 != 0 )); then
  echo "w must be a positive even integer" >&2
  exit 2
fi
if [[ "$output_root" == -* ]]; then
  echo "Output directory must not begin with '-': $output_root" >&2
  exit 2
fi
if [[ -e "$output_root" && ! -d "$output_root" ]]; then
  echo "Output path exists and is not a directory: $output_root" >&2
  exit 2
fi
if [[ -e "$output_root" ]] && find "$output_root" -mindepth 1 -print -quit | grep -q .; then
  echo "Refusing to mix artifacts in non-empty output directory: $output_root" >&2
  exit 2
fi
mkdir -p -- "$output_root"
output_root="$(cd "$output_root" && pwd)"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
workspace_root="$(cd "$script_dir/.." && pwd)"
case_root="$output_root/n${n}_t${t}/${case_name}"

cd "$workspace_root"
"$script_dir/run_figure8_one_layer_case.sh" \
  "$case_name" "$n" "$t" "$width" "$case_root"

/opt/venv/continuum/bin/python "$script_dir/summarize_figure8_communication.py" \
  "$output_root" --case "$n" "$t" --protocol "$summary_protocol" \
  --batch-size "$width" --depth "$depth" --output-dir "$output_root/final"
