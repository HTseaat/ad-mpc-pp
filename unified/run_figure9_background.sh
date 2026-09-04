#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <output-root> <n>" >&2
  exit 1
fi

output_root="$1"
n="$2"
case "$n" in
  4) t=1 ;;
  10) t=3 ;;
  16) t=5 ;;
  22) t=7 ;;
  *) echo "Unsupported Figure 9 committee size: $n" >&2; exit 2 ;;
esac
mkdir -p "$output_root"
log_path="$output_root/background-n${n}.log"

# Close the launching tool's stdout/stderr pipe immediately, so a setsid-launched
# campaign survives an automatic goal-continuation boundary.  All subsequent
# status is durable and auditable in the campaign directory.
exec >>"$log_path" 2>&1

echo "FIG9_BACKGROUND_START n=${n} t=${t} utc=$(date -u +%Y-%m-%dT%H:%M:%SZ) pid=$$"
timeout 2400s ./unified/run_figure9_admpc_communication_local.sh \
  "$n" "$t" 6 100 "$output_root/n${n}-admpc"
timeout 2400s ./unified/run_figure9_batchmul_communication_local.sh \
  "$n" "$t" 6 100 "$output_root/n${n}-batchmul"
timeout 2400s ./unified/run_figure9_bgw_aggtrans_communication_local.sh \
  "$n" "$t" 6 100 "$output_root/n${n}-bgw-aggtrans"
echo "FIG9_BACKGROUND_END n=${n} utc=$(date -u +%Y-%m-%dT%H:%M:%SZ) status=0"
