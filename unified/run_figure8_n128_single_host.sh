#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <new-output-directory>" >&2
  exit 2
fi

output_root="$1"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
overlay_root="${FIG8_OVERLAY_ROOT:-$script_dir/overlay}"
image="${MPC_IMAGE:-sha256:a30f3c25bc71e21f2d610c6c12d6b23bdefe2b6a0a6d2650f616afc3e3eb7907}"
n="${FIG8_N:-128}"
t="${FIG8_T:-42}"
width="${FIG8_WIDTH:-100}"
case_timeout="${CASE_TIMEOUT_SECONDS:-21600}"
read -r -a cases <<<"${FIG8_CASES:-continuum-aggtrans continuum-noagg admpc-linear}"

if ! [[ "$width" =~ ^[0-9]+$ ]] || (( width < 2 || width % 2 != 0 )); then
  echo "FIG8_WIDTH must be a positive even integer" >&2
  exit 2
fi

if [[ -e "$output_root" ]] && find "$output_root" -mindepth 1 -print -quit | grep -q .; then
  echo "refusing non-empty campaign output directory: $output_root" >&2
  exit 2
fi
mkdir -p "$output_root/completed"

text_overlays=(
  opt/unified/run_figure8_one_layer_case.sh
  opt/unified/analyze_protocol_overhead.py
  opt/unified/run_admpc_local.sh
  opt/dumbo-mpc/run_local_network_test.sh
  opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/ipc.py
  opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/hbacss.py
  opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/aggregation_interfaces.py
  opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/protocol_metrics.py
  opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/communication_metrics.py
  opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/admpc2_dynamic_linear.py
  opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/scripts/local_admpc_test.sh
  opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/scripts/admpc2_dynamic_linear_run.py
  opt/admpc/adkg/ipc.py
  opt/admpc/adkg/communication_metrics.py
  opt/admpc/adkg/admpc_dynamic.py
  opt/admpc/adkg/trans.py
  opt/admpc/adkg/acss.py
  opt/admpc/local_admpc_run.sh
  opt/admpc/scripts/run_one_node.py
  opt/admpc/scripts/admpc_dynamic_linear_run.py
  opt/admpc/scripts/admpc_dynamic_batchrand_run.py
)
native_overlays=(
  opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/kzg_ped_out.so
)

docker_args=(
  run --rm --network host --pids-limit=-1
  --ulimit nofile=1048576:1048576
  --env ZMQ_AUTH_MODE=curve
  --env ZMQ_IO_THREADS=1
  --env ZMQ_MAX_SOCKETS=4096
  --env GOMAXPROCS=1
  --env MALLOC_ARENA_MAX=2
  --env OPENBLAS_NUM_THREADS=1
  --env OMP_NUM_THREADS=1
  --env MKL_NUM_THREADS=1
  --env NUMEXPR_NUM_THREADS=1
  --env RAYON_NUM_THREADS=1
)

for relative in "${text_overlays[@]}" "${native_overlays[@]}"; do
  source_path="$overlay_root/$relative"
  if [[ ! -f "$source_path" ]]; then
    echo "missing overlay file: $source_path" >&2
    exit 2
  fi
  docker_args+=(--volume "$source_path:/$relative:ro")
done
docker_args+=(--volume "$output_root:/results")

sudo -n docker image inspect "$image" >/dev/null
for case_name in "${cases[@]}"; do
  case "$case_name" in
    continuum-aggtrans|continuum-noagg|admpc-linear) ;;
    *) echo "unsupported case: $case_name" >&2; exit 2 ;;
  esac
  printf 'START case=%s utc=%s\n' "$case_name" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    | tee -a "$output_root/campaign.log"
  timeout --signal=TERM --kill-after=60s "$case_timeout" \
    sudo -n docker "${docker_args[@]}" \
      --name "fig8-n${n}-${case_name}-$$" \
      "$image" bash /opt/unified/run_figure8_one_layer_case.sh \
      "$case_name" "$n" "$t" "$width" "/results/$case_name" \
    2>&1 | tee "$output_root/${case_name}.console.log"
  printf 'DONE case=%s utc=%s\n' "$case_name" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    | tee -a "$output_root/campaign.log" "$output_root/completed/$case_name.done"
done

sudo -n chown -R "$(id -u):$(id -g)" "$output_root"
printf 'CAMPAIGN_COMPLETE n=%s t=%s w=%s output=%s\n' \
  "$n" "$t" "$width" "$output_root"
