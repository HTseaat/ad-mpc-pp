#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 4 || $# -gt 5 ]]; then
  echo "Usage: run-compare-local <n> <t> <layers> <total_cm> [admpc|admpc-linear|admpc-nonlinear|fluid1|fluid2|hbmpc|hbmpc_attack]" >&2
  exit 1
fi

n="$1"
t="$2"
layers="$3"
total_cm="$4"
protocol="${5:-admpc}"

ts="$(date +%Y%m%d_%H%M%S)"
outdir="/opt/benchmark-compare/${ts}_n${n}_t${t}_l${layers}_cm${total_cm}"
mkdir -p "$outdir"

echo "[1/2] Running AD-MPC (${protocol}) ..."
run-admpc-local "$protocol" "$n" "$t" "$layers" "$total_cm"
mkdir -p "$outdir/admpc"
cp -r /opt/admpc/logs "$outdir/admpc/" 2>/dev/null || true
cp /opt/admpc/extracted_times.csv /opt/admpc/summary_times.csv "$outdir/admpc/" 2>/dev/null || true

echo "[2/2] Running continuum (ad-mpc2) ..."
run-continuum-local "$n" "$t" "$layers" "$total_cm"
mkdir -p "$outdir/continuum"
cp -r /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/log "$outdir/continuum/" 2>/dev/null || true
cp /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/log/trusted_times*.csv "$outdir/continuum/" 2>/dev/null || true

echo "Done. Results saved in: $outdir"
