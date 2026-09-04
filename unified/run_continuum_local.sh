#!/usr/bin/env bash
set -euo pipefail

export ZMQ_AUTH_MODE=curve

if [[ $# -lt 4 || $# -gt 5 ]]; then
  echo "Usage: run-continuum-local <n> <t> <layers|auto> <total_cm> [mixed|linear|nonlinear|bgw-aggtrans|shuffle|shuffle-bgw-static|dumbo-shuffle-beaver]" >&2
  echo "       run-continuum-local <n> <t> <shuffle_k> <shuffle|shuffle-bgw-static|dumbo-shuffle-beaver>" >&2
  exit 1
fi

n="$1"
t="$2"
if [[ $# -eq 4 && ! "$4" =~ ^[0-9]+$ ]]; then
  layers="auto"
  total_cm="$3"
  mode="$4"
else
  layers="$3"
  total_cm="$4"
  mode="${5:-mixed}"
fi

if (( n < 3 * t + 1 )); then
  echo "Invalid params: n=${n}, t=${t}. Must satisfy n >= 3*t+1." >&2
  exit 1
fi

if (( n > 3 * t + 1 )); then
  echo "Note: using n=${n}, t=${t} (n > 3*t+1). This is supported; fault tolerance remains t=${t}."
fi

case "$mode" in
  mixed)
    task="ad-mpc2"
    ;;
  linear)
    task="ad-mpc2-linear"
    ;;
  nonlinear|mul|multiplication)
    task="ad-mpc2-nonlinear"
    ;;
  bgw-aggtrans|bgw|dumbo-bgw)
    task="ad-mpc2-bgw-aggtrans"
    ;;
  shuffle|mixing|mixnet)
    task="ad-mpc2-shuffle"
    ;;
  shuffle-bgw-static|shuffle-bgw|dumbo-shuffle)
    task="ad-mpc2-shuffle-bgw-static"
    ;;
  dumbo-shuffle-beaver|shuffle-beaver|dumbo-beaver-shuffle)
    task="ad-mpc2-dumbo-shuffle-beaver"
    ;;
  *)
    echo "Invalid mode: ${mode}. Expected one of: mixed, linear, nonlinear, bgw-aggtrans, shuffle, shuffle-bgw-static, dumbo-shuffle-beaver" >&2
    exit 1
    ;;
esac

committee_election_mode="${COMMITTEE_ELECTION_MODE:-off}"
committee_election_mode="$(printf '%s' "$committee_election_mode" | tr '[:upper:]' '[:lower:]')"
case "$committee_election_mode" in
  off|shadow|gated) ;;
  *)
    echo "Invalid COMMITTEE_ELECTION_MODE=${COMMITTEE_ELECTION_MODE:-}. Expected off, shadow, or gated." >&2
    exit 1
    ;;
esac
if [[ "$committee_election_mode" != "off" ]]; then
  if [[ "$task" != "ad-mpc2" ]]; then
    echo "Committee election shadow/gated integration currently requires mixed mode." >&2
    exit 1
  fi
  if [[ "$layers" == "auto" ]] || ! [[ "$layers" =~ ^[0-9]+$ ]] || (( layers < 4 )); then
    echo "Committee election shadow/gated integration requires an explicit layer count >= 4." >&2
    exit 1
  fi
  export ZMQ_AUTH_MODE=curve
  export COMMITTEE_ELECTION_MODE="$committee_election_mode"
  export FINISHED_PATTERN="COMMITTEE_ELECTION_PIPELINE_FINISHED"
  if [[ "$committee_election_mode" == "gated" ]]; then
    export FINAL_LAYER_START=$(( (layers - 1) * n ))
    export FINAL_LAYER_PATTERN='my_send_id: .* exec_time:'
    export FINAL_LAYER_THRESHOLD=$(( n - t ))
  fi
fi

shuffle_switch_layers() {
  local k="$1"
  local shuffle_mode="${SHUFFLE_MODE:-single}"
  local rounds=0
  local value="$k"

  while (( value > 1 )); do
    if (( value % 2 != 0 )); then
      echo "Invalid shuffle input size: k=${k}. k must be a power of two." >&2
      exit 1
    fi
    value=$(( value / 2 ))
    rounds=$(( rounds + 1 ))
  done

  case "$shuffle_mode" in
    single|"") echo "$rounds" ;;
    iterated) echo $(( rounds * rounds )) ;;
    *)
      echo "Invalid SHUFFLE_MODE=${shuffle_mode}. Expected single or iterated." >&2
      exit 1
      ;;
  esac
}

shuffle_handoff_interval() {
  local switch_layers="$1"
  local raw="${SHUFFLE_HANDOFF_INTERVAL:-1}"
  raw="$(printf '%s' "$raw" | tr '[:upper:]' '[:lower:]')"

  case "$raw" in
    static|none|no-handoff|nohandoff|inf|infinity)
      echo "$switch_layers"
      ;;
    *)
      if ! [[ "$raw" =~ ^[0-9]+$ ]] || (( raw <= 0 )); then
        echo "Invalid SHUFFLE_HANDOFF_INTERVAL=${SHUFFLE_HANDOFF_INTERVAL:-}. Expected a positive integer or static." >&2
        exit 1
      fi
      if (( raw > switch_layers )); then
        echo "$switch_layers"
      else
        echo "$raw"
      fi
      ;;
  esac
}

if [[ "$task" == "ad-mpc2-shuffle" || "$task" == "ad-mpc2-shuffle-bgw-static" || "$task" == "ad-mpc2-dumbo-shuffle-beaver" ]]; then
  if ! [[ "$total_cm" =~ ^[0-9]+$ ]]; then
    echo "Invalid shuffle input size k: ${total_cm}" >&2
    exit 1
  fi

  switch_layers="$(shuffle_switch_layers "$total_cm")"
  if [[ "$task" == "ad-mpc2-shuffle" ]]; then
    handoff_interval="$(shuffle_handoff_interval "$switch_layers")"
    compute_blocks=$(( (switch_layers + handoff_interval - 1) / handoff_interval ))
    expected_layers=$(( compute_blocks + 2 ))
    echo "Shuffle layers auto-config: k=${total_cm}, switch_layers=${switch_layers}, handoff_interval=${handoff_interval}, compute_blocks=${compute_blocks}, protocol_layers=${expected_layers}"
  elif [[ "$task" == "ad-mpc2-shuffle-bgw-static" ]]; then
    expected_layers=3
    echo "Shuffle BGW-static layers auto-config: k=${total_cm}, switch_layers=${switch_layers}, protocol_layers=${expected_layers}"
  else
    expected_layers=3
    echo "Dumbo shuffle Beaver layers auto-config: k=${total_cm}, switch_layers=${switch_layers}, protocol_layers=${expected_layers}"
  fi

  if [[ "$layers" != "auto" && "$layers" != "$expected_layers" ]]; then
    echo "Note: ignoring supplied layers=${layers}; shuffle mode requires protocol_layers=${expected_layers}."
  fi
  layers="$expected_layers"
fi

source /opt/venv/continuum/bin/activate
export PYTHONPATH="/opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen:${PYTHONPATH:-}"

if [[ "${PROTOCOL_OVERHEAD_METRICS:-0}" =~ ^(1|true|yes|on)$ ]]; then
  : "${PROTOCOL_OVERHEAD_OUTPUT_DIR:?PROTOCOL_OVERHEAD_OUTPUT_DIR is required when protocol metrics are enabled}"
  mkdir -p "${PROTOCOL_OVERHEAD_OUTPUT_DIR}"
fi

# Rebuild KZG shared library on demand if missing in runtime container.
if [[ ! -f /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/kzg_ped_out.so ]]; then
  echo "kzg_ped_out.so missing, rebuilding..."
  mkdir -p /tmp/go-build-cache /tmp/go/pkg/mod
  (
    cd /opt/dumbo-mpc/gnark-crypto/kzg_ped_bls12-381
    GOCACHE=/tmp/go-build-cache GOPATH=/tmp/go GOMODCACHE=/tmp/go/pkg/mod bash ./build_shared_library.sh
    cp -f kzg_ped_out.so /opt/dumbo-mpc/kzg_ped_out.so
  )
fi

# Rebuild Bulletproof shared library on demand if missing in runtime container.
if [[ ! -f /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/libbulletproofs_amcl.so ]]; then
  echo "libbulletproofs_amcl.so missing, rebuilding..."
  mkdir -p /tmp/cargo-home
  (
    cd /opt/dumbo-mpc/bulletproofs-amcl
    CARGO_HOME=/tmp/cargo-home cargo build --release
    cp -f target/release/libbulletproofs_amcl.so /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/libbulletproofs_amcl.so
    cp -f target/release/libbulletproofs_amcl.so /opt/dumbo-mpc/libbulletproofs_amcl.so
  )
fi

cd /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen
python3 scripts/run_key_gen_dyn.py --N "$n" --f "$t" --layers "$layers" --total_cm "$total_cm"

cd /opt/dumbo-mpc
exec ./run_local_network_test.sh "$task" "$n" "$layers" "$total_cm"
