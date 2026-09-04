#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

N=4

usage() {
  echo "Usage: $0 [--cluster-env <path>] [--n <N>]" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cluster-env) CLUSTER_ENV="$2"; export CLUSTER_ENV; shift 2 ;;
    --n) N="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done

if ! [[ "$N" =~ ^[1-9][0-9]*$ ]]; then
  echo "N must be a positive integer" >&2
  exit 1
fi

load_cluster_env
require_immutable_image
select_cluster_ips "$N"
require_tools ssh

SSH_OPTIONS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes)
if [[ -n "${SSH_IDENTITY_FILE:-}" ]]; then
  if [[ ! -r "$SSH_IDENTITY_FILE" ]]; then
    echo "SSH identity file is not readable: ${SSH_IDENTITY_FILE}" >&2
    exit 1
  fi
  SSH_OPTIONS+=(-i "$SSH_IDENTITY_FILE" -o IdentitiesOnly=yes)
fi

if [[ -n "$REMOTE_WORKSPACE_DIR" ]]; then
  remote_root="~/${REMOTE_WORKSPACE_DIR}"
else
  remote_root="~"
fi

echo "Preflight image: ${MPC_IMAGE}"
echo "Expected image ID: ${MPC_IMAGE_ID}"

runtime_paths=(
  /opt/admpc/adkg/acss.py
  /opt/admpc/adkg/admpc_dynamic.py
  /opt/admpc/adkg/admpc_dynamic_shuffle.py
  /opt/admpc/adkg/adtrans_byzantine.py
  /opt/admpc/adkg/adversarial_faults.py
  /opt/admpc/adkg/aprep.py
  /opt/admpc/adkg/broadcast/avid.py
  /opt/admpc/adkg/bundle.py
  /opt/admpc/adkg/communication_metrics.py
  /opt/admpc/adkg/fault_accumulation.py
  /opt/admpc/adkg/ipc.py
  /opt/admpc/adkg/poly_commit_log.py
  /opt/admpc/adkg/protocol_metrics.py
  /opt/admpc/adkg/rand.py
  /opt/admpc/adkg/robust_rec.py
  /opt/admpc/adkg/robust_reconstruction.py
  /opt/admpc/adkg/shuffle_ipc.py
  /opt/admpc/adkg/shuffle_network.py
  /opt/admpc/adkg/trans.py
  /opt/admpc/scripts/admpc_dynamic_batchrand_run.py
  /opt/admpc/scripts/admpc_dynamic_linear_run.py
  /opt/admpc/scripts/admpc_dynamic_nonlinear_run.py
  /opt/admpc/scripts/admpc_dynamic_shuffle_run.py
  /opt/admpc/scripts/check-admpc-linear-progress.sh
  /opt/admpc/scripts/collect-admpc-linear-logs.sh
  /opt/admpc/scripts/common.sh
  /opt/admpc/scripts/config.sh
  /opt/admpc/scripts/control-admpc-linear-cluster.sh
  /opt/admpc/scripts/control-admpc-linear-node.sh
  /opt/admpc/scripts/control-admpc-shuffle-node.sh
  /opt/admpc/scripts/control-node.sh
  /opt/admpc/scripts/distribute-file.sh
  /opt/admpc/scripts/run_one_node.py
  /opt/admpc/scripts/setup_ssh_keys.sh
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/admpc2_dynamic.py
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/admpc2_dynamic_bgw_aggtrans.py
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/admpc2_dynamic_linear.py
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/admpc2_dynamic_nonlinear.py
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/admpc2_dynamic_shuffle.py
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/adversarial_faults.py
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/aggregation_interfaces.py
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/aggtrans_commitment_fork.py
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/batch_multiplication.py
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/batch_multiplication_local.py
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/batchmul_input_commitment_fork.py
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/bgw_multiplication.py
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/broadcast/otmvba.py
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/broadcast/otmvba_dyn.py
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/communication_metrics.py
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/dumbo_mpc_dyn_fault_accumulation.py
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/fault_accumulation.py
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/hbacss.py
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/ipc.py
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/protocol_metrics.py
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver/transfer.py
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/kzg_ped_out.so
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/scripts/admpc2_dynamic_bgw_aggtrans_run.py
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/scripts/admpc2_dynamic_linear_run.py
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/scripts/admpc2_dynamic_nonlinear_run.py
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/scripts/common.sh
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/scripts/config.sh
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/scripts/control-node.sh
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/scripts/distribute-admpc.sh
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/scripts/distribute-file.sh
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/trusted_setup/generate_distributed_config.py
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/trusted_setup/protocol/base_link.py
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/trusted_setup/protocol/distributed_tau.py
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/trusted_setup/protocol/dual_chain.py
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/trusted_setup/protocol/network.py
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/trusted_setup/protocol/verification.py
  /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/trusted_setup/run_node.py
)
runtime_content_expected=""
if [[ "$MPC_IMAGE_ID" == runtime-content:* ]]; then
  runtime_content_expected="${MPC_IMAGE_ID#runtime-content:}"
  if [[ ! "$runtime_content_expected" =~ ^[0-9a-f]{64}$ ]]; then
    echo "Invalid runtime-content fingerprint: ${MPC_IMAGE_ID}" >&2
    exit 1
  fi
  if [[ -z "${MPC_IMAGE_PATCH_REF:-}" ]]; then
    echo "MPC_IMAGE_PATCH_REF is required with runtime-content verification." >&2
    exit 1
  fi
  echo "Expected patch label: ${MPC_IMAGE_PATCH_REF}"
fi

printf -v runtime_paths_remote ' %q' "${runtime_paths[@]}"

for node_id in $(seq 0 "$((N - 1))"); do
  ip="${SELECTED_IPS[$node_id]}"
  host="${NODE_SSH_USERNAME}@${ip}"
  local_before="$(date +%s)"
  result="$(
    ssh "${SSH_OPTIONS[@]}" -T "$host" \
      "set -e; \
       command -v timeout >/dev/null; \
       test \"\$(sysctl -n net.ipv4.ip_forward)\" = 1; \
       test -f ${remote_root}/dumbo-mpc/${MPC_COMPOSE_FILE}; \
       test -f ${remote_root}/admpc/${MPC_COMPOSE_FILE}; \
       image_info=\$(docker image inspect --format '{{.Id}}|{{.Architecture}}|{{if index .Config.Labels \"org.opencontainers.image.adversarial.patch-ref\"}}{{index .Config.Labels \"org.opencontainers.image.adversarial.patch-ref\"}}{{else}}{{if index .Config.Labels \"org.opencontainers.image.trusted-setup.patch-ref\"}}{{index .Config.Labels \"org.opencontainers.image.trusted-setup.patch-ref\"}}{{else}}{{if index .Config.Labels \"org.opencontainers.image.admpc-shuffle.patch-ref\"}}{{index .Config.Labels \"org.opencontainers.image.admpc-shuffle.patch-ref\"}}{{else}}{{index .Config.Labels \"org.opencontainers.image.fig89.patch-ref\"}}{{end}}{{end}}{{end}}' '${MPC_IMAGE}'); \
       runtime_hash='-'; \
       if [ -n '${runtime_content_expected}' ]; then \
         runtime_hash=\$(docker run --rm --entrypoint sha256sum '${MPC_IMAGE}'${runtime_paths_remote} | sha256sum | awk '{print \$1}'); \
       fi; \
       if command -v docker-compose >/dev/null 2>&1; then \
         MPC_IMAGE='${MPC_IMAGE}' docker-compose -f ${remote_root}/dumbo-mpc/${MPC_COMPOSE_FILE} config --services | grep -qx dumbo-mpc; \
         MPC_IMAGE='${MPC_IMAGE}' docker-compose -f ${remote_root}/admpc/${MPC_COMPOSE_FILE} config --services | grep -qx htadkg_adkg; \
         compose_kind=docker-compose; \
       elif docker compose version >/dev/null 2>&1; then \
         MPC_IMAGE='${MPC_IMAGE}' docker compose -f ${remote_root}/dumbo-mpc/${MPC_COMPOSE_FILE} config --services | grep -qx dumbo-mpc; \
         MPC_IMAGE='${MPC_IMAGE}' docker compose -f ${remote_root}/admpc/${MPC_COMPOSE_FILE} config --services | grep -qx htadkg_adkg; \
         compose_kind='docker compose'; \
       else \
         echo 'compose-missing' >&2; exit 127; \
       fi; \
       printf '%s;%s;%s;%s' \"\$image_info\" \"\$runtime_hash\" \"\$compose_kind\" \"\$(date +%s)\""
  )"
  local_after="$(date +%s)"
  IFS=';' read -r image_info runtime_hash compose_kind remote_epoch <<< "$result"
  IFS='|' read -r image_id architecture patch_ref <<< "$image_info"
  if [[ -n "$runtime_content_expected" ]]; then
    if [[ "$runtime_hash" != "$runtime_content_expected" ]]; then
      echo "Node ${node_id} (${ip}) runtime content mismatch: ${runtime_hash}" >&2
      exit 1
    fi
    if [[ "$patch_ref" != "$MPC_IMAGE_PATCH_REF" ]]; then
      echo "Node ${node_id} (${ip}) patch label mismatch: ${patch_ref}" >&2
      exit 1
    fi
  elif [[ "$image_id" != "$MPC_IMAGE_ID" ]]; then
      echo "Node ${node_id} (${ip}) image ID mismatch: ${image_id}" >&2
      exit 1
  fi
  if [[ "$architecture" != "amd64" ]]; then
    echo "Node ${node_id} (${ip}) image architecture is ${architecture}, expected amd64" >&2
    exit 1
  fi
  midpoint=$(( (local_before + local_after) / 2 ))
  skew=$(( remote_epoch - midpoint ))
  if (( skew < -5 || skew > 5 )); then
    echo "Node ${node_id} (${ip}) clock skew ${skew}s exceeds 5s" >&2
    exit 1
  fi
  echo "PASS node=${node_id} ip=${ip} image=${image_id} runtime=${runtime_hash} arch=${architecture} compose=${compose_kind} clock_skew=${skew}s"
done

echo "${N}-node preflight passed. Inter-server port reachability is verified by the CURVE readiness barrier at launch."
