#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

usage() {
  echo "Usage: $0 <N> <t> <batch_size> <layers>"
}

if [[ $# -ne 4 ]]; then
  usage >&2
  exit 1
fi

N="$1"
T="$2"
BATCH_SIZE="$3"
LAYERS="$4"

for value in "$N" "$T" "$BATCH_SIZE" "$LAYERS"; do
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "All arguments must be non-negative integers." >&2
    exit 1
  fi
done
if [[ "$N" -le 0 || "$BATCH_SIZE" -le 0 || "$LAYERS" -le 0 ]]; then
  echo "N, batch_size, and layers must be positive." >&2
  exit 1
fi
if [[ "$N" -lt $((3 * T + 1)) ]]; then
  echo "Dumbo requires N >= 3t + 1 (N=${N}, t=${T})." >&2
  exit 1
fi

load_cluster_env
require_immutable_image
require_tools ssh scp mktemp cp mkdir tar
select_cluster_ips "$N"

GENERATOR_HOST="${NODE_SSH_USERNAME}@${SELECTED_IPS[0]}"
CONF_DIR="mpc_${N}"
if [[ -n "$REMOTE_WORKSPACE_DIR" ]]; then
  REMOTE_ROOT="~/${REMOTE_WORKSPACE_DIR}"
else
  REMOTE_ROOT="~"
fi
REMOTE_ASY_DIR="${REMOTE_ROOT}/dumbo-mpc/dumbo-mpc/AsyRanTriGen"
CONTAINER_ASY_DIR="/opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen"
SSH_OPTIONS=(
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o BatchMode=yes
)
if [[ -n "${SSH_IDENTITY_FILE:-}" ]]; then
  if [[ ! -r "$SSH_IDENTITY_FILE" ]]; then
    echo "SSH identity file is not readable: ${SSH_IDENTITY_FILE}" >&2
    exit 1
  fi
  SSH_OPTIONS+=( -i "$SSH_IDENTITY_FILE" -o IdentitiesOnly=yes )
fi

echo "Generating ${CONF_DIR} inside ${MPC_IMAGE} on ${GENERATOR_HOST}"

# Charm/PBC TBLS material is architecture-sensitive.  The manager is ARM64
# while the workers are AMD64, so generate and validate the configuration in
# the exact immutable image that consumes it.
scp "${SSH_OPTIONS[@]}" "${ASY_SCRIPTS_DIR}/ip.txt" \
  "${GENERATOR_HOST}:${REMOTE_ASY_DIR}/scripts/ip.txt"

if [[ "${REUSE_EXISTING_CONFIG:-0}" == "1" ]]; then
  echo "Reusing existing ${CONF_DIR} on ${GENERATOR_HOST}"
  ssh "${SSH_OPTIONS[@]}" -T "$GENERATOR_HOST" \
    "set -e; \
     test \"\$(find ${REMOTE_ASY_DIR}/conf/${CONF_DIR} -maxdepth 1 -type f -name 'local.*.json' | wc -l)\" \
       -eq '${N}'"
else
  ssh "${SSH_OPTIONS[@]}" -T "$GENERATOR_HOST" \
    "set -e; \
     docker image inspect '${MPC_IMAGE}' >/dev/null; \
     docker run --rm --entrypoint '' \
       -v ${REMOTE_ASY_DIR}/conf:${CONTAINER_ASY_DIR}/conf \
       -v ${REMOTE_ASY_DIR}/scripts/ip.txt:${CONTAINER_ASY_DIR}/scripts/ip.txt:ro \
       -w ${CONTAINER_ASY_DIR} \
       '${MPC_IMAGE}' \
       /opt/venv/continuum/bin/python3 scripts/run_key_gen_dumbo_dyn.py \
         --N '${N}' --f '${T}' --k '${BATCH_SIZE}' --layers '${LAYERS}' \
         --ip-file scripts/ip.txt --port 7001"
fi

if [[ "${SKIP_TBLS_SELF_TEST:-0}" == "1" ]]; then
  echo "Skipping TBLS runtime self-check for ${CONF_DIR}"
else
  ssh "${SSH_OPTIONS[@]}" -T "$GENERATOR_HOST" \
    "set -e; \
     docker run --rm --entrypoint '' \
       -v ${REMOTE_ASY_DIR}/conf:${CONTAINER_ASY_DIR}/conf:ro \
       -w ${CONTAINER_ASY_DIR} \
       '${MPC_IMAGE}' \
       /opt/venv/continuum/bin/python3 -c \"import base64,json,pickle; from pathlib import Path; from beaver.broadcast.crypto.boldyreva import TBLSPublicKey,TBLSPrivateKey,serialize,deserialize1; root=Path('conf/${CONF_DIR}'); cfg=[json.loads((root/f'local.{i}.json').read_text()) for i in range(${N})]; pairs=[(pickle.loads(base64.b64decode(c['extra']['public_key'])),pickle.loads(base64.b64decode(c['extra']['private_key']))) for c in cfg]; assert all(c['N'] == ${N} and c['t'] == ${T} and c['my_id'] == i for i,c in enumerate(cfg)); assert all(len(c['peers']) == ${N} for c in cfg); assert all(sk.i == i for i,(_,sk) in enumerate(pairs)); assert all(pk == pairs[0][0] for pk,_ in pairs); assert len({c['extra']['run_id'] for c in cfg}) == 1; [pk.verify_share(deserialize1(serialize(sk.sign(pk.hash_message('dumbo-config-self-test')))),i,pk.hash_message('dumbo-config-self-test')) for i,(pk,sk) in enumerate(pairs)]; print('Dumbo TBLS runtime self-check passed for ${N} configs')\""
fi

# Docker creates the bind-mounted output as root.  Restore ownership so the
# SSH user can package it and later distribution can replace it cleanly.
ssh "${SSH_OPTIONS[@]}" -T "$GENERATOR_HOST" \
  "set -e; \
   docker run --rm --entrypoint /bin/chown \
     -v ${REMOTE_ASY_DIR}/conf:${CONTAINER_ASY_DIR}/conf \
     '${MPC_IMAGE}' \
     -R \$(id -u):\$(id -g) '${CONTAINER_ASY_DIR}/conf/${CONF_DIR}'"

TMP_DIR="$(mktemp -d -t dumbo-config.XXXXXX)"
trap 'command rm -rf -- "$TMP_DIR"' EXIT
ARCHIVE_PATH="${TMP_DIR}/${CONF_DIR}.tar.xz"

echo "Packing ${CONF_DIR} on ${GENERATOR_HOST} and downloading one archive"
ssh "${SSH_OPTIONS[@]}" -T "$GENERATOR_HOST" \
  "set -e; cd ${REMOTE_ASY_DIR}/conf; tar -cJf - '${CONF_DIR}'" \
  > "$ARCHIVE_PATH"
tar -C "$TMP_DIR" -xJf "$ARCHIVE_PATH"

mkdir -p "${ASY_DIR}/conf/${CONF_DIR}"
cp -a "${TMP_DIR}/${CONF_DIR}/." "${ASY_DIR}/conf/${CONF_DIR}/"

echo "Architecture-compatible Dumbo config copied to ${ASY_DIR}/conf/${CONF_DIR}"
