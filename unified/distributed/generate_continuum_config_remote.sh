#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

usage() {
  echo "Usage: $0 <N> <t> <layers> <total_cm>"
}

if [[ $# -ne 4 ]]; then
  usage >&2
  exit 1
fi

N="$1"
T="$2"
LAYERS="$3"
TOTAL_CM="$4"

for value in "$N" "$T" "$LAYERS" "$TOTAL_CM"; do
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "All arguments must be non-negative integers." >&2
    exit 1
  fi
done
if [[ "$N" -le 0 || "$LAYERS" -le 0 || "$TOTAL_CM" -le 0 ]]; then
  echo "N, layers, and total_cm must be positive." >&2
  exit 1
fi

load_cluster_env
require_immutable_image
require_tools ssh scp mktemp cp mkdir tar
select_cluster_ips "$N"

GENERATOR_HOST="${NODE_SSH_USERNAME}@${SELECTED_IPS[0]}"
CONF_DIR="admpc_${TOTAL_CM}_${LAYERS}_${N}"
if [[ -n "$REMOTE_WORKSPACE_DIR" ]]; then
  REMOTE_ROOT="~/${REMOTE_WORKSPACE_DIR}"
else
  REMOTE_ROOT="~"
fi
REMOTE_ASY_DIR="${REMOTE_ROOT}/dumbo-mpc/dumbo-mpc/AsyRanTriGen"
CONTAINER_ASY_DIR="/opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen"
SSH_OPTIONS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes)
if [[ -n "${SSH_IDENTITY_FILE:-}" ]]; then
  if [[ ! -r "$SSH_IDENTITY_FILE" ]]; then
    echo "SSH identity file is not readable: ${SSH_IDENTITY_FILE}" >&2
    exit 1
  fi
  SSH_OPTIONS+=(-i "$SSH_IDENTITY_FILE" -o IdentitiesOnly=yes)
fi

echo "Generating ${CONF_DIR} inside ${MPC_IMAGE} on ${GENERATOR_HOST}"

# Charm/PBC TBLS serialization is architecture-sensitive. Generate the keys in
# the same immutable image that consumes them on the experiment workers.
scp "${SSH_OPTIONS[@]}" "${ASY_SCRIPTS_DIR}/ip.txt" \
  "${GENERATOR_HOST}:${REMOTE_ASY_DIR}/scripts/ip.txt"

if [[ "${REUSE_EXISTING_CONFIG:-0}" == "1" ]]; then
  echo "Reusing existing ${CONF_DIR} on ${GENERATOR_HOST}"
  ssh "${SSH_OPTIONS[@]}" -T "$GENERATOR_HOST" \
    "set -e; \
     test \"\$(find ${REMOTE_ASY_DIR}/conf/${CONF_DIR} -maxdepth 1 -type f -name 'local.*.json' | wc -l)\" \
       -eq '$((N * LAYERS))'"
else
  ssh "${SSH_OPTIONS[@]}" -T "$GENERATOR_HOST" \
    "set -e; \
     docker image inspect '${MPC_IMAGE}' >/dev/null; \
     docker run --rm --entrypoint '' \
       -v ${REMOTE_ASY_DIR}/conf:${CONTAINER_ASY_DIR}/conf \
       -v ${REMOTE_ASY_DIR}/scripts/ip.txt:${CONTAINER_ASY_DIR}/scripts/ip.txt:ro \
       -w ${CONTAINER_ASY_DIR} \
       '${MPC_IMAGE}' \
       /opt/venv/continuum/bin/python3 scripts/create_json_files.py \
         admpc '${N}' '${T}' '${LAYERS}' '${TOTAL_CM}'"
fi

if [[ "${SKIP_TBLS_SELF_TEST:-0}" == "1" ]]; then
  echo "Skipping TBLS runtime self-check for ${N}x${LAYERS} configs"
else
  ssh "${SSH_OPTIONS[@]}" -T "$GENERATOR_HOST" \
    "set -e; \
     docker run --rm --entrypoint '' \
     -v ${REMOTE_ASY_DIR}/conf:${CONTAINER_ASY_DIR}/conf:ro \
     -w ${CONTAINER_ASY_DIR} \
     '${MPC_IMAGE}' \
     /opt/venv/continuum/bin/python3 -c \"import base64,json,pickle,sys; from pathlib import Path; sys.path.insert(0,'${CONTAINER_ASY_DIR}/scripts'); from beaver.broadcast.crypto.boldyreva import serialize,deserialize1; root=Path('conf/${CONF_DIR}'); cfg=[json.loads((root/f'local.{i}.json').read_text()) for i in range(${N}*${LAYERS})]; pairs=[(pickle.loads(base64.b64decode(c['extra']['public_key'])),pickle.loads(base64.b64decode(c['extra']['private_key']))) for c in cfg]; assert all(sk.i == i % ${N} for i,(_,sk) in enumerate(pairs)); assert all(pk == pairs[(i//${N})*${N}][0] for i,(pk,_) in enumerate(pairs)); [pk.verify_share(deserialize1(serialize(sk.sign(pk.hash_message('continuum-config-self-test')))),i % ${N},pk.hash_message('continuum-config-self-test')) for i,(pk,sk) in enumerate(pairs)]; print('TBLS runtime self-check passed for ${N}x${LAYERS} configs')\""
fi

# The generator runs as root inside Docker. Hand the bind-mounted output back
# to the actual SSH user so non-root EC2 users (for example Ubuntu's `ubuntu`)
# can replace and extract the same configuration during distribution.
ssh "${SSH_OPTIONS[@]}" -T "$GENERATOR_HOST" \
  "set -e; \
   docker run --rm --entrypoint /bin/chown \
     -v ${REMOTE_ASY_DIR}/conf:${CONTAINER_ASY_DIR}/conf \
     '${MPC_IMAGE}' \
     -R \$(id -u):\$(id -g) '${CONTAINER_ASY_DIR}/conf/${CONF_DIR}'"

TMP_DIR="$(mktemp -d -t continuum-config.XXXXXX)"
trap 'command rm -rf -- "$TMP_DIR"' EXIT
ARCHIVE_PATH="${TMP_DIR}/${CONF_DIR}.tar.xz"

# Pull one compressed stream instead of recursively copying hundreds of small
# JSON files.  The latter incurs a network round trip for every file and is
# particularly slow when the generator is reached through a public address.
echo "Packing ${CONF_DIR} on ${GENERATOR_HOST} and downloading one archive"
ssh "${SSH_OPTIONS[@]}" -T "$GENERATOR_HOST" \
  "set -e; cd ${REMOTE_ASY_DIR}/conf; tar -cJf - '${CONF_DIR}'" \
  > "$ARCHIVE_PATH"
tar -C "$TMP_DIR" -xJf "$ARCHIVE_PATH"

mkdir -p "${ASY_DIR}/conf/${CONF_DIR}"
cp -a "${TMP_DIR}/${CONF_DIR}/." "${ASY_DIR}/conf/${CONF_DIR}/"

if [[ "${SKIP_CURVE_ENRICH:-0}" == "1" ]]; then
  echo "Skipping CURVE transport enrichment for ${CONF_DIR}"
else
  "${CURVE_VALIDATION_PYTHON:-/opt/venv/continuum/bin/python3}" \
    "${SCRIPT_DIR}/enrich_continuum_transport_config.py" \
    --config-dir "${ASY_DIR}/conf/${CONF_DIR}" \
    --ip-file "${ASY_SCRIPTS_DIR}/ip.txt" --n "$N" --layers "$LAYERS"
fi

echo "Architecture-compatible config copied to ${ASY_DIR}/conf/${CONF_DIR}"
