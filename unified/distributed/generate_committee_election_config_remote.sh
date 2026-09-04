#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/common.sh"

if [[ $# -ne 5 ]]; then
  echo "Usage: $0 <config-name> <N> <t> <candidates> <base-port>" >&2
  exit 1
fi

CONFIG_NAME="$1"
N="$2"
T="$3"
CANDIDATES="$4"
BASE_PORT="$5"

if ! [[ "$CONFIG_NAME" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "Invalid config name: ${CONFIG_NAME}" >&2
  exit 1
fi

load_cluster_env
require_immutable_image
require_tools ssh scp mktemp cp mkdir
select_cluster_ips "$N"

GENERATOR_HOST="${NODE_SSH_USERNAME}@${SELECTED_IPS[0]}"
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

TMP_DIR="$(mktemp -d -t committee-election-config.XXXXXX)"
trap 'command rm -rf -- "$TMP_DIR"' EXIT
PEER_IP_FILE="${TMP_DIR}/peer_ips.txt"
printf '%s\n' "${SELECTED_PEER_IPS[@]}" > "$PEER_IP_FILE"

retry_transient_connection() {
  local tool="$1"
  shift
  local attempt status started elapsed
  for attempt in 1 2 3; do
    started=$SECONDS
    if command "$tool" "$@"; then
      return 0
    else
      status="$?"
    fi
    elapsed=$((SECONDS - started))
    if [[ "$attempt" -ge 3 || "$elapsed" -ge 15 ]]; then
      return "$status"
    fi
    echo "Transient ${tool} connection failure; retrying attempt $((attempt + 1))/3" >&2
    sleep 2
  done
}

echo "Generating ${CONFIG_NAME} inside ${MPC_IMAGE} on ${GENERATOR_HOST}"
retry_transient_connection ssh "${SSH_OPTIONS[@]}" -T "$GENERATOR_HOST" \
  "set -e; \
   docker image inspect '${MPC_IMAGE}' >/dev/null; \
   docker run --rm --entrypoint '' \
     -v ${REMOTE_ASY_DIR}/conf:${CONTAINER_ASY_DIR}/conf \
     -w ${CONTAINER_ASY_DIR} '${MPC_IMAGE}' \
     /opt/venv/continuum/bin/python3 -m scripts.setup_committee_election \
       --N '${N}' --t '${T}' --K '${CANDIDATES}' --base-port '${BASE_PORT}' \
       --output-dir conf/'${CONFIG_NAME}'; \
   docker run --rm --entrypoint '' \
     -v ${REMOTE_ASY_DIR}/conf:${CONTAINER_ASY_DIR}/conf:ro \
     -w ${CONTAINER_ASY_DIR} '${MPC_IMAGE}' \
     /opt/venv/continuum/bin/python3 -c \"import base64,json,pickle; from pathlib import Path; from beaver.broadcast.crypto.boldyreva import serialize,deserialize1; root=Path('conf/${CONFIG_NAME}'); cfg=[json.loads((root/f'local.{i}.json').read_text()) for i in range(${N})]; pairs=[(pickle.loads(base64.b64decode(c['extra']['public_key'])),pickle.loads(base64.b64decode(c['extra']['private_key']))) for c in cfg]; assert all(sk.i == i for i,(_,sk) in enumerate(pairs)); assert all(pk == pairs[0][0] for pk,_ in pairs); [pk.verify_share(deserialize1(serialize(sk.sign(pk.hash_message('committee-election-config-self-test')))),i,pk.hash_message('committee-election-config-self-test')) for i,(pk,sk) in enumerate(pairs)]; print('Election TBLS runtime self-check passed for ${N} configs')\""

# The generator runs as root inside Docker. Hand the bind-mounted output back
# to the SSH user before distribute-file.sh extracts this directory again.
retry_transient_connection ssh "${SSH_OPTIONS[@]}" -T "$GENERATOR_HOST" \
  "set -e; \
   docker run --rm --entrypoint /bin/chown \
     -v ${REMOTE_ASY_DIR}/conf:${CONTAINER_ASY_DIR}/conf \
     '${MPC_IMAGE}' \
     -R \$(id -u):\$(id -g) '${CONTAINER_ASY_DIR}/conf/${CONFIG_NAME}'"

retry_transient_connection scp "${SSH_OPTIONS[@]}" -r \
  "${GENERATOR_HOST}:${REMOTE_ASY_DIR}/conf/${CONFIG_NAME}" "$TMP_DIR/"

LOCAL_CONFIG_DIR="${ASY_DIR}/conf/${CONFIG_NAME}"
mkdir -p "$LOCAL_CONFIG_DIR"
cp -a "${TMP_DIR}/${CONFIG_NAME}/." "$LOCAL_CONFIG_DIR/"

python3 "${SCRIPT_DIR}/enrich_committee_election_config.py" \
  --config-dir "$LOCAL_CONFIG_DIR" --ip-file "$PEER_IP_FILE" \
  --n "$N" --base-port "$BASE_PORT"

echo "Architecture-compatible election config copied to ${LOCAL_CONFIG_DIR}"
