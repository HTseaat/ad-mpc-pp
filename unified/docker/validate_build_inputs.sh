#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNIFIED_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
WORKSPACE_ROOT="$(cd "${UNIFIED_DIR}/.." && pwd)"
DOCKERFILE="${UNIFIED_DIR}/Dockerfile.unified"

required_files=(
  "$DOCKERFILE"
  "${DOCKERFILE}.dockerignore"
  "${SCRIPT_DIR}/requirements-common.txt"
  "${SCRIPT_DIR}/image_preflight.sh"
  "${UNIFIED_DIR}/build_unified_image.sh"
  "${WORKSPACE_ROOT}/dumbo-mpc/docker-compose.aws.yml"
  "${WORKSPACE_ROOT}/admpc/docker-compose.aws.yml"
  "${WORKSPACE_ROOT}/dumbo-mpc/gnark-crypto/kzg_ped_bls12-381/kzg_ped_out.go"
  "${WORKSPACE_ROOT}/dumbo-mpc/bulletproofs-amcl/Cargo.lock"
  "${WORKSPACE_ROOT}/dumbo-mpc/dumbo-mpc/OptRanTriGen/pairing/Cargo.lock"
  "${WORKSPACE_ROOT}/admpc/pairing/Cargo.lock"
)

for path in "${required_files[@]}"; do
  if [[ ! -f "$path" ]]; then
    echo "missing build input: $path" >&2
    exit 1
  fi
done

if grep -q 'linux-arm64' "$DOCKERFILE"; then
  echo "unified Dockerfile still contains a linux-arm64 download" >&2
  exit 1
fi
grep -q 'linux-amd64' "$DOCKERFILE"
grep -q 'TARGETARCH.*amd64' "$DOCKERFILE"
grep -q '^\*\*/\*\.so$' "${DOCKERFILE}.dockerignore"

bash -n \
  "${UNIFIED_DIR}/build_unified_image.sh" \
  "${SCRIPT_DIR}/capture_stage0_baseline.sh" \
  "${SCRIPT_DIR}/image_preflight.sh" \
  "${SCRIPT_DIR}/validate_build_inputs.sh"

yaml_python="${MPC_YAML_PYTHON:-/opt/venv/continuum/bin/python3}"
if [[ ! -x "$yaml_python" ]]; then
  echo "Python with PyYAML is required for compose validation: $yaml_python" >&2
  exit 1
fi

"$yaml_python" - \
  "${WORKSPACE_ROOT}/dumbo-mpc/docker-compose.aws.yml" \
  "${WORKSPACE_ROOT}/admpc/docker-compose.aws.yml" <<'PY'
from pathlib import Path
import sys
import yaml

for raw_path in sys.argv[1:]:
    path = Path(raw_path)
    with path.open(encoding="utf-8") as handle:
        document = yaml.safe_load(handle)
    services = document.get("services") if isinstance(document, dict) else None
    if not isinstance(services, dict) or len(services) != 1:
        raise SystemExit(f"invalid standalone compose file: {path}")
    service = next(iter(services.values()))
    for volume in service.get("volumes", []):
        target = str(volume).split(":", 1)[-1]
        if target in {"/opt/dumbo-mpc", "/opt/admpc", "/usr/src/adkg"}:
            raise SystemExit(f"production compose masks immutable source: {path}: {volume}")
    print(f"PASS compose: {path}")
PY

echo "PASS unified linux/amd64 build inputs"
if ! command -v docker >/dev/null 2>&1; then
  echo "INFO Docker unavailable here; run build_unified_image.sh on the x86_64 builder."
fi

