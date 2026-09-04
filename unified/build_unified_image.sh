#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DOCKERFILE="${SCRIPT_DIR}/Dockerfile.unified"

image_tag="continuum-aws-amd64:dev"
output_mode="load"
no_cache=0
run_check=1

usage() {
  cat <<'USAGE'
Usage: build_unified_image.sh [options] [image-tag]

Options:
  --push             Push with buildx instead of loading into local Docker.
  --load             Load into local Docker (default).
  --no-cache         Disable Docker build cache.
  --skip-run-check   Skip post-build `docker run` preflight.
  -h, --help         Show this help.

Examples:
  ./unified/build_unified_image.sh continuum-aws-amd64:test
  ./unified/build_unified_image.sh --push 123456789.dkr.ecr.us-east-1.amazonaws.com/continuum:abc123
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --push)
      output_mode="push"
      shift
      ;;
    --load)
      output_mode="load"
      shift
      ;;
    --no-cache)
      no_cache=1
      shift
      ;;
    --skip-run-check)
      run_check=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      image_tag="$1"
      shift
      if [[ $# -gt 0 ]]; then
        echo "Only one image tag may be provided." >&2
        exit 2
      fi
      ;;
  esac
done

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required. Run this script on the x86_64 AWS builder." >&2
  exit 127
fi

host_arch="$(uname -m)"
if command -v git >/dev/null 2>&1 && git -C "$WORKSPACE_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  vcs_ref="$(git -C "$WORKSPACE_ROOT" rev-parse HEAD)"
  if [[ -n "$(git -C "$WORKSPACE_ROOT" status --porcelain)" ]]; then
    vcs_ref="${vcs_ref}-dirty"
  fi
else
  vcs_ref="source-$(find \
    "$WORKSPACE_ROOT/dumbo-mpc/dumbo-mpc/AsyRanTriGen/beaver" \
    "$WORKSPACE_ROOT/dumbo-mpc/dumbo-mpc/AsyRanTriGen/committee_election" \
    "$WORKSPACE_ROOT/dumbo-mpc/dumbo-mpc/AsyRanTriGen/scripts" \
    "$WORKSPACE_ROOT/dumbo-mpc/gnark-crypto/kzg_ped_bls12-381" \
    "$WORKSPACE_ROOT/dumbo-mpc/bulletproofs-amcl/src" \
    "$WORKSPACE_ROOT/admpc/adkg" \
    "$WORKSPACE_ROOT/admpc/scripts" \
    "$WORKSPACE_ROOT/unified" \
    -type f \( -name '*.py' -o -name '*.sh' -o -name '*.go' -o -name '*.rs' \) \
    -print0 | sort -z | xargs -0 sha256sum | sha256sum | awk '{print substr($1,1,16)}')"
fi
build_date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

common_args=(
  --platform linux/amd64
  --file "$DOCKERFILE"
  --tag "$image_tag"
  --build-arg TARGETARCH=amd64
  --build-arg "VCS_REF=${vcs_ref}"
  --build-arg "BUILD_DATE=${build_date}"
  --progress plain
)
if [[ "$no_cache" -eq 1 ]]; then
  common_args+=(--no-cache)
fi

echo "Building ${image_tag}"
echo "Context: ${WORKSPACE_ROOT}"
echo "Platform: linux/amd64"
echo "Source revision: ${vcs_ref}"

if docker buildx version >/dev/null 2>&1; then
  if [[ "$output_mode" == "push" ]]; then
    docker buildx build "${common_args[@]}" --push "$WORKSPACE_ROOT"
  else
    docker buildx build "${common_args[@]}" --load "$WORKSPACE_ROOT"
  fi
else
  if [[ "$host_arch" != "x86_64" ]]; then
    echo "docker buildx is required when the builder host is ${host_arch}." >&2
    exit 1
  fi
  if [[ "$output_mode" == "push" ]]; then
    echo "--push requires docker buildx; build locally and docker push explicitly." >&2
    exit 1
  fi
  docker build "${common_args[@]}" "$WORKSPACE_ROOT"
fi

if [[ "$output_mode" == "load" && "$run_check" -eq 1 ]]; then
  docker run --rm \
    --platform linux/amd64 \
    "$image_tag" \
    /opt/unified/docker/image_preflight.sh --runtime-check
fi

echo "PASS built ${image_tag} (${vcs_ref})"
