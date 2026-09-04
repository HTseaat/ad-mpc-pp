#!/usr/bin/env bash
set -euo pipefail

image_tag="${1:-mpc-unified:latest}"
container_name="${2:-mpc-bench}"

docker run -it --platform linux/amd64 --name "$container_name" "$image_tag"
