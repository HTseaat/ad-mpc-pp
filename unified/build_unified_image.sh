#!/usr/bin/env bash
set -euo pipefail

image_tag="${1:-mpc-unified:latest}"

docker build -f Dockerfile.unified -t "$image_tag" .
