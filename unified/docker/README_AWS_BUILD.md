# Fast x86_64 image build

This is the minimal Stage 1/2 path for producing the first AWS image. It is
independent of the existing ARM image and does not overwrite host `.so` files.

## Builder prerequisites

- x86_64 Ubuntu 20.04 (C6a is recommended)
- Docker Engine with the Compose and Buildx plugins
- outbound HTTPS access for Ubuntu, Go, Rust, GitHub, GNU, and Stanford PBC
- at least 30 GiB free disk space

Place the complete workspace on the builder with this layout:

```text
<workspace>/
  admpc/
  dumbo-mpc/
  unified/
```

Uncommitted source files are included because the build uses the current
filesystem as its context. Generated logs, configs, ARM `.so`, Rust targets,
and Python build directories are excluded by
`Dockerfile.unified.dockerignore`.

## Build

From the workspace root:

```bash
./unified/docker/validate_build_inputs.sh
./unified/build_unified_image.sh continuum-aws-amd64:stage2
```

The build script always targets `linux/amd64`. After loading the image, it
automatically runs `image_preflight.sh`, which verifies:

- architecture and dynamic linking;
- the active KZG, Bulletproof, NTL, and pypairing libraries;
- revised aggregation exports;
- Continuum and AD-MPC imports;
- ZeroMQ CURVE support;
- the protocol entry points required by the current runtime.

To push directly to ECR after logging in:

```bash
./unified/build_unified_image.sh --push \
  <account>.dkr.ecr.<region>.amazonaws.com/continuum:<revision>
```

## Production Compose

The AWS compose files are standalone files and must be selected explicitly:

```bash
cd dumbo-mpc
MPC_IMAGE=continuum-aws-amd64:stage2 \
  docker compose -f docker-compose.aws.yml run --rm dumbo-mpc \
  /opt/unified/docker/image_preflight.sh --runtime-check
```

```bash
cd admpc
MPC_IMAGE=continuum-aws-amd64:stage2 \
  docker compose -f docker-compose.aws.yml run --rm htadkg_adkg \
  /opt/unified/docker/image_preflight.sh --runtime-check
```

The existing development compose files remain unchanged.
