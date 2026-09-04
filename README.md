# Continuum: Concretely Efficient Asynchronous Dynamic MPC with Guaranteed Output Delivery

This repository contains the implementation of Continuum and the scripts used to reproduce the evaluation. The artifact includes protocol implementations, baseline implementations, ablation variants, local test wrappers, and distributed experiment runners.

The codebase includes:

- AD-MPC baseline implementation.
- Continuum implementation.
- Dumbo-MPC baseline code.
- AggTrans-NoAgg and BGW+AggTrans ablation baselines.
- MPC-based shuffle benchmark and static BGW baseline.
- Unified local and distributed runners.

## Repository layout

- `/opt/admpc`: AD-MPC code and scripts
- `/opt/dumbo-mpc`: Continuum and Dumbo-MPC related code
- `/opt/unified`: unified helpers for local and distributed runs
- `/opt/unified/distributed`: distributed benchmark runner
- `/opt/benchmark-distributed`: archived distributed experiment outputs

## 1. Deployment

The unified Docker image currently supports only `linux/amd64` (`x86_64`).

### 1.1 Build unified Docker image

Run from project root:

```bash
cd /opt
./unified/build_unified_image.sh mpc-unified:latest
```

### 1.2 Start container

```bash
cd /opt
./unified/run_unified_container.sh mpc-unified:latest mpc-bench
```

Inside the container, the project root is `/opt`.

### 1.3 Runtime environments and convenience commands

Inside the container, the protocol implementations use separate Python environments:

- Continuum runtime: `/opt/venv/continuum`
- AD-MPC runtime: `/opt/venv/admpc`

The image provides the following commands in `PATH`:

- `enter-continuum`
- `enter-admpc`
- `run-continuum-local`
- `run-admpc-local`
- `run-dumbo-mpc-local`

## 2. Local testing

### 2.1 System overheads

All local tests use ZeroMQ CURVE-authenticated channels. Channel-establishment time is reported separately and excluded from protocol execution time.

#### Trusted setup

Example:

```bash
cd /opt
./unified/run_trusted_setup_local.sh \
  16 5 64 /opt/benchmark-local/trusted-setup-n16-q64
```

Command format:

```bash
./unified/run_trusted_setup_local.sh <n> <t> <Q> <output_dir>
```

Parameter meanings:

- `n`: number of setup parties. The current trusted-setup NTT path requires `n` to be a power of two.
- `t`: Byzantine threshold, must satisfy `n >= 3t + 1`.
- `Q`: requested number of KZG powers, must satisfy `Q >= t + 1`.
- `output_dir`: new or empty output directory for per-party logs, CURVE configurations, public SRS files, metrics, and `summary.json`.

#### Committee election

Example:

```bash
cd /opt
./unified/run_committee_election_local.sh \
  16 5 4 /opt/benchmark-local/committee-election-n16
```

Command format:

```bash
./unified/run_committee_election_local.sh <n> <t> <K> <output_dir>
```

Parameter meanings:

- `n`: number of election parties. The paper evaluates `n=4`, `10`, and `16`.
- `t`: Byzantine threshold, must satisfy `n >= 3t + 1`.
- `K`: number of candidate committees. The paper uses `K=4`.
- `output_dir`: new or empty output directory for generated configurations, per-party logs, and `summary.json`. The summary reports `protocol_completion_ms` and `distributions.channel_setup_ms` separately.

### 2.2 Figure 8: Transfer protocol evaluation

#### Local protocol tests

Example:

```bash
cd /opt
./unified/run_figure8_admpc_local.sh 4 1 6 100
./unified/run_figure8_noagg_local.sh 4 1 6 100
./unified/run_figure8_aggtrans_local.sh 4 1 6 100
```

Command format:

```bash
./unified/run_figure8_admpc_local.sh <n> <t> <d> <w>
./unified/run_figure8_noagg_local.sh <n> <t> <d> <w>
./unified/run_figure8_aggtrans_local.sh <n> <t> <d> <w>
```

Parameter meanings:

- `n`: number of parties in each committee.
- `t`: Byzantine threshold, must satisfy `n >= 3t + 1`.
- `d`: circuit depth, excluding the input and output layers.
- `w`: circuit width, which must be a positive even integer for the all-linear runner.

The scripts derive `layers=d+2` and `total_cm=d*w/2` automatically.

#### Communication and computation overheads

Example:

```bash
cd /opt
./unified/run_figure8_admpc_communication_local.sh \
  4 1 6 100 /opt/benchmark-local/figure8-admpc-communication
./unified/run_figure8_noagg_communication_local.sh \
  4 1 6 100 /opt/benchmark-local/figure8-noagg-communication
./unified/run_figure8_aggtrans_communication_local.sh \
  4 1 6 100 /opt/benchmark-local/figure8-aggtrans-communication
```

Command format:

```bash
./unified/run_figure8_admpc_communication_local.sh <n> <t> <d> <w> <output_dir>
./unified/run_figure8_noagg_communication_local.sh <n> <t> <d> <w> <output_dir>
./unified/run_figure8_aggtrans_communication_local.sh <n> <t> <d> <w> <output_dir>
```

Parameter meanings:

- `n`: number of parties in each committee.
- `t`: Byzantine threshold, must satisfy `n >= 3t + 1`.
- `d`: circuit depth used for the derived whole-circuit total.
- `w`: circuit width and hand-off batch size `B`, which must be a positive even integer.
- `output_dir`: new or empty output directory for the selected protocol's raw per-process artifacts, analysis, and final summaries. Use a different directory for each command.

Each overhead command measures one representative hand-off with `B=w` and writes `summary.json`, `summary.csv`, `summary.md`, and `normalization_audit.json` to `<output_dir>/final/`.

### 2.3 Figure 9: Multiplication protocol evaluation

#### Local protocol tests

Example:

```bash
cd /opt
./unified/run_figure9_admpc_local.sh 4 1 6 100
./unified/run_figure9_batchmul_local.sh 4 1 6 100
./unified/run_figure9_bgw_aggtrans_local.sh 4 1 6 100
```

Command format:

```bash
./unified/run_figure9_admpc_local.sh <n> <t> <d> <w>
./unified/run_figure9_batchmul_local.sh <n> <t> <d> <w>
./unified/run_figure9_bgw_aggtrans_local.sh <n> <t> <d> <w>
```

Parameter meanings:

- `n`: number of parties in each committee.
- `t`: Byzantine threshold, must satisfy `n >= 3t + 1`.
- `d`: circuit depth, excluding the input and output layers.
- `w`: circuit width and number of multiplication gates per computation layer.

The scripts derive `layers=d+2` and `total_cm=d*w` automatically.

#### Communication and computation overheads

Example:

```bash
cd /opt
./unified/run_figure9_admpc_communication_local.sh \
  4 1 6 100 /opt/benchmark-local/figure9-admpc-communication
./unified/run_figure9_batchmul_communication_local.sh \
  4 1 6 100 /opt/benchmark-local/figure9-batchmul-communication
./unified/run_figure9_bgw_aggtrans_communication_local.sh \
  4 1 6 100 /opt/benchmark-local/figure9-bgw-aggtrans-communication
```

Command format:

```bash
./unified/run_figure9_admpc_communication_local.sh <n> <t> <d> <w> <output_dir>
./unified/run_figure9_batchmul_communication_local.sh <n> <t> <d> <w> <output_dir>
./unified/run_figure9_bgw_aggtrans_communication_local.sh <n> <t> <d> <w> <output_dir>
```

Parameter meanings:

- `n`: number of parties in each committee.
- `t`: Byzantine threshold, must satisfy `n >= 3t + 1`.
- `d`: circuit depth used for the derived whole-circuit total.
- `w`: circuit width and multiplication batch size `M`.
- `output_dir`: new or empty output directory for the selected protocol's raw per-process artifacts, analysis, logs, and final summaries. Use a different directory for each command.

Each overhead command measures one representative multiplication layer with `M=w` and writes `summary.json`, `summary.csv`, `summary.md`, and `normalization_audit.json` to `<output_dir>/final/`.

### 2.4 Figure 10: GOD under adversarial faults

The five commands below use the fixed paper configuration `n=16`, `t=5`, `d=6`, and `w=100`, with a 1:1 ratio of multiplication and linear gates in every computation layer. Each command corresponds to one curve in Figure 10.

```bash
cd /opt
./unified/run_figure10_admpc_accum_local.sh
./unified/run_figure10_continuum_accum_local.sh
./unified/run_figure10_dumbo_accum_local.sh
./unified/run_figure10_admpc_attack_local.sh
./unified/run_figure10_continuum_attack_local.sh
```

- `AD-MPC-Accum`: designates `t` silent parties in each computation committee.
- `Continuum-Accum`: designates `t` silent parties in each computation committee.
- `Dumbo-MPC`: designates `t` new silent parties in the static committee in every epoch.
- `AD-MPC-Attack`: delays the selected parties' hand-off messages by 10 seconds in epoch 3 and injects malicious ADTrans contributions in epoch 4.
- `Continuum-Attack`: applies the same delay in epoch 3, followed by malicious AggTrans contributions in epoch 4 and malicious BatchMul contributions in epoch 5.

Each command automatically creates a separate timestamped directory under `/opt/benchmark-local/figure10/`. The directory contains the controller log, per-process logs, generated configuration, and `metadata.env`. Accumulation runs also produce `fault_trace.json` after validating the injected fault schedule and protocol progress.

### 2.5 Figure 11: MPC-based shuffle

Example:

```bash
cd /opt
./unified/run_figure11_admpc_local.sh 4 1
./unified/run_figure11_continuum_local.sh 4 1
./unified/run_figure11_continuum_coarse_local.sh 4 1
./unified/run_figure11_continuum_static_local.sh 4 1
./unified/run_figure11_bgw_ampc_local.sh 4 1
```

Command format:

```bash
./unified/run_figure11_admpc_local.sh <n> <t>
./unified/run_figure11_continuum_local.sh <n> <t>
./unified/run_figure11_continuum_coarse_local.sh <n> <t>
./unified/run_figure11_continuum_static_local.sh <n> <t>
./unified/run_figure11_bgw_ampc_local.sh <n> <t>
```

Parameter meanings:

- `n`: committee size; the paper evaluates `n=4`, `10`, and `16`.
- `t`: Byzantine threshold, must satisfy `n >= 3t + 1`.

All five commands run the 128-input iterated butterfly network with 49 switch layers.

- `AD-MPC` and `Continuum`: change committees after every switch layer.
- `Continuum-Coarse`: changes committees every five switch layers.
- `Continuum-Static`: uses one committee for all switch layers.
- `BGW-AMPC`: uses the static BGW-style multiplication baseline.

### 2.6 Figure 14: Impact of circuit depth on latency

Example:

```bash
cd /opt
./unified/run_figure14_admpc_local.sh 16 5 6
./unified/run_figure14_continuum_local.sh 16 5 6
./unified/run_figure14_dumbo_mpc_local.sh 16 5 6
```

Command format:

```bash
./unified/run_figure14_admpc_local.sh <n> <t> <d>
./unified/run_figure14_continuum_local.sh <n> <t> <d>
./unified/run_figure14_dumbo_mpc_local.sh <n> <t> <d>
```

Parameter meanings:

- `n`: number of parties; Figure 14 uses `n=16`.
- `t`: Byzantine threshold, must satisfy `n >= 3t + 1`; Figure 14 uses `t=5`.
- `d`: circuit depth, excluding the input and output layers; Figure 14 evaluates `d=2`, `4`, `6`, `8`, and `10`.

All three commands use a mixed circuit of fixed width `w=100`, with a 1:1 ratio of multiplication and linear gates in every computation layer. The scripts derive `layers=d+2` and `total_cm=50d` automatically.

## 3. Distributed deployment and experiments

All distributed orchestration is under:

```bash
cd /opt/unified/distributed
```

### 3.1 Configure the distributed cluster

Create the cluster configuration:

```bash
cd /opt/unified/distributed
cp cluster.env.example cluster.env
```

Then edit `cluster.env`. A minimal configuration has the following form:

```bash
NODE_SSH_USERNAME="ubuntu"

MPC_IMAGE="<preloaded-image-tag>"
MPC_IMAGE_ID="sha256:<image-id>"
MPC_COMPOSE_FILE="docker-compose.aws.yml"

REMOTE_WORKSPACE_DIR="Continuum"

CLUSTER_IPS=(
  "203.0.113.11"
  "203.0.113.12"
  "203.0.113.13"
  "203.0.113.14"
)

CLUSTER_PEER_IPS=(
  "10.0.0.11"
  "10.0.0.12"
  "10.0.0.13"
  "10.0.0.14"
)
```

The fields have the following meanings:

- `NODE_SSH_USERNAME`: SSH user shared by the experiment servers.
- `CLUSTER_IPS`: ordered addresses used by the controller for SSH. The order defines party indices and must remain fixed throughout a campaign.
- `CLUSTER_PEER_IPS`: optional ordered addresses used for MPC traffic between servers. Use private or LAN addresses when available. If omitted, `CLUSTER_IPS` is used.
- `MPC_IMAGE` and `MPC_IMAGE_ID`: tag and immutable image ID of the unified image already loaded on every server.
- `MPC_COMPOSE_FILE`: distributed Compose file. Use `docker-compose.aws.yml` for the standard image-only deployment.
- `REMOTE_WORKSPACE_DIR`: optional directory below the remote user's home containing `admpc/` and `dumbo-mpc/`. Omit it when those directories are directly below the remote home directory.

The configured cluster must contain at least as many servers as the largest `n` requested by the experiment preset.

### 3.2 System overheads

All distributed protocol runs use ZeroMQ CURVE-authenticated channels. The Figure 8 and Figure 9 runs below record `channel_setup_ms` separately from protocol execution time, so channel establishment does not require a separate command.

Run the trusted setup with the paper configuration `n=16`, `t=5`, and `Q=64`:

```bash
cd /opt/unified/distributed

./run_trusted_setup_dist.sh --n 16 --t 5 --powers 64
```

The script starts one authenticated setup party on each selected physical server and collects the public SRS files, per-party metrics, and final analysis under `/opt/benchmark-distributed/`.

Run the committee-election overhead experiment separately for each committee size evaluated in the paper:

```bash
cd /opt/unified/distributed

./run_committee_election_dist.sh \
  --n 4 --t 1 --candidates 4 --depth 1
./run_committee_election_dist.sh \
  --n 10 --t 3 --candidates 4 --depth 1
./run_committee_election_dist.sh \
  --n 16 --t 5 --candidates 4 --depth 1
```

Here, `--depth 1` measures one independent election rather than the sequence of elections charged to a multi-epoch end-to-end experiment. Repeat each command 20 times when reproducing the paper results.

### 3.3 Figure 8: Transfer protocol evaluation

The distributed Figure 8 experiments use all-linear circuits with fixed width `w=100` and depth `d=6`. The evaluated committee configurations are `(n,t)=(4,1)`, `(10,3)`, `(16,5)`, `(22,7)`, and `(128,42)`.

Run the three Figure 8 variants separately:

```bash
cd /opt/unified/distributed

./run_figure8_admpc_dist.sh
./run_figure8_noagg_dist.sh
./run_figure8_aggtrans_dist.sh
```

By default, each command runs all five committee configurations. Use `--only-n` to run one configuration, or `--cluster-env` to select a non-default cluster file:

```bash
./run_figure8_aggtrans_dist.sh --only-n 4

./run_figure8_aggtrans_dist.sh \
  --cluster-env /path/to/cluster.env --only-n 16
```

### 3.4 Figure 9: Multiplication protocol evaluation

The distributed Figure 9 experiments use all-multiplication circuits with fixed width `w=100` and depth `d=6`. BatchMul and BGW-AggTrans use `(n,t)=(4,1)`, `(10,3)`, `(16,5)`, `(22,7)`, and `(128,42)`. AD-MPC is evaluated only through `(22,7)` because of its substantially higher latency.

Run the three Figure 9 variants separately:

```bash
cd /opt/unified/distributed

./run_figure9_admpc_dist.sh
./run_figure9_batchmul_dist.sh
./run_figure9_bgw_aggtrans_dist.sh
```

By default, the BatchMul and BGW-AggTrans commands run all five committee configurations, while the AD-MPC command runs the first four. Use `--only-n` to run one configuration, or `--cluster-env` to select a non-default cluster file:

```bash
./run_figure9_batchmul_dist.sh --only-n 4

./run_figure9_batchmul_dist.sh \
  --cluster-env /path/to/cluster.env --only-n 16
```

### 3.5 Figure 10: GOD under adversarial faults

The five commands below use the fixed configuration `n=16`, `t=5`, `d=6`, and `w=100`, with a 1:1 ratio of multiplication and linear gates in every computation layer.

```bash
cd /opt/unified/distributed

./run_figure10_admpc_accum_dist.sh
./run_figure10_continuum_accum_dist.sh
./run_figure10_dumbo_accum_dist.sh
./run_figure10_admpc_attack_dist.sh
./run_figure10_continuum_attack_dist.sh
```

- `AD-MPC-Accum` and `Continuum-Accum` designate `t` silent parties in every computation committee.
- `Dumbo-MPC` designates `t` new silent parties in its static committee in each epoch.
- `AD-MPC-Attack` introduces a 10-second delay followed by malicious ADTrans contributions.
- `Continuum-Attack` introduces the same delay followed by malicious AggTrans and BatchMul contributions.

### 3.6 Figure 11: MPC-based shuffle

The distributed Figure 11 experiments run the 128-input iterated butterfly network with 49 switch layers. The evaluated committee configurations are `(n,t)=(4,1)`, `(10,3)`, and `(16,5)`.

```bash
cd /opt/unified/distributed

./run_figure11_admpc_dist.sh
./run_figure11_continuum_dist.sh
./run_figure11_continuum_coarse_dist.sh
./run_figure11_continuum_static_dist.sh
./run_figure11_bgw_ampc_dist.sh
```

- `AD-MPC` and `Continuum` change committees after every switch layer.
- `Continuum-Coarse` changes committees every five switch layers.
- `Continuum-Static` uses one committee for all switch layers.
- `BGW-AMPC` uses the static BGW-style multiplication baseline.

Use `--only-n` to run one committee configuration. For example:

```bash
./run_figure11_continuum_dist.sh --only-n 4
```

### 3.7 Figure 14: Impact of circuit depth on latency

The distributed Figure 14 experiments use mixed circuits with fixed `n=16`, `t=5`, and `w=100`, with a 1:1 ratio of multiplication and linear gates. The evaluated depths are `d=2`, `4`, `6`, `8`, and `10`.

```bash
cd /opt/unified/distributed

./run_figure14_admpc_dist.sh
./run_figure14_continuum_dist.sh
./run_figure14_dumbo_mpc_dist.sh
```

By default, each command runs all five depths. Use `--only-d` to run one depth, or `--cluster-env` to select a non-default cluster file:

```bash
./run_figure14_continuum_dist.sh --only-d 6

./run_figure14_continuum_dist.sh \
  --cluster-env /path/to/cluster.env --only-d 10
```

## 4. Outputs

All distributed results are stored under:

```text
/opt/benchmark-distributed/
```

