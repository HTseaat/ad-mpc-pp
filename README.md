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

### 1.3 Python environments

- Continuum runtime: `/opt/venv/continuum`
- AD-MPC runtime: `/opt/venv/admpc`

Convenience commands available in PATH:

- `enter-continuum`
- `enter-admpc`
- `run-continuum-local`
- `run-admpc-local`
- `run-dumbo-mpc-local`

Command notes:

- `enter-continuum`: activate `/opt/venv/continuum`, set `PYTHONPATH=/opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen`, and `cd /opt/dumbo-mpc`.
- `enter-admpc`: activate `/opt/venv/admpc`, set `PYTHONPATH=/opt/admpc`, and `cd /opt/admpc`.
- `run-*-local`: one-command wrappers that prepare the correct runtime environment and launch the target protocol test.

## 2. Local testing

### 2.1 AD-MPC local tests

```bash
run-admpc-local admpc 4 1 8 300
run-admpc-local admpc-linear 4 1 8 300
run-admpc-local admpc-nonlinear 4 1 8 300
```

Command format:

```bash
run-admpc-local [admpc|admpc-linear|admpc-nonlinear|fluid1|fluid2|hbmpc|hbmpc_attack] <n> <t> <layers> <total_cm>
```

Parameter meanings:

- `n`: number of parties.
- `t`: Byzantine threshold, must satisfy `n >= 3t + 1`.
- `layers`: total circuit layers used by the local runner.
- `total_cm`: total multiplication-gate budget for the experiment.
- `admpc-linear`: linear-gate-heavy variant.
- `admpc-nonlinear`: nonlinear/multiplication-gate-heavy variant.

### 2.2 Continuum local tests

```bash
run-continuum-local 4 1 8 300
run-continuum-local 4 1 8 300 linear
run-continuum-local 4 1 8 300 nonlinear

# AggTrans-NoAgg ablation for all-linear transfer
DISABLE_AGG_PROTO=1 DISABLE_RLC=1 run-continuum-local 4 1 8 300 linear

# BGW+AggTrans ablation for all-multiplication evaluation
run-continuum-local 4 1 8 300 bgw-aggtrans
BGW_UNBATCHED_VERIFY=1 run-continuum-local 4 1 8 300 bgw-aggtrans
```

Command format:

```bash
run-continuum-local <n> <t> <layers|auto> <total_cm> [mixed|linear|nonlinear|bgw-aggtrans|shuffle|shuffle-bgw-static]
run-continuum-local <n> <t> <shuffle_k> <shuffle|shuffle-bgw-static>
```

The optional mode selects which continuum variant is launched:

- `mixed`: mixed gates (default)
- `linear`: linear-heavy
- `nonlinear`: multiplication-heavy
- `bgw-aggtrans`: ablation baseline using Dumbo-MPC BGW degree reduction followed by AggTrans hand-off
- `shuffle`: switching-network benchmark; in this mode `total_cm` means input size `k`
- `shuffle-bgw-static`: switching-network static baseline using Dumbo-MPC BGW degree reduction for multiplication

### 2.3 Shuffle local tests

```bash
SHUFFLE_MODE=iterated SHUFFLE_HANDOFF_INTERVAL=1 run-continuum-local 4 1 128 shuffle
SHUFFLE_MODE=iterated SHUFFLE_HANDOFF_INTERVAL=3 run-continuum-local 4 1 128 shuffle
SHUFFLE_MODE=iterated SHUFFLE_HANDOFF_INTERVAL=static run-continuum-local 4 1 128 shuffle

SHUFFLE_MODE=iterated run-continuum-local 4 1 128 shuffle-bgw-static
BGW_UNBATCHED_VERIFY=1 SHUFFLE_MODE=iterated run-continuum-local 4 1 128 shuffle-bgw-static
```

The shuffle benchmark uses a butterfly switching network. The input size `k` must be a power of two.

For `shuffle` and `shuffle-bgw-static`, selector signs are generated with the `BatchRandBit` path: random shared field elements are generated, squared and opened, then normalized to shared signs in `{-1, 1}`.

### 2.4 Dumbo-MPC local test (AsyRanTriGen path)

```bash
run-dumbo-mpc-local 4 1 300 full 10
run-dumbo-mpc-local 4 1 300 drop-epoch4 6
```

Command format:

```bash
run-dumbo-mpc-local <n> <t> <k> [full|drop-epoch4] [layers]
```

Arguments:

- `k`: batch size used by `asy-triple` (for a common setup with `width=100, depth=6`, use `k=300`).
- `full`: normal Dumbo-MPC run.
- `drop-epoch4`: dropout test mode used for the GOD experiment.
- `layers`: computation layer count for this run.

## 3. Distributed deployment and experiments

All distributed orchestration is under:

```bash
cd /opt/unified/distributed
```

### 3.1 Configure cluster

```bash
cp cluster.env.example cluster.env
```

Edit `cluster.env`:

- `NODE_SSH_USERNAME`
- `CLUSTER_IPS` (ordered node list)
- `REMOTE_WORKSPACE_DIR` (for layouts like `~/Continuum/admpc`)
- `MPC_IMAGE` (default `continuum:latest`)

### 3.2 Smoke tests (recommended first)

AD-MPC + Continuum (`exp1`, `n=4` only):

```bash
./run_exp1_smoke_n4.sh
```

This sequentially runs:

- `run_suite.sh admpc exp1 --only-n 4`
- `run_suite.sh continuum exp1 --only-n 4`

Dumbo-MPC 4-node smoke (fixed `width=100`, `depth=6`, so default `k=300`):

```bash
./run_dumbo_smoke_n4_d6.sh
```

Default for this dumbo smoke:

- `n=4`, `t=1`
- `width=100`, `depth=6`
- `k=300`
- `mode=full`

### 3.3 Full distributed presets

Unified entry:

```bash
./run_suite.sh <admpc|continuum|bgw-aggtrans|shuffle|shuffle-bgw-static|dumbo> <exp1|exp2|exp3|exp4|exp-shuffle>
```

Protocol shortcuts:

```bash
./run_admpc_dist.sh <exp1|exp2|exp3|exp4>
./run_continuum_dist.sh <exp1|exp2|exp3|exp4>
./run_dumbo_dist.sh <exp3|exp4>
```

Preset summary:

- `exp1`: linear, `w=100`, `d=6`, `(n,t) = (4,1),(10,3),(16,5),(22,7)`
- `exp2`: nonlinear, `w=100`, `d=6`, `(n,t) = (4,1),(10,3),(16,5),(22,7)`
- `exp3`: mixed, `w=100`, fixed `n=16,t=5`, `d in {2,4,6,8,10}`
- `exp4`: mixed, `w=100`, fixed `n=16,t=5,d=6` (dumbo uses `drop-epoch4`)
- `exp-shuffle`: shuffle benchmark, default `SHUFFLE_K=128`; supported protocols are `shuffle` and `shuffle-bgw-static`

Useful options:

```bash
--only-n <n>
--only-d <d>
--sync-code
--timeout <seconds>
--dumbo-timeout <seconds>
--skip-remote-cleanup
--sleep-between-case <seconds>
```

## 4. Running the Evaluation

### 4.1 All-linear transfer experiments

Run AD-MPC and Continuum:

```bash
cd /opt/unified/distributed

./run_suite.sh admpc exp1
./run_suite.sh continuum exp1
```

AggTrans-NoAgg ablation:

```bash
DISABLE_AGG_PROTO=1 DISABLE_RLC=1 ./run_suite.sh continuum exp1
```

Run only one committee size:

```bash
./run_suite.sh continuum exp1 --only-n 4
./run_suite.sh continuum exp1 --only-n 22
```

### 4.2 All-multiplication experiments

```bash
./run_suite.sh admpc exp2
./run_suite.sh continuum exp2
./run_suite.sh bgw-aggtrans exp2
BGW_UNBATCHED_VERIFY=1 ./run_suite.sh bgw-aggtrans exp2
```

Run only one committee size:

```bash
./run_suite.sh continuum exp2 --only-n 16
```

### 4.3 Mixed-circuit depth sweep

```bash
./run_suite.sh admpc exp3
./run_suite.sh continuum exp3
./run_suite.sh dumbo exp3 --dumbo-timeout 900
```

Run a single depth:

```bash
./run_suite.sh continuum exp3 --only-d 6
```

### 4.4 Dropout / GOD experiment

```bash
./run_suite.sh admpc exp4
./run_suite.sh continuum exp4
./run_suite.sh dumbo exp4 --dumbo-timeout 900
```

The Dumbo-MPC dropout run uses `drop-epoch4`, which simulates node dropout during the fourth computation epoch.

### 4.5 Shuffle benchmark

Continuum shuffle:

```bash
SHUFFLE_K=128 SHUFFLE_MODE=iterated SHUFFLE_HANDOFF_INTERVAL=1 \
  ./run_suite.sh shuffle exp-shuffle --timeout 30

SHUFFLE_K=128 SHUFFLE_MODE=iterated SHUFFLE_HANDOFF_INTERVAL=3 \
  ./run_suite.sh shuffle exp-shuffle --timeout 30

SHUFFLE_K=128 SHUFFLE_MODE=iterated SHUFFLE_HANDOFF_INTERVAL=static \
  ./run_suite.sh shuffle exp-shuffle --timeout 30
```

Static BGW shuffle baseline:

```bash
SHUFFLE_K=128 SHUFFLE_MODE=iterated \
  ./run_suite.sh shuffle-bgw-static exp-shuffle --timeout 30
```

## 5. Environment Variables

| Variable | Description |
| --- | --- |
| `DISABLE_RLC=1` | Disable RLC-based batch verification in AggTrans. |
| `DISABLE_AGG_PROTO=1` | Disable prover-side aggregation and send individual witnesses. |
| `BGW_UNBATCHED_VERIFY=1` | Use unbatched verification for Dumbo-MPC BGW degree reduction in BGW-based baselines. |
| `SHUFFLE_K` | Number of shuffle inputs. Default: `128`. |
| `SHUFFLE_MODE=iterated` | Use the iterated butterfly switching network. |
| `SHUFFLE_HANDOFF_INTERVAL=1` | Change committee after every switch layer. |
| `SHUFFLE_HANDOFF_INTERVAL=3` | Change committee every three switch layers. |
| `SHUFFLE_HANDOFF_INTERVAL=static` | Use a fixed committee for the shuffle computation. |

## 6. Outputs

Distributed run results are archived under:

```text
/opt/benchmark-distributed/<timestamp>_<protocol>_<exp>/...
```

Each case contains:

- `metadata.env`
- copied runtime logs
- generated config snapshot

## 7. Cleanup

If an experiment is interrupted, clean remote containers before rerunning:

```bash
cd /opt/unified/distributed

./cleanup_remote_containers.sh
./cleanup_remote_ports.sh --protocol continuum --n 4
./cleanup_remote_ports.sh --protocol dumbo --n 16
```
