# Continuum: Concretely Efficient Asynchronous Dynamic MPC with Guaranteed Output Delivery

This repository contains the implementation and experiment scripts for the paper Continuum: Concretely Efficient Asynchronous Dynamic MPC with Guaranteed Output Delivery.

The codebase combines three protocol paths in one reproducible workspace:

- AD-MPC implementation (`/opt/admpc`)
- Continuum / AsyRanTriGen / Dumbo-MPC path (`/opt/dumbo-mpc`)
- Unified local and distributed orchestration scripts (`/opt/unified`)

## Repository layout

- `/opt/admpc`: AD-MPC code and scripts
- `/opt/dumbo-mpc`: Continuum and Dumbo-MPC related code
- `/opt/unified`: unified helpers for local and distributed runs
- `/opt/unified/distributed`: distributed benchmark runner
- `/opt/papers`: paper PDFs and related material
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
- `run-compare-local`

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
```

Command format:

```bash
run-continuum-local <n> <t> <layers> <total_cm> [mixed|linear|nonlinear]
```

The optional mode selects which continuum variant is launched:

- `mixed`: mixed gates (default)
- `linear`: linear-heavy
- `nonlinear`: multiplication-heavy

### 2.3 Dumbo-MPC local test (AsyRanTriGen path)

```bash
run-dumbo-mpc-local 4 1 300 full 10
```

Arguments:

- `<n> <t> <k> [full|drop-epoch4] [layers]`
- `k`: batch size used by `asy-triple` (for your common setup, `width=100, depth=6`, use `k=300`).
- `full`: normal full run.
- `drop-epoch4`: dropout test mode that injects node-drop behavior at epoch/layer 4 for robustness testing.
- `layers`: computation layer count for this run (default `10`).

### 2.4 One-command local comparison

```bash
run-compare-local 4 1 8 300 admpc
```

Outputs are stored under:

- `/opt/benchmark-compare/<timestamp>_...`

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
./run_suite.sh <admpc|continuum|dumbo> <exp1|exp2|exp3|exp4>
```

Protocol shortcuts:

```bash
./run_admpc_dist.sh <exp1|exp2|exp3|exp4>
./run_continuum_dist.sh <exp1|exp2|exp3|exp4>
./run_dumbo_dist.sh <exp3|exp4>
```

Preset summary:

- `exp1`: linear, `w=100`, `d=6`, `(n,t) = (4,1),(8,2),(12,3),(16,5)`
- `exp2`: nonlinear, `w=100`, `d=6`, `(n,t) = (4,1),(8,2),(12,3),(16,5)`
- `exp3`: mixed, `w=100`, fixed `n=16,t=5`, `d in {2,4,6,8,10}`
- `exp4`: mixed, `w=100`, fixed `n=16,t=5,d=6` (dumbo uses `drop-epoch4`)

Useful options:

```bash
--only-n <n>
--sync-code
--timeout <seconds>
--dumbo-timeout <seconds>
--skip-remote-cleanup
--sleep-between-case <seconds>
```

### 3.4 Outputs

Distributed run results are archived under:

- `/opt/benchmark-distributed/<timestamp>_<protocol>_<exp>/...`

Each case contains:

- `metadata.env`
- copied runtime logs
- generated config snapshot
