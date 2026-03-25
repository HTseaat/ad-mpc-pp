# Distributed Benchmark Runner

This folder provides a single orchestration layer for distributed experiments across:
- AD-MPC (`/opt/admpc`)
- continuum (`/opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen`)
- dumbo-MPC (`asy-triple` path)

## 1. Configure cluster once

```bash
cd /opt/unified/distributed
cp cluster.env.example cluster.env
# edit cluster.env
```

`cluster.env` defines:
- `NODE_SSH_USERNAME`
- ordered `CLUSTER_IPS=(...)`
- Optional `MPC_IMAGE` env can override compose image (default `continuum:latest`).
- Optional `REMOTE_WORKSPACE_DIR` if remote repos are under `~/Continuum`-style parent dir.

## 2. Run one protocol at a time

This runner is intentionally serial per protocol.

```bash
# AD-MPC
./run_admpc_dist.sh exp1

# continuum
./run_continuum_dist.sh exp2

# dumbo (only exp3/exp4)
./run_dumbo_dist.sh exp4 --dumbo-timeout 900
```

Or use the generic entry:

```bash
./run_suite.sh <admpc|continuum|dumbo> <exp1|exp2|exp3|exp4>
```

Useful options:

```bash
--sleep-between-case <seconds>   # default 30, set 0 to disable
--sync-code                      # distribute code before each case
--timeout <seconds>              # admpc/continuum control-node timeout
--dumbo-timeout <seconds>        # dumbo launch timeout
--only-n <n>                     # case filter for exp1/exp2 (e.g., n=4 smoke test)
--skip-remote-cleanup            # skip pre-case cleanup of remote leftover containers
```

For each case, runner behavior is:
- sync `config.sh` / `ip.txt` for current `N`
- run `setup_ssh_keys.sh <N>` automatically (once per `N` in one session)
- cleanup stale compose containers on selected nodes (to avoid port conflicts)
- generate that case's config, distribute files, run protocol
- archive logs into a case-specific output directory (no overwrite across cases)
- pause 30s before next case (configurable)

Manual cleanup helper (when needed):

```bash
./cleanup_remote_ports.sh --protocol continuum --n 4
```

## 3. Experiment presets

- `exp1`: linear gates, `w=100`, `d=6`, `(n,t)={(4,1),(8,2),(12,3),(16,5)}`
- `exp2`: nonlinear gates, `w=100`, `d=6`, `(n,t)={(4,1),(8,2),(12,3),(16,5)}`
- `exp3`: mixed 1:1 gates, `w=100`, `n=16,t=5`, `d={2,4,6,8,10}`
- `exp4`: mixed 1:1 gates, `w=100`, `n=16,t=5`, `d=6`; dumbo uses `drop-epoch4`

## 4. Outputs

Each run writes to:

```text
/opt/benchmark-distributed/<timestamp>_<protocol>_<exp>/...
```

Current version stores raw logs and metadata only. Metric extraction is intentionally left as TODO for later.

## 5. Quick smoke test (exp1, n=4 only)

Run the minimal distributed sanity check before large-scale runs:

```bash
cd /opt/unified/distributed
./run_exp1_smoke_n4.sh
```

This runs:
- `run_suite.sh admpc exp1 --only-n 4`
- `run_suite.sh continuum exp1 --only-n 4`

## 6. Dumbo 4-node smoke (w=100, d=6)

`exp3` for dumbo is fixed at `n=16` in presets.  
Use this helper for a small 4-node sanity run:

```bash
cd /opt/unified/distributed
./run_dumbo_smoke_n4_d6.sh
```

Defaults:
- `n=4`, `t=1`
- `width=100`, `depth=6`
- `k=300` (computed as `width*depth/2`)
- `mode=full`

Useful options:

```bash
./run_dumbo_smoke_n4_d6.sh --sync-code
./run_dumbo_smoke_n4_d6.sh --dumbo-timeout 900
./run_dumbo_smoke_n4_d6.sh --mode drop-epoch4
```
