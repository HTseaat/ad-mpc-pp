# Distributed Benchmark Runner

This folder provides a single orchestration layer for distributed experiments across:
- AD-MPC (`/opt/admpc`)
- continuum (`/opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen`)
- BGW+AggTrans ablation baseline (`bgw-aggtrans`)
- Shuffle / mixing-network benchmark (`shuffle`)
- Shuffle / mixing-network BGW static baseline (`shuffle-bgw-static`)
- Dumbo-MPC offline/online shuffle baseline (`dumbo-shuffle-beaver`)
- dumbo-MPC (`asy-triple` path)
- dumbo-MPC BGW direct multiplication baseline (`dumbo-bgw-direct`)

## 1. Configure cluster once

```bash
cd /opt/unified/distributed
cp cluster.env.example cluster.env
# edit cluster.env
```

`cluster.env` defines:
- `NODE_SSH_USERNAME`
- ordered `CLUSTER_IPS=(...)`
- `MPC_IMAGE` and `MPC_IMAGE_ID` pin the preloaded r3 image; mutable `:latest`
  tags are rejected by default.
- `MPC_COMPOSE_FILE=docker-compose.aws.yml` keeps protocol source immutable.
- Optional `REMOTE_WORKSPACE_DIR` if remote repos are under `~/Continuum`-style parent dir.

## 2. Run one protocol at a time

This runner is intentionally serial per protocol.

```bash
# AD-MPC
./run_admpc_dist.sh exp1

# continuum
./run_continuum_dist.sh exp2

# Dumbo-MPC BGW + AggTrans ablation baseline
./run_suite.sh bgw-aggtrans exp2

# Shuffle / mixing-network benchmark
SHUFFLE_MODE=single SHUFFLE_K=128 ./run_suite.sh shuffle exp-shuffle --timeout 900
SHUFFLE_MODE=iterated SHUFFLE_K=128 SHUFFLE_HANDOFF_INTERVAL=3 ./run_suite.sh shuffle exp-shuffle --timeout 900
SHUFFLE_MODE=iterated SHUFFLE_K=128 SHUFFLE_HANDOFF_INTERVAL=static ./run_suite.sh shuffle exp-shuffle --timeout 900
SHUFFLE_MODE=single SHUFFLE_K=128 ./run_suite.sh shuffle-bgw-static exp-shuffle --timeout 900
SHUFFLE_MODE=iterated SHUFFLE_K=128 ./run_suite.sh shuffle-bgw-static exp-shuffle --timeout 900
SHUFFLE_MODE=single SHUFFLE_K=128 ./run_suite.sh dumbo-shuffle-beaver exp-shuffle --timeout 900
SHUFFLE_MODE=iterated SHUFFLE_K=128 ./run_suite.sh dumbo-shuffle-beaver exp-shuffle --timeout 900

# dumbo (only exp3/exp4)
./run_dumbo_dist.sh exp4 --dumbo-timeout 900

# Figure 10 Accum curves: each command below executes its protocol once
./run_figure10_fault_accumulation_dist.sh --dumbo-timeout 900 --sync-code

# all five Figure 10 curves, once each (three Accum followed by two Attack)
./run_figure10_paper_dist.sh --dumbo-timeout 900 --sync-code

# dumbo BGW direct multiplication baseline
./run_dumbo_bgw_direct_dist.sh exp2 --only-n 4 --dumbo-timeout 900
```

Cleanup remote compose containers after interrupted or completed distributed runs:

```bash
# all protocols on all configured cluster hosts
./cleanup_remote_containers.sh

# only Dumbo/Continuum containers on first 4 configured hosts
./cleanup_remote_containers.sh --protocol dumbo --n 4

# also clean the seed server as an extra host
./cleanup_remote_containers.sh --host 203.0.113.10
```

Or use the generic entry:

```bash
./run_suite.sh <admpc|continuum|bgw-aggtrans|shuffle|shuffle-bgw-static|dumbo-shuffle-beaver|dumbo|dumbo-bgw-direct> <exp1|exp2|exp3|exp4|exp-shuffle>
```

Useful options:

```bash
--sleep-between-case <seconds>   # default 30, set 0 to disable
--sync-code                      # distribute code before each case
--start-delay <seconds>          # future shared start offset (default 30)
--timeout <seconds>              # hard timeout for every remote MPC process
--dumbo-timeout <seconds>        # dumbo launch timeout
--only-n <n>                     # case filter for exp1/exp2 (e.g., n=4 smoke test)
--only-d <d>                     # case filter for exp3 (supported d: 2,4,6,8,10)
--fault-profile <name>           # exp4: accumulation (default), attack, or legacy-drop
--skip-remote-cleanup            # skip pre-case cleanup of remote leftover containers
```

For each case, runner behavior is:
- sync `config.sh` / `ip.txt` for current `N`
- run `setup_ssh_keys.sh <N>` automatically (once per `N` in one session)
- cleanup stale compose containers on selected nodes (to avoid port conflicts)
- generate that case's config, distribute files, run protocol
- validate CURVE identities before distribution
- archive logs into a case-specific output directory (no overwrite across cases)
- for Figure 8/9 n=4, require 32/32 completion and zero CURVE security counters
- pause 30s before next case (configurable)

Manual cleanup helper (when needed):

```bash
./cleanup_remote_ports.sh --protocol continuum --n 4
```

## Figure 8/9 n=4 four-server campaign

After filling the first four ordered IPs in `cluster.env`, run the read-only
preflight first:

```bash
./preflight_fig89_n4.sh
```

The complete preliminary campaign (one warm-up and three measured runs per
variant) is:

```bash
./run_fig89_n4.sh
```

It performs six real four-party CURVE-authenticated elections and charges their
sequential protocol latency to epochs 2 through 7. It then runs:

- Figure 8: AD-MPC, AggTrans-NoAgg, AggTrans V2;
- Figure 9: AD-MPC, BGW-AggTrans, BatchMul V2.

CURVE channel setup remains outside `core_latency_seconds` and is reported as a
separate distribution. The election aggregate is added separately as
`total_with_sequential_election_seconds`. The strict analyzer fails if any of
the 32 logical processes is missing, a final-layer process has no `exec_time`,
or any CURVE authentication/metadata/spoofing counter is non-zero.

Run only the reusable election measurement with:

```bash
./run_committee_election_dist.sh
```

The existing r3 election module internally labels each independent measurement
as target epoch 2. The aggregate records explicit `charged_target_epoch=2..7`;
this gives the desired per-layer sequential cost without rebuilding r3 or
changing the predefined protocol committees.

## 3. Experiment presets

- `exp1`: linear gates, `w=100`, `d=6`, `(n,t)={(4,1),(10,3),(16,5),(22,7)}`
- `exp2`: nonlinear gates, `w=100`, `d=6`, `(n,t)={(4,1),(10,3),(16,5),(22,7)}`
- `exp3`: mixed 1:1 gates, `w=100`, `n=16,t=5`, `d={2,4,6,8,10}`
  Use `--only-d <d>` to run a single depth, e.g. `./run_continuum_dist.sh exp3 --only-d 6`.
- `exp4`: mixed 1:1 gates, `w=100`, `n=16,t=5`, `d=6`.
  In the default `accumulation` profile, AD-MPC and Continuum silence the last
  `t` local IDs in every source computation committee. Dumbo-MPC uses one
  static committee: source epoch 1 permanently silences the last `t` IDs and
  source epoch 2 permanently silences a fresh `t` IDs, so liveness is lost in
  epoch 2. The `attack` profile is available for AD-MPC and Continuum. It delays
  the last `t` source dealers in epoch 3 by 10 seconds, attacks ADtrans or
  AggTrans in source epoch 4, and additionally attacks BatchMul in Continuum
  source epoch 5. `legacy-drop` preserves the old `drop-epoch4` run.
- `dumbo-bgw-direct`: skips Dumbo triple generation and evaluates multiplication layers directly with BGW degree reduction; supported for `exp2`, `exp3`, and `exp4`.
- `exp-shuffle`: shuffle benchmark, default `SHUFFLE_K=128`, `SHUFFLE_MODE=single`.
  Set `SHUFFLE_MODE=iterated` for the iterated switching network, `SHUFFLE_HANDOFF_INTERVAL=1/3/static` for FullDynamic / coarse-grained handoff / no-handoff, and optionally tune sender retention with `SHUFFLE_HANDOFF_GRACE_SECONDS` (default 30).
  `shuffle` and `shuffle-bgw-static` now use malicious-secure shared selector signs from `BatchRandBit`: random-share extraction, square/open, public square root, and normalization to signs in `{-1,1}` before evaluating the switching network.
- `dumbo-shuffle-beaver`: uses the same three-committee client/server/client shape as `shuffle-bgw-static`; the server committee generates Dumbo-MPC Beaver triples with unbatched BGW degree reduction, then evaluates the shuffle network online and opens the output.
  This baseline has not been migrated to the new sign-selector `BatchRandBit` path.

## 4. Outputs

Each run writes to:

```text
/opt/benchmark-distributed/<timestamp>_<protocol>_<exp>/...
```

For Figure 10 accumulation runs, each case also receives a validated
`fault_trace.json`. The repository deliberately does not generate a figure;
the archived raw logs, metadata, fault events, and progress events are the
inputs for external data export and plotting.

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

## 7. Trusted setup, one party per server

Run the authenticated four-server connectivity smoke and then the supplemental
Q=64 measurement with:

```bash
./run_trusted_setup_dist.sh --powers 2
./run_trusted_setup_dist.sh --powers 64
```

Each node independently verifies and serializes the public SRS. The analyzer
requires four equal canonical digests, one successful Continuum KZG smoke,
zero CURVE authentication anomalies, and zero pending protocol tasks. Results
are stored below `/opt/benchmark-distributed/trusted-setup-n4-q<Q>/`.
