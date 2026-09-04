# Figure 8/9 canonical communication

These local experiments measure sender-side application communication for one
representative computation layer. Figure 8 uses an all-linear layer with
`B=w` (the paper uses `B=100`); Figure 9 uses an all-multiplication layer with
`M=w` (the paper uses `M=100`). The runners select protocol tags for the
computation layer and exclude client input distribution and final output
reconstruction.

The experiments do not alter the protocol transport or cryptographic data
path. They enable metrics, run the existing protocol entry points, and then
normalize both implementations under the shared
`bls12-381-fr32-g1-48-v1` accounting profile.

## Run Figure 8

From `/opt`:

```bash
./unified/run_figure8_admpc_communication_local.sh \
  4 1 6 100 /opt/benchmark-local/fig8-admpc
./unified/run_figure8_noagg_communication_local.sh \
  4 1 6 100 /opt/benchmark-local/fig8-noagg
./unified/run_figure8_aggtrans_communication_local.sh \
  4 1 6 100 /opt/benchmark-local/fig8-aggtrans
```

The cases are:

- AD-MPC linear: integrated BatchBundle/RandGen plus ADTrans;
- Continuum AggTrans;
- Continuum AggTrans-NoAgg.

Standalone BatchRand is deliberately not run or added to Figure 8.

## Run Figure 9

```bash
./unified/run_figure9_admpc_communication_local.sh \
  4 1 6 100 /opt/benchmark-local/fig9-admpc
./unified/run_figure9_batchmul_communication_local.sh \
  4 1 6 100 /opt/benchmark-local/fig9-batchmul
./unified/run_figure9_bgw_aggtrans_communication_local.sh \
  4 1 6 100 /opt/benchmark-local/fig9-bgw-aggtrans
```

The cases are:

- AD-MPC nonlinear: integrated RandGen, ADPrep (including its nested
  BatchRand), Exec, and ADTrans;
- Continuum BatchMul;
- BGW followed by AggTrans.

No standalone BatchRand measurement is added after the integrated AD-MPC run.

Each Figure 8 and Figure 9 runner measures one user-selected `(n,t,d,w)`
configuration.

## Output

Each protocol run writes raw per-process artifacts and per-case analyses. The
`final` directory contains:

- `summary.csv`: canonical bytes per computation layer and per sharing/gate;
- `summary.json`: the same comparable values plus experiment metadata;
- `summary.md`: a human-readable table;
- `normalization_audit.json`: hashes, completeness checks, and the measured
  calibration terms used by the normalizer.

The public summary files do not show a second native/pickle result. Native
lengths remain only in raw/audit artifacts so the canonical conversion can be
reproduced and checked.

The Figure 8 and Figure 9 protocol summaries remain separate.
