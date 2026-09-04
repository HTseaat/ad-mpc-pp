# Trusted setup standalone experiment

This directory contains the standalone implementation and measurement work for
the one-time Continuum trusted-setup experiment. It is deliberately isolated
from the current Continuum execution path.

## Stage status

- Stage 0 (upstream snapshot and environment baseline): complete.
- Stage 1 (upstream all-honest single G1 chain): complete.
- Stage 2 (canonical parameters, CLI, and fail-closed node configs): complete.
- Stage 3 (explicit `g2`/`[tau]g2` export and pairing checks): complete.
- Stage 4 (h-based powers-of-two commitments and DLEQ links): complete.
- Stage 5 (independently tagged second `ALL_POWERS(h)` chain): complete.
- Stage 6 (canonical compressed SRS file and digest): complete.
- Stage 7 (output signatures and state-release hardening): deferred.
- Stage 8 (standalone Continuum Go KZG compatibility smoke): complete.
- Stage 9 (structured timing and communication instrumentation): complete.
- Stage 10 (formal n=16 local pilot): deferred.
- Stage 11: the supplemental n=4 WAN path and one Q=64 diagnostic are
  complete; the repeated formal n=16 WAN campaign remains deferred.

In particular, nothing under this directory is imported by
`scripts/run_key_gen.py`, `scripts/run_key_gen_dyn.py`, or the Continuum local
runner. The CRS currently used by Continuum is unchanged; the future CRS
generated here will initially be used only for a standalone ceremony benchmark
and compatibility smoke test.

The runner can now optionally write a standalone public CRS artifact and a
structured benchmark record. It still does not import that artifact into
Continuum or change any current Continuum configuration.

## Four-server runner

The distributed path runs exactly one party per physical server over a
run-scoped, allowlisted ZeroMQ CURVE channel. Each party performs public
pairing/DLEQ checks and writes the canonical SRS independently. The controller
compares all four SRS digests; it never collects the parties' scalar shares.

From the controller workspace, run the small connectivity smoke test with:

```bash
/opt/unified/distributed/run_trusted_setup_dist.sh --powers 2
```

Use `--powers 64` for the n=4 measurement after the smoke test succeeds. The
distributed n=4 result is supplemental; the planned paper configuration is
still n=16, t=5, Q=64.

## Stage 0 contents

- `upstream/qsdh-py/`: clean snapshot of the tracked files at the selected
  upstream commit. It contains no `.git` directory or locally compiled objects.
- `upstream/SOURCE.lock.json`: source URL, commit, Git tree, license, and
  snapshot digest.
- `upstream/KNOWN_LIMITATIONS.md`: review of the core honest path and incomplete
  Byzantine/fallback paths that affect how results may be described.
- `environment/STAGE0_ENVIRONMENT.md`: upstream-declared and locally observed
  dependency versions.
- `baseline/continuum-protected-files.sha256`: point-in-time hashes of the
  current Continuum SRS generator, runners, and the `n=16` configs.
- `scripts/verify_stage0.py`: standard-library-only integrity checker.

## Build and run stages 1--6, 8, and 9

Build native dependencies in the disposable, ignored working copy:

```bash
cd /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen
bash trusted_setup/scripts/build_upstream.sh --clean
```

Run one local all-honest committee directly from parameters:

```bash
/opt/venv/admpc/bin/python -m trusted_setup.run_local \
  --n 16 --t 5 --powers 8 --run-id local-n16
```

Here `--powers` is the number of G1 elements requested. It is rounded up to a
power of two exactly once by `SetupParams`; both requested and effective values
are printed. The current NTT path also requires `n` to be a power of two.
The eventual experiment should use `Q=64`; `Q=32` is also a sufficient smaller
choice. There is no need to use `Q=1024`.

Generate an SRS file, structured metrics, and run the standalone compatibility
check against Continuum's actual Go `kzg_ped` package:

```bash
/opt/venv/admpc/bin/python -m trusted_setup.run_local \
  --n 16 --t 5 --powers 64 --run-id setup-n16-q64 \
  --output-srs trusted_setup/output/setup-n16-q64.json \
  --metrics-output trusted_setup/output/setup-n16-q64.metrics.json \
  --kzg-smoke
```

`--kzg-smoke` is optional and requires `--output-srs`. It validates the Python
artifact digest first, then imports the chains into the same local gnark-crypto
`kzg_ped` source used to build Continuum's shared library. The first Go run may
need the dependencies already pinned by that module's `go.mod`/`go.sum`.

Node configurations can be generated and checked before protocol startup:

```bash
/opt/venv/admpc/bin/python -m trusted_setup.generate_config \
  --n 16 --t 5 --powers 8 --run-id local-n16 \
  --output-dir /tmp/trusted-setup-n16

/opt/venv/admpc/bin/python -m trusted_setup.run_local \
  --config-dir /tmp/trusted-setup-n16
```

Run the complete current regression suite (stage 7 intentionally excluded):

```bash
bash trusted_setup/scripts/test_stages_1_9.sh
```

The test matrix covers `(n,t,Q)=(4,1,2),(8,2,4),(16,5,8)`, reconstructs the
hidden scalar in the test harness, checks every G1 element, checks the exported
G2 element, and verifies every pairing recurrence. Dedicated stage-4 tests also
check the canonical public bases, every domain-separated Chaum--Pedersen link,
complete `t_commits_h` agreement, H/proof tampering, transcript index binding,
and protocol-task cleanup. Stage-5 tests check complete g/h chains, agreement at
every party, both pairing recurrences, distinct `AP_G`/`AP_H` routes, h-chain
tampering, and an h-chain constructed with a different alpha. The old
`test_stages_1_3.sh`, `test_stages_1_4.sh`, and `test_stages_1_5.sh` commands
remain compatibility aliases to this suite.

Stage-6/8/9 tests additionally cover requested/effective truncation, canonical
round trips and digest tampering, cross-party digest agreement, direct
Continuum Go KZG commit/open/verify, value/proof/CRS corruption, phase timing,
and transport-compatible per-party communication records.

The stage-4 protocol lives in `protocol/base_link.py`. It uses the binding's
standard `G1()`/`G2()` generators and derives h with
`G1.hash(b"Continuum/KZG-Pedersen/h/v1")`. That legacy binding maps a
SHA-256-derived deterministic stream to a subgroup point; it does not expose a
scalar relation between g and h. The DLEQ Fiat--Shamir transcript separately
binds the `BASE_LINK` domain, run ID, party ID, power index, bases, statements,
and nonce commitments.

The stage-5 adapter in `protocol/dual_chain.py` leaves upstream code unchanged.
The original g-chain runs below the outer `AP_G` route; after `BASE_LINK`
finishes, the h-chain runs below `AP_H`, reusing the same scalar shares,
verified `t_commits_h`, and G2 powers. The implementation runs the chains
sequentially and reports separate g/h all-powers timing fields.

Stage 6 stores compressed G1/G2 points as Base64 in
`continuum-kzg-srs-v1`, and hashes a canonical public-only payload. Stage 9
counts the same pickled remote payload used by upstream's real ZMQ transport;
self-sends and ZMQ/TCP framing are excluded and this scope is written into each
metrics file. `protocol_elapsed_seconds` covers the ceremony protocol, while
`end_to_end_elapsed_seconds` additionally covers final verification and SRS
serialization. The external Go smoke time is reported separately.

The complete current suite has 25 tests. Local timings and the current single
n=4 WAN run are diagnostic only, not the repeated formal n=16 result to quote
as the paper's primary trusted-setup measurement.

## Verify the stage-0 baseline

Run from any directory:

```bash
python3 /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/trusted_setup/scripts/verify_stage0.py
```

The source check is permanent. The protected-file check is intentionally a
point-in-time baseline: a later, intentional Continuum key-generation run may
rewrite `conf/mpc_16/local.*.json`, in which case those config mismatches should
be reviewed rather than hidden by refreshing the baseline.

To verify only the immutable upstream snapshot:

```bash
python3 /opt/dumbo-mpc/dumbo-mpc/AsyRanTriGen/trusted_setup/scripts/verify_stage0.py --source-only
```

## Licensing boundary

The vendored `qsdh-py` snapshot is GPLv3 software and retains its original
license. Future changes derived from that source must remain clearly marked and
handled under the applicable license. No license claim is made here for the
surrounding repository.

The stages 1--5 adapter invokes and follows the structure of that GPLv3
implementation and should be handled under the same licensing boundary.
