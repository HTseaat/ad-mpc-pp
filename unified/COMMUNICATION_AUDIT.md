# Local linear communication audit

`measure_linear_communication.py` compares Continuum AggTrans and the AD-MPC
Figure 8 linear baseline without starting distributed workers.

The metric is **serialized application-payload bytes sent to remote parties**.
Self-send, CURVE readiness, ZeroMQ/TCP framing, committee election, input
distribution, and output reconstruction are excluded.

## Default comparison

```bash
python3 unified/measure_linear_communication.py
```

The default profile is the locally calibrated `n=4, t=1, B=100` case and the
default depth is `d=6`. Two distinct modes are printed:

- `implementation`: the current repository's observed serialized traffic;
- `paper`: a paper-faithful projection using canonical binary field/group
  sizes and the locally measured dissemination/control behavior.

The paper mode includes the AD-MPC `BatchRand + BatchBundle + ADTrans`
pipeline and restores Algorithm 4's per-item public fields. For Continuum it
broadcasts common data once instead of duplicating it inside every receiver's
private ciphertext.

The conservative default retransmits the old commitment vector `C^l`. To
treat it as an already-public cached input:

```bash
python3 unified/measure_linear_communication.py \
  --mode paper --old-commitments cached
```

## Machine-readable output

```bash
python3 unified/measure_linear_communication.py --mode paper --format json \
  --output /tmp/linear-communication.json

python3 unified/measure_linear_communication.py --mode paper --format csv \
  --output /tmp/linear-communication.csv
```

`--protocol continuum` and `--protocol admpc` restrict the output to one
protocol. `--depth` may be changed because it only repeats an identical
handoff.

The script deliberately rejects `n`, `t`, or `B` values that do not match the
selected calibration profile. Add a new profile with local payload/phase
measurements for another parameter set; do not extrapolate an exact-byte
result from the `n=4` control-message calibration.

The profile also pins SHA-256 hashes for the message builders, dissemination
code, serialization, and active AD-MPC driver. The command fails if those
sources changed, preventing a stale calibration from silently being reported
as current. `--allow-stale-calibration` is available for inspection only and
records in JSON that the source check was skipped.

The `implementation` per-transfer value is a local observed calibration. A
`d>1` total repeats that representative handoff; it is not a re-analysis of a
particular distributed trace.

## Calibration provenance

The default profile is
`unified/communication_models/linear_n4_t1_b100.json`. It contains raw phase
totals, per-dealer RBC payload lengths, per-receiver AVID ciphertext lengths,
canonical cryptographic element sizes, and source-code provenance. Reported
totals are derived from these entries rather than stored as expected final
answers.

## Figure 8 local communication runs

One committee size and one protocol can be measured per command with:

```bash
./unified/run_figure8_admpc_communication_local.sh \
  4 1 6 100 /opt/benchmark-local/<admpc-run-name>
./unified/run_figure8_noagg_communication_local.sh \
  4 1 6 100 /opt/benchmark-local/<noagg-run-name>
./unified/run_figure8_aggtrans_communication_local.sh \
  4 1 6 100 /opt/benchmark-local/<aggtrans-run-name>
```

The arguments are `<n> <t> <d> <w> <output_dir>`. The final JSON, CSV, and
Markdown reports are written below that command's output directory.

The local setup uses three layers for the main paths (one handoff). A
metrics-only completion barrier keeps fast nodes online until slow nodes
finish, and its tag is excluded from the reported communication. Client inputs
are distributed by quotient/remainder so the logical handoff batch remains
exactly `w` even when `n` does not divide `2w`.
