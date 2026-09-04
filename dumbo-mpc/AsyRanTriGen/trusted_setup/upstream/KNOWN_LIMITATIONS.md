# Upstream core-path review

This note records the stage-0 review of commit
`d30147a388586ab9712dd2834491f51954278a72`. Line references below are to the
unchanged snapshot in `qsdh-py/`.

## Path suitable for the planned benchmark

The upstream code has an explicit all-honest control path:

1. `adkg/adkg.py` runs ACSS and asynchronous common subset.
2. `adkg/randousha.py` extracts a shared random `tau` and random double shares.
3. `adkg/squaring.py` derives shares and commitments to powers of two.
4. `adkg/g2_powers.py` derives the G2 powers used for verification.
5. `adkg/all_powers.py` expands the G1 powers-of-two commitments to all powers.

This is the path that stage 1 will reproduce. Its existence does **not** make
the repository production-ready: the upstream README itself warns against
production use, and the paths below remain incomplete.

## Incomplete Byzantine and fallback behavior

| Area | Upstream marker | Consequence for this project |
| --- | --- | --- |
| ACSS implication | `adkg/acss_ht.py:85`, `:125` | The implicated ciphertext/RBC payload is replaced by `None`; malicious-dealer implication and share recovery are not a complete executable path. |
| ACSS binding | `adkg/acss_ht.py:317` | A hash-matching check is left as a TODO. This needs review before claiming malicious robustness of the implementation. |
| Random double sharing | `adkg/randousha.py:116` | A correction is applied to shares without the corresponding commitment update. The honest path must be tested algebraically; adversarial use is out of scope. |
| Reconstruction validation | `adkg/randousha.py:168-170` | Reconstructed values are not checked and OEC handling is not implemented. |
| Failed consistency checks | `adkg/randousha.py:265` | There is no fallback when the low/high commitment consistency assertion fails. An adversarial run may abort or block instead of recovering. |
| Optimized reliable broadcast | `adkg/broadcast/optqrbc.py:158` | The leader/committed-hash termination condition is explicitly marked for rechecking. The production protocol must not rely on this unreviewed path. |
| Agreement failures | `adkg/broadcast/tylerba.py:202`, `:238`, `:266`, `:302` | Several invalid-message branches deliberately raise while their final handling is marked FIXME. |
| Task termination | top-level `README.md` TODO | Some broadcast tasks are known not to terminate cleanly. Stage 1 must explicitly cancel and await local tasks. |

These limitations are why the first measurement is expressly an all-honest
ceremony benchmark. It must not be presented as an experimental evaluation of
Byzantine fallback, guaranteed termination under faults, or production
hardening.

## Structural limitations relevant to adaptation

- `adkg/utils/poly_misc.py:13` requires the transform size (and therefore the
  current participant-count path) to be a power of two. The official `n=16`
  experiment satisfies this; arbitrary `n` is a later optional stage.
- `logq` is used directly throughout the code and `q=2**logq` is set in
  `adkg/adkg.py:34`. Stage 2 must centralize the external `Q` meaning rather than
  silently inheriting this convention.
- `adkg/run_adkg` computes `g2powers` but its public output at
  `adkg/adkg.py:348` omits them. Stage 3 must export `g2` and `[tau]g2`
  explicitly.
- The upstream output contains only one all-powers G1 chain. Continuum needs two
  G1 chains with the same hidden exponent and independent public bases; that is
  deliberately deferred until after the original single-chain path works.
- There is no Continuum SRS serialization or runner integration in the upstream
  implementation. The planned experiment will remain standalone.

## Lower-priority TODOs

The core modules also contain performance and engineering TODOs (FFT/NTT
optimizations, more specific exceptions, proof batching, transcript cleanup,
and cache handling). They may affect speed or code quality, but they do not by
themselves define the all-honest stage-1 path. The complete markers remain
searchable with:

```bash
rg -n 'TODO|FIXME|XXX|NotImplemented' upstream/qsdh-py/adkg
```
