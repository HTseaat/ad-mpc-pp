# Continuum non-integration baseline

`continuum-protected-files.sha256` records the files that stage 0 promises not
to modify:

- current KZG-Pedersen source and shared libraries;
- current key-generation and local runner scripts;
- the unified Continuum runner;
- the existing `n=16` local configuration files.

Paths are relative to `/opt`, which is also derived by the verification script
from the trusted-setup directory location. No trusted-setup output is referenced
by any of these files.

The config hashes are a point-in-time audit record. Normal execution of the
existing key generator may intentionally refresh those files. Such a change
does not imply trusted-setup integration, but it should be reviewed before this
baseline is deliberately updated.

On 2026-08-10, an in-memory call to the unchanged `pyNewSRS(1)` entry point
returned JSON containing both `Pk` and `Vk`; the shared-library hash remained
`760dc67d8b4c6000d991f332bdfc82807cc3ad108ebd7382310b9a1d137723b8`
before and after the call. No config or CRS file was written by this check.
