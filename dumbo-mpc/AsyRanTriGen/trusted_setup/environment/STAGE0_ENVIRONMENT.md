# Stage-0 dependency and host record

Captured on 2026-08-10. This separates what upstream declares from what was
actually present on the local ARM host used for preliminary inspection. It is
an environment record, not yet the pinned deployment image for the formal WAN
experiment.

## Upstream-declared environment

The vendored `qsdh-py/Dockerfile` specifies:

- base image `python:3.7.13-slim`;
- NTL `11.3.2`, built with GMP and OpenMP;
- Rust `nightly` without a date pin;
- Python packages `cffi`, `Cython`, `gmpy2`, `psutil`, `pycrypto`, `pyzmq`,
  `zfec`, `uvloop`, `numpy`, and `reedsolo`, without version pins;
- the bundled `pairing/` Rust/Python extension.

The top-level `setup.py` declares Python `>=3.7` and the runtime dependencies
`gmpy2`, `zfec`, `pycrypto`, `cffi`, `psutil`, and `pyzmq`. Because most versions
and the Rust nightly are unpinned, the upstream Dockerfile is not by itself a
bit-for-bit dependency lock.

The bundled pairing binding declares:

- package/crate: `pypairing`;
- Cargo package version: `0.16.0`;
- licenses: MIT OR Apache-2.0;
- curve implementation: bundled BLS12-381 code;
- locally generated `pairing/Cargo.lock` SHA-256:
  `320d30537b4f32758025ad9107335d6a3546a22cb1e9cd18757cacee91982e7f`.

The upstream repository ignores `pairing/Cargo.lock`, so it is not part of the
locked Git snapshot. The isolated build regenerates it offline and refuses to
continue unless its digest matches the value above.

## Locally observed host and toolchain

```text
OS: Ubuntu 20.04.6 LTS (Focal Fossa)
kernel: Linux 6.10.14-linuxkit
architecture: aarch64, little endian
logical CPUs: 8
Python: 3.8.10
Rust: rustc 1.97.0-nightly (66da6cae1 2026-04-20)
Cargo: 1.97.0-nightly (7ecf0285e 2026-04-18)
Go: go1.20.14 linux/arm64
GCC/G++: 9.4.0
GNU Make: 4.2.1
CMake: 3.16.3
GNU ld/binutils: 2.34
OpenSSL: 1.1.1f
NTL development package: 11.4.3-1build1
GMP development package: 6.2.0 (Ubuntu epoch version 2:6.2.0+dfsg-4ubuntu0.1)
FLINT development package: 2.5.2-21build1
MPFR development package: 4.0.2-1
MPC development package: 1.1.0-1
libffi development package: 3.3-4
```

## Locally observed Python environment

The existing `/opt/venv/continuum` environment contained:

```text
Cython==0.29.36
cffi==1.17.1
gmpy2==2.2.2
numpy==1.24.4
psutil==7.2.2
pycryptodome==3.23.0
pypairing==0.1.0 (editable/local OptRanTriGen source)
pytest==8.3.5
pyzmq==27.1.0
reedsolo==1.7.0
setuptools-rust==1.8.1
uvloop==0.22.1
zfec==1.6.0.0 (installed from a temporary local source path)
```

`pycrypto` and `pytest-asyncio` were not installed in that environment.
`pycryptodome` provides the `Crypto` namespace but is not the exact package
declared by upstream. This discrepancy must be resolved in the standalone setup
environment rather than by changing Continuum's existing virtual environment.

## Preliminary local build artifacts (not vendored)

During source inspection, the upstream NTL and Rust extensions were compiled in
`/tmp/qsdh-py`. They were intentionally excluded from the source snapshot:

```text
adkg/ntl/_hbmpc_ntl_helpers.cpython-38-aarch64-linux-gnu.so
  sha256: 3a43e6f58d63f860790d79131c11dd11075db7ab22ecf24ddf5478e9da3acb34
pairing/pypairing/pypairing.so
  sha256: c4754aae0170a21d45df25ec7189c24f7e96baedb8b64cb830bb73a566bd68e3
```

The NTL extension dynamically links to the host GMP, C++ standard library,
OpenMP, libm, libc, and related runtime libraries. Stage 1 should create a
standalone reproducible build path inside `trusted_setup`; it must not replace
Continuum's existing `pypairing` or `kzg_ped_out.so`.
