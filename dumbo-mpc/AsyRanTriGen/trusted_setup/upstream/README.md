# qsdh-py upstream snapshot

This is a clean source snapshot used as the starting point for the standalone
Powers-of-Tau experiment.

- Upstream: `https://github.com/sourav1547/qsdh-py.git`
- Commit: `d30147a388586ab9712dd2834491f51954278a72`
- Git tree: `7b1372fe0a4c2129e47776bf969df1da50f6d6ba`
- Commit date: `2022-11-30T00:01:18-08:00`
- Commit subject: `eval data`
- Upstream package version: `0.0.0.dev`
- Top-level license: GNU General Public License v3.0

The snapshot was produced from Git-tracked files only. In particular, it does
not contain the local NTL-generated C++ file, Python extension, Rust extension,
`.pytest_cache`, or `.git` metadata that existed in the temporary inspection
checkout.

Equivalent reproduction procedure:

```bash
git clone https://github.com/sourav1547/qsdh-py.git
git -C qsdh-py checkout d30147a388586ab9712dd2834491f51954278a72
git -C qsdh-py archive --format=tar d30147a388586ab9712dd2834491f51954278a72
```

For the canonical `git archive` byte stream, the SHA-256 digest is
`09acd95547ad399d2938a3eea07b5ecd9cf107005ed6fe26d0e90cb02d04077c`.
The extracted snapshot has a separate, platform-independent manifest digest in
`SOURCE.lock.json`; verify it with `../scripts/verify_stage0.py --source-only`.

The upstream README explicitly labels the repository a research implementation
that may contain security issues and should not be used in production. Our use
is correspondingly limited to an all-honest, one-time setup-cost experiment;
see `KNOWN_LIMITATIONS.md` before interpreting or extending it.

