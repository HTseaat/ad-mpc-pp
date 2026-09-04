"""Run a standalone smoke test against Continuum's actual Go kzg_ped code."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

from .serialization import load_srs


TRUSTED_SETUP_ROOT = Path(__file__).resolve().parent
GO_SOURCE = TRUSTED_SETUP_ROOT / "continuum_kzg_smoke.go"
GO_BINARY = TRUSTED_SETUP_ROOT / "continuum_kzg_smoke"
GNARK_MODULE = TRUSTED_SETUP_ROOT.parents[2] / "gnark-crypto" / "kzg_ped_bls12-381"


def run_kzg_smoke(path: Path | str, *, timeout_seconds: float = 120.0) -> dict[str, Any]:
    source = Path(path).resolve()
    record = load_srs(source)
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    if not GNARK_MODULE.is_dir():
        raise RuntimeError(f"Continuum gnark module is missing: {GNARK_MODULE}")

    environment = os.environ.copy()
    environment["GOWORK"] = "off"
    started = time.perf_counter()
    command = (
        [str(GO_BINARY), "--srs", str(source)]
        if GO_BINARY.is_file() and os.access(GO_BINARY, os.X_OK)
        else ["go", "run", str(GO_SOURCE), "--srs", str(source)]
    )
    completed = subprocess.run(
        command,
        cwd=GNARK_MODULE,
        env=environment,
        text=True,
        capture_output=True,
        timeout=timeout_seconds,
        check=False,
    )
    elapsed = time.perf_counter() - started
    if completed.returncode != 0:
        raise RuntimeError(
            "Continuum Go KZG smoke test failed: "
            + (completed.stderr.strip() or completed.stdout.strip())
        )
    try:
        result = json.loads(completed.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as exc:
        raise RuntimeError("Go KZG smoke test returned invalid JSON") from exc
    if not result.get("ok"):
        raise RuntimeError(f"Continuum Go KZG checks failed: {result}")
    result["elapsed_seconds"] = elapsed
    result["srs_digest"] = record.digest
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--srs", required=True, type=Path)
    parser.add_argument("--timeout", default=120.0, type=float)
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = run_kzg_smoke(args.srs, timeout_seconds=args.timeout)
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(
            "Continuum Go KZG smoke: PASS "
            f"(powers={result['requested_powers']}, "
            f"coefficients={result['polynomial_coefficient_count']}, "
            f"elapsed={result['elapsed_seconds']:.6f}s)"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
