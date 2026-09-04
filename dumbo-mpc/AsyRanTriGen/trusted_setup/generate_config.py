"""Generate consistent local node configurations for the standalone setup."""

from __future__ import annotations

import argparse
from pathlib import Path

from .config import SetupParams, write_local_configs


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n", required=True, type=int)
    parser.add_argument("--t", required=True, type=int)
    parser.add_argument("--powers", required=True, type=int)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--base-port", default=17000, type=int)
    parser.add_argument("--force", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    params = SetupParams.create(
        args.n, args.t, args.powers, run_id=args.run_id
    )
    paths = write_local_configs(
        params,
        args.output_dir,
        host=args.host,
        base_port=args.base_port,
        force=args.force,
    )
    print(
        f"wrote {len(paths)} configs: n={params.n}, t={params.t}, "
        f"requested_powers={params.requested_powers}, "
        f"effective_powers={params.effective_powers}, log_q={params.log_q}, "
        f"run_id={params.run_id}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

