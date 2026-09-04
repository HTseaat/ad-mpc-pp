"""Generate one CURVE-authenticated trusted-setup config per remote node."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .config import NodeConfig, SetupParams
from .protocol.network import build_curve_transport_configs


def write_distributed_configs(
    params: SetupParams,
    peers: list[str],
    output_dir: Path,
    *,
    force: bool = False,
) -> tuple[Path, ...]:
    if len(peers) != params.n:
        raise ValueError("provide exactly one --peer per setup party")
    node_configs = [NodeConfig.create(params, party_id, peers) for party_id in range(params.n)]
    transport_configs = build_curve_transport_configs(params.run_id, params.n)
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = tuple(output_dir / f"local.{party_id}.json" for party_id in range(params.n))
    existing = [path for path in paths if path.exists()]
    if existing and not force:
        raise FileExistsError(f"refusing to overwrite {existing[0]}")
    for path, node_config, transport in zip(paths, node_configs, transport_configs):
        value = node_config.as_dict()
        value["transport"] = transport
        path.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return paths


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n", required=True, type=int)
    parser.add_argument("--t", required=True, type=int)
    parser.add_argument("--powers", required=True, type=int)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--peer", required=True, action="append")
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--force", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    params = SetupParams.create(args.n, args.t, args.powers, run_id=args.run_id)
    paths = write_distributed_configs(
        params, args.peer, args.output_dir, force=args.force
    )
    print(
        f"wrote {len(paths)} CURVE configs: n={params.n}, t={params.t}, "
        f"requested_powers={params.requested_powers}, run_id={params.run_id}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
