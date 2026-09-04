#!/usr/bin/env python3
"""Replace localhost election endpoints with the selected distributed peers."""

import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config-dir", required=True, type=Path)
    parser.add_argument("--ip-file", required=True, type=Path)
    parser.add_argument("--n", required=True, type=int)
    parser.add_argument("--base-port", required=True, type=int)
    args = parser.parse_args()

    ips = [line.strip() for line in args.ip_file.read_text().splitlines() if line.strip()]
    if len(ips) < args.n:
        raise ValueError(f"need {args.n} peer IPs, found {len(ips)}")
    ips = ips[: args.n]

    paths = [args.config_dir / f"local.{node_id}.json" for node_id in range(args.n)]
    missing = [str(path) for path in paths if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"missing election configs: {missing}")

    configs = [json.loads(path.read_text()) for path in paths]
    registry = configs[0]["extra"]["election_registry"]
    for candidate_index, candidate in enumerate(registry["candidates"]):
        for local_id, member in enumerate(candidate["members"]):
            member["endpoint_id"] = (
                f"{ips[local_id]}:{args.base_port + 1 + candidate_index}"
            )

    peers = [f"{ip}:{args.base_port}" for ip in ips]
    for path, config in zip(paths, configs):
        config["peers"] = peers
        config["extra"]["election_registry"] = registry
        path.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n")

    print(f"Added distributed endpoints to {len(paths)} election configs")


if __name__ == "__main__":
    main()
