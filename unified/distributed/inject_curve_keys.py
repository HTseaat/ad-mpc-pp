#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path

import zmq


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("config_dir", type=Path)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()

    files = sorted(
        args.config_dir.glob("local.*.json"),
        key=lambda path: int(path.stem.split(".")[1]),
    )
    if not files:
        raise SystemExit(f"No local.*.json files in {args.config_dir}")

    configs = []
    ids = []
    for path in files:
        with path.open("r", encoding="utf-8") as handle:
            config = json.load(handle)
        configs.append((path, config))
        ids.append(config["my_send_id"])

    expected_ids = list(range(len(files)))
    if ids != expected_ids:
        raise SystemExit("Config my_send_id values are not contiguous and ordered")

    keypairs = [zmq.curve_keypair() for _ in files]
    public_keys = [public.decode("ascii") for public, _ in keypairs]
    zap_domain = f"continuum-{args.run_id}"

    for global_id, (path, config) in enumerate(configs):
        extra = config["extra"]
        extra["run_id"] = args.run_id
        extra["curve_public_key"] = public_keys[global_id]
        extra["curve_secret_key"] = keypairs[global_id][1].decode("ascii")
        extra["curve_public_keys"] = public_keys
        extra["curve_zap_domain"] = zap_domain
        temporary = path.with_suffix(path.suffix + ".curve.tmp")
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(config, handle, indent=4, ensure_ascii=False)
        os.replace(temporary, path)

    print(
        f"Injected CURVE keys into {len(files)} configs; "
        f"run_id={args.run_id}; zap_domain={zap_domain}"
    )


if __name__ == "__main__":
    main()
