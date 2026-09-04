#!/usr/bin/env python3
"""Generate one CURVE identity per global AD-MPC transport process."""

import argparse
import json
import os
import uuid

import zmq


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--parties", required=True, type=int)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    if args.parties <= 0:
        parser.error("--parties must be positive")

    keypairs = [zmq.curve_keypair() for _ in range(args.parties)]
    public_keys = [public.decode("ascii") for public, _ in keypairs]
    run_id = uuid.uuid4().hex
    zap_domain = f"admpc-{run_id}"
    os.makedirs(args.output_dir, exist_ok=True)

    for party_id, (public_key, secret_key) in enumerate(keypairs):
        config = {
            "curve_public_key": public_key.decode("ascii"),
            "curve_secret_key": secret_key.decode("ascii"),
            "curve_public_keys": public_keys,
            "curve_zap_domain": zap_domain,
            "run_id": run_id,
        }
        path = os.path.join(args.output_dir, f"local.{party_id}.json")
        with open(path, "w", encoding="utf-8") as config_file:
            json.dump(config, config_file, indent=2)

    print(
        f"Generated {args.parties} AD-MPC CURVE identities in "
        f"{args.output_dir} (run_id={run_id})"
    )


if __name__ == "__main__":
    main()
