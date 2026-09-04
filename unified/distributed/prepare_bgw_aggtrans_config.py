#!/usr/bin/env python3
"""Retarget an architecture-compatible Continuum config to a new inventory."""

import argparse
import json
import os
from pathlib import Path


CURVE_FIELDS = (
    "curve_public_key",
    "curve_secret_key",
    "curve_public_keys",
    "curve_zap_domain",
)


def numbered_config_files(config_dir: Path):
    return sorted(
        config_dir.glob("local.*.json"),
        key=lambda path: int(path.stem.split(".")[1]),
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config-dir", type=Path, required=True)
    parser.add_argument("--ip-file", type=Path, required=True)
    parser.add_argument("--n", type=int, required=True)
    parser.add_argument("--t", type=int, required=True)
    parser.add_argument("--layers", type=int, required=True)
    parser.add_argument("--total-cm", type=int, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--auth-mode", choices=("null", "curve"), default="null")
    args = parser.parse_args()

    ips = [line.strip() for line in args.ip_file.read_text().splitlines() if line.strip()]
    if len(ips) != args.n or len(set(ips)) != args.n:
        raise SystemExit(
            f"Expected {args.n} unique IPs in {args.ip_file}, found {len(ips)}"
        )

    files = numbered_config_files(args.config_dir)
    expected_files = args.n * args.layers
    if len(files) != expected_files:
        raise SystemExit(
            f"Expected {expected_files} configs in {args.config_dir}, found {len(files)}"
        )

    peers = [
        f"{ip}:{7001 + layer_id}"
        for layer_id in range(args.layers)
        for ip in ips
    ]

    for global_id, path in enumerate(files):
        with path.open("r", encoding="utf-8") as handle:
            config = json.load(handle)

        expected = {
            "N": args.n,
            "t": args.t,
            "my_id": global_id % args.n,
            "my_send_id": global_id,
            "layers": args.layers,
            "total_cm": args.total_cm,
        }
        actual = {name: config.get(name) for name in expected}
        if actual != expected:
            raise SystemExit(f"Unexpected shape in {path}: {actual!r} != {expected!r}")

        config["peers"] = peers
        extra = config.get("extra")
        if not isinstance(extra, dict):
            raise SystemExit(f"Missing extra object in {path}")
        extra["run_id"] = args.run_id
        if args.auth_mode == "null":
            for field in CURVE_FIELDS:
                extra.pop(field, None)

        temporary = path.with_suffix(path.suffix + ".retarget.tmp")
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(config, handle, indent=4, ensure_ascii=False)
        os.replace(temporary, path)

    print(
        f"Prepared {len(files)} configs: N={args.n}, t={args.t}, "
        f"layers={args.layers}, total_cm={args.total_cm}, auth={args.auth_mode}, "
        f"first_ip={ips[0]}, last_ip={ips[-1]}, run_id={args.run_id}"
    )


if __name__ == "__main__":
    main()
