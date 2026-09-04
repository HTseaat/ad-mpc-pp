#!/usr/bin/env python3
"""Fail closed on malformed multi-layer MPC/CURVE configuration directories."""

import argparse
import json
from pathlib import Path
import sys

import zmq


CURVE_FIELDS = (
    "curve_public_key",
    "curve_public_keys",
    "curve_secret_key",
    "curve_zap_domain",
    "run_id",
)


class ConfigValidationError(ValueError):
    pass


def _load_ip_file(path):
    return [line.strip() for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def validate_config_dir(
    config_dir,
    *,
    n,
    layers,
    ip_file=None,
    require_curve=True,
    base_port=7001,
    port_layout="layer",
):
    root = Path(config_dir)
    if n <= 0 or layers <= 0:
        raise ConfigValidationError("n and layers must be positive")
    expected_count = n * layers
    expected_paths = [root / f"local.{global_id}.json" for global_id in range(expected_count)]
    missing = [str(path) for path in expected_paths if not path.is_file()]
    if missing:
        raise ConfigValidationError(f"missing {len(missing)} config(s), first={missing[0]}")
    unexpected = sorted(
        path.name
        for path in root.glob("local.*.json")
        if path not in set(expected_paths)
    )
    if unexpected:
        raise ConfigValidationError(f"unexpected stale config(s): {unexpected[:4]}")

    configs = [json.loads(path.read_text(encoding="utf-8")) for path in expected_paths]
    peers = configs[0].get("peers")
    if not isinstance(peers, list) or len(peers) != expected_count:
        raise ConfigValidationError(
            f"peers must contain {expected_count} global endpoints"
        )

    expected_ips = _load_ip_file(ip_file)[:n] if ip_file else None
    if expected_ips is not None and len(expected_ips) != n:
        raise ConfigValidationError(f"IP file has fewer than n={n} non-empty entries")

    run_ids = set()
    zap_domains = set()
    public_key_lists = set()
    own_public_keys = []
    for global_id, config in enumerate(configs):
        if config.get("N") != n or config.get("layers") != layers:
            raise ConfigValidationError(f"local.{global_id}.json has N/layers mismatch")
        if config.get("my_send_id") != global_id or config.get("my_id") != global_id % n:
            raise ConfigValidationError(f"local.{global_id}.json has identity mismatch")
        if config.get("peers") != peers:
            raise ConfigValidationError(f"local.{global_id}.json has a divergent peers list")

        if expected_ips is not None:
            endpoint = peers[global_id]
            try:
                host, port_text = endpoint.rsplit(":", 1)
                port = int(port_text)
            except (AttributeError, TypeError, ValueError) as exc:
                raise ConfigValidationError(f"invalid endpoint for global id {global_id}: {endpoint!r}") from exc
            expected_port = base_port if port_layout == "shared" else base_port + global_id // n
            if host != expected_ips[global_id % n] or port != expected_port:
                raise ConfigValidationError(
                    f"global id {global_id} maps to {endpoint}, expected "
                    f"{expected_ips[global_id % n]}:{expected_port}"
                )

        if not require_curve:
            continue
        extra = config.get("extra")
        if not isinstance(extra, dict):
            raise ConfigValidationError(f"local.{global_id}.json has no extra object")
        missing_curve = [field for field in CURVE_FIELDS if not extra.get(field)]
        if missing_curve:
            raise ConfigValidationError(
                f"local.{global_id}.json is missing CURVE field(s): {', '.join(missing_curve)}"
            )
        public_keys = extra["curve_public_keys"]
        if not isinstance(public_keys, list) or len(public_keys) != expected_count:
            raise ConfigValidationError(
                f"local.{global_id}.json has invalid curve_public_keys length"
            )
        if extra["curve_public_key"] != public_keys[global_id]:
            raise ConfigValidationError(f"local.{global_id}.json public key index mismatch")
        try:
            derived_public = zmq.curve_public(extra["curve_secret_key"].encode("ascii")).decode("ascii")
        except (AttributeError, UnicodeError, ValueError, zmq.ZMQError) as exc:
            raise ConfigValidationError(f"local.{global_id}.json has an invalid CURVE secret key") from exc
        if derived_public != extra["curve_public_key"]:
            raise ConfigValidationError(f"local.{global_id}.json CURVE keypair mismatch")
        run_ids.add(extra["run_id"])
        zap_domains.add(extra["curve_zap_domain"])
        public_key_lists.add(tuple(public_keys))
        own_public_keys.append(extra["curve_public_key"])

    if require_curve:
        if len(run_ids) != 1 or len(zap_domains) != 1 or len(public_key_lists) != 1:
            raise ConfigValidationError("CURVE run_id/domain/public-key allowlist diverges across configs")
        if len(set(own_public_keys)) != expected_count:
            raise ConfigValidationError("CURVE public keys are not unique per global process")

    return {
        "config_dir": str(root.resolve()),
        "curve_enabled": bool(require_curve),
        "endpoint_count": len(peers),
        "layers": layers,
        "n": n,
        "process_count": expected_count,
        "run_id": next(iter(run_ids)) if run_ids else None,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config-dir", required=True)
    parser.add_argument("--n", type=int, required=True)
    parser.add_argument("--layers", type=int, required=True)
    parser.add_argument("--ip-file")
    parser.add_argument("--auth-mode", choices=("curve", "null"), default="curve")
    parser.add_argument("--base-port", type=int, default=7001)
    parser.add_argument("--port-layout", choices=("layer", "shared"), default="layer")
    args = parser.parse_args()
    try:
        summary = validate_config_dir(
            args.config_dir,
            n=args.n,
            layers=args.layers,
            ip_file=args.ip_file,
            require_curve=args.auth_mode == "curve",
            base_port=args.base_port,
            port_layout=args.port_layout,
        )
    except (ConfigValidationError, OSError, json.JSONDecodeError) as exc:
        print(f"configuration validation failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
