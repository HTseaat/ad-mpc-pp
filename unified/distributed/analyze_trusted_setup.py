#!/usr/bin/env python3
"""Validate and aggregate one distributed trusted-setup execution."""

from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path


EXPECTED_FORMAT = "continuum-trusted-setup-distributed-node-v1"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", required=True, type=Path)
    parser.add_argument("--expected-n", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def analyze(input_dir: Path, expected_n: int) -> dict:
    paths = sorted(input_dir.glob("node-*.metrics.json"))
    if len(paths) != expected_n:
        raise ValueError(f"expected {expected_n} metrics files, found {len(paths)}")
    records = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
    if any(record.get("format") != EXPECTED_FORMAT for record in records):
        raise ValueError("unexpected distributed metrics format")
    party_ids = [record.get("party_id") for record in records]
    if sorted(party_ids) != list(range(expected_n)):
        raise ValueError(f"party IDs are incomplete or duplicated: {party_ids}")
    records.sort(key=lambda record: record["party_id"])
    party_ids = [record["party_id"] for record in records]
    if not all(record.get("success") is True for record in records):
        raise ValueError("one or more setup parties reported failure")
    params_json = {
        json.dumps(record["params"], sort_keys=True) for record in records
    }
    if len(params_json) != 1:
        raise ValueError("setup parameters disagree across parties")
    digests = {record["artifact"]["digest"] for record in records}
    sizes = {record["artifact"]["size_bytes"] for record in records}
    if len(digests) != 1 or len(sizes) != 1:
        raise ValueError("canonical SRS outputs disagree across parties")
    transport_digests = {
        record["transport"]["transport_digest"] for record in records
    }
    if len(transport_digests) != 1:
        raise ValueError("transport registry digest disagrees across parties")
    for record in records:
        transport = record["transport"]
        if any(
            transport[name] != 0
            for name in (
                "curve_denied_count",
                "invalid_auth_metadata_count",
                "identity_spoofing_count",
            )
        ):
            raise ValueError(f"CURVE authentication anomaly at party {record['party_id']}")
        if record["pending_protocol_tasks"] != 0:
            raise ValueError(f"pending protocol tasks at party {record['party_id']}")
        if not all(record["verification"].values()):
            raise ValueError(f"public verification failed at party {record['party_id']}")

    protocol_times = [record["protocol_elapsed_seconds"] for record in records]
    end_to_end_times = [record["end_to_end_elapsed_seconds"] for record in records]
    communication = [
        record["transport"]["total_remote_payload_bytes"] for record in records
    ]
    channel_setup_times = [
        record["transport"]["channel_setup_seconds"] for record in records
    ]
    phase_names = sorted(records[0]["phase_seconds"])
    phase_max = {
        name: max(
            value
            for value in (record["phase_seconds"][name] for record in records)
            if value is not None
        )
        if any(record["phase_seconds"][name] is not None for record in records)
        else None
        for name in phase_names
    }
    kzg_records = [
        record["continuum_kzg_smoke"]
        for record in records
        if record["continuum_kzg_smoke"] is not None
    ]
    if len(kzg_records) != 1 or not kzg_records[0].get("ok"):
        raise ValueError("expected exactly one successful Continuum KZG smoke check")
    return {
        "format": "continuum-trusted-setup-distributed-summary-v1",
        "success": True,
        "params": records[0]["params"],
        "party_ids": sorted(party_ids),
        "artifact": {
            "digest": next(iter(digests)),
            "size_bytes": next(iter(sizes)),
            "all_parties_equal": True,
        },
        "protocol_elapsed_seconds": {
            "per_party": protocol_times,
            "max": max(protocol_times),
            "median": statistics.median(protocol_times),
        },
        "end_to_end_elapsed_seconds": {
            "per_party": end_to_end_times,
            "max": max(end_to_end_times),
            "median": statistics.median(end_to_end_times),
        },
        "channel_setup_seconds": {
            "per_party": channel_setup_times,
            "max": max(channel_setup_times),
            "median": statistics.median(channel_setup_times),
        },
        "phase_seconds_max": phase_max,
        "communication": {
            "sent_bytes_per_party": communication,
            "sent_bytes_median": statistics.median(communication),
            "sent_bytes_max": max(communication),
        },
        "curve_authentication_anomalies": 0,
        "continuum_kzg_smoke": kzg_records[0],
        "transport_digest": next(iter(transport_digests)),
    }


def main() -> int:
    args = parse_args()
    summary = analyze(args.input_dir, args.expected_n)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
