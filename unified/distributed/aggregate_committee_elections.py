#!/usr/bin/env python3
"""Aggregate six standalone election measurements as sequential layer cost."""

import argparse
import json
import math
from pathlib import Path
import sys


class ElectionAggregationError(ValueError):
    pass


def aggregate(session_dir, *, first_epoch=2, count=6, expected_n=None, expected_t=None):
    root = Path(session_dir)
    measurements = []
    run_ids = set()
    for charged_epoch in range(first_epoch, first_epoch + count):
        path = root / f"epoch-{charged_epoch}" / "summary.json"
        if not path.is_file():
            raise ElectionAggregationError(f"missing election summary: {path}")
        record = json.loads(path.read_text(encoding="utf-8"))
        completion_ms = record.get("protocol_completion_ms")
        if (
            isinstance(completion_ms, bool)
            or not isinstance(completion_ms, (int, float))
            or not math.isfinite(completion_ms)
            or completion_ms < 0
        ):
            raise ElectionAggregationError(f"invalid protocol_completion_ms in {path}")
        record_n = record.get("n")
        record_t = record.get("t")
        if expected_n is None:
            expected_n = record_n
        if expected_t is None:
            expected_t = record_t
        if record_n != expected_n or record_t != expected_t or record.get("node_count") != expected_n:
            raise ElectionAggregationError(f"unexpected n/t/node_count in {path}")
        run_id = record.get("run_id")
        if not run_id or run_id in run_ids:
            raise ElectionAggregationError("each election measurement must have a unique run_id")
        run_ids.add(run_id)
        measurements.append(
            {
                "charged_target_epoch": charged_epoch,
                "committee_id": record["committee_id"],
                "protocol_completion_ms": completion_ms,
                "protocol_target_epoch": record["target_epoch"],
                "run_id": run_id,
                "summary": str(path.resolve()),
            }
        )
    return {
        "aggregation_schema_version": 1,
        "charging_model": f"{count} real elections charged sequentially before handoff",
        "election_count": count,
        "measurements": measurements,
        "n": expected_n,
        "sequential_election_total_ms": sum(
            item["protocol_completion_ms"] for item in measurements
        ),
        "t": expected_t,
    }


def _write_markdown(path, summary):
    lines = [
        "# Sequential committee-election overhead",
        "",
        "| Charged epoch | Election latency (ms) | Selected committee |",
        "|---:|---:|---|",
    ]
    for item in summary["measurements"]:
        lines.append(
            f"| {item['charged_target_epoch']} | {item['protocol_completion_ms']:.3f} | "
            f"`{item['committee_id']}` |"
        )
    lines.extend(
        (
            f"| **Sequential total** | **{summary['sequential_election_total_ms']:.3f}** | |",
            "",
            f"Each measurement is a real {summary['n']}-party authenticated election. The "
            "benchmark module labels its internal protocol context as target epoch 2; the "
            "`charged_target_epoch` column records where that independently measured cost is added.",
            "",
        )
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--session-dir", required=True)
    parser.add_argument("--first-epoch", type=int, default=2)
    parser.add_argument("--count", type=int, default=6)
    parser.add_argument("--expected-n", type=int)
    parser.add_argument("--expected-t", type=int)
    parser.add_argument("--output")
    parser.add_argument("--markdown")
    args = parser.parse_args()
    output = Path(args.output) if args.output else Path(args.session_dir) / "election_summary.json"
    markdown = Path(args.markdown) if args.markdown else Path(args.session_dir) / "election_summary.md"
    try:
        summary = aggregate(
            args.session_dir, first_epoch=args.first_epoch, count=args.count,
            expected_n=args.expected_n, expected_t=args.expected_t
        )
    except (ElectionAggregationError, OSError, KeyError, ValueError, json.JSONDecodeError) as exc:
        print(f"election aggregation failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
    output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _write_markdown(markdown, summary)
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
