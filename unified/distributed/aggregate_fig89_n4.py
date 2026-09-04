#!/usr/bin/env python3
"""Aggregate measured (not warm-up) Figure 8/9 n=4 case summaries."""

import argparse
from collections import defaultdict
import json
import math
from pathlib import Path
import statistics
import sys


EXPECTED = {
    ("exp1", "admpc"),
    ("exp1", "aggtrans-noagg"),
    ("exp1", "aggtrans-v2"),
    ("exp2", "admpc"),
    ("exp2", "bgw-aggtrans"),
    ("exp2", "batchmul-v2"),
}


class FigureAggregationError(ValueError):
    pass


def _distribution(values):
    values = list(values)
    return {
        "max": max(values),
        "mean": statistics.mean(values),
        "median": statistics.median(values),
        "min": min(values),
        "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
    }


def aggregate(root, repetitions):
    measured = Path(root) / "measured"
    groups = defaultdict(list)
    for path in sorted(measured.glob("round-*/*/*/summary.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        key = (record.get("experiment"), record.get("protocol_variant"))
        if key not in EXPECTED:
            raise FigureAggregationError(f"unexpected measured case {key} at {path}")
        if record.get("n") != 4 or record.get("depth") != 6 or record.get("process_count") != 32:
            raise FigureAggregationError(f"invalid n/depth/process count at {path}")
        groups[key].append((path, record))

    missing = sorted(EXPECTED - set(groups))
    extra_counts = {
        f"{experiment}:{variant}": len(records)
        for (experiment, variant), records in groups.items()
        if len(records) != repetitions
    }
    if missing:
        raise FigureAggregationError(f"missing result groups: {missing}")
    if extra_counts:
        raise FigureAggregationError(
            f"expected {repetitions} runs per group, got {extra_counts}"
        )

    cases = []
    election_totals = set()
    for key in sorted(groups):
        experiment, variant = key
        records = groups[key]
        core = [record["core_latency_seconds"] for _, record in records]
        combined = []
        for path, record in records:
            for value_name, value in (("core_latency_seconds", record["core_latency_seconds"]),):
                if not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
                    raise FigureAggregationError(f"invalid {value_name} at {path}")
            if "sequential_election_total_ms" not in record:
                raise FigureAggregationError(f"missing election overhead at {path}")
            election_totals.add(record["sequential_election_total_ms"])
            combined.append(record["total_with_sequential_election_seconds"])
        cases.append(
            {
                "experiment": experiment,
                "protocol_variant": variant,
                "run_count": len(records),
                "core_latency_seconds": _distribution(core),
                "total_with_sequential_election_seconds": _distribution(combined),
                "runs": [str(path.resolve()) for path, _ in records],
            }
        )
    if len(election_totals) != 1:
        raise FigureAggregationError("measured cases do not use one frozen election summary")
    return {
        "aggregation_schema_version": 1,
        "cases": cases,
        "n": 4,
        "repetitions": repetitions,
        "sequential_election_total_ms": next(iter(election_totals)),
    }


def _write_markdown(path, summary):
    lines = [
        "# Figure 8/9 n=4 preliminary results",
        "",
        f"Measured repetitions per variant: {summary['repetitions']}",
        "",
        "| Figure | Variant | Core median (s) | Core + elections median (s) |",
        "|---|---|---:|---:|",
    ]
    for case in summary["cases"]:
        figure = "Fig. 8" if case["experiment"] == "exp1" else "Fig. 9"
        lines.append(
            f"| {figure} | `{case['protocol_variant']}` | "
            f"{case['core_latency_seconds']['median']:.6f} | "
            f"{case['total_with_sequential_election_seconds']['median']:.6f} |"
        )
    lines.extend(
        (
            "",
            f"Sequential six-election overhead: {summary['sequential_election_total_ms']:.3f} ms.",
            "",
        )
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--repetitions", type=int, required=True)
    args = parser.parse_args()
    try:
        summary = aggregate(args.root, args.repetitions)
    except (FigureAggregationError, OSError, KeyError, ValueError, json.JSONDecodeError) as exc:
        print(f"Figure 8/9 aggregation failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
    root = Path(args.root)
    (root / "fig89_n4_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    _write_markdown(root / "fig89_n4_summary.md", summary)
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
