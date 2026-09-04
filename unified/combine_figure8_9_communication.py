#!/usr/bin/env python3
"""Combine normalized Figure 8 and Figure 9 outputs into one final table."""

import argparse
import csv
import io
import json
from pathlib import Path


SCHEMA = "figure8-9-canonical-communication-v1"


class CombineError(ValueError):
    pass


def _require(condition, message):
    if not condition:
        raise CombineError(message)


def _load_summary(path, expected_figure):
    path = Path(path)
    if path.is_dir():
        final_path = path / "final" / "summary.json"
        path = final_path if final_path.is_file() else path / "summary.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    _require(document.get("experiment", {}).get("figure") == expected_figure,
             f"{path}: expected Figure {expected_figure} summary")
    _require("canonical_serialization" in document,
             f"{path}: canonical serialization metadata missing")
    return document, path.resolve()


def combine(figure8_path, figure9_path):
    figure8, resolved8 = _load_summary(figure8_path, 8)
    figure9, resolved9 = _load_summary(figure9_path, 9)
    profile8 = figure8["canonical_serialization"].get("profile")
    profile9 = figure9["canonical_serialization"].get("profile")
    _require(profile8 == profile9, "Figure 8/9 canonical profiles differ")
    _require(profile8, "canonical profile is empty")

    rows = []
    for document, unit in ((figure8, "sharing"), (figure9, "gate")):
        experiment = document["experiment"]
        for case in document["cases"]:
            for protocol, result in case["canonical"].items():
                rows.append({
                    "figure": int(experiment["figure"]),
                    "circuit": experiment["circuit"],
                    "n": int(case["n"]),
                    "t": int(case["t"]),
                    "adtrans_alg4_mode": case["adtrans_alg4_mode"],
                    "protocol": protocol,
                    "canonical_bytes_per_computation_layer": int(
                        result["canonical_bytes_per_computation_layer"]
                    ),
                    "normalization_unit": unit,
                    "canonical_bytes_per_unit": float(
                        result[f"canonical_bytes_per_{unit}"]
                    ),
                })
    rows.sort(key=lambda row: (row["figure"], row["n"], row["protocol"]))
    return {
        "schema": SCHEMA,
        "canonical_profile": profile8,
        "sources": {"figure8": str(resolved8), "figure9": str(resolved9)},
        "rows": rows,
    }


def render_csv(report):
    output = io.StringIO()
    fields = (
        "figure", "circuit", "n", "t", "adtrans_alg4_mode", "protocol",
        "canonical_bytes_per_computation_layer", "normalization_unit",
        "canonical_bytes_per_unit",
    )
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    writer.writerows(report["rows"])
    return output.getvalue()


def render_markdown(report):
    lines = [
        "# Figure 8/9 canonical communication",
        "",
        f"Canonical profile: `{report['canonical_profile']}`.",
        "",
        "| figure | circuit | n | t | ADTrans mode | protocol | canonical B/layer | unit | B/unit |",
        "|---:|:---|---:|---:|:---|:---|---:|:---|---:|",
    ]
    for row in report["rows"]:
        lines.append(
            "| {figure} | {circuit} | {n} | {t} | {mode} | {protocol} | "
            "{layer:,} | {unit} | {per_unit:,.2f} |".format(
                figure=row["figure"], circuit=row["circuit"], n=row["n"],
                t=row["t"], mode=row["adtrans_alg4_mode"],
                protocol=row["protocol"],
                layer=row["canonical_bytes_per_computation_layer"],
                unit=row["normalization_unit"],
                per_unit=row["canonical_bytes_per_unit"],
            )
        )
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("figure8")
    parser.add_argument("figure9")
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args(argv)
    try:
        report = combine(args.figure8, args.figure9)
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "summary.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (output_dir / "summary.csv").write_text(
            render_csv(report), encoding="utf-8"
        )
        markdown = render_markdown(report)
        (output_dir / "summary.md").write_text(markdown, encoding="utf-8")
    except (OSError, ValueError) as exc:
        parser.exit(2, f"canonical communication merge failed: {exc}\n")
    print(markdown, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
