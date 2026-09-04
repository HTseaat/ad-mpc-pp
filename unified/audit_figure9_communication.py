#!/usr/bin/env python3
"""Fail-closed audit for a canonical local Figure 9 campaign."""

import argparse
import json
import re
from pathlib import Path

try:
    from unified.summarize_figure9_communication import (
        BATCH_SIZE,
        PARAMETERS,
        _analyze_case,
        _payload_calibration,
        _require,
        build_report,
        render_csv,
        render_markdown,
    )
except ModuleNotFoundError:
    from summarize_figure9_communication import (
        BATCH_SIZE,
        PARAMETERS,
        _analyze_case,
        _payload_calibration,
        _require,
        build_report,
        render_csv,
        render_markdown,
    )


SCHEMA = "figure9-canonical-communication-audit-v2"
FATAL_LOG_PATTERN = re.compile(r"Traceback|AssertionError|MemoryError|Killed")


def audit(campaign_root, circuit_depth=6):
    root = Path(campaign_root).resolve()
    case_checks = []
    for n, t in PARAMETERS:
        base = root / f"n{n}_t{t}"
        specifications = (
            ("admpc-nonlinear", "admpc-nonlinear", 3 * n),
            ("continuum-batchmul", "batchmul", 3 * n),
            ("bgw-aggtrans", "bgw-aggtrans", 3 * n),
        )
        loaded = {}
        for directory, variant, process_count in specifications:
            docs, summary, integrity = _analyze_case(
                base / directory, variant, process_count, n, t
            )
            loaded[directory] = (docs, summary)
            fatal_logs = []
            for log_path in sorted((base / directory / "logs").glob("*.log")):
                text = log_path.read_text(encoding="utf-8", errors="replace")
                finished = re.search(r"(?m)^Finished$", text)
                active_text = text[:finished.start()] if finished else text
                if FATAL_LOG_PATTERN.search(active_text):
                    fatal_logs.append(str(log_path))
            _require(not fatal_logs, f"fatal protocol logs: {fatal_logs}")
            case_checks.append({
                "n": n,
                "t": t,
                "case": directory,
                **integrity,
                "fatal_log_markers": False,
            })

        mul_docs, mul_summary = loaded["continuum-batchmul"]
        bgw_docs, bgw_summary = loaded["bgw-aggtrans"]
        mul_calibration = _payload_calibration(
            mul_docs, mul_summary["component_bytes"]["batchmul"],
            "batchmul", n, t, "dynamic", require_batch=True,
        )
        bgw_calibration = _payload_calibration(
            bgw_docs, bgw_summary["component_bytes"]["bgw"],
            "bgw", n, t, "static", require_batch=True,
        )
        _require(mul_calibration["factor_proof_bytes"] == 5050,
                 f"n={n}: BatchMul factor proof size mismatch")
        _require(bgw_calibration["product_proof_count"] == BATCH_SIZE,
                 f"n={n}: BGW product proof count mismatch")

    report, normalization_audit = build_report(root, circuit_depth)
    final_dir = root / "final"
    persisted_report = json.loads(
        (final_dir / "summary.json").read_text(encoding="utf-8")
    )
    persisted_normalization = json.loads(
        (final_dir / "normalization_audit.json").read_text(encoding="utf-8")
    )
    _require(persisted_report == report, "persisted canonical summary is stale")
    _require(persisted_normalization == normalization_audit,
             "persisted normalization audit is stale")
    _require(
        (final_dir / "summary.csv").read_text(encoding="utf-8").splitlines()
        == render_csv(report).splitlines(),
        "persisted canonical CSV is stale",
    )
    _require(
        (final_dir / "summary.md").read_text(encoding="utf-8")
        == render_markdown(report),
        "persisted canonical Markdown is stale",
    )
    _require(
        all(
            case["adtrans_alg4_mode"]
            == report["cases"][0]["adtrans_alg4_mode"]
            for case in report["cases"]
        ),
        "ADTrans mode differs between committee sizes",
    )
    return {
        "schema": SCHEMA,
        "campaign_root": str(root),
        "canonical_summary_verified": True,
        "standalone_batchrand_expected": False,
        "case_checks": case_checks,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign_root")
    parser.add_argument("--depth", type=int, default=6)
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    try:
        result = audit(args.campaign_root, args.depth)
    except (OSError, ValueError) as exc:
        parser.exit(2, f"figure9 communication audit failed: {exc}\n")
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
