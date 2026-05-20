#!/usr/bin/env python3
import argparse
import json
import re
import subprocess
import csv
from collections import defaultdict
from pathlib import Path


INPUT_PATTERNS = (
    re.compile(r"Starting Batch AVSS"),
    re.compile(r"Starting AVSS with shares_num"),
    re.compile(r"inputs_num:"),
    re.compile(r"Starting ACSS to share"),
)

TRANS_PATTERN = re.compile(r"layer ID:\s*(\d+)\s+trans_foll_time:\s*([\d\.eE+-]+)")
MUL_PATTERN = re.compile(r"layer ID:\s*(\d+)\s+mul_foll_time:\s*([\d\.eE+-]+)")
LAYER_PATTERN = re.compile(r"layer ID:\s*(\d+)\s+layer_time:\s*([\d\.eE+-]+)")
TRUSTED_PATTERN = re.compile(r"layer ID:\s*(\d+)\s+trusted_verification_time:\s*([\d\.eE+-]+)")
RECV_INPUT_PATTERN = re.compile(r"layer ID:\s*(\d+)\s+recv_input_time:\s*([\d\.eE+-]+)")
RECON_PATTERN = re.compile(r"layer ID:\s*(\d+)\s+reconstructed trans_values length:\s*(\d+)")

CONT_FILE_PATTERN = re.compile(r"node(\d+)_cont(\d+)\.log$")
DUMBO_NODE_PATTERN = re.compile(r"node(\d+)\.log$")
TIMESTAMP_PREFIX = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}\s+")


def read_lines(path: Path):
    return path.read_text(encoding="utf-8", errors="ignore").splitlines()


def strip_timestamp(line: str) -> str:
    return TIMESTAMP_PREFIX.sub("", line)


def find_case_log_dir(case_dir: Path) -> Path:
    logs_dir = case_dir / "logs"
    if logs_dir.is_dir():
        return logs_dir
    raise FileNotFoundError(f"Missing logs directory under {case_dir}")


def collect_input_logs(log_dir: Path):
    results = []
    for path in sorted(log_dir.glob("node*_cont1.log")):
        node = CONT_FILE_PATTERN.match(path.name).group(1)
        matched = []
        for line in read_lines(path):
            if any(p.search(line) for p in INPUT_PATTERNS):
                matched.append(line)
            if len(matched) >= 4:
                break
        if matched:
            results.append((node, matched))
    return results


def parse_continuum_metrics(log_dir: Path):
    data = {}
    recon_lines = []
    final_cont = defaultdict(int)

    for path in sorted(log_dir.glob("node*_cont*.log")):
        m = CONT_FILE_PATTERN.match(path.name)
        if not m:
            continue
        node = int(m.group(1))
        cont = int(m.group(2))
        final_cont[node] = max(final_cont[node], cont)
        entry = data.setdefault((node, cont), {})
        for line in read_lines(path):
            for pattern, key in (
                (TRANS_PATTERN, "trans_foll_time"),
                (MUL_PATTERN, "mul_foll_time"),
                (LAYER_PATTERN, "layer_time"),
                (TRUSTED_PATTERN, "trusted_verification_time"),
                (RECV_INPUT_PATTERN, "recv_input_time"),
            ):
                mm = pattern.search(line)
                if mm:
                    entry[key] = float(mm.group(2))
            rm = RECON_PATTERN.search(line)
            if rm:
                recon_lines.append((node, cont, int(rm.group(1)), int(rm.group(2)), line))

    rows = []
    grouped = defaultdict(list)
    for (node, cont), vals in data.items():
        grouped[node].append({"node": node, "cont": cont, **vals})

    for node, recs in grouped.items():
        recs.sort(key=lambda r: r["cont"])
        prev_layer_time = None
        for rec in recs:
            tf = rec.get("trans_foll_time")
            mf = rec.get("mul_foll_time", 0.0)
            if tf is not None and prev_layer_time is not None:
                real_trans = tf - prev_layer_time
            else:
                real_trans = tf if tf is not None else 0.0
            trusted = rec.get("trusted_verification_time")
            if trusted is None:
                trusted = rec.get("recv_input_time")
            if trusted is None:
                trusted = real_trans + mf
            rec["real_trans_time"] = real_trans
            rec["trusted_verification_time"] = trusted
            if "layer_time" in rec:
                prev_layer_time = rec["layer_time"]
            rows.append(rec)

    layer_avgs = []
    by_cont = defaultdict(list)
    for row in rows:
        by_cont[row["cont"]].append(row)
    for cont, recs in sorted(by_cont.items()):
        trusted_vals = [r["trusted_verification_time"] for r in recs if "trusted_verification_time" in r]
        layer_vals = [r["layer_time"] for r in recs if "layer_time" in r]
        layer_avgs.append(
            {
                "cont": cont,
                "avg_trusted_verification_time": sum(trusted_vals) / len(trusted_vals) if trusted_vals else None,
                "avg_layer_time": sum(layer_vals) / len(layer_vals) if layer_vals else None,
                "num_nodes": len(recs),
                "rows": recs,
            }
        )

    trusted_only = [row["avg_trusted_verification_time"] for row in layer_avgs if row["avg_trusted_verification_time"] is not None]
    trimmed = None
    if len(trusted_only) > 3:
        middle = trusted_only[2:-1]
        if middle:
            trimmed = sum(middle) / len(middle)

    final_recon = []
    for node, cont in sorted(final_cont.items()):
        candidates = [item for item in recon_lines if item[0] == node and item[1] == cont]
        if candidates:
            final_recon.append(candidates[-1])

    return rows, layer_avgs, trimmed, final_recon


def run_extract_trusted_time(case_dir: Path, log_dir: Path):
    script_candidates = [
        case_dir / "extract_trusted_time.py",
        case_dir.parent / "extract_trusted_time.py",
    ]
    script_path = None
    for candidate in script_candidates:
        if candidate.is_file():
            script_path = candidate
            break

    if script_path is None:
        return {
            "script_path": None,
            "stdout": "",
            "layer_avg_rows": [],
            "overall_rows": [],
            "error": "未找到 extract_trusted_time.py 脚本。",
        }

    proc = subprocess.run(
        ["python3", str(script_path)],
        cwd=str(log_dir),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore",
    )

    layer_avg_csv = log_dir / "trusted_times_layer_avg.csv"
    overall_csv = log_dir / "trusted_times_overall_avg_trimmed.csv"

    layer_avg_rows = []
    overall_rows = []

    if layer_avg_csv.is_file():
        with layer_avg_csv.open("r", encoding="utf-8", newline="") as f:
            layer_avg_rows = list(csv.DictReader(f))

    if overall_csv.is_file():
        with overall_csv.open("r", encoding="utf-8", newline="") as f:
            overall_rows = list(csv.DictReader(f))

    return {
        "script_path": script_path,
        "stdout": proc.stdout.strip(),
        "stderr": proc.stderr.strip(),
        "returncode": proc.returncode,
        "layer_avg_rows": layer_avg_rows,
        "overall_rows": overall_rows,
        "error": None if proc.returncode == 0 else f"extract_trusted_time.py 执行失败，返回码 {proc.returncode}",
    }


def build_report_json(case_dir: Path, input_logs, layer_avgs, final_recon, exact_trusted):
    result = {
        "title": "Table 5-7 Test Output Summary",
        "continuum_case_dir": str(case_dir),
        "input_share_reception_and_execution_logs": [],
        "stage_verification_time_summary": {
            "note": "Trusted verification time is reported using the current log semantics and reflects cumulative growth as circuit layers progress.",
            "stages": [],
        },
        "per_node_verification_times_by_stage": [],
        "final_output_reconstruction_logs": [],
        "overall_average_trusted_verification_time": {},
    }

    for node, matched in input_logs:
        result["input_share_reception_and_execution_logs"].append(
            {
                "node": int(node),
                "logs": [strip_timestamp(line) for line in matched],
            }
        )

    for item in layer_avgs:
        cont = item["cont"]
        if 2 <= cont <= 6:
            prev_layer = cont - 1
            result["stage_verification_time_summary"]["stages"].append(
                {
                    "stage": cont,
                    "description": f"Stage {cont} execution, after completing trusted verification for layer {prev_layer} output",
                    "avg_trusted_verification_time_sec": item["avg_trusted_verification_time"],
                }
            )
            result["per_node_verification_times_by_stage"].append(
                {
                    "stage": cont,
                    "description": f"Each node completes trusted verification for layer {prev_layer}",
                    "nodes": [
                        {
                            "node": row["node"],
                            "trusted_verification_time_sec": row.get("trusted_verification_time"),
                        }
                        for row in sorted(item["rows"], key=lambda r: r["node"])
                    ],
                }
            )

    for node, cont, layer_id, value_len, line in final_recon:
        result["final_output_reconstruction_logs"].append(
            {
                "node": node,
                "reconstructed_value_count": value_len,
                "log": strip_timestamp(line),
            }
        )

    avg_section = result["overall_average_trusted_verification_time"]
    if exact_trusted.get("script_path") is None:
        avg_section["error"] = "extract_trusted_time.py not found."
    elif exact_trusted.get("error"):
        avg_section["error"] = exact_trusted["error"]
    else:
        avg_section["script"] = str(exact_trusted["script_path"])
        avg_section["per_layer_average_trusted_verification_time"] = [
            {
                "layer": int(row["layer"]) if row.get("layer") else None,
                "avg_trusted_verification_time_sec": float(row["avg_trusted_verification_time"]) if row.get("avg_trusted_verification_time") else None,
                "num_nodes": int(row["num_nodes"]) if row.get("num_nodes") else None,
            }
            for row in exact_trusted.get("layer_avg_rows", [])
        ]
        avg_section["overall_average"] = [
            {
                "total_layers": int(row["total_layers"]) if row.get("total_layers") else None,
                "used_layers": int(row["used_layers"]) if row.get("used_layers") else None,
                "avg_trusted_verification_time_sec": float(row["trimmed_avg_trusted_verification_time"]) if row.get("trimmed_avg_trusted_verification_time") else None,
            }
            for row in exact_trusted.get("overall_rows", [])
        ]

    return result


def main():
    parser = argparse.ArgumentParser(description="Collect Table 5-7 demo outputs into one JSON file.")
    parser.add_argument("--case-dir", required=True, help="Continuum case directory, e.g. /opt/benchmark-distributed/.../n4_t1_d6")
    parser.add_argument(
        "--output",
        help="输出JSON路径，默认：<case-dir>/table5_7_summary.json",
    )
    args = parser.parse_args()

    case_dir = Path(args.case_dir).resolve()
    log_dir = find_case_log_dir(case_dir)
    output_path = Path(args.output).resolve() if args.output else case_dir / "table5_7_summary.json"

    input_logs = collect_input_logs(log_dir)
    _, layer_avgs, _, final_recon = parse_continuum_metrics(log_dir)
    exact_trusted = run_extract_trusted_time(case_dir, log_dir)

    payload = build_report_json(case_dir, input_logs, layer_avgs, final_recon, exact_trusted)
    output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    print(json.dumps(payload, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
