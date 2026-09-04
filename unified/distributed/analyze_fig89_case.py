#!/usr/bin/env python3
"""Validate and summarize one distributed Figure 8/9 case."""

import argparse
import json
import math
from pathlib import Path
import re
import statistics
import sys


LOG_NAME_RE = re.compile(r"^node(?P<node>[1-9][0-9]*)_cont(?P<layer>[1-9][0-9]*)\.log$")
EXEC_RE = re.compile(r"my_send_id:\s*(\d+)\s+exec_time:\s*([0-9]+(?:\.[0-9]+)?)")
LAYER_TIME_RE = re.compile(
    r"layer ID:\s*(\d+)\s+layer_time:\s*([0-9]+(?:\.[0-9]+)?)"
)
READY_RE = re.compile(
    r"CURVE channel ready:(?:\s*topology=(?P<topology>[^ ]+))?\s*"
    r"peers=(?P<peers>\d+)\s+channel_setup_ms=(?P<ms>[0-9]+(?:\.[0-9]+)?)"
)
AD_MPC_READY_RE = re.compile(
    r"my_send_id:\s*(?P<global_id>\d+)\s+CURVE channel_setup_ms:\s*"
    r"(?P<ms>[0-9]+(?:\.[0-9]+)?)"
)
AUTH_RE = re.compile(
    r"CURVE authentication failures:\s*(\d+);\s*invalid metadata:\s*(\d+);\s*"
    r"identity spoofing events:\s*(\d+)"
)
ERROR_PATTERNS = (
    "CURVE readiness timed out",
    "One or more remote runs failed",
    "Killed",
    "Out of memory",
    "Address already in use",
)
TRACEBACK_MARKER = "Traceback (most recent call last)"
KNOWN_CLEANUP_WARNING = "Task was destroyed but it is pending!"
KNOWN_CLEANUP_EXCEPTIONS = (
    "RuntimeError: Event loop is closed",
    "ValueError: coroutine already executing",
)
SPLIT_EVENT_LOOP_CLEANUP_RE = re.compile(
    r"RuntimeError(?P<interleaved>"
    r"(?:(?!Traceback \(most recent call last\):).){1,16384}?"
    r"): Event loop is closed",
    re.DOTALL,
)


class CaseAnalysisError(ValueError):
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


def _load_metadata(path):
    result = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key] = value
    return result


def _normalize_split_cleanup_exceptions(text):
    """Repair only known task-warning interleaving inside cleanup exceptions."""

    def replace(match):
        lines = [line.strip() for line in match.group("interleaved").splitlines()]
        if lines and all(
            KNOWN_CLEANUP_WARNING in line or line.startswith("task: <Task pending")
            for line in lines
        ):
            return "RuntimeError: Event loop is closed"
        return match.group(0)

    return SPLIT_EVENT_LOOP_CLEANUP_RE.sub(replace, text)


def analyze_case(case_dir, election_summary=None):
    root = Path(case_dir)
    metadata_path = root / "metadata.env"
    log_dir = root / "logs"
    if not metadata_path.is_file():
        raise CaseAnalysisError(f"missing metadata: {metadata_path}")
    if not log_dir.is_dir():
        raise CaseAnalysisError(f"missing logs directory: {log_dir}")
    metadata = _load_metadata(metadata_path)
    try:
        n = int(metadata["n"])
        layers = int(metadata["layers_total"])
        depth = int(metadata["d"])
    except (KeyError, ValueError) as exc:
        raise CaseAnalysisError("metadata has invalid n/layers_total/d") from exc
    if n != 4 or depth != 6 or layers != 8:
        raise CaseAnalysisError(
            f"this analyzer is scoped to n=4,d=6,layers=8; got n={n},d={depth},layers={layers}"
        )

    expected_count = n * layers
    log_by_global_id = {}
    for path in sorted(log_dir.glob("*.log")):
        match = LOG_NAME_RE.match(path.name)
        if not match:
            continue
        node_number = int(match.group("node"))
        layer_number = int(match.group("layer"))
        if not 1 <= node_number <= n or not 1 <= layer_number <= layers:
            raise CaseAnalysisError(f"unexpected process log name: {path.name}")
        global_id = (layer_number - 1) * n + node_number - 1
        if global_id in log_by_global_id:
            raise CaseAnalysisError(f"duplicate process log for global id {global_id}")
        log_by_global_id[global_id] = path
    missing_ids = sorted(set(range(expected_count)) - set(log_by_global_id))
    if missing_ids:
        raise CaseAnalysisError(f"missing process logs for global ids {missing_ids}")

    exec_times = {}
    layer_times = {}
    channel_setup_ms = {}
    ready_peer_counts = {}
    topologies = set()
    cleanup_warning_processes = []
    for global_id, path in sorted(log_by_global_id.items()):
        text = path.read_text(encoding="utf-8", errors="replace")
        found_errors = [marker for marker in ERROR_PATTERNS if marker in text]
        if found_errors:
            raise CaseAnalysisError(
                f"global id {global_id} log contains failure marker(s): {found_errors}"
            )
        exec_records = [(int(item), float(seconds)) for item, seconds in EXEC_RE.findall(text)]
        own_records = [seconds for item, seconds in exec_records if item == global_id]
        if len(own_records) != 1:
            raise CaseAnalysisError(
                f"global id {global_id} has {len(own_records)} matching exec_time records"
            )
        own_exec_match = next(
            match
            for match in EXEC_RE.finditer(text)
            if int(match.group(1)) == global_id
        )
        before_completion = text[: own_exec_match.end()]
        after_completion = text[own_exec_match.end() :]
        if TRACEBACK_MARKER in before_completion:
            raise CaseAnalysisError(
                f"global id {global_id} has a traceback before protocol completion"
            )
        cleanup_tracebacks = after_completion.count(TRACEBACK_MARKER)
        if cleanup_tracebacks:
            normalized_cleanup = _normalize_split_cleanup_exceptions(
                after_completion
            )
            known_cleanup_exceptions = sum(
                normalized_cleanup.count(marker)
                for marker in KNOWN_CLEANUP_EXCEPTIONS
            )
            if (
                KNOWN_CLEANUP_WARNING not in after_completion
                or known_cleanup_exceptions != cleanup_tracebacks
            ):
                raise CaseAnalysisError(
                    f"global id {global_id} has an unrecognized traceback after completion"
                )
            cleanup_warning_processes.append(global_id)
        exec_time = own_records[0]
        if not math.isfinite(exec_time) or exec_time < 0:
            raise CaseAnalysisError(f"global id {global_id} has invalid exec_time")
        exec_times[global_id] = exec_time

        expected_layer = global_id // n
        own_layer_records = [
            float(seconds)
            for layer, seconds in LAYER_TIME_RE.findall(text)
            if int(layer) == expected_layer
        ]
        if len(own_layer_records) != 1:
            raise CaseAnalysisError(
                f"global id {global_id} has {len(own_layer_records)} matching layer_time records"
            )
        layer_time = own_layer_records[0]
        if not math.isfinite(layer_time) or layer_time < 0:
            raise CaseAnalysisError(f"global id {global_id} has invalid layer_time")
        layer_times[global_id] = layer_time

        if metadata.get("zmq_auth_mode") == "curve":
            ready_records = list(READY_RE.finditer(text))
            if metadata.get("protocol") == "admpc":
                admpc_ready_records = list(AD_MPC_READY_RE.finditer(text))
                own_ready_records = [
                    record
                    for record in admpc_ready_records
                    if int(record.group("global_id")) == global_id
                ]
                if len(own_ready_records) != 1:
                    raise CaseAnalysisError(
                        f"global id {global_id} has {len(own_ready_records)} AD-MPC CURVE readiness records"
                    )
                channel_setup_ms[global_id] = float(own_ready_records[0].group("ms"))
                ready_peer_counts[global_id] = expected_count - 1
                topologies.add("full")
            else:
                if len(ready_records) != 1:
                    raise CaseAnalysisError(
                        f"global id {global_id} has {len(ready_records)} CURVE readiness records"
                    )
                ready = ready_records[0]
                channel_setup_ms[global_id] = float(ready.group("ms"))
                ready_peer_counts[global_id] = int(ready.group("peers"))
                if ready.group("topology"):
                    topologies.add(ready.group("topology"))
                auth_records = [tuple(map(int, record)) for record in AUTH_RE.findall(text)]
                if len(auth_records) != 1:
                    raise CaseAnalysisError(
                        f"global id {global_id} has {len(auth_records)} CURVE authentication summaries"
                    )
                if auth_records[0] != (0, 0, 0):
                    raise CaseAnalysisError(
                        f"global id {global_id} has non-zero CURVE security counters {auth_records[0]}"
                    )

    final_ids = list(range((layers - 1) * n, layers * n))
    core_latency_seconds = max(layer_times[global_id] for global_id in final_ids)
    protocol = metadata.get("protocol")
    experiment = metadata.get("experiment")
    if protocol == "admpc":
        protocol_variant = "admpc"
    elif protocol == "bgw-aggtrans":
        protocol_variant = "bgw-aggtrans"
    elif protocol == "continuum" and experiment == "exp1":
        protocol_variant = (
            "aggtrans-noagg" if metadata.get("disable_agg_proto") == "1" else "aggtrans-v2"
        )
    elif protocol == "continuum" and experiment == "exp2":
        protocol_variant = "batchmul-v2"
    else:
        protocol_variant = protocol or "unknown"

    summary = {
        "analysis_schema_version": 1,
        "case_dir": str(root.resolve()),
        "channel_setup_excluded_from_core_latency": True,
        "core_latency_seconds": core_latency_seconds,
        "core_latency_source": "max_final_layer_time",
        "depth": depth,
        "exec_time_seconds": _distribution(exec_times.values()),
        "layer_time_seconds": _distribution(layer_times.values()),
        "experiment": experiment,
        "final_layer_global_ids": final_ids,
        "image": metadata.get("mpc_image"),
        "layers": layers,
        "n": n,
        "process_count": len(exec_times),
        "protocol": protocol,
        "protocol_variant": protocol_variant,
        "t": int(metadata["t"]),
        "total_cm": int(metadata["total_cm"]),
        "transport_auth_mode": metadata.get("zmq_auth_mode"),
        "known_cleanup_warning_processes": cleanup_warning_processes,
    }
    if channel_setup_ms:
        summary["channel_setup_ms"] = _distribution(channel_setup_ms.values())
        summary["curve_ready_peer_counts"] = sorted(set(ready_peer_counts.values()))
        summary["curve_topologies"] = sorted(topologies) if topologies else ["unspecified"]

    if election_summary:
        election = json.loads(Path(election_summary).read_text(encoding="utf-8"))
        election_ms = float(election["sequential_election_total_ms"])
        if not math.isfinite(election_ms) or election_ms < 0:
            raise CaseAnalysisError("invalid sequential_election_total_ms")
        summary["committee_election_summary"] = str(Path(election_summary).resolve())
        summary["sequential_election_total_ms"] = election_ms
        summary["total_with_sequential_election_seconds"] = (
            core_latency_seconds + election_ms / 1000.0
        )
    return summary


def _write_markdown(path, summary):
    lines = [
        "# Figure 8/9 n=4 case summary",
        "",
        f"- Protocol: `{summary['protocol']}`",
        f"- Experiment: `{summary['experiment']}`",
        f"- Complete processes: {summary['process_count']}/{summary['n'] * summary['layers']}",
        f"- Core latency: {summary['core_latency_seconds']:.6f} s",
    ]
    if "channel_setup_ms" in summary:
        lines.append(
            f"- CURVE setup (max, reported separately): {summary['channel_setup_ms']['max']:.3f} ms"
        )
        lines.append(f"- CURVE ready peer counts: {summary['curve_ready_peer_counts']}")
    if "sequential_election_total_ms" in summary:
        lines.append(
            f"- Six sequential elections: {summary['sequential_election_total_ms']:.3f} ms"
        )
        lines.append(
            f"- Core + sequential elections: {summary['total_with_sequential_election_seconds']:.6f} s"
        )
    lines.extend(("", "Validation status: **PASS**", ""))
    path.write_text("\n".join(lines), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--case-dir", required=True)
    parser.add_argument("--election-summary")
    parser.add_argument("--output")
    parser.add_argument("--markdown")
    args = parser.parse_args()
    output = Path(args.output) if args.output else Path(args.case_dir) / "summary.json"
    markdown = Path(args.markdown) if args.markdown else Path(args.case_dir) / "summary.md"
    try:
        summary = analyze_case(args.case_dir, args.election_summary)
    except (CaseAnalysisError, OSError, KeyError, ValueError, json.JSONDecodeError) as exc:
        print(f"case validation failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
    output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _write_markdown(markdown, summary)
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
