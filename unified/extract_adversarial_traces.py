#!/usr/bin/env python3
"""Validate and normalize the four Stage-7 adversarial experiment traces."""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
import json
from pathlib import Path
import re
from statistics import mean
from typing import Dict, Iterable, List, Sequence, Tuple


LAYER_TIME_RE = re.compile(
    r"layer ID:\s*(\d+)\s+layer_time:\s*([\d.eE+-]+)"
)
START_TIME_RE = re.compile(r"ADMPC start time:\s*([\d.eE+-]+)")
TOP_EXEC_RE = re.compile(r"^my_send_id:\s*\d+\s+exec_time:\s*([\d.eE+-]+)")
OUTPUT_RECON_RE = re.compile(
    r"layer ID:\s*(\d+)\s+reconstructed trans_values length:\s*(\d+)"
)
CURVE_READY_RE = re.compile(r"CURVE (?:channel ready:|channel_setup_ms:)")
CURVE_AUTH_RE = re.compile(
    r"CURVE authentication failures:\s*(\d+);\s*invalid metadata:\s*(\d+);\s*"
    r"identity spoofing events:\s*(\d+)"
)
CURVE_AUTH_ANOMALY_MARKERS = (
    "Rejected CURVE client authentication",
    "Dropping CURVE message with unmapped User-Id",
    "Dropping CURVE identity spoof",
    "Dropping CURVE readiness message with mismatched run_id",
)
FAULT_PREFIX = "FAULT_EVENT "
FATAL_PATTERNS = (
    "AssertionError",
    "Segmentation fault",
    "Task exception was never retrieved",
    "zmq.error.ZMQError",
)


@dataclass(frozen=True)
class ScenarioSpec:
    name: str
    protocol: str
    log_dir: Path
    layout: str = "local"


def expected_log_path(
    protocol: str,
    log_dir: Path,
    n: int,
    physical_layer: int,
    local_id: int,
    layout: str = "local",
) -> Path:
    if layout == "distributed":
        return log_dir / f"node{local_id + 1}_cont{physical_layer + 1}.log"
    if layout != "local":
        raise ValueError(f"unsupported log layout {layout!r}")
    if protocol == "continuum":
        return log_dir / f"logs-{physical_layer * n + local_id}.log"
    if protocol == "admpc":
        return log_dir / f"node{local_id}_layer{physical_layer + 1}.log"
    raise ValueError(f"unsupported protocol {protocol!r}")


def read_scenario(
    spec: ScenarioSpec, n: int, layers: int
) -> Tuple[List[Dict[str, object]], List[Dict[str, object]], Dict[str, object]]:
    per_layer: Dict[int, List[float]] = {layer: [] for layer in range(layers)}
    events: List[Dict[str, object]] = []
    start_times: List[float] = []
    top_exec_times: List[float] = []
    output_reconstruction_lengths: List[int] = []
    curve_ready_count = 0
    curve_auth_summaries: List[Tuple[int, int, int]] = []
    curve_auth_anomalies: List[str] = []
    fatal_markers: List[str] = []
    missing_logs: List[str] = []

    for layer in range(layers):
        for local_id in range(n):
            path = expected_log_path(
                spec.protocol, spec.log_dir, n, layer, local_id, spec.layout
            )
            if not path.is_file():
                missing_logs.append(str(path))
                continue
            layer_value = None
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    start_match = START_TIME_RE.search(line)
                    if start_match:
                        start_times.append(float(start_match.group(1)))

                    layer_match = LAYER_TIME_RE.search(line)
                    if layer_match and int(layer_match.group(1)) == layer:
                        layer_value = float(layer_match.group(2))

                    exec_match = TOP_EXEC_RE.search(line)
                    if exec_match and layer == layers - 1:
                        top_exec_times.append(float(exec_match.group(1)))

                    output_match = OUTPUT_RECON_RE.search(line)
                    if output_match and int(output_match.group(1)) == layers - 1:
                        output_reconstruction_lengths.append(int(output_match.group(2)))

                    if CURVE_READY_RE.search(line):
                        curve_ready_count += 1

                    auth_match = CURVE_AUTH_RE.search(line)
                    if auth_match:
                        curve_auth_summaries.append(
                            tuple(int(auth_match.group(index)) for index in range(1, 4))
                        )

                    for marker in CURVE_AUTH_ANOMALY_MARKERS:
                        if marker in line:
                            curve_auth_anomalies.append(f"{path.name}: {marker}")

                    if FAULT_PREFIX in line:
                        raw = line.split(FAULT_PREFIX, 1)[1].strip()
                        try:
                            payload = json.loads(raw)
                        except json.JSONDecodeError:
                            fatal_markers.append(f"invalid FAULT_EVENT JSON in {path}")
                        else:
                            payload["_log_path"] = str(path)
                            events.append(payload)

                    for marker in FATAL_PATTERNS:
                        if marker in line:
                            fatal_markers.append(f"{path.name}: {marker}")

            if layer_value is not None:
                per_layer[layer].append(layer_value)

    layer_rows: List[Dict[str, object]] = []
    for layer in range(layers):
        values = per_layer[layer]
        if len(values) == n:
            layer_rows.append(
                {
                    "scenario": spec.name,
                    "protocol": spec.protocol,
                    "physical_layer": layer,
                    "completed_layers": layer + 1,
                    "completion_time_sec": max(values),
                    "min_node_time_sec": min(values),
                    "mean_node_time_sec": mean(values),
                    "max_node_time_sec": max(values),
                    "completed_nodes": len(values),
                }
            )

    common_start = min(start_times) if start_times else None
    event_rows: List[Dict[str, object]] = []
    for event in events:
        if event.get("event") == "config":
            continue
        wall_time = event.get("wall_time")
        relative = ""
        if common_start is not None and isinstance(wall_time, (int, float)):
            relative = float(wall_time) - common_start
        event_rows.append(
            {
                "scenario": spec.name,
                "protocol": spec.protocol,
                "event": event.get("event", ""),
                "component": event.get("component", ""),
                "physical_layer": event.get("physical_layer_id", ""),
                "local_party_id": event.get("local_party_id", ""),
                "relative_time_sec": relative,
                "details_json": json.dumps(
                    {
                        key: value
                        for key, value in event.items()
                        if key
                        not in {
                            "schema",
                            "protocol",
                            "mode",
                            "target",
                            "wall_time",
                            "global_party_id",
                            "local_party_id",
                            "physical_layer_id",
                            "event",
                            "component",
                            "_log_path",
                        }
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            }
        )

    metadata = {
        "events": events,
        "missing_logs": missing_logs,
        "fatal_markers": fatal_markers,
        "layer_marker_counts": {
            str(layer): len(per_layer[layer]) for layer in range(layers)
        },
        "top_exec_times": top_exec_times,
        "output_reconstruction_lengths": output_reconstruction_lengths,
        "curve_ready_count": curve_ready_count,
        "curve_auth_summaries": curve_auth_summaries,
        "curve_auth_anomalies": curve_auth_anomalies,
    }
    return layer_rows, event_rows, metadata


def event_matches(event: Dict[str, object], name: str, component: str = "") -> bool:
    return event.get("event") == name and (
        not component or event.get("component") == component
    )


def count_events(events: Sequence[Dict[str, object]], name: str, component: str = "") -> int:
    return sum(event_matches(event, name, component) for event in events)


def clean_subsets(
    events: Sequence[Dict[str, object]], event_name: str, component: str = ""
) -> int:
    return sum(
        1
        for event in events
        if event_matches(event, event_name, component)
        and event.get("corrupted_dealers_in_subset") == []
    )


def validate_scenario(
    spec: ScenarioSpec,
    metadata: Dict[str, object],
    n: int,
    t: int,
    layers: int,
) -> Dict[str, object]:
    events = metadata["events"]
    errors: List[str] = []
    if metadata["missing_logs"]:
        errors.append(f"missing {len(metadata['missing_logs'])} log files")
    incomplete = [
        layer
        for layer, count in metadata["layer_marker_counts"].items()
        if count != n
    ]
    if incomplete:
        errors.append(f"incomplete layer markers at {incomplete}")
    if len(metadata["top_exec_times"]) != n:
        errors.append(
            f"expected {n} output exec markers, got {len(metadata['top_exec_times'])}"
        )
    if metadata["fatal_markers"]:
        errors.append(f"found {len(metadata['fatal_markers'])} fatal markers")

    counts = {
        "mutation": count_events(events, "byzantine_mutation"),
        "delay_scheduled": count_events(events, "delay_scheduled"),
        "delay_released": count_events(events, "delay_released"),
    }

    if spec.name.endswith("delay"):
        if counts["mutation"] != 0:
            errors.append("delay scenario emitted a Byzantine mutation")
        if counts["delay_scheduled"] != t or counts["delay_released"] != t:
            errors.append(
                f"expected {t} scheduled/released delays, got "
                f"{counts['delay_scheduled']}/{counts['delay_released']}"
            )
    elif spec.name == "continuum-byzantine":
        agg_mutations = count_events(events, "byzantine_mutation", "aggtrans")
        batch_mutations = count_events(events, "byzantine_mutation", "batchmul")
        agg_verified = count_events(events, "aggtrans_verification", "aggtrans")
        batch_verified = count_events(events, "batchmul_verification", "batchmul")
        agg_clean = clean_subsets(events, "aggtrans_common_subset", "aggtrans")
        batch_clean = clean_subsets(events, "batchmul_common_subset", "batchmul")
        counts.update(
            {
                "aggtrans_mutations": agg_mutations,
                "batchmul_mutations": batch_mutations,
                "aggtrans_verifications": agg_verified,
                "batchmul_verifications": batch_verified,
                "aggtrans_clean_subsets": agg_clean,
                "batchmul_clean_subsets": batch_clean,
            }
        )
        if (agg_mutations, batch_mutations) != (t, t):
            errors.append(
                f"expected {t}/{t} AggTrans/BatchMul mutations, got "
                f"{agg_mutations}/{batch_mutations}"
            )
        expected_verifications = n * t
        if agg_verified != expected_verifications or batch_verified != expected_verifications:
            errors.append(
                f"expected {expected_verifications}/{expected_verifications} "
                "AggTrans/BatchMul verifications, got "
                f"{agg_verified}/{batch_verified}"
            )
        if agg_clean != n or batch_clean != n:
            errors.append(
                f"expected {n}/{n} clean subsets, got {agg_clean}/{batch_clean}"
            )
    elif spec.name == "admpc-byzantine":
        verified = count_events(events, "adtrans_verification", "adtrans")
        robust = sum(
            1
            for event in events
            if event_matches(event, "adtrans_robust_filter", "adtrans")
            and event.get("post_decode_mismatch_dealers")
            and event.get("corrupted_dealers_detected")
        )
        clean = clean_subsets(events, "adtrans_common_subset")
        counts.update(
            {
                "adtrans_verifications": verified,
                "adtrans_robust_exclusions": robust,
                "adtrans_clean_subsets": clean,
            }
        )
        if counts["mutation"] != t:
            errors.append(f"expected {t} ADtrans mutations, got {counts['mutation']}")
        expected_verifications = n * t
        if verified != expected_verifications or robust != n or clean != n:
            errors.append(
                f"expected {expected_verifications}/{n}/{n} "
                "ADtrans verification/filter/subset events, "
                f"got {verified}/{robust}/{clean}"
            )

    output_times = metadata["top_exec_times"]
    return {
        "protocol": spec.protocol,
        "log_dir": str(spec.log_dir),
        "success": not errors,
        "errors": errors,
        "counts": counts,
        "layer_marker_counts": metadata["layer_marker_counts"],
        "output_exec_count": len(output_times),
        "output_exec_mean_sec": mean(output_times) if output_times else None,
        "output_exec_min_sec": min(output_times) if output_times else None,
        "output_exec_max_sec": max(output_times) if output_times else None,
        "fatal_markers": metadata["fatal_markers"],
    }


def write_tsv(path: Path, rows: Sequence[Dict[str, object]], fieldnames: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, delimiter="\t")
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--n", type=int, required=True)
    parser.add_argument("--t", type=int, required=True)
    parser.add_argument("--layers", type=int, required=True)
    parser.add_argument("--continuum-delay", type=Path, required=True)
    parser.add_argument("--continuum-byzantine", type=Path, required=True)
    parser.add_argument("--admpc-delay", type=Path, required=True)
    parser.add_argument("--admpc-byzantine", type=Path, required=True)
    parser.add_argument("--trace-output", type=Path, required=True)
    parser.add_argument("--event-output", type=Path, required=True)
    parser.add_argument("--summary-output", type=Path, required=True)
    args = parser.parse_args()

    specs = (
        ScenarioSpec("continuum-delay", "continuum", args.continuum_delay),
        ScenarioSpec("continuum-byzantine", "continuum", args.continuum_byzantine),
        ScenarioSpec("admpc-delay", "admpc", args.admpc_delay),
        ScenarioSpec("admpc-byzantine", "admpc", args.admpc_byzantine),
    )

    layer_rows: List[Dict[str, object]] = []
    event_rows: List[Dict[str, object]] = []
    summaries: Dict[str, object] = {}
    for spec in specs:
        scenario_layers, scenario_events, metadata = read_scenario(
            spec, args.n, args.layers
        )
        layer_rows.extend(scenario_layers)
        event_rows.extend(scenario_events)
        summaries[spec.name] = validate_scenario(
            spec, metadata, args.n, args.t, args.layers
        )

    write_tsv(
        args.trace_output,
        layer_rows,
        (
            "scenario",
            "protocol",
            "physical_layer",
            "completed_layers",
            "completion_time_sec",
            "min_node_time_sec",
            "mean_node_time_sec",
            "max_node_time_sec",
            "completed_nodes",
        ),
    )
    write_tsv(
        args.event_output,
        sorted(
            event_rows,
            key=lambda row: (
                row["scenario"],
                float(row["relative_time_sec"] or 0.0),
                str(row["event"]),
            ),
        ),
        (
            "scenario",
            "protocol",
            "event",
            "component",
            "physical_layer",
            "local_party_id",
            "relative_time_sec",
            "details_json",
        ),
    )
    args.summary_output.parent.mkdir(parents=True, exist_ok=True)
    args.summary_output.write_text(
        json.dumps(summaries, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    failures = [name for name, summary in summaries.items() if not summary["success"]]
    if failures:
        print("Stage-7 validation failed: " + ", ".join(failures))
        return 1
    print("Stage-7 validation passed for all four scenarios")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
