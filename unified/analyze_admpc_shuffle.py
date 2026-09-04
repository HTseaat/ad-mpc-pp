#!/usr/bin/env python3
"""Fail-closed Figure 12 analyzer for AD-MPC shuffle logs.

The paper-facing bar has exactly two additive components: exposed RandGen and
the remaining AD-MPC latency.  Raw overlapping phase durations remain in the
node logs and are deliberately not summed into the bar.
"""

import argparse
import csv
import json
import math
import re
import sys
from collections import defaultdict
from pathlib import Path


FINISHED_PREFIX = "ADMPC_SHUFFLE_FINISHED "
FINISHED_SCHEMA = "admpc-shuffle-finished-v2"
PHASE_SCHEMA = "admpc-shuffle-phase-timing-v1"
SUMMARY_SCHEMA = "admpc-shuffle-fig12-breakdown-v1"
ERROR_PATTERNS = (
    re.compile(r"Traceback"),
    re.compile(r"shuffle handoff ACK timeout"),
    re.compile(r"readiness timed out"),
    re.compile(r"CURVE authentication failures: [1-9]"),
    re.compile(r"identity spoofing events: [1-9]"),
)


class ShuffleAnalysisError(ValueError):
    pass


def _require(condition, message):
    if not condition:
        raise ShuffleAnalysisError(message)


def load_markers(log_dir):
    paths = sorted(Path(log_dir).glob("*.log"))
    _require(paths, f"no .log files found in {log_dir}")
    markers = []
    for path in paths:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            raise ShuffleAnalysisError(f"cannot read {path}: {exc}") from exc
        for line_number, line in enumerate(lines, 1):
            for pattern in ERROR_PATTERNS:
                _require(
                    pattern.search(line) is None,
                    f"error marker {pattern.pattern!r} in {path}:{line_number}",
                )
            if not line.startswith(FINISHED_PREFIX):
                continue
            try:
                marker = json.loads(line[len(FINISHED_PREFIX) :])
            except ValueError as exc:
                raise ShuffleAnalysisError(
                    f"invalid completion JSON in {path}:{line_number}: {exc}"
                ) from exc
            marker["_log_path"] = str(path)
            markers.append(marker)
    _require(markers, f"no {FINISHED_PREFIX.strip()} markers found in {log_dir}")
    return markers


def _validate_phase_timing(marker):
    process_id = int(marker["global_id"])
    result = marker.get("result")
    _require(isinstance(result, dict), f"process {process_id} has no result object")
    timing = result.get("phase_timing")
    _require(isinstance(timing, dict), f"process {process_id} has no phase_timing")
    _require(
        timing.get("schema") == PHASE_SCHEMA,
        f"process {process_id} has unsupported phase timing schema",
    )
    phases = timing.get("phases")
    _require(isinstance(phases, dict), f"process {process_id} phases must be an object")
    for name, values in phases.items():
        _require(isinstance(values, dict), f"invalid phase {name} in process {process_id}")
        started = float(values.get("started_at_seconds", -1))
        completed = float(values.get("completed_at_seconds", -1))
        duration = float(values.get("duration_seconds", -1))
        _require(
            all(math.isfinite(value) and value >= 0 for value in (started, completed, duration)),
            f"non-finite/negative phase {name} in process {process_id}",
        )
        _require(completed >= started, f"phase {name} ends before it starts in process {process_id}")
        _require(
            math.isclose(completed - started, duration, rel_tol=1e-6, abs_tol=1e-6),
            f"phase {name} duration mismatch in process {process_id}",
        )
    return timing


def analyze_markers(markers):
    _require(markers, "empty marker set")
    stable_fields = (
        "schema",
        "run_id",
        "n",
        "t",
        "k",
        "mode",
        "switch_layers",
        "physical_layers",
        "transport_topology",
    )
    reference = markers[0]
    for field in stable_fields:
        _require(field in reference, f"completion marker is missing {field}")
    _require(reference["schema"] == FINISHED_SCHEMA, "unsupported completion schema")
    _require(reference["transport_topology"] == "adjacent", "transport is not adjacent")

    n = int(reference["n"])
    t = int(reference["t"])
    k = int(reference["k"])
    switch_layers = int(reference["switch_layers"])
    physical_layers = int(reference["physical_layers"])
    _require(n > 0 and 0 <= t < n, "invalid n/t")
    _require(physical_layers == switch_layers + 2, "physical/switch layer mismatch")

    by_id = {}
    by_layer = defaultdict(list)
    for marker in markers:
        path = marker.get("_log_path", "<memory>")
        for field in stable_fields:
            _require(marker.get(field) == reference[field], f"run mismatch for {field} in {path}")
        process_id = int(marker["global_id"])
        _require(process_id not in by_id, f"duplicate global_id {process_id}")
        layer = int(marker["layer"])
        local_party = int(marker["local_party"])
        _require(layer == process_id // n, f"wrong layer for process {process_id}")
        _require(local_party == process_id % n, f"wrong local party for process {process_id}")
        _require(0 <= layer < physical_layers, f"invalid layer {layer}")
        expected_peers = (2 * n - 1) if layer in (0, physical_layers - 1) else (3 * n - 1)
        _require(
            int(marker.get("allowed_peer_count", -1)) == expected_peers,
            f"wrong adjacent peer count in process {process_id}",
        )
        elapsed = float(marker.get("elapsed", -1))
        _require(math.isfinite(elapsed) and elapsed >= 0, f"invalid elapsed in process {process_id}")
        _validate_phase_timing(marker)
        by_id[process_id] = marker
        by_layer[layer].append(marker)

    expected_processes = n * physical_layers
    _require(
        sorted(by_id) == list(range(expected_processes)),
        f"incomplete run: expected IDs 0..{expected_processes - 1}, got {sorted(by_id)}",
    )
    for layer in range(physical_layers):
        _require(len(by_layer[layer]) == n, f"layer {layer} has {len(by_layer[layer])}/{n} markers")

    outputs = by_layer[physical_layers - 1]
    output_digests = set()
    for marker in outputs:
        result = marker["result"]
        _require(result.get("role") == "output", "final layer contains a non-output result")
        _require(result.get("permutation_valid") is True, "output permutation validation failed")
        _require(int(result.get("output_count", -1)) == k, "wrong output count")
        _require(
            result.get("input_multiset_digest") == result.get("output_multiset_digest"),
            "input/output digest mismatch",
        )
        output_digests.add(result["output_multiset_digest"])
    _require(len(output_digests) == 1, "output parties disagree on digest")

    per_layer = []
    randgen_seconds = 0.0
    required_compute_phases = {
        "state_receive",
        "bundle_receive",
        "rand_candidates_receive",
        "aprep_receive",
        "rand_sign_normalization",
        "switch_execution",
        "state_transfer",
        "incoming_ack_send",
        "handoff_ack_wait",
    }
    for layer in range(1, physical_layers - 1):
        samples = []
        normalization_samples = []
        for marker in by_layer[layer]:
            result = marker["result"]
            _require(result.get("role") == "compute", f"layer {layer} has non-compute result")
            timing = result["phase_timing"]
            phases = timing["phases"]
            _require(
                required_compute_phases <= set(phases),
                f"process {marker['global_id']} is missing compute phase timing",
            )
            exposed = float(timing.get("randgen_exposed_seconds", -1))
            _require(
                math.isfinite(exposed) and 0 <= exposed <= float(marker["elapsed"]),
                f"invalid exposed RandGen in process {marker['global_id']}",
            )
            samples.append(exposed)
            normalization_samples.append(
                float(phases["rand_sign_normalization"]["duration_seconds"])
            )
        layer_exposed = max(samples)
        randgen_seconds += layer_exposed
        per_layer.append(
            {
                "layer": layer,
                "randgen_exposed_seconds": layer_exposed,
                "party_samples_seconds": samples,
                "max_normalization_seconds": max(normalization_samples),
            }
        )

    total_seconds = max(float(marker["elapsed"]) for marker in outputs)
    tolerance = max(1e-6, total_seconds * 1e-6)
    _require(
        randgen_seconds <= total_seconds + tolerance,
        f"exposed RandGen {randgen_seconds:.6f}s exceeds total {total_seconds:.6f}s",
    )
    randgen_seconds = min(randgen_seconds, total_seconds)
    admpc_seconds = total_seconds - randgen_seconds

    return {
        "schema": SUMMARY_SCHEMA,
        "run_id": reference["run_id"],
        "parameters": {
            "n": n,
            "t": t,
            "k": k,
            "mode": reference["mode"],
            "switch_layers": switch_layers,
            "physical_layers": physical_layers,
            "transport_topology": "adjacent",
        },
        "completion": {
            "expected_processes": expected_processes,
            "completed_processes": len(markers),
            "valid_output_parties": len(outputs),
            "output_multiset_digest": output_digests.pop(),
        },
        "latency_seconds": {
            "total": total_seconds,
            "randgen": randgen_seconds,
            "admpc": admpc_seconds,
        },
        "figure12_stack_order": ["admpc", "randgen"],
        "randgen_accounting": (
            "sum across compute layers of the maximum per-party positive tail "
            "from state-ready until normalized signs-ready; pipeline-hidden "
            "RandGen is excluded so randgen + admpc equals end-to-end total"
        ),
        "total_accounting": "maximum elapsed time among all n valid output parties",
        "per_compute_layer": per_layer,
    }


def write_outputs(output_dir, summary):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    with (output_dir / "summary.json").open("w", encoding="utf-8") as stream:
        json.dump(summary, stream, indent=2, sort_keys=True)
        stream.write("\n")
    fields = [
        "run_id",
        "n",
        "t",
        "k",
        "mode",
        "switch_layers",
        "physical_layers",
        "total_latency_seconds",
        "randgen_latency_seconds",
        "admpc_latency_seconds",
        "output_multiset_digest",
    ]
    row = {
        "run_id": summary["run_id"],
        **summary["parameters"],
        "total_latency_seconds": summary["latency_seconds"]["total"],
        "randgen_latency_seconds": summary["latency_seconds"]["randgen"],
        "admpc_latency_seconds": summary["latency_seconds"]["admpc"],
        "output_multiset_digest": summary["completion"]["output_multiset_digest"],
    }
    with (output_dir / "figure12_breakdown.csv").open(
        "w", encoding="utf-8", newline=""
    ) as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerow(row)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log_dir", help="directory containing one log per logical process")
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args(argv)
    try:
        summary = analyze_markers(load_markers(args.log_dir))
        write_outputs(args.output_dir, summary)
    except ShuffleAnalysisError as exc:
        print(f"AD-MPC shuffle analysis failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
