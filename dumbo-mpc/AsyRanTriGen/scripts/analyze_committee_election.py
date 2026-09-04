"""Validate standalone election logs and emit the frozen Stage-5 summary."""

import argparse
import json
import math
import os
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from committee_election.network import METRICS_SCHEMA_VERSION
from scripts.run_committee_election import FINISHED_MARKER, METRICS_MARKER


class ElectionAnalysisError(ValueError):
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


def load_metrics(log_dir, expected_n):
    records = []
    for node_id in range(expected_n):
        path = os.path.join(log_dir, f"node-{node_id}.log")
        if not os.path.isfile(path):
            raise ElectionAnalysisError(f"missing node log: {path}")
        with open(path, encoding="utf-8") as log_file:
            lines = log_file.read().splitlines()
        if FINISHED_MARKER not in lines:
            raise ElectionAnalysisError(f"node {node_id} has no finished marker")
        payloads = [line[len(METRICS_MARKER):] for line in lines if line.startswith(METRICS_MARKER)]
        if len(payloads) != 1:
            raise ElectionAnalysisError(
                f"node {node_id} has {len(payloads)} metrics records; expected one"
            )
        record = json.loads(payloads[0])
        if record.get("metrics_schema_version") != METRICS_SCHEMA_VERSION:
            raise ElectionAnalysisError(f"node {node_id} metrics schema mismatch")
        if record.get("node_id") != node_id or record.get("n") != expected_n:
            raise ElectionAnalysisError(f"node {node_id} identity/config mismatch")
        records.append(record)
    return records


def analyze(records):
    if not records:
        raise ElectionAnalysisError("no metrics records")
    agreement_fields = (
        "candidate_index",
        "committee_id",
        "registry_digest",
        "run_id",
        "signature_digest",
        "target_epoch",
    )
    for field in agreement_fields:
        if len({record[field] for record in records}) != 1:
            raise ElectionAnalysisError(f"honest nodes disagree on {field}")
    n = records[0]["n"]
    if len(records) != n:
        raise ElectionAnalysisError(f"received {len(records)} records; expected {n}")
    numeric_fields = (
        "bytes_sent_remote",
        "certificate_verify_ms",
        "channel_setup_ms",
        "combine_ms",
        "election_total_ms",
        "messages_sent_remote",
        "network_wait_ms",
        "selection_ms",
        "share_verify_ms_total",
        "sign_ms",
    )
    distributions = {}
    for field in numeric_fields:
        values = [record[field] for record in records]
        if any(isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0 for value in values):
            raise ElectionAnalysisError(f"invalid numeric value for {field}")
        distributions[field] = _distribution(values)
    return {
        "K": records[0]["K"],
        "candidate_index": records[0]["candidate_index"],
        "committee_id": records[0]["committee_id"],
        "distributions": distributions,
        "metrics_schema_version": METRICS_SCHEMA_VERSION,
        "n": n,
        "node_count": len(records),
        "protocol_completion_ms": distributions["election_total_ms"]["max"],
        "registry_digest": records[0]["registry_digest"],
        "run_id": records[0]["run_id"],
        "signature_digest": records[0]["signature_digest"],
        "t": records[0]["t"],
        "target_epoch": records[0]["target_epoch"],
        "total_bytes_sent_remote": sum(record["bytes_sent_remote"] for record in records),
        "total_messages_sent_remote": sum(record["messages_sent_remote"] for record in records),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log-dir", required=True)
    parser.add_argument("--expected-n", type=int, required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    summary = analyze(load_metrics(args.log_dir, args.expected_n))
    with open(args.output, "w", encoding="utf-8") as output_file:
        json.dump(summary, output_file, indent=2, sort_keys=True)
        output_file.write("\n")
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
