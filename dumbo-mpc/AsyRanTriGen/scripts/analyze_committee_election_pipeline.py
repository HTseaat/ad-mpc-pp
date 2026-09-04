"""Validate Stage-6/7 election and handoff-gate records in Continuum logs."""

import argparse
import json
import os

PIPELINE_ELECTION_MARKER = "COMMITTEE_ELECTION_PIPELINE "
PIPELINE_GATE_MARKER = "COMMITTEE_ELECTION_GATE "


def resolve_pipeline_mode(value):
    mode = str(value).strip().lower()
    if mode not in {"off", "shadow", "gated"}:
        raise ValueError(f"unsupported committee election mode: {value!r}")
    return mode


class PipelineAnalysisError(ValueError):
    pass


def _records(path, marker):
    with open(path, encoding="utf-8", errors="replace") as log_file:
        lines = log_file.read().splitlines()
    records = []
    for line in lines:
        position = line.find(marker)
        if position >= 0:
            records.append(json.loads(line[position + len(marker):]))
    return records


def analyze_pipeline(*, log_dir, n, layers, mode, completion_policy="all", t=None):
    mode = resolve_pipeline_mode(mode)
    if mode == "off":
        raise PipelineAnalysisError("pipeline analyzer requires shadow or gated mode")
    if completion_policy not in {"all", "output-threshold"}:
        raise PipelineAnalysisError("unsupported completion policy")
    if completion_policy == "output-threshold":
        if t is None or isinstance(t, bool) or not isinstance(t, int) or t < 0 or t >= n:
            raise PipelineAnalysisError("output-threshold policy requires 0 <= t < n")
    elections = []
    gates = []
    completed_processes = 0
    completed_output_ids = []
    output_start = (layers - 1) * n
    for global_id in range(n * layers):
        path = os.path.join(log_dir, f"logs-{global_id}.log")
        if not os.path.isfile(path):
            raise PipelineAnalysisError(f"missing process log {path}")
        with open(path, encoding="utf-8", errors="replace") as log_file:
            log_text = log_file.read()
        process_completed = f"my_send_id: {global_id} exec_time:" in log_text
        if process_completed:
            completed_processes += 1
            if global_id >= output_start:
                completed_output_ids.append(global_id)
        if completion_policy == "all":
            if log_text.splitlines().count("COMMITTEE_ELECTION_PIPELINE_FINISHED") != 1:
                raise PipelineAnalysisError(
                    f"process {global_id} did not cross the pipeline completion barrier exactly once"
                )
            if not process_completed:
                raise PipelineAnalysisError(f"process {global_id} did not finish Continuum")
        elections.extend(_records(path, PIPELINE_ELECTION_MARKER))
        gates.extend(_records(path, PIPELINE_GATE_MARKER))
    if completion_policy == "output-threshold" and len(completed_output_ids) < n - t:
        raise PipelineAnalysisError(
            f"only {len(completed_output_ids)} output processes completed; expected at least {n - t}"
        )
    expected_targets = tuple(range(2, layers))
    minimum_per_target = n if completion_policy == "all" else n - t
    target_summaries = []
    for target_epoch in expected_targets:
        election_group = [
            record for record in elections if record["target_epoch"] == target_epoch
        ]
        gate_group = [record for record in gates if record["target_epoch"] == target_epoch]
        if not (
            minimum_per_target <= len(election_group) <= n
            and minimum_per_target <= len(gate_group) <= n
        ):
            raise PipelineAnalysisError(
                f"target epoch {target_epoch} lacks the required records"
            )
        election_ids = {record["local_id"] for record in election_group}
        gate_ids = {record["local_id"] for record in gate_group}
        if len(election_ids) != len(election_group) or not election_ids <= set(range(n)):
            raise PipelineAnalysisError(f"target epoch {target_epoch} election IDs are invalid")
        if len(gate_ids) != len(gate_group) or gate_ids != election_ids:
            raise PipelineAnalysisError(f"target epoch {target_epoch} gate IDs differ")
        expected_election_source = (
            target_epoch - 1 if mode == "gated" else max(1, target_epoch - 2)
        )
        expected_gate_source = max(1, target_epoch - 1)
        if {record["physical_source_layer"] for record in election_group} != {
            expected_election_source
        }:
            raise PipelineAnalysisError(
                f"target epoch {target_epoch} was elected by the wrong source layer"
            )
        if {record["physical_source_layer"] for record in gate_group} != {
            expected_gate_source
        }:
            raise PipelineAnalysisError(
                f"target epoch {target_epoch} gated the wrong source layer"
            )
        for field in ("committee_id", "registry_digest", "signature_digest"):
            if len({record[field] for record in election_group}) != 1:
                raise PipelineAnalysisError(
                    f"target epoch {target_epoch} disagrees on {field}"
                )
        election_signature = election_group[0]["signature_digest"]
        if {record["signature_digest"] for record in gate_group} != {
            election_signature
        }:
            raise PipelineAnalysisError(
                f"target epoch {target_epoch} gate used a different certificate"
            )
        if any(record["mode"] != mode for record in election_group + gate_group):
            raise PipelineAnalysisError("pipeline mode differs across records")
        if election_group[0]["committee_id"] != (
            f"candidate-{election_group[0]['candidate_index']:02d}"
        ):
            raise PipelineAnalysisError("candidate index and committee ID differ")
        if mode == "shadow" and any(record["handoff_wait_ms"] != 0 for record in gate_group):
            raise PipelineAnalysisError("shadow mode must not block a handoff")
        if mode == "gated" and any(
            record["election_deadline_missed"] and record["handoff_wait_ms"] <= 0
            for record in gate_group
        ):
            raise PipelineAnalysisError("a missed gated deadline did not expose a wait")
        target_summaries.append(
            {
                "candidate_index": election_group[0]["candidate_index"],
                "committee_id": election_group[0]["committee_id"],
                "deadline_miss_count": sum(
                    bool(record["election_deadline_missed"])
                    for record in gate_group
                ),
                "max_election_total_ms": max(
                    record["election_total_ms"] for record in election_group
                ),
                "max_handoff_wait_ms": max(
                    record["handoff_wait_ms"] for record in gate_group
                ),
                "signature_digest": election_signature,
                "target_epoch": target_epoch,
            }
        )
    return {
        "election_record_count": len(elections),
        "completed_process_count": completed_processes,
        "completed_output_ids": completed_output_ids,
        "completion_policy": completion_policy,
        "gate_record_count": len(gates),
        "layers": layers,
        "mode": mode,
        "n": n,
        "targets": target_summaries,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log-dir", required=True)
    parser.add_argument("--N", type=int, required=True)
    parser.add_argument("--layers", type=int, required=True)
    parser.add_argument("--mode", required=True)
    parser.add_argument(
        "--completion-policy",
        choices=("all", "output-threshold"),
        default="all",
    )
    parser.add_argument("--t", type=int)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    summary = analyze_pipeline(
        log_dir=args.log_dir,
        n=args.N,
        layers=args.layers,
        mode=args.mode,
        completion_policy=args.completion_policy,
        t=args.t,
    )
    with open(args.output, "w", encoding="utf-8") as output_file:
        json.dump(summary, output_file, indent=2, sort_keys=True)
        output_file.write("\n")
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
