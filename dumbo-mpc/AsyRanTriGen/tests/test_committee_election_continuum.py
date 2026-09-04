import json
import os
import tempfile
import unittest

from committee_election.continuum import (
    ContinuumElectionError,
    PIPELINE_ELECTION_MARKER,
    PIPELINE_GATE_MARKER,
    resolve_pipeline_mode,
)
from scripts.analyze_committee_election_pipeline import (
    PipelineAnalysisError,
    analyze_pipeline,
)


class PipelineModeTests(unittest.TestCase):
    def test_modes_are_normalized_and_invalid_values_fail_closed(self):
        self.assertEqual(resolve_pipeline_mode(" SHADOW "), "shadow")
        self.assertEqual(resolve_pipeline_mode("gated"), "gated")
        with self.assertRaises(ContinuumElectionError):
            resolve_pipeline_mode("selected")


class PipelineAnalyzerTests(unittest.TestCase):
    def write_fixture(self, directory, mode):
        n = 2
        layers = 4
        by_global_id = {global_id: [] for global_id in range(n * layers)}
        for target_epoch in (2, 3):
            source_layer = (
                target_epoch - 1 if mode == "gated" else 1
            )
            for local_id in range(n):
                election = {
                    "candidate_index": 0,
                    "certificate_ready_unix_ms": 12.0,
                    "committee_id": "candidate-00",
                    "election_started_unix_ms": 10.0,
                    "election_total_ms": 2.0,
                    "local_id": local_id,
                    "mode": mode,
                    "network_wait_ms": 1.0,
                    "physical_source_layer": source_layer,
                    "registry_digest": "a" * 64,
                    "signature_digest": f"{target_epoch}" * 64,
                    "target_epoch": target_epoch,
                }
                gate_layer = target_epoch - 1
                missed = mode == "gated"
                gate = {
                    "certificate_ready_unix_ms": 12.0,
                    "election_deadline_missed": missed,
                    "election_started_unix_ms": 10.0,
                    "handoff_ready_unix_ms": 11.0,
                    "handoff_start_unix_ms": 13.0 if missed else 11.0,
                    "handoff_wait_ms": 2.0 if missed else 0.0,
                    "local_id": local_id,
                    "mode": mode,
                    "overlap_window_ms": 1.0,
                    "physical_source_layer": gate_layer,
                    "signature_digest": f"{target_epoch}" * 64,
                    "target_epoch": target_epoch,
                    "would_block_ms": 1.0,
                }
                by_global_id[source_layer * n + local_id].append(
                    PIPELINE_ELECTION_MARKER + json.dumps(election)
                )
                by_global_id[gate_layer * n + local_id].append(
                    PIPELINE_GATE_MARKER + json.dumps(gate)
                )
        for global_id, lines in by_global_id.items():
            lines.extend(
                [
                    f"my_send_id: {global_id} exec_time: 1.0",
                    "COMMITTEE_ELECTION_PIPELINE_FINISHED",
                ]
            )
            with open(
                os.path.join(directory, f"logs-{global_id}.log"),
                "w",
                encoding="utf-8",
            ) as log_file:
                log_file.write("\n".join(lines))
                log_file.write("\n")

    def test_shadow_and_gated_fixtures_validate(self):
        for mode in ("shadow", "gated"):
            with tempfile.TemporaryDirectory() as directory:
                self.write_fixture(directory, mode)
                summary = analyze_pipeline(
                    log_dir=directory, n=2, layers=4, mode=mode
                )
            self.assertEqual(summary["election_record_count"], 4)
            self.assertEqual(summary["gate_record_count"], 4)

    def test_shadow_blocking_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            self.write_fixture(directory, "shadow")
            path = os.path.join(directory, "logs-2.log")
            with open(path, encoding="utf-8") as log_file:
                value = log_file.read().replace(
                    '"handoff_wait_ms": 0.0', '"handoff_wait_ms": 1.0', 1
                )
            with open(path, "w", encoding="utf-8") as log_file:
                log_file.write(value)
            with self.assertRaises(PipelineAnalysisError):
                analyze_pipeline(log_dir=directory, n=2, layers=4, mode="shadow")

    def test_output_threshold_accepts_one_output_straggler(self):
        with tempfile.TemporaryDirectory() as directory:
            self.write_fixture(directory, "gated")
            path = os.path.join(directory, "logs-7.log")
            with open(path, encoding="utf-8") as log_file:
                lines = [
                    line
                    for line in log_file.read().splitlines()
                    if "my_send_id: 7 exec_time:" not in line
                    and line != "COMMITTEE_ELECTION_PIPELINE_FINISHED"
                ]
            with open(path, "w", encoding="utf-8") as log_file:
                log_file.write("\n".join(lines) + "\n")
            summary = analyze_pipeline(
                log_dir=directory,
                n=2,
                t=1,
                layers=4,
                mode="gated",
                completion_policy="output-threshold",
            )
            self.assertEqual(summary["completed_output_ids"], [6])

    def test_output_threshold_rejects_too_few_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            self.write_fixture(directory, "gated")
            for global_id in (6, 7):
                path = os.path.join(directory, f"logs-{global_id}.log")
                with open(path, encoding="utf-8") as log_file:
                    value = log_file.read().replace(
                        f"my_send_id: {global_id} exec_time: 1.0", ""
                    )
                with open(path, "w", encoding="utf-8") as log_file:
                    log_file.write(value)
            with self.assertRaises(PipelineAnalysisError):
                analyze_pipeline(
                    log_dir=directory,
                    n=2,
                    t=1,
                    layers=4,
                    mode="gated",
                    completion_policy="output-threshold",
                )


if __name__ == "__main__":
    unittest.main()
