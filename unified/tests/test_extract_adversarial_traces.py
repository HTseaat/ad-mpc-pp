import tempfile
from pathlib import Path
import unittest

from unified.extract_adversarial_traces import (
    ScenarioSpec,
    expected_log_path,
    read_scenario,
    validate_scenario,
)


class TraceExtractionTests(unittest.TestCase):
    def _write_logs(self, root, protocol, n=2, layers=3):
        for layer in range(layers):
            for local_id in range(n):
                path = expected_log_path(protocol, root, n, layer, local_id)
                path.write_text(
                    "2026-08-11 00:00:00,000 INFO ADMPC start time: 100.0\n"
                    f"layer ID: {layer} layer_time: {layer + local_id / 10 + 1}\n"
                    + (
                        f"my_send_id: {layer * n + local_id} exec_time: 3.{local_id}\n"
                        if layer == layers - 1
                        else ""
                    ),
                    encoding="utf-8",
                )

    def test_continuum_layer_trace_uses_committee_maximum(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_logs(root, "continuum")
            rows, events, metadata = read_scenario(
                ScenarioSpec("continuum-delay", "continuum", root), 2, 3
            )
            self.assertEqual(len(rows), 3)
            self.assertAlmostEqual(rows[1]["completion_time_sec"], 2.1)
            self.assertEqual(metadata["top_exec_times"], [3.0, 3.1])
            self.assertEqual(events, [])

    def test_admpc_filename_mapping_and_complete_markers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_logs(root, "admpc")
            rows, _, metadata = read_scenario(
                ScenarioSpec("admpc-delay", "admpc", root), 2, 3
            )
            self.assertEqual(len(rows), 3)
            self.assertEqual(metadata["missing_logs"], [])
            self.assertEqual(metadata["layer_marker_counts"], {"0": 2, "1": 2, "2": 2})

    def test_distributed_continuum_filename_mapping(self):
        root = Path("/tmp/example")
        self.assertEqual(
            expected_log_path("continuum", root, 4, 3, 2, "distributed"),
            root / "node3_cont4.log",
        )

    def test_byzantine_verification_count_scales_with_t(self):
        n, t, layers = 4, 2, 3
        events = []
        for component in ("aggtrans", "batchmul"):
            events.extend(
                {"event": "byzantine_mutation", "component": component}
                for _ in range(t)
            )
            events.extend(
                {"event": f"{component}_verification", "component": component}
                for _ in range(n * t)
            )
            events.extend(
                {
                    "event": f"{component}_common_subset",
                    "component": component,
                    "corrupted_dealers_in_subset": [],
                }
                for _ in range(n)
            )
        metadata = {
            "events": events,
            "missing_logs": [],
            "fatal_markers": [],
            "layer_marker_counts": {str(layer): n for layer in range(layers)},
            "top_exec_times": [1.0] * n,
        }
        summary = validate_scenario(
            ScenarioSpec("continuum-byzantine", "continuum", Path(".")),
            metadata,
            n,
            t,
            layers,
        )
        self.assertTrue(summary["success"], summary["errors"])


if __name__ == "__main__":
    unittest.main()
