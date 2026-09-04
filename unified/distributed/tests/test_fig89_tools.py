import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


case_tool = load_module("analyze_fig89_case", "analyze_fig89_case.py")
election_tool = load_module(
    "aggregate_committee_elections", "aggregate_committee_elections.py"
)
figure_tool = load_module("aggregate_fig89_n4", "aggregate_fig89_n4.py")


class Figure89ToolsTest(unittest.TestCase):
    def test_case_analyzer_requires_all_32_authenticated_processes(self):
        with tempfile.TemporaryDirectory() as temporary:
            case_dir = Path(temporary)
            (case_dir / "logs").mkdir()
            (case_dir / "metadata.env").write_text(
                "\n".join(
                    (
                        "protocol=continuum",
                        "experiment=exp1",
                        "n=4",
                        "t=1",
                        "d=6",
                        "layers_total=8",
                        "total_cm=300",
                        "zmq_auth_mode=curve",
                        "disable_agg_proto=0",
                        "mpc_image=test-r3",
                    )
                )
                + "\n",
                encoding="utf-8",
            )
            for global_id in range(32):
                layer = global_id // 4 + 1
                node = global_id % 4 + 1
                (case_dir / "logs" / f"node{node}_cont{layer}.log").write_text(
                    "\n".join(
                        (
                            "CURVE channel ready: peers=31 channel_setup_ms=12.5",
                            f"layer ID: {layer - 1} layer_time: {global_id + 0.20}",
                            f"my_send_id: {global_id} exec_time: {global_id + 0.25}",
                            "CURVE authentication failures: 0; invalid metadata: 0; identity spoofing events: 0",
                        )
                    )
                    + "\n",
                    encoding="utf-8",
                )
            election = case_dir / "election.json"
            election.write_text(
                json.dumps({"sequential_election_total_ms": 600.0}), encoding="utf-8"
            )
            summary = case_tool.analyze_case(case_dir, election)
            self.assertEqual(summary["process_count"], 32)
            self.assertEqual(summary["protocol_variant"], "aggtrans-v2")
            self.assertEqual(summary["core_latency_seconds"], 31.2)
            self.assertEqual(summary["total_with_sequential_election_seconds"], 31.8)
            self.assertEqual(summary["known_cleanup_warning_processes"], [])

            cleanup_log = case_dir / "logs" / "node1_cont1.log"
            cleanup_log.write_text(
                cleanup_log.read_text(encoding="utf-8")
                + "Task was destroyed but it is pending!\n"
                + "Traceback (most recent call last):\n"
                + "ValueError: coroutine already executing\n",
                encoding="utf-8",
            )
            summary = case_tool.analyze_case(case_dir, election)
            self.assertEqual(summary["known_cleanup_warning_processes"], [0])

            cleanup_log.write_text(
                cleanup_log.read_text(encoding="utf-8")
                + "Task was destroyed but it is pending!\n"
                + "Traceback (most recent call last):\n"
                + "  File \"uvloop/loop.pyx\", line 705, in _check_closed\n"
                + "RuntimeError2026-08-18 04:52:34:[ERROR]: "
                + "Task was destroyed but it is pending!\n"
                + "task: <Task pending name='Task-1'>\n"
                + ": Event loop is closed\n",
                encoding="utf-8",
            )
            summary = case_tool.analyze_case(case_dir, election)
            self.assertEqual(summary["known_cleanup_warning_processes"], [0])

            cleanup_log.write_text(
                "Traceback (most recent call last):\n"
                + cleanup_log.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            with self.assertRaises(case_tool.CaseAnalysisError):
                case_tool.analyze_case(case_dir, election)

            (case_dir / "logs" / "node4_cont8.log").unlink()
            with self.assertRaises(case_tool.CaseAnalysisError):
                case_tool.analyze_case(case_dir, election)

    def test_election_aggregator_charges_six_unique_runs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for epoch in range(2, 8):
                epoch_dir = root / f"epoch-{epoch}"
                epoch_dir.mkdir()
                (epoch_dir / "summary.json").write_text(
                    json.dumps(
                        {
                            "committee_id": f"candidate-{epoch % 4}",
                            "n": 4,
                            "node_count": 4,
                            "protocol_completion_ms": epoch * 10.0,
                            "run_id": f"run-{epoch}",
                            "t": 1,
                            "target_epoch": 2,
                        }
                    ),
                    encoding="utf-8",
                )
            summary = election_tool.aggregate(root)
            self.assertEqual(summary["election_count"], 6)
            self.assertEqual(summary["sequential_election_total_ms"], 270.0)

    def test_figure_aggregator_excludes_warmups(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for repetition in (1, 2):
                for experiment, variant in sorted(figure_tool.EXPECTED):
                    case_dir = (
                        root
                        / "measured"
                        / f"round-{repetition}"
                        / f"session-{experiment}-{variant}"
                        / "n4"
                    )
                    case_dir.mkdir(parents=True)
                    value = float(repetition)
                    (case_dir / "summary.json").write_text(
                        json.dumps(
                            {
                                "core_latency_seconds": value,
                                "depth": 6,
                                "experiment": experiment,
                                "n": 4,
                                "process_count": 32,
                                "protocol_variant": variant,
                                "sequential_election_total_ms": 300.0,
                                "total_with_sequential_election_seconds": value + 0.3,
                            }
                        ),
                        encoding="utf-8",
                    )
            warmup = root / "warmup" / "round-1" / "ignored" / "n4"
            warmup.mkdir(parents=True)
            (warmup / "summary.json").write_text("{}", encoding="utf-8")
            summary = figure_tool.aggregate(root, repetitions=2)
            self.assertEqual(len(summary["cases"]), 6)
            self.assertEqual(summary["cases"][0]["core_latency_seconds"]["median"], 1.5)


if __name__ == "__main__":
    unittest.main()
