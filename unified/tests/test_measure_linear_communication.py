import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "measure_linear_communication.py"
SPEC = importlib.util.spec_from_file_location("measure_linear_communication", SCRIPT)
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


def _report(**overrides):
    arguments = {
        "n": 4,
        "t": 1,
        "batch_size": 100,
        "depth": 6,
        "mode": "both",
        "protocol": "all",
        "old_commitments": "retransmit",
    }
    arguments.update(overrides)
    return tool.calculate(tool.load_profile(), **arguments)


class LinearCommunicationAuditTest(unittest.TestCase):
    def test_n4_reference_totals_are_derived_from_components(self):
        report = _report()
        implementation = report["results"]["implementation"]
        paper = report["results"]["paper"]

        self.assertEqual(
            implementation["continuum"]["per_transfer_payload_bytes"], 4_862_933
        )
        self.assertEqual(
            implementation["admpc"]["per_transfer_payload_bytes"], 3_138_376
        )
        self.assertEqual(paper["continuum"]["per_transfer_payload_bytes"], 995_985)
        self.assertEqual(paper["admpc"]["per_transfer_payload_bytes"], 4_008_112)
        self.assertEqual(paper["continuum"]["total_payload_bytes"], 5_975_910)
        self.assertEqual(paper["admpc"]["total_payload_bytes"], 24_048_672)
        self.assertEqual(
            sum(paper["continuum"]["components_per_transfer"].values()), 995_985
        )
        self.assertEqual(
            sum(paper["admpc"]["components_per_transfer"].values()), 4_008_112
        )
        self.assertAlmostEqual(
            report["comparisons"]["paper"][
                "continuum_reduction_vs_admpc_percent"
            ],
            75.15076924,
        )

    def test_cached_old_commitments_is_separate_conservative_choice(self):
        report = _report(mode="paper", old_commitments="cached")
        continuum = report["results"]["paper"]["continuum"]
        self.assertEqual(continuum["per_transfer_payload_bytes"], 842_129)
        self.assertEqual(continuum["total_payload_bytes"], 5_052_774)

    def test_depth_changes_repetition_but_not_per_transfer(self):
        report = _report(mode="paper", depth=2)
        continuum = report["results"]["paper"]["continuum"]
        self.assertEqual(continuum["per_transfer_payload_bytes"], 995_985)
        self.assertEqual(continuum["total_payload_bytes"], 1_991_970)
        self.assertAlmostEqual(continuum["bytes_per_sharing"], 9_959.85)

    def test_uncalibrated_parameters_fail_closed(self):
        with self.assertRaisesRegex(
            tool.CommunicationModelError, "no exact local calibration"
        ):
            _report(n=10, t=3)

    def test_changed_source_hash_fails_closed_but_can_be_explicitly_skipped(self):
        profile = json.loads(tool.DEFAULT_PROFILE.read_text(encoding="utf-8"))
        first_source = next(iter(profile["source_sha256"]))
        profile["source_sha256"][first_source] = "0" * 64
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "profile.json"
            path.write_text(json.dumps(profile), encoding="utf-8")
            with self.assertRaisesRegex(
                tool.CommunicationModelError, "calibration source check failed"
            ):
                tool.load_profile(path)
            loaded = tool.load_profile(path, check_source_hashes=False)
            self.assertFalse(loaded["_source_status"]["checked"])

    def test_json_csv_and_table_renderers_include_auditable_values(self):
        report = _report(mode="paper")
        self.assertIn(
            '"per_transfer_payload_bytes": 995985', tool.render(report, "json")
        )
        self.assertIn("paper,continuum,4,1,100,6", tool.render(report, "csv"))
        table = tool.render(report, "table")
        self.assertIn("995,985 B", table)
        self.assertIn("4,008,112 B", table)


if __name__ == "__main__":
    unittest.main()
