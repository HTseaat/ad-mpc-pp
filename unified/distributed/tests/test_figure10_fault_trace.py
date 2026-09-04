import argparse
from pathlib import Path
import sys
import unittest


SCRIPT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPT_DIR))

from verify_figure10_fault_trace import validate  # noqa: E402


def args(protocol):
    return argparse.Namespace(protocol=protocol, n=16, t=5, d=6, count=5)


class Figure10TraceValidationTests(unittest.TestCase):
    def test_admpc_requires_t_silent_members_in_each_committee(self):
        events = []
        completed = set()
        for layer in range(1, 7):
            for party in range(11, 16):
                events.append(
                    {
                        "event": "silent_entered",
                        "physical_layer_id": layer,
                        "local_party_id": party,
                    }
                )
            completed.update(layer * 16 + party for party in range(11))
        completed.update(range(112, 128))
        self.assertTrue(validate(args("admpc"), events, completed)["valid"])

    def test_continuum_requires_t_silent_members_in_each_committee(self):
        events = []
        for layer in range(1, 7):
            for party in range(11, 16):
                events.append(
                    {
                        "event": "silent_entered",
                        "physical_layer_id": layer,
                        "local_party_id": party,
                    }
                )
        completed = set()
        for layer in range(1, 7):
            completed.update(layer * 16 + party for party in range(11))
        completed.update(range(112, 128))
        summary = validate(args("continuum"), events, completed)
        self.assertTrue(summary["valid"], summary["errors"])

        events.pop()
        self.assertFalse(validate(args("continuum"), events, completed)["valid"])

    def test_dumbo_requires_threshold_crossing_at_epoch_two(self):
        schedule = {1: range(11, 16), 2: range(6, 11)}
        events = [
            {"event": "silent_entered", "epoch": epoch, "local_party_id": party}
            for epoch, parties in schedule.items()
            for party in parties
        ]
        progress = [
            {"event": "epoch_completed", "epoch": epoch, "local_party_id": party}
            for epoch, parties in {1: range(11)}.items()
            for party in parties
        ]
        summary = validate(args("dumbo"), events, set(), progress)
        self.assertTrue(summary["valid"], summary["errors"])
        self.assertEqual(summary["expected_cumulative_silent_at_crossing"], 10)


if __name__ == "__main__":
    unittest.main()
