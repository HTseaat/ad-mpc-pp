import importlib.util
import sys
import unittest
from pathlib import Path


SCRIPT = Path("/opt/unified/simulate_adprep_avid_communication.py")
SPEC = importlib.util.spec_from_file_location("adprep_avid_sim", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class AdprepAvidSimulationTests(unittest.TestCase):
    def test_public_payload_formula(self):
        self.assertEqual(MODULE._public_payload_bytes(600), 57_794)
        self.assertEqual(MODULE._public_payload_bytes(134), 13_058)

    def test_source_calibration_inverts_current_wire_layout(self):
        n, t = 4, 1
        source_layer, target_layer, dealer = 0, 1, 0
        private_per_receiver = 169_472
        raw_sum = (
            MODULE._public_payload_bytes(600)
            + MODULE._public_payload_bytes(MODULE._rand_poly_count(n, t))
            + n * private_per_receiver
        )
        dummy = 100_000
        proposal_overhead = sum(
            MODULE._pickle_size(
                MODULE._current_message(
                    source_layer,
                    dealer,
                    target_layer,
                    instance,
                    1,
                    bytes(dummy),
                )
            )
            - dummy
            for instance in ("main", "rand")
        )
        controls = sum(
            MODULE._pickle_size(
                MODULE._current_message(
                    source_layer,
                    dealer,
                    target_layer,
                    instance,
                    message_type,
                    bytes(32),
                )
            )
            for instance in ("main", "rand")
            for message_type in (2, 3)
        )
        source_bytes = n * (raw_sum + proposal_overhead + controls)
        result = MODULE.infer_combined_private_ciphertext_bytes(
            source_bytes, n, t, source_layer, dealer, target_layer
        )
        self.assertEqual(
            result["combined_private_ciphertext_bytes_per_receiver"],
            private_per_receiver,
        )

    def test_local_measurements_calibrate_exactly(self):
        expected = {(4, 1): 169_472, (10, 3): 259_888, (16, 5): 291_504}
        if not MODULE.DEFAULT_LOCAL_ROOT.is_dir():
            self.skipTest("Figure 9 local artifacts are unavailable")
        for (n, t), private_bytes in expected.items():
            case = MODULE.load_local_case(MODULE.DEFAULT_LOCAL_ROOT, n, t)
            self.assertEqual(
                case.calibration[
                    "combined_private_ciphertext_bytes_per_receiver"
                ],
                private_bytes,
            )

    def test_transport_message_multiplicity_and_split_bound(self):
        n, t = 16, 5
        combined = 291_504
        splits = MODULE.private_split_stripe_bounds(combined, n, t)
        lower = MODULE.simulate_rbc_avid_transport(
            n, t, 0, 1,
            splits["lower"]["main_ciphertext_bytes"],
            splits["lower"]["rand_ciphertext_bytes"],
        )
        upper = MODULE.simulate_rbc_avid_transport(
            n, t, 0, 1,
            splits["upper"]["main_ciphertext_bytes"],
            splits["upper"]["rand_ciphertext_bytes"],
        )
        # For every dealer and both ACSS instances: n RBC VAL + n AVID VAL,
        # then six destination all-to-all message classes in total.
        expected_messages = 2 * n * (2 * n + 6 * n * (n - 1))
        self.assertEqual(lower.total_messages, expected_messages)
        self.assertEqual(upper.total_messages, expected_messages)
        self.assertLessEqual(
            upper.total_bytes - lower.total_bytes,
            n * n * (2 * n - 1),
        )

    def test_conservative_interval_covers_64k_frame_boundary(self):
        if not MODULE.DEFAULT_LOCAL_ROOT.is_dir():
            self.skipTest("Figure 9 local artifacts are unavailable")
        case = MODULE.load_local_case(MODULE.DEFAULT_LOCAL_ROOT, 4, 1)
        result = MODULE.evaluate_case(case)
        combined = case.calibration[
            "combined_private_ciphertext_bytes_per_receiver"
        ]
        main_bytes = MODULE._minimum_ciphertext_bytes(600)
        rand_bytes = combined - main_bytes
        extreme = MODULE.simulate_rbc_avid_transport(
            4, 1, 0, 1, main_bytes, rand_bytes
        )
        retained = result["bounds"]["lower"]["measured_handoffs"][0][
            "retained_measured_other_ap_bytes"
        ]
        actual_candidate = retained + extreme.total_bytes
        low = result["bounds"]["lower"]["per_handoff_simulated_ap_bytes"]
        high = result["bounds"]["upper"]["per_handoff_simulated_ap_bytes"]
        self.assertLessEqual(low, actual_candidate)
        self.assertLessEqual(actual_candidate, high)
        for bound_name in ("lower", "upper"):
            bound = result["bounds"][bound_name]
            components = bound["d_total_components_bytes"]
            self.assertEqual(
                components["public_rbc"]
                + components["private_avid"]
                + components["retained_measured_other_ap"],
                bound["d_total_simulated_ap_bytes"],
            )


if __name__ == "__main__":
    unittest.main()
