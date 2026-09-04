import unittest

from scripts.admpc_dynamic_nonlinear_run import _communication_metrics_context


class NonlinearMetricsContextTests(unittest.TestCase):
    def test_figure9_nonlinear_artifacts_expect_proof_metrics(self):
        context = _communication_metrics_context(
            n=4,
            t=1,
            layers=8,
            my_id=0,
            my_send_id=0,
            total_cm=600,
        )

        self.assertEqual(context["experiment"], "figure9")
        self.assertEqual(context["protocol_variant"], "admpc-nonlinear")
        self.assertIs(context["parameters"]["proof_metrics_expected"], True)
        self.assertEqual(
            context["parameters"]["evaluation_verifier_mode"],
            "legacy-inner-proof-only",
        )


if __name__ == "__main__":
    unittest.main()
