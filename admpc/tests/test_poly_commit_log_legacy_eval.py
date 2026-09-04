import unittest
from unittest.mock import patch

from pypairing import G1, ZR

from adkg.poly_commit_log import PolyCommitLog


class InnerProofOnlyEvaluationVerifierTests(unittest.TestCase):
    def setUp(self):
        self.verifier = PolyCommitLog.__new__(PolyCommitLog)
        self.verifier.gs = [G1.rand(b"g0"), G1.rand(b"g1")]
        self.verifier.h = G1.rand(b"h")
        self.verifier.u = G1.rand(b"u")
        self.shared = [
            b"not-a-merkle-root",
            1,
            G1.rand(b"S"),
            [G1.rand(b"D")],
            ZR.random(),
        ]
        self.witness = [
            [],
            G1.rand(b"T"),
            [ZR.random()],
            (b"core-proof", b"tail-proof"),
        ]

    def test_verifier_unconditionally_uses_inner_proof_only_path(self):
        # Empty commitments/shares would fail the removed outer dimension and
        # binding checks.  The benchmark verifier must still call Rust once.
        with patch(
            "adkg.poly_commit_log."
            "polycommit_verify_double_batch_inner_product_one_known_but_differenter",
            return_value=True,
        ) as rust_verify:
            self.assertTrue(self.verifier.batch_verify_eval_rs(
                [], 1, [], self.shared, self.witness, degree=1
            ))
        rust_verify.assert_called_once()

    def test_verifier_returns_rust_inner_proof_result(self):
        with patch(
            "adkg.poly_commit_log."
            "polycommit_verify_double_batch_inner_product_one_known_but_differenter",
            return_value=False,
        ) as rust_verify:
            self.assertFalse(self.verifier.batch_verify_eval_rs(
                [], 1, [], self.shared, self.witness, degree=1
            ))
        rust_verify.assert_called_once()


if __name__ == "__main__":
    unittest.main()
