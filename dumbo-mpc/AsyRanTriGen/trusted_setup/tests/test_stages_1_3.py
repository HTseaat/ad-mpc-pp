from __future__ import annotations

import asyncio
import unittest

from trusted_setup.config import SetupParams
from trusted_setup.protocol.distributed_tau import run_local_setup
from trusted_setup.protocol.verification import (
    tamper_is_rejected,
    tampered_dleq_proof_is_rejected,
    tampered_h_commitment_is_rejected,
    verify_result,
)


class StageOneToThreeIntegrationTests(unittest.TestCase):
    def test_development_matrix(self):
        for n, t, powers in ((4, 1, 2), (8, 2, 4), (16, 5, 8)):
            with self.subTest(n=n, t=t, powers=powers):
                params = SetupParams.create(
                    n, t, powers, run_id=f"stages-1-3-n{n}-t{t}-q{powers}"
                )
                result = asyncio.run(run_local_setup(params))
                report = verify_result(result)
                self.assertTrue(report.ok, report)
                self.assertTrue(tamper_is_rejected(result))
                self.assertTrue(tampered_h_commitment_is_rejected(result))
                self.assertTrue(tampered_dleq_proof_is_rejected(result))
                self.assertEqual(result.pending_protocol_tasks, 0)


if __name__ == "__main__":
    unittest.main()
