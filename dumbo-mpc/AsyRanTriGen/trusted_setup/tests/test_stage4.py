from __future__ import annotations

import asyncio
import unittest

from trusted_setup.config import SetupParams
from trusted_setup.protocol.base_link import (
    BASE_LINK_TAG,
    H_HASH_DOMAIN,
    public_bases,
    verify_same_exponent,
)
from trusted_setup.protocol.distributed_tau import run_local_setup
from trusted_setup.protocol.verification import (
    tampered_dleq_proof_is_rejected,
    tampered_h_commitment_is_rejected,
    verify_result,
)


class StageFourBaseLinkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.params = SetupParams.create(
            4, 1, 4, run_id="stage-4-base-link-tests"
        )
        cls.result = asyncio.run(run_local_setup(cls.params))

    def test_canonical_public_bases(self):
        from pypairing import G1, G2

        g, h, g2 = public_bases()
        self.assertEqual(g, G1())
        self.assertEqual(h, G1.hash(H_HASH_DOMAIN))
        self.assertEqual(g2, G2())
        self.assertNotEqual(g, h)

    def test_all_honest_links_and_complete_views_verify(self):
        report = verify_result(self.result)
        self.assertTrue(report.public_bases_ok)
        self.assertTrue(report.base_link_dleq_ok)
        self.assertTrue(report.all_parties_same_h_commitments)
        self.assertTrue(report.all_parties_same_base_link_messages)
        self.assertTrue(report.reconstructed_h_powers_ok)
        self.assertTrue(report.pairing_recurrence_ok)
        self.assertTrue(report.ok, report)

        first = self.result.parties[0]
        self.assertEqual(len(first.t_commits_h), self.params.log_q + 1)
        self.assertTrue(
            all(len(row) == self.params.n + 1 for row in first.t_commits_h)
        )
        self.assertTrue(
            all(
                party.t_commits_h == first.t_commits_h
                for party in self.result.parties
            )
        )

    def test_h_commitment_and_proof_tampering_are_rejected(self):
        self.assertTrue(tampered_h_commitment_is_rejected(self.result))
        self.assertTrue(tampered_dleq_proof_is_rejected(self.result))

    def test_transcript_binds_power_index(self):
        first = self.result.parties[0]
        message = first.base_link_messages[0]
        proof = message.proofs[0]
        self.assertTrue(
            verify_same_exponent(
                first.t_commits_g[0][1],
                message.h_commitments[0],
                proof,
                g=self.result.g,
                h=self.result.h,
                run_id=self.params.run_id,
                party_id=0,
                power_index=0,
            )
        )
        self.assertFalse(
            verify_same_exponent(
                first.t_commits_g[0][1],
                message.h_commitments[0],
                proof,
                g=self.result.g,
                h=self.result.h,
                run_id=self.params.run_id,
                party_id=0,
                power_index=1,
            )
        )

    def test_stage_four_output_has_the_expected_powers_of_two_shape(self):
        first = self.result.parties[0]
        self.assertEqual(
            len(first.powers_of_two_h1), self.params.log_q + 1
        )
        self.assertEqual(len(first.h_chain), self.params.effective_powers)
        self.assertEqual(BASE_LINK_TAG, "BASE_LINK")


if __name__ == "__main__":
    unittest.main()
