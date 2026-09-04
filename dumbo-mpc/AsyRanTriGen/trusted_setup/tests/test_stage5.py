from __future__ import annotations

import asyncio
import unittest

from trusted_setup.config import SetupParams
from trusted_setup.protocol.distributed_tau import run_local_setup
from trusted_setup.protocol.dual_chain import AP_G_TAG, AP_H_TAG
from trusted_setup.protocol.verification import (
    mismatched_alpha_h_chain_is_rejected,
    tampered_h_chain_is_rejected,
    verify_result,
)


class StageFiveDualChainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.params = SetupParams.create(
            4, 1, 4, run_id="stage-5-dual-chain-tests"
        )
        cls.result = asyncio.run(run_local_setup(cls.params))

    def test_both_chains_are_complete_and_identical_at_every_party(self):
        first = self.result.parties[0]
        self.assertEqual(len(first.g_chain), self.params.effective_powers)
        self.assertEqual(len(first.h_chain), self.params.effective_powers)
        self.assertEqual(first.g_chain[0], self.result.g)
        self.assertEqual(first.h_chain[0], self.result.h)
        self.assertNotEqual(first.g_chain, first.h_chain)
        self.assertTrue(
            all(party.g_chain == first.g_chain for party in self.result.parties)
        )
        self.assertTrue(
            all(party.h_chain == first.h_chain for party in self.result.parties)
        )

    def test_both_chains_use_the_same_alpha(self):
        report = verify_result(self.result)
        self.assertTrue(report.reconstructed_chain_ok)
        self.assertTrue(report.reconstructed_h_chain_ok)
        self.assertTrue(report.pairing_recurrence_ok)
        self.assertTrue(report.h_pairing_recurrence_ok)
        self.assertTrue(report.ok, report)

    def test_h_chain_tamper_and_different_alpha_are_rejected(self):
        self.assertTrue(tampered_h_chain_is_rejected(self.result))
        self.assertTrue(mismatched_alpha_h_chain_is_rejected(self.result))

    def test_all_powers_routes_are_distinct_and_timed(self):
        self.assertEqual(AP_G_TAG, "AP_G")
        self.assertEqual(AP_H_TAG, "AP_H")
        self.assertNotEqual(AP_G_TAG, AP_H_TAG)
        self.assertGreater(self.result.g_all_powers_elapsed_seconds, 0)
        self.assertGreater(self.result.h_all_powers_elapsed_seconds, 0)
        self.assertEqual(self.result.pending_protocol_tasks, 0)


if __name__ == "__main__":
    unittest.main()
