import asyncio
from dataclasses import replace
import unittest

from beaver.broadcast.crypto.boldyreva import dealer
from committee_election.crypto import sign_share
from committee_election.model import ElectionContext
from committee_election.protocol import (
    ElectionTimeout,
    FaultPlan,
    InProcessElectionHarness,
    InjectedEnvelope,
    InsufficientSharesError,
    build_share_envelope,
)
from tests.test_committee_election_model import make_registry


class InProcessElectionProtocolTests(unittest.TestCase):
    def setUp(self):
        self.registry = make_registry(candidate_count=4, committee_size=4)
        self.context = ElectionContext.for_registry(
            run_id="async-run",
            source_committee_id="P1",
            target_epoch=2,
            registry=self.registry,
        )
        self.pk, self.sks = dealer(4, 2, seed=300)

    def harness(self, context=None):
        return InProcessElectionHarness(
            n=4,
            t=1,
            public_key=self.pk,
            private_keys=self.sks,
            registry=self.registry,
            context=context or self.context,
        )

    def test_all_honest_different_arrival_orders_agree(self):
        plan = FaultPlan(
            delivery_order_by_receiver={
                0: (0, 1, 2, 3),
                1: (3, 2, 1, 0),
                2: (1, 3, 0, 2),
                3: (2, 0, 3, 1),
            }
        )
        result = asyncio.run(self.harness().run(fault_plan=plan))
        self.assertEqual(len(result.nodes), 4)
        self.assertEqual(len(result.signature_digests), 1)
        self.assertEqual(len(result.committee_ids), 1)
        self.assertEqual(result.active_tasks_after, 0)

    def test_one_omission_does_not_block_completion(self):
        result = asyncio.run(
            self.harness().run(fault_plan=FaultPlan(omitted_senders=(3,)))
        )
        self.assertEqual(len(result.nodes), 4)
        for node in result.nodes.values():
            self.assertNotIn(3, node.metrics.accepted_share_ids)

    def test_one_invalid_sender_is_rejected_and_honest_nodes_complete(self):
        result = asyncio.run(
            self.harness().run(fault_plan=FaultPlan(invalid_senders=(3,)))
        )
        for node in result.nodes.values():
            self.assertEqual(node.metrics.rejection_counts.get("invalid_share"), 1)
            self.assertNotIn(3, node.metrics.accepted_share_ids)

    def test_duplicate_replay_context_mismatch_and_sender_spoof_are_rejected(self):
        valid_share, _ = sign_share(self.sks[0], self.pk, 0, self.context)
        cross_context = replace(self.context, target_epoch=3)
        cross_share, _ = sign_share(self.sks[1], self.pk, 1, cross_context)
        cross_envelope = build_share_envelope(cross_context, 1, cross_share)
        spoof_envelope = build_share_envelope(self.context, 1, valid_share)
        plan = FaultPlan(
            duplicate_senders=(0,),
            injected_envelopes=(
                InjectedEnvelope(0, 1, cross_envelope),
                InjectedEnvelope(0, 0, spoof_envelope),
            ),
        )
        result = asyncio.run(self.harness().run(fault_plan=plan))
        node0 = result.nodes[0]
        self.assertGreaterEqual(node0.metrics.rejection_counts.get("duplicate_share", 0), 1)
        self.assertEqual(node0.metrics.rejection_counts.get("context_mismatch"), 1)
        self.assertEqual(node0.metrics.rejection_counts.get("sender_mismatch"), 1)

    def test_registry_mismatch_malformed_share_and_unknown_sender_are_rejected(self):
        valid_share, _ = sign_share(self.sks[0], self.pk, 0, self.context)
        valid_envelope = build_share_envelope(self.context, 0, valid_share)
        share3, _ = sign_share(self.sks[3], self.pk, 3, self.context)
        envelope3 = build_share_envelope(self.context, 3, share3)
        plan = FaultPlan(
            delay_ms_by_sender={3: 10},
            injected_envelopes=(
                InjectedEnvelope(
                    0,
                    0,
                    replace(valid_envelope, registry_digest="0" * 64),
                ),
                InjectedEnvelope(
                    0,
                    3,
                    replace(envelope3, signature_share_b64="not-base64!"),
                ),
                InjectedEnvelope(0, 99, replace(valid_envelope, sender_local_id=99)),
            )
        )
        result = asyncio.run(self.harness().run(fault_plan=plan))
        rejections = result.nodes[0].metrics.rejection_counts
        self.assertEqual(rejections.get("context_mismatch"), 1)
        self.assertEqual(rejections.get("malformed_share"), 1)
        self.assertEqual(rejections.get("sender_out_of_range"), 1)

    def test_more_than_t_omissions_fail_closed(self):
        harness = self.harness()
        with self.assertRaises(InsufficientSharesError):
            asyncio.run(
                harness.run(fault_plan=FaultPlan(omitted_senders=(1, 2, 3)))
            )
        self.assertEqual(harness.active_tasks_after, 0)

    def test_two_target_epochs_run_concurrently_without_crossing(self):
        context3 = replace(self.context, target_epoch=3)

        async def run_both():
            return await asyncio.gather(
                self.harness(self.context).run(),
                self.harness(context3).run(),
            )

        result2, result3 = asyncio.run(run_both())
        self.assertEqual(len(result2.signature_digests), 1)
        self.assertEqual(len(result3.signature_digests), 1)
        self.assertNotEqual(result2.signature_digests, result3.signature_digests)
        self.assertTrue(all(node.certificate.target_epoch == 2 for node in result2.nodes.values()))
        self.assertTrue(all(node.certificate.target_epoch == 3 for node in result3.nodes.values()))

    def test_timeout_cancels_all_background_tasks(self):
        harness = self.harness()
        plan = FaultPlan(delay_ms_by_sender={0: 200, 1: 200, 2: 200, 3: 200})
        with self.assertRaises(ElectionTimeout):
            asyncio.run(harness.run(fault_plan=plan, timeout=0.01))
        self.assertEqual(harness.active_tasks_after, 0)


if __name__ == "__main__":
    unittest.main()
