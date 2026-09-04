import asyncio
import itertools
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from pypairing import G1, ZR, dotprod

from adkg.rand import (
    Rand_Foll,
    batchrand_batch_count,
    batchrand_extraction_matrix,
)
from adkg.utils.bitmap import Bitmap


class _ControlledFollowerACSS:
    def __init__(self, dealer_results):
        self.dealer_results = dealer_results
        self.killed = False

    async def avss(self, _avss_id, dealer_id, _rounds):
        return await self.dealer_results[dealer_id]

    def kill(self):
        self.killed = True


def _determinant(matrix):
    if len(matrix) == 1:
        return matrix[0][0]
    total = ZR(0)
    for column, value in enumerate(matrix[0]):
        minor = [
            row[:column] + row[column + 1:]
            for row in matrix[1:]
        ]
        term = value * _determinant(minor)
        total = total + term if column % 2 == 0 else total - term
    return total


def _make_follower():
    follower = Rand_Foll.__new__(Rand_Foll)
    follower.n = 4
    follower.t = 1
    follower.deg = 1
    follower.sc = 2
    follower.my_id = 0
    follower.public_keys = [None] * follower.n
    follower.private_key = None
    follower.g = None
    follower.h = None
    follower.pc = None
    follower.ZR = ZR
    follower.G1 = G1
    follower.dotprod = dotprod
    follower.get_send = lambda _tag: None
    follower.subscribe_recv = lambda _tag: None
    follower.mpc_instance = SimpleNamespace(layer_ID=1)
    follower.metrics_protocol = "batchrand"
    follower.quorum_size = follower.n - follower.t
    follower.outputs_per_batch = follower.t + 1
    follower.rand_extraction_matrix = batchrand_extraction_matrix(
        ZR, follower.t
    )
    follower.acss_instances = []
    follower.rbc_tasks = []
    return follower


def _dealer_result(dealer, rounds=1):
    values = [ZR(10 * dealer + index + 1) for index in range(rounds)]
    return dealer, 0, {"msg": [values]}, f"commitments-{dealer}"


class BatchRandParameterTests(unittest.TestCase):
    def test_batch_count_uses_t_plus_one_outputs(self):
        self.assertEqual(batchrand_batch_count(100, 1), 50)
        self.assertEqual(batchrand_batch_count(100, 3), 25)
        self.assertEqual(batchrand_batch_count(100, 5), 17)
        self.assertEqual(batchrand_batch_count(100, 7), 13)
        self.assertEqual(batchrand_batch_count(0, 1), 1)

    def test_extraction_matrix_has_mds_vandermonde_orientation(self):
        for threshold in (1, 3):
            matrix = batchrand_extraction_matrix(ZR, threshold)
            rows = threshold + 1
            columns = 2 * threshold + 1
            self.assertEqual(len(matrix), rows)
            self.assertTrue(all(len(row) == columns for row in matrix))
            for selected_columns in itertools.combinations(
                    range(columns), rows):
                square = [
                    [row[column] for column in selected_columns]
                    for row in matrix
                ]
                self.assertNotEqual(_determinant(square), ZR(0))


class BatchRandQuorumTests(unittest.IsolatedAsyncioTestCase):
    async def test_run_rand_rejects_legacy_n_minus_t_round_count(self):
        follower = _make_follower()
        with self.assertRaisesRegex(ValueError, "ceil\\(w/\\(t\\+1\\)\\)"):
            await follower.run_rand(100, 34)

    async def test_run_rand_returns_without_waiting_for_late_dealer(self):
        follower = _make_follower()
        loop = asyncio.get_running_loop()
        dealer_results = [loop.create_future() for _ in range(follower.n)]

        async def fake_agreement(key_proposal, _outputs, _dealer_ready):
            async def finish_agreement():
                return None

            async def extract():
                return tuple(key_proposal), [[ZR(7), ZR(8)]]

            return finish_agreement(), extract(), []

        follower.agreement_dynamic = fake_agreement
        with patch(
            "adkg.rand.ACSS_Foll",
            side_effect=lambda *_args, **_kwargs: _ControlledFollowerACSS(
                dealer_results
            ),
        ):
            protocol = asyncio.create_task(follower.run_rand(2, 1))
            await asyncio.sleep(0)
            for dealer in (0, 2, 3):
                dealer_results[dealer].set_result(_dealer_result(dealer))

            shares = await asyncio.wait_for(protocol, timeout=0.2)
            self.assertEqual(shares, [ZR(7), ZR(8)])
            self.assertEqual(follower.common_subset, (0, 2, 3))
            self.assertFalse(follower.acss_task.done())

            dealer_results[1].set_result(_dealer_result(1))
            await asyncio.wait_for(follower.acss_task, timeout=0.2)

        follower.kill()

    async def test_quorum_advances_and_late_dealer_is_collected(self):
        follower = _make_follower()
        loop = asyncio.get_running_loop()
        dealer_results = [loop.create_future() for _ in range(follower.n)]
        instances = []

        def make_acss(*_args, **_kwargs):
            instance = _ControlledFollowerACSS(dealer_results)
            instances.append(instance)
            return instance

        outputs = {}
        dealer_ready = [asyncio.Event() for _ in range(follower.n)]
        quorum_proposal = loop.create_future()

        with patch("adkg.rand.ACSS_Foll", side_effect=make_acss):
            collector = asyncio.create_task(
                follower.acss_step(
                    1, outputs, quorum_proposal, dealer_ready
                )
            )
            await asyncio.sleep(0)

            for dealer in (3, 0, 2):
                dealer_results[dealer].set_result(_dealer_result(dealer))
                await asyncio.sleep(0)

            proposal = await asyncio.wait_for(quorum_proposal, timeout=0.2)
            self.assertEqual(proposal, (0, 2, 3))
            self.assertEqual(set(outputs), {0, 2, 3})
            self.assertFalse(collector.done())
            self.assertFalse(dealer_ready[1].is_set())

            dealer_results[1].set_result(_dealer_result(1))
            await asyncio.wait_for(collector, timeout=0.2)
            self.assertEqual(set(outputs), {0, 1, 2, 3})
            self.assertTrue(dealer_ready[1].is_set())
            self.assertEqual(len(follower.acss_instances), follower.n)

        follower.kill()
        self.assertTrue(all(instance.killed for instance in instances))

    async def test_failed_dealer_does_not_fail_valid_quorum(self):
        follower = _make_follower()
        loop = asyncio.get_running_loop()
        dealer_results = [loop.create_future() for _ in range(follower.n)]
        outputs = {}
        dealer_ready = [asyncio.Event() for _ in range(follower.n)]
        quorum_proposal = loop.create_future()

        with patch(
            "adkg.rand.ACSS_Foll",
            side_effect=lambda *_args, **_kwargs: _ControlledFollowerACSS(
                dealer_results
            ),
        ):
            collector = asyncio.create_task(
                follower.acss_step(
                    1, outputs, quorum_proposal, dealer_ready
                )
            )
            await asyncio.sleep(0)
            dealer_results[1].set_exception(ValueError("invalid dealer"))
            for dealer in (0, 2, 3):
                dealer_results[dealer].set_result(_dealer_result(dealer))

            proposal = await asyncio.wait_for(quorum_proposal, timeout=0.2)
            await asyncio.wait_for(collector, timeout=0.2)
            self.assertEqual(proposal, (0, 2, 3))
            self.assertEqual(set(outputs), {0, 2, 3})
            self.assertFalse(dealer_ready[1].is_set())

        follower.kill()

    async def test_exact_proposal_waits_only_for_named_dealers(self):
        follower = _make_follower()
        outputs = {}
        dealer_ready = [asyncio.Event() for _ in range(follower.n)]
        encoded = follower._encode_proposal((1, 2, 3))
        predicate = asyncio.create_task(
            follower._proposal_is_valid(
                encoded, outputs, dealer_ready
            )
        )
        await asyncio.sleep(0)
        self.assertFalse(predicate.done())

        for dealer in (1, 2, 3):
            outputs[dealer] = [[ZR(dealer)]]
            dealer_ready[dealer].set()
        self.assertTrue(await asyncio.wait_for(predicate, timeout=0.2))

        too_small = Bitmap(follower.n)
        too_small.set_bit(1)
        too_small.set_bit(2)
        self.assertFalse(await follower._proposal_is_valid(
            bytes(too_small.array), outputs, dealer_ready
        ))

        noncanonical = bytearray(encoded)
        noncanonical[0] |= 1
        self.assertIsNone(follower._decode_proposal(noncanonical))

    async def test_extraction_uses_only_common_set_and_outputs_t_plus_one(self):
        follower = _make_follower()
        follower.rand_num = 2
        common_set = (1, 2, 3)
        acss_outputs = {
            dealer: [[ZR(10 * dealer + 1), ZR(10 * dealer + 2)]]
            for dealer in common_set
        }
        # A late/unselected dealer must not influence extraction.
        acss_outputs[0] = [[ZR(999), ZR(999)]]
        dealer_ready = [asyncio.Event() for _ in range(follower.n)]
        for dealer in common_set:
            dealer_ready[dealer].set()
        rbc_values = [None, list(common_set), [0, 1, 2], None]
        rbc_signal = asyncio.Event()
        rbc_signal.set()

        selected, extracted = await follower.generate_rand_dynamic(
            acss_outputs, dealer_ready, rbc_values, rbc_signal
        )
        self.assertEqual(selected, common_set)
        self.assertEqual(len(extracted), follower.rand_num)
        self.assertTrue(all(
            len(batch) == follower.t + 1 for batch in extracted
        ))

        for batch_index in range(follower.rand_num):
            inputs = [
                acss_outputs[dealer][0][batch_index]
                for dealer in common_set
            ]
            expected = [
                dotprod(row, inputs)
                for row in follower.rand_extraction_matrix
            ]
            self.assertEqual(extracted[batch_index], expected)


if __name__ == "__main__":
    unittest.main()
