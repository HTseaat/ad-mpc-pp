import asyncio
import itertools
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from pypairing import G1, ZR, blsmultiexp as multiexp, dotprod

from adkg.bundle import (
    Bundle_Foll,
    batchbundle_batch_count,
    batchbundle_extraction_matrix,
)
from adkg.utils.bitmap import Bitmap


class _ControlledFollowerACSS:
    def __init__(self, dealer_results):
        self.dealer_results = dealer_results
        self.killed = False

    async def avss_bundle(self, _avss_id, dealer_id, _secret_count):
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
    follower = Bundle_Foll.__new__(Bundle_Foll)
    follower.n = 4
    follower.t = 1
    follower.deg = 1
    follower.sc = 2
    follower.my_id = 0
    follower.public_keys = [None] * follower.n
    follower.private_key = None
    follower.g = G1.rand(b"g")
    follower.h = G1.rand(b"h")
    follower.pc = None
    follower.ZR = ZR
    follower.G1 = G1
    follower.multiexp = multiexp
    follower.dotprod = dotprod
    follower.get_send = lambda _tag: None
    follower.subscribe_recv = lambda _tag: None
    follower.mpc_instance = SimpleNamespace(layer_ID=1)
    follower.metrics_protocol = "randgen"
    follower.quorum_size = follower.n - follower.t
    follower.outputs_per_batch = follower.t + 1
    follower.bundle_extraction_matrix = batchbundle_extraction_matrix(
        ZR, follower.t
    )
    follower.acss_instances = []
    follower.rbc_tasks = []
    return follower


def _dealer_result(dealer, follower, batch_count=1):
    rand_values = [
        ZR(100 * dealer + batch + 1)
        for batch in range(batch_count)
    ]
    hat_values = [
        ZR(100 * dealer + batch_count + batch + 1)
        for batch in range(batch_count)
    ]
    commitments = [
        multiexp([follower.g, follower.h], [rand, hat])
        for rand, hat in zip(rand_values, hat_values)
    ]
    return (
        dealer,
        0,
        {"msg": [rand_values + hat_values]},
        f"commitments-{dealer}",
        [commitments],
    )


class BatchBundleParameterTests(unittest.TestCase):
    def test_batch_count_uses_t_plus_one_outputs(self):
        self.assertEqual(batchbundle_batch_count(100, 1), 50)
        self.assertEqual(batchbundle_batch_count(100, 3), 25)
        self.assertEqual(batchbundle_batch_count(100, 5), 17)
        self.assertEqual(batchbundle_batch_count(100, 7), 13)
        self.assertEqual(batchbundle_batch_count(0, 1), 1)

    def test_extraction_matrix_has_mds_vandermonde_orientation(self):
        for threshold in (1, 3):
            matrix = batchbundle_extraction_matrix(ZR, threshold)
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


class BatchBundleQuorumTests(unittest.IsolatedAsyncioTestCase):
    async def test_run_bundle_rejects_legacy_n_minus_t_round_count(self):
        follower = _make_follower()
        with self.assertRaisesRegex(ValueError, "ceil\\(w/\\(t\\+1\\)\\)"):
            await follower.run_bundle(100, 34)

    async def test_run_bundle_returns_without_waiting_for_late_dealer(self):
        follower = _make_follower()
        loop = asyncio.get_running_loop()
        dealer_results = [loop.create_future() for _ in range(follower.n)]

        async def fake_agreement(
                key_proposal, _outputs, _w_outputs, _dealer_ready):
            async def finish_agreement():
                return None

            async def extract():
                return (
                    tuple(key_proposal),
                    [[ZR(7), ZR(8)]],
                    [[ZR(9), ZR(10)]],
                    [[G1.identity(), G1.identity()]],
                )

            return finish_agreement(), extract(), []

        follower.agreement_dynamic = fake_agreement
        with patch(
            "adkg.bundle.ACSS_Foll",
            side_effect=lambda *_args, **_kwargs: _ControlledFollowerACSS(
                dealer_results
            ),
        ):
            protocol = asyncio.create_task(follower.run_bundle(2, 1))
            await asyncio.sleep(0)
            for dealer in (0, 2, 3):
                dealer_results[dealer].set_result(
                    _dealer_result(dealer, follower)
                )

            rand, hat, commitments = await asyncio.wait_for(
                protocol, timeout=0.2
            )
            self.assertEqual(rand, [ZR(7), ZR(8)])
            self.assertEqual(hat, [ZR(9), ZR(10)])
            self.assertEqual(commitments, [G1.identity(), G1.identity()])
            self.assertEqual(follower.common_subset, (0, 2, 3))
            self.assertFalse(follower.acss_task.done())

            dealer_results[1].set_result(_dealer_result(1, follower))
            await asyncio.wait_for(follower.acss_task, timeout=0.2)

        follower.kill()

    async def test_quorum_advances_and_w_outputs_are_dealer_keyed(self):
        follower = _make_follower()
        loop = asyncio.get_running_loop()
        dealer_results = [loop.create_future() for _ in range(follower.n)]
        instances = []

        def make_acss(*_args, **_kwargs):
            instance = _ControlledFollowerACSS(dealer_results)
            instances.append(instance)
            return instance

        outputs = {}
        w_outputs = {}
        dealer_ready = [asyncio.Event() for _ in range(follower.n)]
        quorum_proposal = loop.create_future()

        with patch("adkg.bundle.ACSS_Foll", side_effect=make_acss):
            collector = asyncio.create_task(
                follower.acss_step(
                    2,
                    outputs,
                    w_outputs,
                    quorum_proposal,
                    dealer_ready,
                )
            )
            await asyncio.sleep(0)

            for dealer in (3, 0, 2):
                dealer_results[dealer].set_result(
                    _dealer_result(dealer, follower)
                )
                await asyncio.sleep(0)

            proposal = await asyncio.wait_for(quorum_proposal, timeout=0.2)
            self.assertEqual(proposal, (0, 2, 3))
            self.assertEqual(set(outputs), {0, 2, 3})
            self.assertEqual(set(w_outputs), {0, 2, 3})
            self.assertFalse(collector.done())
            self.assertFalse(dealer_ready[1].is_set())

            dealer_results[1].set_result(_dealer_result(1, follower))
            await asyncio.wait_for(collector, timeout=0.2)
            self.assertEqual(set(outputs), {0, 1, 2, 3})
            self.assertEqual(set(w_outputs), {0, 1, 2, 3})

        follower.kill()
        self.assertTrue(all(instance.killed for instance in instances))

    async def test_failed_dealer_does_not_fail_valid_quorum(self):
        follower = _make_follower()
        loop = asyncio.get_running_loop()
        dealer_results = [loop.create_future() for _ in range(follower.n)]
        outputs = {}
        w_outputs = {}
        dealer_ready = [asyncio.Event() for _ in range(follower.n)]
        quorum_proposal = loop.create_future()

        with patch(
            "adkg.bundle.ACSS_Foll",
            side_effect=lambda *_args, **_kwargs: _ControlledFollowerACSS(
                dealer_results
            ),
        ):
            collector = asyncio.create_task(
                follower.acss_step(
                    2,
                    outputs,
                    w_outputs,
                    quorum_proposal,
                    dealer_ready,
                )
            )
            await asyncio.sleep(0)
            dealer_results[1].set_exception(ValueError("invalid dealer"))
            for dealer in (0, 2, 3):
                dealer_results[dealer].set_result(
                    _dealer_result(dealer, follower)
                )

            proposal = await asyncio.wait_for(quorum_proposal, timeout=0.2)
            await asyncio.wait_for(collector, timeout=0.2)
            self.assertEqual(proposal, (0, 2, 3))
            self.assertEqual(set(outputs), {0, 2, 3})
            self.assertEqual(set(w_outputs), {0, 2, 3})
            self.assertFalse(dealer_ready[1].is_set())

        follower.kill()

    async def test_exact_proposal_waits_only_for_named_dealers(self):
        follower = _make_follower()
        outputs = {}
        w_outputs = {}
        dealer_ready = [asyncio.Event() for _ in range(follower.n)]
        encoded = follower._encode_proposal((1, 2, 3))
        predicate = asyncio.create_task(
            follower._proposal_is_valid(
                encoded, outputs, w_outputs, dealer_ready
            )
        )
        await asyncio.sleep(0)
        self.assertFalse(predicate.done())

        for dealer in (1, 2, 3):
            result = _dealer_result(dealer, follower)
            outputs[dealer] = result[2]["msg"]
            w_outputs[dealer] = result[4]
            dealer_ready[dealer].set()
        self.assertTrue(await asyncio.wait_for(predicate, timeout=0.2))

        too_small = Bitmap(follower.n)
        too_small.set_bit(1)
        too_small.set_bit(2)
        self.assertFalse(await follower._proposal_is_valid(
            bytes(too_small.array), outputs, w_outputs, dealer_ready
        ))

        noncanonical = bytearray(encoded)
        noncanonical[0] |= 1
        self.assertIsNone(follower._decode_proposal(noncanonical))

    async def test_extraction_uses_one_common_set_for_r_hat_and_w(self):
        follower = _make_follower()
        batch_count = 2
        follower.rand_num = 2 * batch_count
        common_set = (1, 2, 3)
        acss_outputs = {}
        w_outputs = {}
        for dealer in common_set:
            result = _dealer_result(dealer, follower, batch_count)
            acss_outputs[dealer] = result[2]["msg"]
            w_outputs[dealer] = result[4]

        # A completed but unselected dealer must not affect any output.
        late_result = _dealer_result(0, follower, batch_count)
        acss_outputs[0] = late_result[2]["msg"]
        w_outputs[0] = late_result[4]

        dealer_ready = [asyncio.Event() for _ in range(follower.n)]
        for dealer in common_set:
            dealer_ready[dealer].set()
        rbc_values = [None, list(common_set), [0, 1, 2], None]
        rbc_signal = asyncio.Event()
        rbc_signal.set()

        selected, rand, hat, commitments = (
            await follower.generate_rand_dynamic(
                acss_outputs,
                w_outputs,
                dealer_ready,
                rbc_values,
                rbc_signal,
            )
        )
        self.assertEqual(selected, common_set)
        self.assertEqual(len(rand), batch_count)
        self.assertTrue(all(
            len(batch) == follower.t + 1 for batch in rand
        ))
        self.assertTrue(all(
            len(batch) == follower.t + 1 for batch in hat
        ))
        self.assertTrue(all(
            len(batch) == follower.t + 1 for batch in commitments
        ))

        for batch_index in range(batch_count):
            rand_inputs = [
                acss_outputs[dealer][0][batch_index]
                for dealer in common_set
            ]
            hat_inputs = [
                acss_outputs[dealer][0][batch_count + batch_index]
                for dealer in common_set
            ]
            commitment_inputs = [
                w_outputs[dealer][0][batch_index]
                for dealer in common_set
            ]
            for output_index, row in enumerate(
                    follower.bundle_extraction_matrix):
                self.assertEqual(
                    rand[batch_index][output_index],
                    dotprod(row, rand_inputs),
                )
                self.assertEqual(
                    hat[batch_index][output_index],
                    dotprod(row, hat_inputs),
                )
                self.assertEqual(
                    commitments[batch_index][output_index],
                    multiexp(commitment_inputs, row),
                )
                self.assertEqual(
                    commitments[batch_index][output_index],
                    multiexp(
                        [follower.g, follower.h],
                        [
                            rand[batch_index][output_index],
                            hat[batch_index][output_index],
                        ],
                    ),
                )


if __name__ == "__main__":
    unittest.main()
