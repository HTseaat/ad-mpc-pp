import asyncio
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from beaver.batch_multiplication import BatchMul_Foll
from beaver.broadcast.otmvba_dyn import OptimalCommonSet


class _FakeACSS:
    def __init__(self):
        self.output_queue = asyncio.Queue()
        self._stop = asyncio.Event()

    async def avss(self, *args, **kwargs):
        await self._stop.wait()

    def kill(self):
        self._stop.set()


class BatchMulCollectorTests(unittest.IsolatedAsyncioTestCase):
    async def test_n128_t42_freezes_86_dealers(self):
        follower = BatchMul_Foll.__new__(BatchMul_Foll)
        follower.n = 128
        follower.t = 42
        follower.my_id = 0
        follower.public_keys = None
        follower.private_key = None
        follower.srs = None
        follower.get_send = lambda tag: None
        follower.subscribe_recv = lambda tag: None
        follower.mpc_instance = SimpleNamespace(
            layer_ID=2, fault_controller=None, metrics_recorder=None
        )

        fake_acss = _FakeACSS()
        outputs = {}
        dealer_ready = [asyncio.Event() for _ in range(follower.n)]
        quorum_proposal = asyncio.get_running_loop().create_future()

        with patch(
            "beaver.batch_multiplication.ACSS_Foll", return_value=fake_acss
        ):
            collector = asyncio.create_task(
                follower.acss_step(
                    "avss_with_aggbatch_multiplication",
                    outputs,
                    1,
                    quorum_proposal,
                    dealer_ready,
                )
            )
            await asyncio.sleep(0)
            for dealer in range(86):
                await fake_acss.output_queue.put(
                    (dealer, 0, b"s", b"c", b"left", b"right")
                )
            proposal = await asyncio.wait_for(quorum_proposal, timeout=0.5)
            self.assertEqual(len(proposal), 86)
            self.assertEqual(proposal, tuple(range(86)))

            for dealer in range(86, 128):
                await fake_acss.output_queue.put(
                    (dealer, 0, b"s", b"c", b"left", b"right")
                )
            await asyncio.wait_for(collector, timeout=0.5)

        fake_acss.kill()
        for task in follower.acss_tasks:
            task.cancel()
        await asyncio.gather(*follower.acss_tasks, return_exceptions=True)

    async def test_n_minus_t_quorum_is_frozen_and_late_dealer_wakes_mvba(self):
        recorded_quorums = []
        follower = BatchMul_Foll.__new__(BatchMul_Foll)
        follower.n = 5
        follower.t = 1
        follower.my_id = 0
        follower.public_keys = None
        follower.private_key = None
        follower.srs = None
        follower.get_send = lambda tag: None
        follower.subscribe_recv = lambda tag: None
        follower.mpc_instance = SimpleNamespace(
            layer_ID=2,
            fault_controller=None,
            metrics_recorder=SimpleNamespace(
                record_proof_quorum=lambda **entry: recorded_quorums.append(
                    entry
                )
            ),
        )

        fake_acss = _FakeACSS()
        outputs = {}
        dealer_ready = [asyncio.Event() for _ in range(follower.n)]
        quorum_proposal = asyncio.get_running_loop().create_future()

        with patch(
            "beaver.batch_multiplication.ACSS_Foll", return_value=fake_acss
        ):
            collector = asyncio.create_task(
                follower.acss_step(
                    "avss_with_aggbatch_multiplication",
                    outputs,
                    1,
                    quorum_proposal,
                    dealer_ready,
                )
            )
            await asyncio.sleep(0)

            for dealer in (4, 2, 0, 3):
                await fake_acss.output_queue.put(
                    (
                        dealer, 0, f"s{dealer}".encode(),
                        f"c{dealer}".encode(), b"left", b"right",
                    )
                )

            proposal = await asyncio.wait_for(quorum_proposal, timeout=0.2)
            self.assertEqual(proposal, (0, 2, 3, 4))
            self.assertEqual(len(proposal), follower.n - follower.t)
            self.assertEqual(recorded_quorums, [{
                "protocol": "batchmul", "target_layer": 2,
                "receiver_local_id": 0, "dealer_ids": (0, 2, 3, 4),
                "required_count": 4,
            }])
            self.assertFalse(dealer_ready[1].is_set())

            acs = OptimalCommonSet.__new__(OptimalCommonSet)
            acs.acss_outputs = outputs
            acs.acss_signal = asyncio.Event()
            acs.dealer_ready = dealer_ready
            waiter = asyncio.create_task(acs._wait_for_dealers([1]))
            await asyncio.sleep(0)
            self.assertFalse(waiter.done())

            await fake_acss.output_queue.put(
                (1, 0, b"s1", b"c1", b"left", b"right")
            )
            await asyncio.wait_for(collector, timeout=0.2)
            await asyncio.wait_for(waiter, timeout=0.2)
            self.assertIn(1, outputs)
            self.assertTrue(dealer_ready[1].is_set())

        fake_acss.kill()
        for task in follower.acss_tasks:
            task.cancel()
        await asyncio.gather(*follower.acss_tasks, return_exceptions=True)

    async def test_late_commitment_fork_is_never_published(self):
        follower = BatchMul_Foll.__new__(BatchMul_Foll)
        follower.n = 4
        follower.t = 1
        follower.my_id = 0
        follower.public_keys = None
        follower.private_key = None
        follower.srs = None
        follower.get_send = lambda tag: None
        follower.subscribe_recv = lambda tag: None
        follower.mpc_instance = SimpleNamespace(
            layer_ID=2, fault_controller=None, metrics_recorder=None
        )

        fake_acss = _FakeACSS()
        outputs = {}
        dealer_ready = [asyncio.Event() for _ in range(follower.n)]
        quorum_proposal = asyncio.get_running_loop().create_future()

        with patch(
            "beaver.batch_multiplication.ACSS_Foll", return_value=fake_acss
        ):
            collector = asyncio.create_task(
                follower.acss_step(
                    "avss_with_aggbatch_multiplication",
                    outputs,
                    1,
                    quorum_proposal,
                    dealer_ready,
                )
            )
            await asyncio.sleep(0)
            for dealer in (0, 1, 2):
                await fake_acss.output_queue.put(
                    (dealer, 0, b"s", b"c", b"left", b"right")
                )
            await asyncio.wait_for(quorum_proposal, timeout=0.2)
            await fake_acss.output_queue.put(
                (3, 0, b"s", b"c", b"fork-left", b"right")
            )
            await asyncio.sleep(0)
            self.assertNotIn(3, outputs)
            self.assertFalse(dealer_ready[3].is_set())
            await fake_acss.output_queue.put(
                (3, 0, b"s", b"c", b"left", b"right")
            )
            await asyncio.wait_for(collector, timeout=0.2)
            self.assertIn(3, outputs)
            self.assertTrue(dealer_ready[3].is_set())

        fake_acss.kill()
        for task in follower.acss_tasks:
            task.cancel()
        await asyncio.gather(*follower.acss_tasks, return_exceptions=True)


if __name__ == "__main__":
    unittest.main()
