import asyncio
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from beaver.broadcast.otmvba_dyn import OptimalCommonSet
from beaver.transfer import Transfer_Foll, _aggtrans_quorum_protocol


class _FakeACSS:
    def __init__(self):
        self.output_queue = asyncio.Queue()
        self._stop = asyncio.Event()

    async def avss(self, *args, **kwargs):
        await self._stop.wait()

    def kill(self):
        self._stop.set()


def test_quorum_protocol_uses_effective_noagg_mode():
    assert _aggtrans_quorum_protocol(
        SimpleNamespace(mode="avss_with_transfer"),
        "avss_with_aggtransfer",
    ) == "aggtrans-noagg"
    assert _aggtrans_quorum_protocol(
        SimpleNamespace(mode="avss_with_aggtransfer"),
        "avss_with_aggtransfer",
    ) == "aggtrans"


class DealerAvailabilityTests(unittest.IsolatedAsyncioTestCase):
    def _make_acs(self):
        acs = OptimalCommonSet.__new__(OptimalCommonSet)
        acs.acss_outputs = {0: {}}
        acs.acss_signal = asyncio.Event()
        acs.dealer_ready = [asyncio.Event() for _ in range(4)]
        acs.dealer_ready[0].set()
        return acs

    async def test_late_dealer_wakes_existing_waiter(self):
        acs = self._make_acs()
        waiter = asyncio.create_task(acs._wait_for_dealers([0, 3]))
        await asyncio.sleep(0)
        self.assertFalse(waiter.done())

        acs.acss_outputs[3] = {}
        acs.dealer_ready[3].set()

        await asyncio.wait_for(waiter, timeout=0.2)

    async def test_dealer_available_before_wait_returns_immediately(self):
        acs = self._make_acs()
        acs.acss_outputs[3] = {}
        acs.dealer_ready[3].set()

        await asyncio.wait_for(acs._wait_for_dealers([0, 3]), timeout=0.2)

    async def test_multiple_waiters_are_all_woken(self):
        acs = self._make_acs()
        waiters = [
            asyncio.create_task(acs._wait_for_dealers([3]))
            for _ in range(3)
        ]
        await asyncio.sleep(0)
        self.assertTrue(all(not waiter.done() for waiter in waiters))

        acs.acss_outputs[3] = {}
        acs.dealer_ready[3].set()

        await asyncio.wait_for(asyncio.gather(*waiters), timeout=0.2)


class AggTransCollectorTests(unittest.IsolatedAsyncioTestCase):
    async def test_quorum_is_frozen_and_late_matching_dealer_is_published(self):
        recorded_quorums = []
        follower = Transfer_Foll.__new__(Transfer_Foll)
        follower.n = 4
        follower.t = 1
        follower.my_id = 0
        follower.public_keys = None
        follower.private_key = None
        follower.srs = None
        follower.get_send = lambda tag: None
        follower.subscribe_recv = lambda tag: None
        follower.mpc_instance = SimpleNamespace(
            layer_ID=1,
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

        with patch("beaver.transfer.ACSS_Foll", return_value=fake_acss):
            collector = asyncio.create_task(
                follower.acss_step(
                    "avss_with_aggtransfer",
                    outputs,
                    1,
                    quorum_proposal,
                    dealer_ready,
                )
            )
            await asyncio.sleep(0)

            await fake_acss.output_queue.put((0, 0, b"s0", b"c0", b"majority"))
            await fake_acss.output_queue.put((2, 0, b"s2", b"c2", b"majority"))
            await fake_acss.output_queue.put((3, 0, b"s3", b"c3", b"majority"))

            proposal = await asyncio.wait_for(quorum_proposal, timeout=0.2)
            self.assertEqual(proposal, (0, 2, 3))
            self.assertEqual(recorded_quorums, [{
                "protocol": "aggtrans", "target_layer": 1,
                "receiver_local_id": 0, "dealer_ids": (0, 2, 3),
                "required_count": 3,
            }])
            self.assertEqual(set(outputs), {0, 2, 3})
            self.assertTrue(all(dealer_ready[d].is_set() for d in proposal))
            self.assertFalse(dealer_ready[1].is_set())
            self.assertFalse(collector.done())

            # A late dealer with a different original commitment must neither
            # enter outputs nor publish availability.
            await fake_acss.output_queue.put((1, 0, b"s1", b"c1", b"fork"))
            await asyncio.sleep(0)
            self.assertNotIn(1, outputs)
            self.assertFalse(dealer_ready[1].is_set())
            self.assertFalse(collector.done())

            await fake_acss.output_queue.put(
                (1, 0, b"s1-late", b"c1-late", b"majority")
            )
            await asyncio.wait_for(collector, timeout=0.2)
            self.assertTrue(dealer_ready[1].is_set())
            self.assertEqual(set(outputs), {0, 1, 2, 3})

        fake_acss.kill()
        for task in follower.acss_tasks:
            task.cancel()
        await asyncio.gather(*follower.acss_tasks, return_exceptions=True)


if __name__ == "__main__":
    unittest.main()
