import asyncio
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from beaver.bgw_multiplication import BGWReduction


class _FakeACSS:
    def __init__(self):
        self.output_queue = asyncio.Queue()
        self._stop = asyncio.Event()

    async def avss(self, *args, **kwargs):
        await self._stop.wait()

    def kill(self):
        self._stop.set()


class BGWCollectorTests(unittest.IsolatedAsyncioTestCase):
    async def test_quorum_is_frozen_before_late_outputs_and_recorded(self):
        recorded_quorums = []
        reduction = BGWReduction.__new__(BGWReduction)
        reduction.n = 5
        reduction.t = 1
        reduction.my_id = 0
        reduction.public_keys = None
        reduction.private_key = None
        reduction.srs = None
        reduction.get_send = lambda tag: None
        reduction.subscribe_recv = lambda tag: None
        reduction.mpc_instance = SimpleNamespace(
            layer_ID=2,
            metrics_recorder=SimpleNamespace(
                record_proof_quorum=lambda **entry: recorded_quorums.append(
                    entry
                )
            ),
        )

        fake_acss = _FakeACSS()
        outputs = {}
        quorum_proposal = asyncio.get_running_loop().create_future()
        acss_signal = asyncio.Event()
        values = json.dumps({"commitment": [], "proof": []}).encode()

        with patch(
            "beaver.bgw_multiplication.Hbacss1", return_value=fake_acss
        ):
            collector = asyncio.create_task(
                reduction.acss_step(
                    outputs, values, quorum_proposal, acss_signal
                )
            )
            await asyncio.sleep(0)

            # Queue the quorum and the last dealer without yielding.  The
            # frozen proposal must not grow even if the collector drains all
            # queued outputs before the awaiting protocol task resumes.
            for dealer in (4, 2, 0, 3, 1):
                await fake_acss.output_queue.put(
                    (
                        dealer,
                        0,
                        f"s{dealer}".encode(),
                        f"c{dealer}".encode(),
                    )
                )

            proposal = await asyncio.wait_for(
                quorum_proposal, timeout=0.2
            )
            await asyncio.wait_for(collector, timeout=0.2)

            self.assertEqual(proposal, (0, 2, 3, 4))
            self.assertEqual(len(proposal), reduction.n - reduction.t)
            self.assertEqual(set(outputs), set(range(reduction.n)))
            self.assertTrue(acss_signal.is_set())
            self.assertEqual(recorded_quorums, [{
                "protocol": "bgw",
                "target_layer": 2,
                "receiver_local_id": 0,
                "dealer_ids": (0, 2, 3, 4),
                "required_count": 4,
            }])

        fake_acss.kill()
        for task in reduction.acss_tasks:
            task.cancel()
        await asyncio.gather(
            *reduction.acss_tasks, return_exceptions=True
        )


if __name__ == "__main__":
    unittest.main()
