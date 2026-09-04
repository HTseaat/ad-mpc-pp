import asyncio
from pickle import dumps
import unittest

import zmq

from adkg.ipc import NodeCommunicator


class PayloadAccountingTests(unittest.IsolatedAsyncioTestCase):
    async def _account(self, auth_mode, auth_config=None):
        communicator = NodeCommunicator(
            [object(), object()], 0, auth_mode=auth_mode,
            auth_config=auth_config, readiness_barrier=False,
        )
        queue = asyncio.Queue()
        messages = [("", ("GR12", {"value": 1})), ("", ("GR12", b"abc"))]
        for message in messages:
            queue.put_nowait(message)
        queue.put_nowait(NodeCommunicator.LAST_MSG)

        async def fake_send(_frames):
            return None

        await communicator._process_node_messages(1, queue, fake_send)
        snapshot = communicator.snapshot_communication_metrics()
        communicator.zmq_context.destroy(linger=0)
        return snapshot, messages

    async def test_full_tag_bytes_and_messages_match_pickle(self):
        snapshot, messages = await self._account("null")
        expected = sum(len(dumps(message)) for message in messages)
        self.assertEqual(snapshot["total_remote_payload_bytes"], expected)
        self.assertEqual(snapshot["by_tag"]["GR12"], {"bytes": expected, "messages": 2})

    async def test_null_and_curve_accounting_are_identical(self):
        keypairs = [zmq.curve_keypair() for _ in range(2)]
        public_keys = [pair[0].decode("ascii") for pair in keypairs]
        config = {
            "curve_public_key": public_keys[0],
            "curve_secret_key": keypairs[0][1].decode("ascii"),
            "curve_public_keys": public_keys,
            "curve_zap_domain": "accounting-test",
            "run_id": "accounting-test",
        }
        null_snapshot, _ = await self._account("null")
        curve_snapshot, _ = await self._account("curve", config)
        self.assertEqual(null_snapshot, curve_snapshot)

    async def test_control_and_self_send_are_not_counted(self):
        communicator = NodeCommunicator([object(), object()], 0, auth_mode="null")
        communicator.send(0, ("", ("TR2", b"self")))
        queue = asyncio.Queue()
        queue.put_nowait(("admpc-curve-channel-control-v1", "run", "ack"))
        queue.put_nowait(NodeCommunicator.LAST_MSG)

        async def fake_send(_frames):
            return None

        await communicator._process_node_messages(1, queue, fake_send)
        self.assertEqual(communicator.snapshot_communication_metrics()["total_remote_payload_bytes"], 0)
        communicator.zmq_context.destroy(linger=0)


if __name__ == "__main__":
    unittest.main()
