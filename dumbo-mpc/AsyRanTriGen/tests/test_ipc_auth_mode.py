import os
import asyncio
import json
from pickle import dumps
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import zmq

from beaver.ipc import NodeCommunicator, resolve_auth_mode, validate_curve_config
from beaver.communication_metrics import CommunicationMetricsArtifact


class AuthModeTests(unittest.TestCase):
    def test_default_is_null(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(resolve_auth_mode(), "null")

    def test_environment_value_is_normalized(self):
        with patch.dict(os.environ, {"ZMQ_AUTH_MODE": " CURVE "}, clear=True):
            self.assertEqual(resolve_auth_mode(), "curve")

    def test_explicit_argument_overrides_environment(self):
        with patch.dict(os.environ, {"ZMQ_AUTH_MODE": "curve"}, clear=True):
            self.assertEqual(resolve_auth_mode("null"), "null")

    def test_unknown_mode_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unsupported ZeroMQ auth mode"):
            resolve_auth_mode("tls")

    def test_curve_mode_without_config_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "requires.*authenticated-channel config"):
            NodeCommunicator([], 0, auth_mode="curve")

    def test_application_message_accounting_accepts_mapping_payloads(self):
        self.assertEqual(
            NodeCommunicator._application_message_type(
                ("committee_election:share:2", {"sender_local_id": 0})
            ),
            "committee_election:share:2",
        )
        self.assertEqual(
            NodeCommunicator._application_message_type(("", ("TR2", object()))),
            "TR2",
        )
        self.assertEqual(NodeCommunicator._application_message_type({}), "APP")

    def test_full_tags_do_not_collide(self):
        self.assertNotEqual(
            NodeCommunicator._application_message_type(("committee_election:share:2", {})),
            NodeCommunicator._application_message_type(("committee_election:certificate:2", {})),
        )


class PayloadAccountingTests(unittest.IsolatedAsyncioTestCase):
    async def _account(self, auth_mode, auth_config=None):
        peers = [object(), object()]
        communicator = NodeCommunicator(
            peers, 0, auth_mode=auth_mode, auth_config=auth_config,
            readiness_barrier=False,
        )
        queue = asyncio.Queue()
        messages = [("", ("TR2", {"value": 1})), ("", ("TR2", b"abc"))]
        for message in messages:
            queue.put_nowait(message)
        queue.put_nowait(NodeCommunicator.LAST_MSG)
        sent = []

        async def fake_send(frames):
            sent.append(frames)

        await communicator._process_node_messages(1, queue, fake_send)
        snapshot = communicator.snapshot_communication_metrics()
        communicator.zmq_context.destroy(linger=0)
        return snapshot, messages, sent

    async def test_payload_bytes_and_message_count_match_pickle(self):
        snapshot, messages, sent = await self._account("null")
        expected = sum(len(dumps(message)) for message in messages)
        self.assertEqual(snapshot["total_remote_payload_bytes"], expected)
        self.assertEqual(snapshot["total_remote_messages"], 2)
        self.assertEqual(snapshot["by_tag"]["TR2"], {"bytes": expected, "messages": 2})
        self.assertEqual(len(sent), 2)

    async def test_null_and_curve_accounting_are_identical(self):
        keypairs = [zmq.curve_keypair() for _ in range(2)]
        public_keys = [pair[0].decode("ascii") for pair in keypairs]
        curve_config = {
            "curve_public_key": public_keys[0],
            "curve_secret_key": keypairs[0][1].decode("ascii"),
            "curve_public_keys": public_keys,
            "curve_zap_domain": "accounting-test",
            "run_id": "accounting-test",
        }
        null_snapshot, _, _ = await self._account("null")
        curve_snapshot, _, _ = await self._account("curve", curve_config)
        self.assertEqual(null_snapshot, curve_snapshot)

    async def test_self_send_and_curve_control_are_excluded(self):
        communicator = NodeCommunicator([object(), object()], 0, auth_mode="null")
        communicator.send(0, ("", ("TR2", b"self")))
        queue = asyncio.Queue()
        queue.put_nowait(("continuum-curve-channel-control-v1", "run", "ping"))
        queue.put_nowait(NodeCommunicator.LAST_MSG)

        async def fake_send(_frames):
            return None

        await communicator._process_node_messages(1, queue, fake_send)
        self.assertEqual(communicator.snapshot_communication_metrics()["total_remote_payload_bytes"], 0)
        communicator.zmq_context.destroy(linger=0)


class ArtifactTests(unittest.TestCase):
    def test_metrics_are_noop_by_default(self):
        with patch.dict(os.environ, {}, clear=True):
            artifact = CommunicationMetricsArtifact()
            self.assertFalse(artifact.enabled)
            self.assertIsNone(artifact.write({}, {}, True))

    def test_atomic_artifact_contains_only_counters_and_public_metadata(self):
        context = {
            "implementation": "continuum", "experiment": "figure8",
            "protocol_variant": "aggtrans", "run_id": "unit",
            "parameters": {"expected_processes": 1},
            "process": {"global_process_id": 0, "local_party_id": 0, "physical_layer": 0},
            "selection": {"included_tags": ["TR2"]},
        }
        with TemporaryDirectory() as output_dir:
            artifact = CommunicationMetricsArtifact(context, enabled=True, output_dir=output_dir)
            artifact.register_batch(
                protocol="aggtrans", tag="TR2", source_layer=1, target_layer=2,
                batch_size=50, role="source", operation_id="aggtrans:2", unit="sharing",
            )
            path = artifact.write(
                {"total_remote_payload_bytes": 7, "total_remote_messages": 1, "by_tag": {"TR2": {"bytes": 7, "messages": 1}}},
                {"auth_mode": "null", "drained_on_exit": True}, True,
            )
            with open(path, "r", encoding="utf-8") as stream:
                contents = stream.read()
            self.assertIn('"batch_size": 50', contents)
            self.assertNotIn("secret", contents.lower())

    def test_node_communicator_writes_protocol_complete_checkpoint(self):
        context = {
            "implementation": "continuum", "experiment": "figure9",
            "protocol_variant": "bgw-aggtrans", "run_id": "checkpoint",
            "parameters": {"expected_processes": 1},
            "process": {
                "global_process_id": 0, "local_party_id": 0,
                "physical_layer": 0,
            },
            "selection": {"included_tags": ["M_BGW_1"]},
        }
        with TemporaryDirectory() as output_dir:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            communicator = None
            try:
                communicator = NodeCommunicator(
                    [object()], 0, auth_mode="null",
                    metrics_context=context, metrics_enabled=True,
                    metrics_output_dir=output_dir,
                )
                path = communicator.write_metrics_checkpoint()
                with open(path, "r", encoding="utf-8") as stream:
                    checkpoint = json.load(stream)
                self.assertTrue(checkpoint["completed"])
                self.assertEqual(
                    checkpoint["artifact_state"],
                    "protocol-complete-checkpoint",
                )
                self.assertFalse(
                    checkpoint["transport"]["drained_on_exit"]
                )
            finally:
                if communicator is not None:
                    communicator.zmq_context.destroy(linger=0)
                loop.close()
                asyncio.set_event_loop(None)


class CurveConfigTests(unittest.TestCase):
    def setUp(self):
        self.keypairs = [zmq.curve_keypair() for _ in range(3)]
        self.public_keys = [pair[0].decode("ascii") for pair in self.keypairs]
        self.peers = [object(), object(), object()]

    def config_for(self, party_id):
        return {
            "curve_public_key": self.public_keys[party_id],
            "curve_secret_key": self.keypairs[party_id][1].decode("ascii"),
            "curve_public_keys": list(self.public_keys),
            "curve_zap_domain": "continuum-test",
            "run_id": "unit-test-run",
        }

    def test_valid_global_identity_mapping(self):
        config = validate_curve_config(self.peers, 2, self.config_for(2))
        self.assertEqual(config["party_by_user_id"][self.keypairs[2][0]], 2)
        self.assertEqual(len(config["public_keys"]), len(self.peers))

    def test_duplicate_public_key_is_rejected(self):
        auth_config = self.config_for(1)
        auth_config["curve_public_keys"][2] = auth_config["curve_public_keys"][1]
        with self.assertRaisesRegex(ValueError, "duplicate public keys"):
            validate_curve_config(self.peers, 1, auth_config)

    def test_registry_length_must_match_global_peer_count(self):
        auth_config = self.config_for(0)
        auth_config["curve_public_keys"].pop()
        with self.assertRaisesRegex(ValueError, "one per global transport identity"):
            validate_curve_config(self.peers, 0, auth_config)

    def test_own_public_key_must_match_global_index(self):
        auth_config = self.config_for(0)
        auth_config["curve_public_key"] = self.public_keys[1]
        with self.assertRaisesRegex(ValueError, r"curve_public_keys\[0\]"):
            validate_curve_config(self.peers, 0, auth_config)

    def test_secret_key_must_match_public_key(self):
        auth_config = self.config_for(0)
        auth_config["curve_secret_key"] = self.keypairs[1][1].decode("ascii")
        with self.assertRaisesRegex(ValueError, "does not match curve_public_key"):
            validate_curve_config(self.peers, 0, auth_config)

    def test_malformed_z85_key_is_rejected(self):
        auth_config = self.config_for(0)
        auth_config["curve_public_key"] = "short"
        with self.assertRaisesRegex(ValueError, "exactly 40 Z85 bytes"):
            validate_curve_config(self.peers, 0, auth_config)


if __name__ == "__main__":
    unittest.main()
