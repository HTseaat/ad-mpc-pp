from __future__ import annotations

import asyncio
import json
import socket
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from trusted_setup.config import SetupParams
from trusted_setup.generate_distributed_config import write_distributed_configs
from trusted_setup.protocol.network import (
    CurveNodeCommunicator,
    build_curve_transport_configs,
    load_node_transport,
    validate_curve_transport_config,
)


def _unused_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class DistributedConfigTests(unittest.TestCase):
    def test_configs_bind_private_key_to_party_and_common_registry(self):
        params = SetupParams.create(4, 1, 2, run_id="distributed-config")
        peers = [f"192.0.2.{index + 1}:7001" for index in range(4)]
        with tempfile.TemporaryDirectory() as directory:
            paths = write_distributed_configs(params, peers, Path(directory))
            values = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
            validated = [
                load_node_transport(
                    path, party_id=index, n=4, run_id=params.run_id
                )
                for index, path in enumerate(paths)
            ]
        self.assertEqual(len(paths), 4)
        self.assertEqual(
            {value["transport"]["transport_digest"] for value in values},
            {validated[0]["transport_digest"]},
        )
        self.assertEqual(
            len({value["transport"]["curve_secret_key"] for value in values}), 4
        )
        self.assertTrue(
            all(
                validated[index]["public_key"]
                == validated[index]["public_keys"][index]
                for index in range(4)
            )
        )

    def test_registry_tamper_fails_closed(self):
        config = build_curve_transport_configs("tamper", 2)[0]
        config["curve_public_keys"] = list(reversed(config["curve_public_keys"]))
        with self.assertRaises(ValueError):
            validate_curve_transport_config(
                config, party_id=0, n=2, run_id="tamper"
            )


class CurveTransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_authenticated_round_trip_and_metrics(self):
        ports = (_unused_port(), _unused_port())
        while ports[0] == ports[1]:
            ports = (ports[0], _unused_port())
        peers = [f"127.0.0.1:{port}" for port in ports]
        raw_configs = build_curve_transport_configs("network-round-trip", 2)
        configs = [
            validate_curve_transport_config(
                raw_configs[index],
                party_id=index,
                n=2,
                run_id="network-round-trip",
            )
            for index in range(2)
        ]

        async def run_party(party_id: int):
            async with CurveNodeCommunicator(
                peers,
                party_id,
                configs[party_id],
                readiness_timeout=10,
                linger_seconds=0,
            ) as communicator:
                communicator.send(1 - party_id, ("TEST", party_id))
                sender, message = await asyncio.wait_for(
                    communicator.recv(), timeout=5
                )
                return sender, message, communicator.snapshot()

        results = await asyncio.gather(run_party(0), run_party(1))
        for party_id, (sender, message, metrics) in enumerate(results):
            self.assertEqual(sender, 1 - party_id)
            self.assertEqual(message, ("TEST", 1 - party_id))
            self.assertEqual(metrics["total_remote_messages"], 1)
            self.assertGreater(metrics["total_remote_payload_bytes"], 0)
            self.assertEqual(metrics["curve_denied_count"], 0)
            self.assertEqual(metrics["identity_spoofing_count"], 0)


class DistributedPublicVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from trusted_setup.protocol.distributed_tau import run_local_setup

        cls.params = SetupParams.create(4, 1, 2, run_id="public-verification")
        cls.result = asyncio.run(run_local_setup(cls.params))

    def test_each_party_passes_without_central_alpha_reconstruction(self):
        from trusted_setup.protocol.verification import (
            verify_distributed_party_result,
        )
        from trusted_setup.serialization import build_srs

        digests = set()
        for party in self.result.parties:
            single_party = replace(self.result, parties=(party,))
            report = verify_distributed_party_result(single_party)
            self.assertTrue(report.ok, report)
            digests.add(build_srs(single_party, already_verified=True).digest)
        self.assertEqual(len(digests), 1)


if __name__ == "__main__":
    unittest.main()
