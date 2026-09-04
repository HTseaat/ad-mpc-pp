from __future__ import annotations

import asyncio
import json
import pickle
import tempfile
import unittest
from dataclasses import asdict, replace
from pathlib import Path

from trusted_setup.config import SetupParams
from trusted_setup.kzg_smoke import run_kzg_smoke
from trusted_setup.metrics import build_metrics_record, write_metrics
from trusted_setup.protocol.distributed_tau import run_local_setup
from trusted_setup.protocol.verification import verify_result
from trusted_setup.serialization import build_srs, load_srs, write_srs


class StagesSixEightNineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temporary.name)
        cls.params = SetupParams.create(
            4, 1, 3, run_id="stages-6-8-9-tests"
        )
        cls.result = asyncio.run(run_local_setup(cls.params))
        cls.report = verify_result(cls.result)
        cls.srs = build_srs(cls.result, already_verified=cls.report.ok)
        cls.srs_path = write_srs(cls.srs, cls.directory / "srs.json")
        cls.kzg_result = run_kzg_smoke(cls.srs_path)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_stage6_round_trip_truncation_and_digest(self):
        loaded = load_srs(self.srs_path)
        self.assertEqual(loaded, self.srs)
        self.assertEqual(loaded.requested_powers, 3)
        self.assertEqual(loaded.effective_powers, 4)
        self.assertEqual(len(loaded.g1_g), 3)
        self.assertEqual(len(loaded.g1_h), 3)
        self.assertEqual(loaded.digest, loaded.expected_digest())
        serialized = self.srs_path.read_text(encoding="ascii")
        self.assertNotIn("alpha_share", serialized)
        self.assertNotIn("power_shares", serialized)
        self.assertNotIn("private_key", serialized)

    def test_every_party_produces_the_same_canonical_digest(self):
        digests = {
            build_srs(
                replace(self.result, parties=(party,)), already_verified=True
            ).digest
            for party in self.result.parties
        }
        self.assertEqual(digests, {self.srs.digest})

    def test_stage6_rejects_tampering(self):
        value = json.loads(self.srs_path.read_text(encoding="ascii"))
        value["g1_g"][1] = value["g1_g"][0]
        tampered = self.directory / "tampered.json"
        tampered.write_text(json.dumps(value), encoding="ascii")
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            load_srs(tampered)

    def test_stage8_uses_continuum_go_kzg_and_rejects_tampering(self):
        self.assertTrue(self.kzg_result["commit_open_verify"])
        self.assertTrue(self.kzg_result["tampered_value_rejected"])
        self.assertTrue(self.kzg_result["tampered_proof_rejected"])
        self.assertTrue(self.kzg_result["tampered_crs_rejected"])
        self.assertTrue(self.kzg_result["ok"])
        self.assertTrue(self.kzg_result["package"].endswith("/kzg_ped"))

    def test_stage9_metrics_are_structured_and_transport_compatible(self):
        negatives = {
            "g_chain_tamper_rejected": True,
            "h_commitment_tamper_rejected": True,
            "dleq_proof_tamper_rejected": True,
            "h_chain_tamper_rejected": True,
            "mismatched_alpha_h_chain_rejected": True,
        }
        record = build_metrics_record(
            result=self.result,
            verification=asdict(self.report),
            negative_tests=negatives,
            end_to_end_seconds=self.result.elapsed_seconds + 0.02,
            verification_seconds=0.01,
            serialization_seconds=0.01,
            srs=self.srs,
            srs_path=self.srs_path,
            kzg_smoke=self.kzg_result,
        )
        metrics_path = write_metrics(record, self.directory / "metrics.json")
        loaded = json.loads(metrics_path.read_text(encoding="utf-8"))
        communication = loaded["communication"]
        self.assertTrue(loaded["success"])
        self.assertGreaterEqual(
            loaded["end_to_end_elapsed_seconds"],
            loaded["protocol_elapsed_seconds"],
        )
        self.assertEqual(
            communication["encoding"],
            f"python-pickle-protocol-{pickle.DEFAULT_PROTOCOL}",
        )
        self.assertEqual(len(communication["sent_bytes_per_party"]), 4)
        self.assertGreater(communication["sent_bytes_median"], 0)
        self.assertGreater(communication["sent_bytes_max"], 0)
        self.assertTrue(
            all(value > 0 for value in communication["sent_messages_per_party"])
        )
        self.assertIn(
            "AP_H", communication["sent_bytes_by_outer_tag_per_party"][0]
        )
        self.assertEqual(loaded["artifact"]["digest"], self.srs.digest)


if __name__ == "__main__":
    unittest.main()
