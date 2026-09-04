import asyncio
import json
import os
import tempfile
import unittest

from beaver.broadcast.crypto.boldyreva import dealer
from committee_election.model import ElectionContext
from committee_election.network import METRICS_SCHEMA_VERSION, run_network_election
from scripts.analyze_committee_election import (
    ElectionAnalysisError,
    analyze,
    load_metrics,
)
from scripts.run_committee_election import FINISHED_MARKER, METRICS_MARKER
from tests.test_committee_election_model import make_registry


class NetworkElectionTests(unittest.TestCase):
    def setUp(self):
        self.registry = make_registry()
        self.context = ElectionContext.for_registry(
            run_id="network-test",
            source_committee_id="P1",
            target_epoch=2,
            registry=self.registry,
        )
        self.public_key, self.private_keys = dealer(4, 2, seed=500)

    def test_global_transport_mapping_and_one_omission(self):
        async def scenario():
            global_ids = (20, 21, 22, 23)
            queues = {global_id: asyncio.Queue() for global_id in global_ids}

            def sender(source_global_id):
                def send(destination, payload):
                    queues[destination].put_nowait((source_global_id, payload))
                return send

            results = await asyncio.gather(
                *(
                    run_network_election(
                        local_id=local_id,
                        public_key=self.public_key,
                        private_key=self.private_keys[local_id],
                        registry=self.registry,
                        context=self.context,
                        participant_global_ids=global_ids,
                        send=sender(global_ids[local_id]),
                        recv=queues[global_ids[local_id]].get,
                        omit_share=local_id == 3,
                    )
                    for local_id in range(4)
                )
            )
            return results

        results = asyncio.run(scenario())
        self.assertEqual(
            len({result.node_result.certificate.signature_digest for result in results}),
            1,
        )
        self.assertEqual(results[3].messages_sent_remote, 0)
        self.assertTrue(all(result.network_wait_ms >= 0 for result in results))


class MetricsAnalyzerTests(unittest.TestCase):
    def record(self, node_id):
        return {
            "K": 4,
            "bytes_sent_remote": 100 + node_id,
            "candidate_index": 2,
            "certificate_verify_ms": 1.0,
            "channel_setup_ms": 2.0,
            "combine_ms": 3.0,
            "committee_id": "candidate-02",
            "election_total_ms": 10.0 + node_id,
            "invalid_shares_rejected": 0,
            "messages_sent_remote": 3,
            "metrics_schema_version": METRICS_SCHEMA_VERSION,
            "n": 4,
            "network_wait_ms": 4.0,
            "node_id": node_id,
            "registry_digest": "a" * 64,
            "rejection_counts": {},
            "run_id": "run",
            "selection_ms": 1.0,
            "share_verify_ms_total": 2.0,
            "sign_ms": 1.0,
            "signature_digest": "b" * 64,
            "source_committee_id": "P1",
            "t": 1,
            "target_epoch": 2,
            "used_share_ids": [0, 1],
            "valid_shares_received": 2,
        }

    def test_complete_logs_are_deterministic_and_use_max_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            for node_id in range(4):
                with open(
                    os.path.join(directory, f"node-{node_id}.log"),
                    "w",
                    encoding="utf-8",
                ) as log_file:
                    log_file.write(
                        METRICS_MARKER
                        + json.dumps(self.record(node_id), sort_keys=True)
                        + "\n"
                    )
                    log_file.write(FINISHED_MARKER + "\n")
            records = load_metrics(directory, 4)
            first = analyze(records)
            second = analyze(records)
        self.assertEqual(first, second)
        self.assertEqual(first["protocol_completion_ms"], 13.0)
        self.assertEqual(first["total_bytes_sent_remote"], 406)

    def test_missing_node_and_disagreement_are_rejected(self):
        records = [self.record(node_id) for node_id in range(4)]
        with self.assertRaises(ElectionAnalysisError):
            analyze(records[:3])
        records[3]["signature_digest"] = "c" * 64
        with self.assertRaises(ElectionAnalysisError):
            analyze(records)


if __name__ == "__main__":
    unittest.main()
