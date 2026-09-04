import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from adkg.communication_metrics import CommunicationMetricsArtifact
from adkg.protocol_metrics import (
    ACSS_GENERATE_COMPONENTS,
    finalize_operation,
    proof_metadata,
    timed_call,
)


class _Recorder:
    def __init__(self, artifact):
        self.communication_metrics = artifact


class _Mpc:
    layer_ID = 1
    metrics_normalization_count = 8

    def __init__(self, artifact):
        self.metrics_recorder = _Recorder(artifact)


class _Acss:
    my_id = 0
    metrics_protocol = "adprep"

    def __init__(self, artifact):
        self.mpc_instance = _Mpc(artifact)


def _context():
    return {
        "implementation": "admpc",
        "experiment": "figure9",
        "protocol_variant": "admpc-nonlinear",
        "run_id": "unit",
        "parameters": {"expected_processes": 1},
        "process": {
            "global_process_id": 0,
            "local_party_id": 0,
            "physical_layer": 1,
        },
        "selection": {"included_tags": ["AP1"]},
    }


def test_admpc_crypto_metric_uses_logical_normalization_count(tmp_path):
    artifact = CommunicationMetricsArtifact(
        _context(), enabled=True, output_dir=tmp_path,
    )
    acss = _Acss(artifact)
    metadata = proof_metadata(
        acss, direction="generate", dealer_local_id=0,
        receiver_local_id=None, batch_size=48,
    )
    timed_call(acss, metadata, "commitment_generation", lambda: 1)
    timed_call(acss, metadata, "evaluation_proof_generation", lambda: 2)
    finalize_operation(acss, metadata, ACSS_GENERATE_COMPONENTS, success=True)

    path = artifact.write(
        {"total_remote_payload_bytes": 0, "total_remote_messages": 0,
         "by_tag": {}},
        {"auth_mode": "null", "drained_on_exit": True},
        True,
    )
    proof = json.loads(Path(path).read_text())["proof_metrics"]
    assert {entry["normalization_count"] for entry in proof} == {8}
    assert {entry["batch_size"] for entry in proof} == {48}
    components = {entry["component"]: entry for entry in proof}
    assert components["total"]["elapsed_ns"] == (
        components["commitment_generation"]["elapsed_ns"]
        + components["evaluation_proof_generation"]["elapsed_ns"]
    )


def test_admpc_proof_recorder_accepts_parallel_receiver_operations(tmp_path):
    artifact = CommunicationMetricsArtifact(
        _context(), enabled=True, output_dir=tmp_path,
    )

    def record(dealer):
        acss = _Acss(artifact)
        metadata = proof_metadata(
            acss, direction="generate", dealer_local_id=dealer,
            receiver_local_id=None, batch_size=8,
        )
        timed_call(acss, metadata, "commitment_generation", lambda: dealer)
        timed_call(acss, metadata, "evaluation_proof_generation", lambda: dealer)
        finalize_operation(acss, metadata, ACSS_GENERATE_COMPONENTS, success=True)

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(record, range(4)))

    totals = [
        entry for entry in artifact._proof_metrics
        if entry["component"] == "total"
    ]
    assert len(totals) == 4


def test_admpc_frozen_proof_quorum_is_persisted(tmp_path):
    artifact = CommunicationMetricsArtifact(
        _context(), enabled=True, output_dir=tmp_path,
    )
    artifact.record_proof_quorum({
        "protocol": "adtrans", "target_layer": 2,
        "receiver_local_id": 0, "dealer_ids": [3, 0, 2],
        "required_count": 3,
    })
    path = artifact.write(
        {"total_remote_payload_bytes": 0, "total_remote_messages": 0,
         "by_tag": {}},
        {"auth_mode": "null", "drained_on_exit": True}, True,
    )
    quorums = json.loads(Path(path).read_text())["proof_quorums"]
    assert quorums == [{
        "protocol": "adtrans", "target_layer": 2,
        "receiver_local_id": 0, "dealer_ids": [0, 2, 3],
        "required_count": 3,
    }]


def test_admpc_proof_quorum_rejects_invalid_or_duplicate_record(tmp_path):
    artifact = CommunicationMetricsArtifact(
        _context(), enabled=True, output_dir=tmp_path,
    )
    with pytest.raises(ValueError, match="exactly required_count"):
        artifact.record_proof_quorum({
            "protocol": "adtrans", "target_layer": 2,
            "receiver_local_id": 0, "dealer_ids": [0, 0, 1],
            "required_count": 3,
        })

    quorum = {
        "protocol": "adtrans", "target_layer": 2,
        "receiver_local_id": 0, "dealer_ids": [0, 1, 2],
        "required_count": 3,
    }
    artifact.record_proof_quorum(quorum)
    with pytest.raises(ValueError, match="duplicate proof quorum"):
        artifact.record_proof_quorum(quorum)
