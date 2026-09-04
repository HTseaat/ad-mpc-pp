import json
from tempfile import TemporaryDirectory

import pytest

from beaver.communication_metrics import CommunicationMetricsArtifact
from beaver.hbacss import _timed_bgw_unbatched_call
from beaver.protocol_metrics import (
    AGGTRANS_NOAGG_GENERATE_COMPONENTS,
    AGGTRANS_NOAGG_VERIFY_COMPONENTS,
    BATCHMUL_VERIFY_COMPONENTS,
    BGW_GENERATE_COMPONENTS,
    BGW_VERIFY_COMPONENTS,
    aggtrans_generate_components,
    aggtrans_verify_components,
    bgw_effective_batch_size,
    finalize_operation,
    proof_metadata,
    timed_call,
)


class _Recorder:
    def __init__(self, artifact):
        self.communication_metrics = artifact


class _Mpc:
    def __init__(self, artifact, layer=2):
        self.layer_ID = layer
        self.metrics_recorder = _Recorder(artifact)


def _context():
    return {
        "implementation": "continuum", "experiment": "figure8",
        "protocol_variant": "aggtrans", "run_id": "unit",
        "parameters": {"expected_processes": 1},
        "process": {
            "global_process_id": 0, "local_party_id": 0,
            "physical_layer": 2,
        },
        "selection": {"included_tags": ["TR2"]},
    }


def test_timed_components_finalize_to_exact_sum():
    with TemporaryDirectory() as output_dir:
        artifact = CommunicationMetricsArtifact(
            _context(), enabled=True, output_dir=output_dir,
        )
        mpc = _Mpc(artifact)
        metadata = proof_metadata(
            mpc, protocol="aggtrans", operation="aggpub_verify",
            dealer_local_id=1, receiver_local_id=0, batch_size=100,
        )
        assert timed_call(mpc, metadata, "a", lambda: 1) == 1
        assert timed_call(
            mpc, metadata, "b", lambda: 0,
            success=lambda result: result == 1,
        ) == 0
        finalize_operation(mpc, metadata, ("a", "b"), success=False)
        path = artifact.write(
            {"total_remote_payload_bytes": 0, "total_remote_messages": 0,
             "by_tag": {}},
            {"auth_mode": "null", "drained_on_exit": True}, True,
        )
        with open(path, encoding="utf-8") as stream:
            proof = json.load(stream)["proof_metrics"]
        components = {entry["component"]: entry for entry in proof}
        assert components["total"]["elapsed_ns"] == (
            components["a"]["elapsed_ns"] + components["b"]["elapsed_ns"]
        )
        assert components["b"]["success"] is False
        assert components["total"]["success"] is False


def test_checkpoint_is_atomically_replaced_by_final_artifact():
    with TemporaryDirectory() as output_dir:
        artifact = CommunicationMetricsArtifact(
            _context(), enabled=True, output_dir=output_dir,
        )
        communication = {
            "total_remote_payload_bytes": 0,
            "total_remote_messages": 0,
            "by_tag": {},
        }
        checkpoint_path = artifact.write(
            communication,
            {"auth_mode": "curve", "drained_on_exit": False},
            completed=True,
            artifact_state="protocol-complete-checkpoint",
        )
        with open(checkpoint_path, encoding="utf-8") as stream:
            checkpoint = json.load(stream)
        assert checkpoint["artifact_state"] == "protocol-complete-checkpoint"
        assert checkpoint["completed"] is True
        assert checkpoint["transport"]["drained_on_exit"] is False

        final_path = artifact.write(
            communication,
            {"auth_mode": "curve", "drained_on_exit": True},
            completed=True,
            artifact_state="final",
        )
        assert final_path == checkpoint_path
        with open(final_path, encoding="utf-8") as stream:
            final = json.load(stream)
        assert final["artifact_state"] == "final"
        assert final["transport"]["drained_on_exit"] is True


def test_frozen_proof_quorum_is_persisted_for_n_minus_t_analysis():
    with TemporaryDirectory() as output_dir:
        artifact = CommunicationMetricsArtifact(
            _context(), enabled=True, output_dir=output_dir,
        )
        artifact.record_proof_quorum({
            "protocol": "aggtrans", "target_layer": 2,
            "receiver_local_id": 0, "dealer_ids": [2, 0, 1],
            "required_count": 3,
        })
        path = artifact.write(
            {"total_remote_payload_bytes": 0, "total_remote_messages": 0,
             "by_tag": {}},
            {"auth_mode": "null", "drained_on_exit": True}, True,
        )
        with open(path, encoding="utf-8") as stream:
            quorums = json.load(stream)["proof_quorums"]
        assert quorums == [{
            "protocol": "aggtrans", "target_layer": 2,
            "receiver_local_id": 0, "dealer_ids": [0, 1, 2],
            "required_count": 3,
        }]


def test_proof_quorum_rejects_wrong_or_duplicate_cardinality():
    with TemporaryDirectory() as output_dir:
        artifact = CommunicationMetricsArtifact(
            _context(), enabled=True, output_dir=output_dir,
        )
        with pytest.raises(ValueError, match="exactly required_count"):
            artifact.record_proof_quorum({
                "protocol": "aggtrans", "target_layer": 2,
                "receiver_local_id": 0, "dealer_ids": [0, 0, 1],
                "required_count": 3,
            })


def test_disabled_metrics_take_direct_call_path():
    artifact = CommunicationMetricsArtifact(enabled=False)
    mpc = _Mpc(artifact)
    metadata = proof_metadata(
        mpc, protocol="batchmul", operation="ipakzg_generate",
        dealer_local_id=0, receiver_local_id=None, batch_size=3,
    )
    marker = []
    assert timed_call(mpc, metadata, "factor_proof", lambda: marker.append(1)) is None
    finalize_operation(mpc, metadata, ("factor_proof",), success=True)
    assert marker == [1]
    assert artifact._proof_metrics == []


def test_aggtrans_metric_components_follow_feature_mode():
    assert aggtrans_generate_components("v2") == ("aggpub_prove",)
    assert aggtrans_verify_components("v2") == ("aggpub_verify",)
    assert aggtrans_generate_components("legacy") == ("legacy_aggpub_prove",)
    assert aggtrans_verify_components("legacy") == ("legacy_aggpub_verify",)
    assert aggtrans_generate_components("shadow") == (
        "aggpub_prove", "legacy_aggpub_prove",
    )
    assert aggtrans_verify_components("shadow") == ("aggpub_verify",)


def test_noagg_metrics_cover_generation_and_all_receiver_checks():
    assert AGGTRANS_NOAGG_GENERATE_COMPONENTS == (
        "commitment_opening_generation",
        "pedersen_commitment_preparation",
    )
    assert AGGTRANS_NOAGG_VERIFY_COMPONENTS == (
        "evaluation_proof_verify",
        "old_anchor_batch_verify",
        "fresh_zero_batch_verify",
    )


def test_stage6_batchmul_metrics_record_one_native_aggped_batch():
    assert BATCHMUL_VERIFY_COMPONENTS == (
        "factor_verify",
        "aggped_batch_verify",
    )


def test_bgw_metrics_cover_generation_and_all_four_verifier_relations():
    assert BGW_GENERATE_COMPONENTS == (
        "degree_reduction_proof_generation",
    )
    assert BGW_VERIFY_COMPONENTS == (
        "share_evaluation_verify",
        "hidden_evaluation_verify",
        "zero_evaluation_verify",
        "product_relation_verify",
    )


def test_bgw_effective_batch_size_preserves_figure9_width():
    assert {
        n: bgw_effective_batch_size(n, 100)
        for n in (4, 10, 16, 22)
    } == {4: 100, 10: 100, 16: 100, 22: 100}


def test_bgw_metadata_can_pin_computation_to_one_physical_layer():
    artifact = CommunicationMetricsArtifact(enabled=False)
    mpc = _Mpc(artifact, layer=3)
    metadata = proof_metadata(
        mpc, protocol="bgw", operation="bgw_verify",
        dealer_local_id=1, receiver_local_id=2, batch_size=100,
        source_layer=3, target_layer=3, unit="gate",
    )
    assert metadata["source_layer"] == 3
    assert metadata["target_layer"] == 3
    assert metadata["unit"] == "gate"


def test_bgw_unbatched_wrapper_records_the_native_call_only():
    with TemporaryDirectory() as output_dir:
        artifact = CommunicationMetricsArtifact(
            _context(), enabled=True, output_dir=output_dir,
        )
        mpc = _Mpc(artifact, layer=3)
        metadata = proof_metadata(
            mpc, protocol="bgw", operation="bgw_verify",
            dealer_local_id=1, receiver_local_id=0, batch_size=100,
            source_layer=3, target_layer=3, unit="gate",
        )
        result = _timed_bgw_unbatched_call(
            "fakeUnbatchedVerify", lambda: 1, (),
            mpc_instance=mpc, proof_metric=metadata,
            metric_component="share_evaluation_verify",
            success=lambda value: value == 1,
        )
        assert result == 1
        assert len(artifact._proof_metrics) == 1
        record = artifact._proof_metrics[0]
        assert record["component"] == "share_evaluation_verify"
        assert record["success"] is True
        assert record["elapsed_ns"] >= 0


def test_exception_records_failed_component_and_is_reraised():
    with TemporaryDirectory() as output_dir:
        artifact = CommunicationMetricsArtifact(
            _context(), enabled=True, output_dir=output_dir,
        )
        mpc = _Mpc(artifact)
        metadata = proof_metadata(
            mpc, protocol="batchmul", operation="ipakzg_verify",
            dealer_local_id=0, receiver_local_id=0, batch_size=3,
        )
        with pytest.raises(RuntimeError, match="bad proof"):
            timed_call(
                mpc, metadata, "factor_verify",
                lambda: (_ for _ in ()).throw(RuntimeError("bad proof")),
            )
        assert artifact._proof_metrics[0]["success"] is False
