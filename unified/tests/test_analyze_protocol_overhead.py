import json

import pytest

from unified.analyze_protocol_overhead import (
    MetricsValidationError,
    analyze_documents,
    write_outputs,
)


def _fixture_documents():
    tags_by_process = [
        {"A1": (1, 1)},
        {"TR2": (10, 1)},
        {"TR2": (20, 2), "TR3": (30, 3)},
        {"TR3": (40, 4)},
    ]
    batches_by_process = [
        [],
        [{"protocol": "aggtrans", "tag": "TR2", "source_layer": 1, "target_layer": 2, "batch_size": 5, "role": "source", "operation_id": "aggtrans:2", "unit": "sharing"}],
        [
            {"protocol": "aggtrans", "tag": "TR2", "source_layer": 1, "target_layer": 2, "batch_size": 5, "role": "destination", "operation_id": "aggtrans:2", "unit": "sharing"},
            {"protocol": "aggtrans", "tag": "TR3", "source_layer": 2, "target_layer": 3, "batch_size": 5, "role": "source", "operation_id": "aggtrans:3", "unit": "sharing"},
        ],
        [{"protocol": "aggtrans", "tag": "TR3", "source_layer": 2, "target_layer": 3, "batch_size": 5, "role": "destination", "operation_id": "aggtrans:3", "unit": "sharing"}],
    ]
    documents = []
    for process_id, tags in enumerate(tags_by_process):
        by_tag = {tag: {"bytes": values[0], "messages": values[1]} for tag, values in tags.items()}
        documents.append({
            "schema": "protocol-communication-v1",
            "implementation": "continuum",
            "experiment": "figure8",
            "protocol_variant": "aggtrans",
            "run_id": "fixture",
            "parameters": {
                "committee_size": 1, "threshold": 0, "total_layers": 4,
                "circuit_depth": 2, "total_cm": 10, "configured_width": 10,
                "expected_batch_size": 5, "expected_operations": 2,
                "expected_processes": 4,
            },
            "process": {"global_process_id": process_id, "local_party_id": 0, "physical_layer": process_id},
            "selection": {"included_tags": ["TR2", "TR3"], "excluded_tag_prefixes": ["A"], "normalization_unit": "sharing"},
            "completed": True,
            "transport": {"auth_mode": "null", "drained_on_exit": True},
            "communication": {
                "total_remote_payload_bytes": sum(value[0] for value in tags.values()),
                "total_remote_messages": sum(value[1] for value in tags.values()),
                "by_tag": by_tag,
            },
            "protocol_batches": batches_by_process[process_id],
        })
    return documents


def test_exact_totals_and_outputs(tmp_path):
    summary, raw_rows, process_rows, proof_rows = analyze_documents(_fixture_documents())
    assert summary["system_total_payload_bytes"] == 100
    assert summary["excluded_payload_bytes"] == 1
    assert summary["normalization_count"] == 10
    assert summary["bytes_per_sharing"] == 10
    assert summary["average_bytes_per_party"] == 25
    assert summary["proof_computation"]["enabled"] is False
    write_outputs(tmp_path, summary, raw_rows, process_rows, proof_rows)
    assert json.loads((tmp_path / "summary.json").read_text())["system_total_payload_bytes"] == 100
    assert (tmp_path / "summary.csv").is_file()
    assert (tmp_path / "raw_by_process_tag.csv").is_file()
    assert (tmp_path / "raw_by_process.csv").is_file()
    assert (tmp_path / "raw_proof_metrics.csv").is_file()
    assert (tmp_path / "proof_summary.csv").is_file()
    assert (tmp_path / "proof_paper_critical_path.csv").is_file()


def test_missing_process_fails_closed():
    with pytest.raises(MetricsValidationError, match="incomplete case"):
        analyze_documents(_fixture_documents()[:-1])


def test_duplicate_process_fails_closed():
    documents = _fixture_documents()
    documents[-1]["process"]["global_process_id"] = 2
    with pytest.raises(MetricsValidationError, match="duplicate"):
        analyze_documents(documents)


def test_wrong_batch_size_fails_closed():
    documents = _fixture_documents()
    documents[1]["protocol_batches"][0]["batch_size"] = 6
    with pytest.raises(MetricsValidationError, match="inconsistent batch|wrong batch"):
        analyze_documents(documents)


def test_unknown_tag_fails_closed():
    documents = _fixture_documents()
    documents[0]["communication"]["by_tag"]["mystery"] = {"bytes": 9, "messages": 1}
    documents[0]["communication"]["total_remote_payload_bytes"] += 9
    documents[0]["communication"]["total_remote_messages"] += 1
    with pytest.raises(MetricsValidationError, match="unknown communication tag"):
        analyze_documents(documents)


def _with_proof_metrics(documents):
    for document in documents:
        document["parameters"]["proof_metrics_expected"] = True
    for document in documents:
        document["proof_metrics"] = []
        document["proof_quorums"] = []
    for target_layer in (2, 3):
        generator = documents[target_layer - 1]
        _add_proof_operation(
            generator, "aggtrans", "aggtrans_bacss_generate",
            f"bacss-gen:{target_layer}", ("commitment_opening_generation",),
            target_layer, 0, None,
        )
        _add_proof_operation(
            generator, "aggtrans", "aggpub_generate",
            f"gen:{target_layer}", ("aggpub_prove",), target_layer, 0, None,
        )
        verifier = documents[target_layer]
        verifier["proof_quorums"].append({
            "protocol": "aggtrans", "target_layer": target_layer,
            "receiver_local_id": 0, "dealer_ids": [0],
            "required_count": 1,
        })
        _add_proof_operation(
            verifier, "aggtrans", "aggtrans_bacss_verify",
            f"bacss-verify:{target_layer}", ("evaluation_proof_verify",),
            target_layer, 0, 0,
        )
        _add_proof_operation(
            verifier, "aggtrans", "aggpub_verify",
            f"verify:{target_layer}", ("aggpub_verify",), target_layer, 0, 0,
        )
    return documents


def _add_proof_operation(document, protocol, operation, operation_id, components,
                         target_layer, dealer, receiver, batch_size=5,
                         normalization_count=None):
    metadata = {
        "protocol": protocol, "operation": operation,
        "operation_id": operation_id, "source_layer": target_layer - 1,
        "target_layer": target_layer, "dealer_local_id": dealer,
        "receiver_local_id": receiver, "batch_size": batch_size,
    }
    if normalization_count is not None:
        metadata["normalization_count"] = normalization_count
    for index, component in enumerate(components, 1):
        document["proof_metrics"].append({
            **metadata, "component": component,
            "elapsed_ns": index, "success": True,
        })
    document["proof_metrics"].append({
        **metadata, "component": "total",
        "elapsed_ns": sum(range(1, len(components) + 1)),
        "success": True, "included_components": list(components),
    })


def _batchmul_proof_documents():
    documents = []
    for process_id in range(8):
        source = process_id < 4
        local_id = process_id % 4
        document = {
            "schema": "protocol-communication-v1",
            "implementation": "continuum",
            "experiment": "figure9",
            "protocol_variant": "batchmul",
            "run_id": "batchmul-fixture",
            "parameters": {
                "committee_size": 4, "threshold": 1, "total_layers": 3,
                "circuit_depth": 1, "total_cm": 5, "configured_width": 5,
                "expected_batch_size": 5, "expected_operations": 1,
                "expected_processes": 8, "proof_metrics_expected": True,
            },
            "process": {
                "global_process_id": process_id,
                "local_party_id": local_id,
                "physical_layer": 1 if source else 2,
            },
            "selection": {
                "included_tags": ["M2"], "excluded_tag_prefixes": ["A"],
                "normalization_unit": "gate",
            },
            "completed": True,
            "transport": {"auth_mode": "null", "drained_on_exit": True},
            "communication": {
                "total_remote_payload_bytes": 1,
                "total_remote_messages": 1,
                "by_tag": {"M2": {"bytes": 1, "messages": 1}},
            },
            "protocol_batches": [{
                "protocol": "batchmul", "tag": "M2",
                "source_layer": 1, "target_layer": 2, "batch_size": 5,
                "role": "source" if source else "destination",
                "operation_id": "batchmul:2", "unit": "gate",
            }],
            "proof_metrics": [],
            "proof_quorums": [],
        }
        if source:
            _add_proof_operation(
                document, "batchmul", "ipakzg_generate",
                f"ipakzg-generate:{local_id}",
                (
                    "multiplication_witness_preparation", "factor_proof",
                    "output_commitment_preparation", "challenge_derivation",
                    "output_zero_aggregation", "left_anchor_aggregation",
                    "right_anchor_aggregation", "anchor_share_preparation",
                    "pedersen_commitment_preparation",
                ),
                2, local_id, None,
            )
        else:
            document["proof_quorums"].append({
                "protocol": "batchmul", "target_layer": 2,
                "receiver_local_id": local_id, "dealer_ids": [0, 1, 2],
                "required_count": 3,
            })
            for dealer in range(4):
                _add_proof_operation(
                    document, "batchmul", "batchmul_bacss_verify",
                    f"bacss-verify:{local_id}:{dealer}",
                    ("evaluation_proof_verify",), 2, dealer, local_id,
                )
                _add_proof_operation(
                    document, "batchmul", "ipakzg_verify",
                    f"ipakzg-verify:{local_id}:{dealer}",
                    ("factor_verify", "aggped_batch_verify"),
                    2, dealer, local_id,
                )
        documents.append(document)
    return documents


def test_batchmul_computation_uses_frozen_n_minus_t_quorum():
    summary, _, _, proof_rows = analyze_documents(
        _batchmul_proof_documents()
    )
    proof = summary["proof_computation"]
    critical = proof["paper_critical_path"]
    assert critical["protocol"] == "batchmul"
    assert critical["verification_dealers_per_receiver"] == 3
    assert critical["raw_verification_samples_by_operation"] == {
        "batchmul_bacss_verify": 16, "ipakzg_verify": 16,
    }
    assert critical["selected_verification_samples_by_operation"] == {
        "batchmul_bacss_verify": 12, "ipakzg_verify": 12,
    }
    assert critical[
        "background_verification_samples_excluded_by_operation"
    ] == {"batchmul_bacss_verify": 4, "ipakzg_verify": 4}
    assert critical["mean_generation_batch_elapsed_ns_per_server_layer"] == 45
    assert critical["mean_quorum_verification_batch_elapsed_ns_per_server_layer"] == 12
    assert critical["mean_total_batch_elapsed_ns_per_server_layer"] == 57
    included_totals = [
        row for row in proof_rows
        if row["component"] == "total" and row.get("paper_critical_included")
    ]
    assert len(included_totals) == 4 + 12 + 12


def _noagg_proof_documents():
    documents = []
    committee_size = 4
    for process_id in range(2 * committee_size):
        source = process_id < committee_size
        local_id = process_id % committee_size
        document = {
            "schema": "protocol-communication-v1",
            "implementation": "continuum",
            "experiment": "figure8",
            "protocol_variant": "aggtrans-noagg",
            "run_id": "noagg-fixture",
            "parameters": {
                "committee_size": committee_size, "threshold": 1,
                "total_layers": 3, "circuit_depth": 1, "total_cm": 5,
                "configured_width": 5, "expected_batch_size": 5,
                "expected_operations": 1,
                "expected_processes": 2 * committee_size,
                "proof_metrics_expected": True,
            },
            "process": {
                "global_process_id": process_id,
                "local_party_id": local_id,
                "physical_layer": 1 if source else 2,
            },
            "selection": {
                "included_tags": ["TR2"],
                "excluded_tag_prefixes": ["A"],
                "normalization_unit": "sharing",
            },
            "completed": True,
            "transport": {"auth_mode": "null", "drained_on_exit": True},
            "communication": {
                "total_remote_payload_bytes": 1,
                "total_remote_messages": 1,
                "by_tag": {"TR2": {"bytes": 1, "messages": 1}},
            },
            "protocol_batches": [{
                "protocol": "aggtrans-noagg", "tag": "TR2",
                "source_layer": 1, "target_layer": 2, "batch_size": 5,
                "role": "source" if source else "destination",
                "operation_id": "aggtrans-noagg:2", "unit": "sharing",
            }],
            "proof_metrics": [],
            "proof_quorums": [],
        }
        if source:
            _add_proof_operation(
                document, "aggtrans-noagg", "noagg_generate",
                f"noagg-generate:{local_id}",
                (
                    "commitment_opening_generation",
                    "pedersen_commitment_preparation",
                ),
                2, local_id, None,
            )
        else:
            document["proof_quorums"].append({
                "protocol": "aggtrans-noagg", "target_layer": 2,
                "receiver_local_id": local_id, "dealer_ids": [0, 1, 2],
                "required_count": 3,
            })
            for dealer_id in range(committee_size):
                _add_proof_operation(
                    document, "aggtrans-noagg", "batch_verify",
                    f"noagg-verify:{local_id}:{dealer_id}",
                    (
                        "evaluation_proof_verify",
                        "old_anchor_batch_verify",
                        "fresh_zero_batch_verify",
                    ),
                    2, dealer_id, local_id,
                )
        documents.append(document)
    return documents


def test_noagg_computation_uses_generation_and_frozen_n_minus_t_quorum():
    summary, _, _, proof_rows = analyze_documents(_noagg_proof_documents())
    proof = summary["proof_computation"]
    critical = proof["paper_critical_path"]
    assert critical["protocol"] == "aggtrans-noagg"
    assert critical["verification_dealers_per_receiver"] == 3
    assert critical["raw_verification_samples_by_operation"] == {
        "batch_verify": 16,
    }
    assert critical["selected_verification_samples_by_operation"] == {
        "batch_verify": 12,
    }
    assert critical[
        "background_verification_samples_excluded_by_operation"
    ] == {"batch_verify": 4}
    assert critical["mean_generation_batch_elapsed_ns_per_server_layer"] == 3
    assert critical[
        "mean_quorum_verification_batch_elapsed_ns_per_server_layer"
    ] == 18
    assert critical["mean_total_batch_elapsed_ns_per_server_layer"] == 21
    assert critical["mean_total_elapsed_ns_per_unit"] == 4.2
    included_totals = [
        row for row in proof_rows
        if row["component"] == "total" and row.get("paper_critical_included")
    ]
    assert len(included_totals) == 4 + 12


def _adtrans_proof_documents():
    documents = []
    committee_size = 4
    for process_id in range(3 * committee_size):
        layer = process_id // committee_size
        local_id = process_id % committee_size
        by_tag = {}
        batches = []
        if layer == 0:
            by_tag["GR1"] = {"bytes": 1, "messages": 1}
            batches.append({
                "protocol": "randgen", "tag": "GR1",
                "source_layer": 0, "target_layer": 1, "batch_size": 5,
                "role": "source", "operation_id": "layer:1",
                "unit": "sharing",
            })
        elif layer == 1:
            by_tag.update({
                "GR1": {"bytes": 1, "messages": 1},
                "TR2": {"bytes": 1, "messages": 1},
            })
            batches.extend(({
                "protocol": "randgen", "tag": "GR1",
                "source_layer": 0, "target_layer": 1, "batch_size": 5,
                "role": "destination", "operation_id": "layer:1",
                "unit": "sharing",
            }, {
                "protocol": "adtrans", "tag": "TR2",
                "source_layer": 1, "target_layer": 2, "batch_size": 5,
                "role": "source", "operation_id": "layer:1",
                "unit": "sharing",
            }))
        else:
            by_tag["TR2"] = {"bytes": 1, "messages": 1}
            batches.append({
                "protocol": "adtrans", "tag": "TR2",
                "source_layer": 1, "target_layer": 2, "batch_size": 5,
                "role": "destination", "operation_id": "layer:1",
                "unit": "sharing",
            })

        document = {
            "schema": "protocol-communication-v1",
            "implementation": "admpc",
            "experiment": "figure8",
            "protocol_variant": "admpc-linear",
            "run_id": "adtrans-fixture",
            "parameters": {
                "committee_size": committee_size, "threshold": 1,
                "total_layers": 3, "circuit_depth": 1, "total_cm": 5,
                "configured_width": 5, "expected_batch_size": 5,
                "expected_operations": 1,
                "expected_processes": 3 * committee_size,
                "proof_metrics_expected": True,
            },
            "process": {
                "global_process_id": process_id,
                "local_party_id": local_id,
                "physical_layer": layer,
            },
            "selection": {
                "included_tags": ["GR1", "TR2"],
                "excluded_tag_prefixes": ["A"],
                "normalization_unit": "sharing",
            },
            "completed": True,
            "transport": {"auth_mode": "null", "drained_on_exit": True},
            "communication": {
                "total_remote_payload_bytes": sum(
                    value["bytes"] for value in by_tag.values()
                ),
                "total_remote_messages": sum(
                    value["messages"] for value in by_tag.values()
                ),
                "by_tag": by_tag,
            },
            "protocol_batches": batches,
            "proof_metrics": [],
            "proof_quorums": [],
        }
        documents.append(document)

    randgen_generate_components = (
        "commitment_generation", "evaluation_proof_generation",
        "consistency_proof_generation",
    )
    randgen_verify_components = (
        "consistency_proof_verify", "evaluation_proof_verify",
    )
    adtrans_generate_components = (
        "consistency_proof_generation", "transfer_commitment_generation",
        "evaluation_proof_generation",
    )
    adtrans_verify_components = (
        "commitment_aggregation", "evaluation_proof_verify",
        "consistency_proof_verify",
    )
    for local_id in range(committee_size):
        _add_proof_operation(
            documents[local_id], "randgen", "randgen_generate",
            f"randgen-generate:{local_id}", randgen_generate_components,
            1, local_id, None,
        )
        for dealer_id in (0, 1, 2):
            _add_proof_operation(
                documents[committee_size + local_id],
                "randgen", "randgen_verify",
                f"randgen-verify:{local_id}:{dealer_id}",
                randgen_verify_components, 1, dealer_id, local_id,
            )
        _add_proof_operation(
            documents[committee_size + local_id],
            "adtrans", "adtrans_generate",
            f"adtrans-generate:{local_id}", adtrans_generate_components,
            2, local_id, None,
        )

        verifier = documents[2 * committee_size + local_id]
        selected_dealers = [0, 2, 3] if local_id % 2 == 0 else [0, 1, 3]
        verifier["proof_quorums"].append({
            "protocol": "adtrans", "target_layer": 2,
            "receiver_local_id": local_id,
            "dealer_ids": selected_dealers, "required_count": 3,
        })
        for dealer_id in range(committee_size):
            _add_proof_operation(
                verifier, "adtrans", "adtrans_verify",
                f"adtrans-verify:{local_id}:{dealer_id}",
                adtrans_verify_components, 2, dealer_id, local_id,
            )
    return documents


def test_adtrans_computation_uses_frozen_n_minus_t_quorum():
    summary, _, _, proof_rows = analyze_documents(
        _adtrans_proof_documents()
    )
    critical = summary["proof_computation"]["paper_critical_path"]
    assert critical["protocol"] == "adtrans"
    assert critical["verification_dealers_per_receiver"] == 3
    assert critical["raw_verification_samples_by_operation"] == {
        "adtrans_verify": 16,
    }
    assert critical["selected_verification_samples_by_operation"] == {
        "adtrans_verify": 12,
    }
    assert critical[
        "background_verification_samples_excluded_by_operation"
    ] == {"adtrans_verify": 4}
    assert critical["mean_generation_batch_elapsed_ns_per_server_layer"] == 6
    assert critical[
        "mean_quorum_verification_batch_elapsed_ns_per_server_layer"
    ] == 18
    assert critical["mean_total_batch_elapsed_ns_per_server_layer"] == 24
    assert critical["mean_total_elapsed_ns_per_unit"] == 4.8
    included_totals = [
        row for row in proof_rows
        if row["component"] == "total" and row.get("paper_critical_included")
    ]
    assert len(included_totals) == 4 + 12


def test_adtrans_computation_requires_the_frozen_protocol_quorum():
    documents = _adtrans_proof_documents()
    documents[8]["proof_quorums"] = []
    with pytest.raises(MetricsValidationError, match="proof quorums"):
        analyze_documents(documents)


def test_proof_metrics_exact_components_and_totals():
    summary, _, _, proof_rows = analyze_documents(
        _with_proof_metrics(_fixture_documents())
    )
    proof = summary["proof_computation"]
    assert proof["enabled"] is True
    assert proof["operations"]["aggpub_generate"]["samples"] == 2
    assert proof["operations"]["aggpub_verify"]["samples"] == 2
    assert proof["operations"]["aggpub_generate"]["mean_batch_elapsed_ns"] == 1
    assert proof["full_crypto_phases"]["generation"]["mean_elapsed_ns_per_unit"] == 0.4
    critical = proof["paper_critical_path"]
    assert critical["verification_dealers_per_receiver"] == 1
    assert critical["mean_generation_batch_elapsed_ns_per_server_layer"] == 2
    assert critical[
        "mean_quorum_verification_batch_elapsed_ns_per_server_layer"
    ] == 2
    assert critical["mean_total_batch_elapsed_ns_per_server_layer"] == 4
    assert critical["mean_total_elapsed_ns_per_unit"] == 0.8
    assert len(proof_rows) == 16


def test_partial_checkpoint_preserves_available_proof_computation():
    documents = _with_proof_metrics(_fixture_documents())[1:]
    documents[0]["artifact_state"] = "protocol-complete-checkpoint"
    documents[0]["transport"]["drained_on_exit"] = False

    summary, _, process_rows, proof_rows = analyze_documents(
        documents, allow_incomplete=True,
    )

    assert summary["case_complete"] is False
    assert summary["communication_complete"] is False
    assert summary["system_total_payload_bytes"] is None
    assert summary["measured_processes"] == 3
    assert summary["missing_process_ids"] == [0]
    assert summary["checkpoint_process_ids"] == [1]
    assert summary["proof_computation"]["enabled"] is True
    assert summary["proof_computation"]["complete_case"] is False
    assert summary["proof_computation"]["operations"][
        "aggpub_generate"
    ]["samples"] == 2
    assert len(process_rows) == 3
    assert proof_rows


def test_bgw_aggtrans_computation_covers_both_protocol_stages():
    documents = _fixture_documents()
    for document in documents:
        document["experiment"] = "figure9"
        document["protocol_variant"] = "bgw-aggtrans"
        document["parameters"]["proof_metrics_expected"] = True
        document["proof_metrics"] = []
        document["proof_quorums"] = []

    bgw_verify_components = (
        "share_evaluation_verify",
        "hidden_evaluation_verify",
        "zero_evaluation_verify",
        "product_relation_verify",
    )
    for target_layer in (2, 3):
        generator = documents[target_layer - 1]
        verifier = documents[target_layer]
        generator["proof_quorums"].append({
            "protocol": "bgw", "target_layer": target_layer - 1,
            "receiver_local_id": 0, "dealer_ids": [0],
            "required_count": 1,
        })
        verifier["proof_quorums"].append({
            "protocol": "aggtrans", "target_layer": target_layer,
            "receiver_local_id": 0, "dealer_ids": [0],
            "required_count": 1,
        })
        _add_proof_operation(
            generator, "bgw", "bgw_generate",
            f"bgw-generate:{target_layer}",
            ("degree_reduction_proof_generation",),
            target_layer - 1, 0, None,
        )
        _add_proof_operation(
            generator, "bgw", "bgw_verify",
            f"bgw-verify:{target_layer}", bgw_verify_components,
            target_layer - 1, 0, 0,
        )
        _add_proof_operation(
            generator, "aggtrans", "aggtrans_bacss_generate",
            f"aggtrans-bacss-generate:{target_layer}",
            ("commitment_opening_generation",),
            target_layer, 0, None,
        )
        _add_proof_operation(
            generator, "aggtrans", "aggpub_generate",
            f"aggtrans-generate:{target_layer}", ("aggpub_prove",),
            target_layer, 0, None,
        )
        _add_proof_operation(
            verifier, "aggtrans", "aggtrans_bacss_verify",
            f"aggtrans-bacss-verify:{target_layer}",
            ("evaluation_proof_verify",),
            target_layer, 0, 0,
        )
        _add_proof_operation(
            verifier, "aggtrans", "aggpub_verify",
            f"aggtrans-verify:{target_layer}", ("aggpub_verify",),
            target_layer, 0, 0,
        )

    summary, _, _, proof_rows = analyze_documents(documents)
    proof = summary["proof_computation"]
    assert proof["enabled"] is True
    assert proof["operations"]["bgw_generate"]["samples"] == 2
    assert proof["operations"]["bgw_verify"]["samples"] == 2
    assert proof["full_crypto_phases"]["combined_generation"][
        "mean_elapsed_ns_per_unit"
    ] == pytest.approx(0.6)
    assert proof["full_crypto_phases"]["combined_verification"][
        "mean_elapsed_ns_per_unit"
    ] == pytest.approx(2.4)
    assert proof["full_crypto_phases"][
        "combined_generation_and_verification"
    ]["mean_elapsed_ns_per_unit"] == pytest.approx(3.0)
    critical = proof["paper_critical_path"]
    assert proof["scope"] == (
        "local_commitment_and_proof_cryptographic_operations_only"
    )
    assert "interpolation" in proof["excluded"]
    assert critical["protocol"] == "bgw-aggtrans"
    assert critical["quorum_protocols"] == ["bgw", "aggtrans"]
    assert critical["quorum_records"] == 4
    assert critical["mean_total_batch_elapsed_ns_per_server_layer"] == 15
    assert critical["mean_total_elapsed_ns_per_unit"] == 3
    assert critical["components"]["bgw"][
        "mean_total_batch_elapsed_ns_per_server_layer"
    ] == 11
    assert critical["components"]["aggtrans"][
        "mean_total_batch_elapsed_ns_per_server_layer"
    ] == 4
    assert len(proof_rows) == 30


def test_bgw_aggtrans_computation_requires_both_frozen_quorums():
    documents = _fixture_documents()
    for document in documents:
        document["experiment"] = "figure9"
        document["protocol_variant"] = "bgw-aggtrans"
        document["parameters"]["proof_metrics_expected"] = True
        document["proof_metrics"] = []
        document["proof_quorums"] = []

    bgw_verify_components = (
        "share_evaluation_verify", "hidden_evaluation_verify",
        "zero_evaluation_verify", "product_relation_verify",
    )
    for target_layer in (2, 3):
        generator = documents[target_layer - 1]
        verifier = documents[target_layer]
        # Deliberately provide only the existing AggTrans quorum.
        verifier["proof_quorums"].append({
            "protocol": "aggtrans", "target_layer": target_layer,
            "receiver_local_id": 0, "dealer_ids": [0],
            "required_count": 1,
        })
        _add_proof_operation(
            generator, "bgw", "bgw_generate",
            f"bgw-generate:{target_layer}",
            ("degree_reduction_proof_generation",),
            target_layer - 1, 0, None,
        )
        _add_proof_operation(
            generator, "bgw", "bgw_verify",
            f"bgw-verify:{target_layer}", bgw_verify_components,
            target_layer - 1, 0, 0,
        )
        _add_proof_operation(
            generator, "aggtrans", "aggtrans_bacss_generate",
            f"aggtrans-bacss-generate:{target_layer}",
            ("commitment_opening_generation",),
            target_layer, 0, None,
        )
        _add_proof_operation(
            generator, "aggtrans", "aggpub_generate",
            f"aggtrans-generate:{target_layer}", ("aggpub_prove",),
            target_layer, 0, None,
        )
        _add_proof_operation(
            verifier, "aggtrans", "aggtrans_bacss_verify",
            f"aggtrans-bacss-verify:{target_layer}",
            ("evaluation_proof_verify",), target_layer, 0, 0,
        )
        _add_proof_operation(
            verifier, "aggtrans", "aggpub_verify",
            f"aggtrans-verify:{target_layer}", ("aggpub_verify",),
            target_layer, 0, 0,
        )

    with pytest.raises(
        MetricsValidationError, match="wrong number of bgw proof quorums"
    ):
        analyze_documents(documents)


def test_aggtrans_computation_requires_the_frozen_protocol_quorum():
    documents = _with_proof_metrics(_fixture_documents())
    documents[2]["proof_quorums"] = []
    with pytest.raises(MetricsValidationError, match="proof quorums"):
        analyze_documents(documents)


def test_missing_proof_component_fails_closed():
    documents = _with_proof_metrics(_fixture_documents())
    documents[1]["proof_metrics"].pop(0)
    with pytest.raises(MetricsValidationError, match="wrong components"):
        analyze_documents(documents)


def test_failed_proof_fails_closed_without_short_circuit_gap():
    documents = _with_proof_metrics(_fixture_documents())
    operation = documents[2]["proof_metrics"]
    operation[0]["success"] = False
    next(
        item for item in operation
        if item["operation_id"] == operation[0]["operation_id"]
        and item["component"] == "total"
    )["success"] = False
    with pytest.raises(MetricsValidationError, match="unsuccessful proof operation"):
        analyze_documents(documents)


def test_admpc_crypto_batches_normalize_by_logical_gate_count():
    documents = _fixture_documents()
    for document in documents:
        document["implementation"] = "admpc"
        document["protocol_variant"] = "admpc-nonlinear"
        document["parameters"]["proof_metrics_expected"] = True
        document["proof_metrics"] = []
        document["proof_quorums"] = []

    operation_components = {
        "randgen_generate": (
            "commitment_generation", "evaluation_proof_generation",
            "consistency_proof_generation",
        ),
        "randgen_verify": (
            "consistency_proof_verify", "evaluation_proof_verify",
        ),
        "adprep_generate": (
            "commitment_generation", "evaluation_proof_generation",
        ),
        "adprep_verify": ("evaluation_proof_verify",),
        "adprep_rand_generate": (
            "commitment_generation", "evaluation_proof_generation",
        ),
        "adprep_rand_verify": ("evaluation_proof_verify",),
        "adtrans_generate": (
            "consistency_proof_generation", "transfer_commitment_generation",
            "evaluation_proof_generation",
        ),
        "adtrans_verify": (
            "commitment_aggregation", "evaluation_proof_verify",
            "consistency_proof_verify",
        ),
    }
    for target_layer in (2, 3):
        documents[target_layer]["proof_quorums"].append({
            "protocol": "adtrans", "target_layer": target_layer,
            "receiver_local_id": 0, "dealer_ids": [0],
            "required_count": 1,
        })
        for operation, components in operation_components.items():
            generating = operation.endswith("generate")
            document = documents[target_layer - 1 if generating else target_layer]
            protocol = operation.rsplit("_", 1)[0]
            crypto_batch = 30 if protocol == "adprep" else 2
            _add_proof_operation(
                document, protocol, operation,
                f"{operation}:{target_layer}", components,
                target_layer, 0, None if generating else 0,
                batch_size=crypto_batch, normalization_count=5,
            )

    summary, _, _, _ = analyze_documents(documents)
    proof = summary["proof_computation"]
    assert proof["operations"]["adprep_generate"]["batch_size"] == 30
    assert proof["operations"]["adprep_generate"]["normalization_count"] == 5
    assert proof["full_crypto_phases"]["adprep_generation"][
        "included_operations"
    ] == ["adprep_rand_generate", "adprep_generate"]
