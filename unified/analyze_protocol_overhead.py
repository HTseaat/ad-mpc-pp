#!/usr/bin/env python3
"""Strict protocol-overhead analyzer with opt-in partial checkpoint support."""

import argparse
import csv
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path


SCHEMA = "protocol-communication-v1"

PROOF_COMPONENTS = {
    "aggtrans_bacss_generate": ("commitment_opening_generation",),
    "aggpub_generate": ("aggpub_prove",),
    "aggtrans_bacss_verify": ("evaluation_proof_verify",),
    "aggpub_verify": ("aggpub_verify",),
    "noagg_generate": (
        "commitment_opening_generation", "pedersen_commitment_preparation",
    ),
    "batch_verify": (
        "evaluation_proof_verify", "old_anchor_batch_verify",
        "fresh_zero_batch_verify",
    ),
    "ipakzg_generate": (
        "multiplication_witness_preparation", "factor_proof",
        "output_commitment_preparation", "challenge_derivation",
        "output_zero_aggregation", "left_anchor_aggregation",
        "right_anchor_aggregation", "anchor_share_preparation",
        "pedersen_commitment_preparation",
    ),
    "batchmul_bacss_verify": ("evaluation_proof_verify",),
    "ipakzg_verify": ("factor_verify", "aggped_batch_verify"),
    "bgw_generate": ("degree_reduction_proof_generation",),
    "bgw_verify": (
        "share_evaluation_verify", "hidden_evaluation_verify",
        "zero_evaluation_verify", "product_relation_verify",
    ),
    "randgen_generate": (
        "commitment_generation", "evaluation_proof_generation",
        "consistency_proof_generation",
    ),
    "randgen_verify": (
        "consistency_proof_verify", "evaluation_proof_verify",
    ),
    "batchrand_generate": (
        "commitment_generation", "evaluation_proof_generation",
    ),
    "batchrand_verify": ("evaluation_proof_verify",),
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

VARIANT_OPERATIONS = {
    "aggtrans": {
        "aggtrans_bacss_generate", "aggpub_generate",
        "aggtrans_bacss_verify", "aggpub_verify",
    },
    "aggtrans-noagg": {"noagg_generate", "batch_verify"},
    "batchmul": {
        "ipakzg_generate", "batchmul_bacss_verify", "ipakzg_verify",
    },
    "bgw-aggtrans": {
        "bgw_generate", "bgw_verify",
        "aggtrans_bacss_generate", "aggpub_generate",
        "aggtrans_bacss_verify", "aggpub_verify",
    },
    "admpc-linear": {
        "randgen_generate", "randgen_verify",
        "adtrans_generate", "adtrans_verify",
    },
    "admpc-batchrand": {
        "batchrand_generate", "batchrand_verify",
    },
    "admpc-nonlinear": {
        "randgen_generate", "randgen_verify",
        "adprep_generate", "adprep_verify",
        "adprep_rand_generate", "adprep_rand_verify",
        "adtrans_generate", "adtrans_verify",
    },
}

FULL_CRYPTO_PHASES = {
    "aggtrans": {
        "generation": ("aggtrans_bacss_generate", "aggpub_generate"),
        "verification": ("aggtrans_bacss_verify", "aggpub_verify"),
    },
    "aggtrans-noagg": {
        "generation": ("noagg_generate",),
        "verification": ("batch_verify",),
    },
    "batchmul": {
        "generation": ("ipakzg_generate",),
        "verification": ("batchmul_bacss_verify", "ipakzg_verify"),
    },
    "bgw-aggtrans": {
        "bgw_generation": ("bgw_generate",),
        "bgw_verification": ("bgw_verify",),
        "aggtrans_generation": (
            "aggtrans_bacss_generate", "aggpub_generate",
        ),
        "aggtrans_verification": (
            "aggtrans_bacss_verify", "aggpub_verify",
        ),
        "combined_generation": (
            "bgw_generate", "aggtrans_bacss_generate", "aggpub_generate",
        ),
        "combined_verification": (
            "bgw_verify", "aggtrans_bacss_verify", "aggpub_verify",
        ),
        "combined_generation_and_verification": (
            "bgw_generate", "bgw_verify",
            "aggtrans_bacss_generate", "aggpub_generate",
            "aggtrans_bacss_verify", "aggpub_verify",
        ),
    },
    "admpc-linear": {
        "randgen_generation": ("randgen_generate",),
        "randgen_verification": ("randgen_verify",),
        "adtrans_generation": ("adtrans_generate",),
        "adtrans_verification": ("adtrans_verify",),
    },
    "admpc-batchrand": {
        "batchrand_generation": ("batchrand_generate",),
        "batchrand_verification": ("batchrand_verify",),
    },
    "admpc-nonlinear": {
        "randgen_generation": ("randgen_generate",),
        "randgen_verification": ("randgen_verify",),
        "adprep_generation": ("adprep_rand_generate", "adprep_generate"),
        "adprep_verification": ("adprep_rand_verify", "adprep_verify"),
        "adtrans_generation": ("adtrans_generate",),
        "adtrans_verification": ("adtrans_verify",),
    },
}

AGGTRANS_GENERATE_OPERATIONS = {
    "aggtrans_bacss_generate", "aggpub_generate",
}
AGGTRANS_VERIFY_OPERATIONS = {
    "aggtrans_bacss_verify", "aggpub_verify",
}
BATCHMUL_GENERATE_OPERATIONS = {"ipakzg_generate"}
BATCHMUL_VERIFY_OPERATIONS = {
    "batchmul_bacss_verify", "ipakzg_verify",
}
NOAGG_GENERATE_OPERATIONS = {"noagg_generate"}
NOAGG_VERIFY_OPERATIONS = {"batch_verify"}
ADTRANS_GENERATE_OPERATIONS = {"adtrans_generate"}
ADTRANS_VERIFY_OPERATIONS = {"adtrans_verify"}
BGW_GENERATE_OPERATIONS = {"bgw_generate"}
BGW_VERIFY_OPERATIONS = {"bgw_verify"}
QUORUM_PROOF_CONFIGS = {
    "aggtrans": ({
        "protocol": "aggtrans",
        "generate": AGGTRANS_GENERATE_OPERATIONS,
        "verify": AGGTRANS_VERIFY_OPERATIONS,
    },),
    "bgw-aggtrans": (
        {
            "protocol": "bgw",
            "generate": BGW_GENERATE_OPERATIONS,
            "verify": BGW_VERIFY_OPERATIONS,
        },
        {
            "protocol": "aggtrans",
            "generate": AGGTRANS_GENERATE_OPERATIONS,
            "verify": AGGTRANS_VERIFY_OPERATIONS,
        },
    ),
    "aggtrans-noagg": ({
        "protocol": "aggtrans-noagg",
        "generate": NOAGG_GENERATE_OPERATIONS,
        "verify": NOAGG_VERIFY_OPERATIONS,
    },),
    "batchmul": ({
        "protocol": "batchmul",
        "generate": BATCHMUL_GENERATE_OPERATIONS,
        "verify": BATCHMUL_VERIFY_OPERATIONS,
    },),
    "admpc-linear": ({
        "protocol": "adtrans",
        "generate": ADTRANS_GENERATE_OPERATIONS,
        "verify": ADTRANS_VERIFY_OPERATIONS,
    },),
    "admpc-nonlinear": ({
        "protocol": "adtrans",
        "generate": ADTRANS_GENERATE_OPERATIONS,
        "verify": ADTRANS_VERIFY_OPERATIONS,
    },),
}


class MetricsValidationError(ValueError):
    pass


def _require(condition, message):
    if not condition:
        raise MetricsValidationError(message)


def _analyze_quorum_protocol(
        documents, totals_by_operation, quorum_config, committee_size,
        threshold, handoffs, allow_incomplete):
    """Select one protocol's frozen n-t generation/verification workload."""
    quorum_protocol = quorum_config["protocol"]
    generate_operations = set(quorum_config["generate"])
    verify_operations = set(quorum_config["verify"])
    required_count = committee_size - threshold
    quorum_by_key = {}

    for document in documents:
        process_id = int(document["process"]["global_process_id"])
        local_party_id = int(document["process"]["local_party_id"])
        for quorum in document["proof_quorums"]:
            if quorum.get("protocol") != quorum_protocol:
                continue
            receiver = int(quorum.get("receiver_local_id", -1))
            target_layer = int(quorum.get("target_layer", -1))
            declared_count = int(quorum.get("required_count", -1))
            dealer_ids = tuple(
                int(value) for value in quorum.get("dealer_ids", ())
            )
            _require(
                receiver == local_party_id,
                f"proof quorum receiver mismatch in process {process_id}",
            )
            _require(
                declared_count == required_count,
                f"wrong proof quorum size in process {process_id}",
            )
            _require(
                len(dealer_ids) == required_count
                and len(set(dealer_ids)) == required_count
                and all(0 <= value < committee_size for value in dealer_ids),
                f"invalid proof quorum dealers in process {process_id}",
            )
            key = (process_id, target_layer, receiver)
            _require(
                key not in quorum_by_key,
                f"duplicate {quorum_protocol} proof quorum {key}",
            )
            quorum_by_key[key] = frozenset(dealer_ids)

    if not allow_incomplete:
        _require(
            len(quorum_by_key) == committee_size * handoffs,
            "wrong number of {} proof quorums: expected {}, got {}".format(
                quorum_protocol, committee_size * handoffs,
                len(quorum_by_key),
            ),
        )

    selected_total_keys = set()
    verification_groups = defaultdict(int)
    selected_by_operation = defaultdict(int)
    for operation in sorted(verify_operations):
        totals = totals_by_operation.get(operation, ())
        dealers_by_quorum = defaultdict(set)
        selected_count_by_quorum = defaultdict(int)
        for total in totals:
            key = (
                int(total["global_process_id"]),
                int(total["target_layer"]),
                int(total["receiver_local_id"]),
            )
            _require(
                key in quorum_by_key,
                f"missing {quorum_protocol} proof quorum for "
                f"{operation} verifier {key}",
            )
            dealer_id = int(total["dealer_local_id"])
            if dealer_id in quorum_by_key[key]:
                dealers_by_quorum[key].add(dealer_id)
                selected_count_by_quorum[key] += 1
                verification_groups[key] += int(total["elapsed_ns"])
                selected_by_operation[operation] += 1
                selected_total_keys.add((
                    int(total["global_process_id"]), total["operation_id"],
                ))
        for key, dealer_ids in quorum_by_key.items():
            if allow_incomplete and key not in dealers_by_quorum:
                continue
            _require(
                dealers_by_quorum[key] == dealer_ids
                and selected_count_by_quorum[key] == required_count,
                f"{operation} does not cover the frozen "
                f"{quorum_protocol} quorum {key}",
            )

    generation_groups = defaultdict(int)
    generation_operations_by_group = defaultdict(set)
    for operation in sorted(generate_operations):
        for total in totals_by_operation.get(operation, ()):
            key = (
                int(total["global_process_id"]),
                int(total["target_layer"]),
                int(total["dealer_local_id"]),
            )
            generation_groups[key] += int(total["elapsed_ns"])
            generation_operations_by_group[key].add(operation)
            selected_total_keys.add((
                int(total["global_process_id"]), total["operation_id"],
            ))
    for key, operations in generation_operations_by_group.items():
        _require(
            operations == generate_operations,
            f"incomplete {quorum_protocol} generation group {key}",
        )

    if not allow_incomplete:
        _require(
            len(generation_groups) == committee_size * handoffs,
            f"wrong number of {quorum_protocol} generation "
            "server/layer samples",
        )
        _require(
            len(verification_groups) == committee_size * handoffs,
            f"wrong number of {quorum_protocol} quorum verification "
            "server/layer samples",
        )

    generation_elapsed = list(generation_groups.values())
    verification_elapsed = list(verification_groups.values())
    available = bool(generation_elapsed and verification_elapsed)
    mean_generation = (
        statistics.fmean(generation_elapsed) if generation_elapsed else None
    )
    mean_verification = (
        statistics.fmean(verification_elapsed)
        if verification_elapsed else None
    )
    mean_total = (
        mean_generation + mean_verification if available else None
    )
    raw_verify_samples = {
        operation: len(totals_by_operation.get(operation, ()))
        for operation in sorted(verify_operations)
    }
    summary = {
        "available": available,
        "protocol": quorum_protocol,
        "definition": (
            "one_generation_plus_n_minus_t_selected_dealer_"
            "verifications_per_server_per_layer"
        ),
        "verification_dealers_per_receiver": required_count,
        "quorum_records": len(quorum_by_key),
        "generation_server_layer_samples": len(generation_elapsed),
        "verification_server_layer_samples": len(verification_elapsed),
        "raw_verification_samples_by_operation": raw_verify_samples,
        "selected_verification_samples_by_operation": {
            operation: selected_by_operation.get(operation, 0)
            for operation in sorted(verify_operations)
        },
        "background_verification_samples_excluded_by_operation": {
            operation: raw_verify_samples[operation]
            - selected_by_operation.get(operation, 0)
            for operation in sorted(verify_operations)
        },
        "mean_generation_batch_elapsed_ns_per_server_layer": mean_generation,
        "mean_quorum_verification_batch_elapsed_ns_per_server_layer": (
            mean_verification
        ),
        "mean_total_batch_elapsed_ns_per_server_layer": mean_total,
    }
    return summary, selected_total_keys


def _combine_quorum_protocol_summaries(
        variant, component_summaries, expected_batch_size):
    """Combine independent protocol quorums into one paper table value."""
    for component in component_summaries.values():
        component_total = component[
            "mean_total_batch_elapsed_ns_per_server_layer"
        ]
        component["mean_total_elapsed_ns_per_unit"] = (
            component_total / expected_batch_size
            if component_total is not None else None
        )
    if len(component_summaries) == 1:
        return next(iter(component_summaries.values()))

    available = all(
        component["available"] for component in component_summaries.values()
    )

    def combined_mean(field):
        if not available:
            return None
        return sum(component[field] for component in component_summaries.values())

    mean_generation = combined_mean(
        "mean_generation_batch_elapsed_ns_per_server_layer"
    )
    mean_verification = combined_mean(
        "mean_quorum_verification_batch_elapsed_ns_per_server_layer"
    )
    mean_total = combined_mean(
        "mean_total_batch_elapsed_ns_per_server_layer"
    )
    generation_sample_counts = [
        component["generation_server_layer_samples"]
        for component in component_summaries.values()
    ]
    verification_sample_counts = [
        component["verification_server_layer_samples"]
        for component in component_summaries.values()
    ]

    def merge_sample_map(field):
        merged = {}
        for component in component_summaries.values():
            for operation, count in component[field].items():
                _require(
                    operation not in merged,
                    f"duplicate quorum operation {operation!r}",
                )
                merged[operation] = count
        return dict(sorted(merged.items()))

    return {
        "available": available,
        "protocol": variant,
        "quorum_protocols": list(component_summaries),
        "definition": (
            "sum_of_independent_protocol_generation_plus_n_minus_t_"
            "selected_dealer_verifications_per_server_per_layer"
        ),
        "verification_dealers_per_receiver": next(iter(
            component_summaries.values()
        ))["verification_dealers_per_receiver"],
        "quorum_records": sum(
            component["quorum_records"]
            for component in component_summaries.values()
        ),
        # Each component contributes one observation for the same logical
        # multiplication layer.  Complete cases have equal counts; for a
        # partial checkpoint this reports the jointly available lower bound.
        "generation_server_layer_samples": min(generation_sample_counts),
        "verification_server_layer_samples": min(
            verification_sample_counts
        ),
        "raw_verification_samples_by_operation": merge_sample_map(
            "raw_verification_samples_by_operation"
        ),
        "selected_verification_samples_by_operation": merge_sample_map(
            "selected_verification_samples_by_operation"
        ),
        "background_verification_samples_excluded_by_operation": (
            merge_sample_map(
                "background_verification_samples_excluded_by_operation"
            )
        ),
        "mean_generation_batch_elapsed_ns_per_server_layer": mean_generation,
        "mean_quorum_verification_batch_elapsed_ns_per_server_layer": (
            mean_verification
        ),
        "mean_total_batch_elapsed_ns_per_server_layer": mean_total,
        "mean_total_elapsed_ns_per_unit": (
            mean_total / expected_batch_size
            if mean_total is not None else None
        ),
        "components": component_summaries,
    }


def _analyze_proof_metrics(
        documents, reference, allow_incomplete=False, coverage=None):
    parameters = reference["parameters"]
    if not bool(parameters.get("proof_metrics_expected", False)):
        return {"enabled": False, "operations": {}}, []

    variant = reference["protocol_variant"]
    _require(variant in VARIANT_OPERATIONS, f"no proof-metric specification for {variant!r}")
    expected_operations = VARIANT_OPERATIONS[variant]
    expected_batch_size = int(parameters["expected_batch_size"])
    committee_size = int(parameters["committee_size"])
    threshold = int(parameters["threshold"])
    handoffs = int(parameters["expected_operations"])
    records = []
    grouped = defaultdict(list)
    for document in documents:
        process_id = int(document["process"]["global_process_id"])
        process_records = document.get("proof_metrics")
        _require(isinstance(process_records, list), f"proof_metrics must be a list in process {process_id}")
        for metric in process_records:
            record = dict(metric)
            record["global_process_id"] = process_id
            operation = record.get("operation")
            _require(operation in expected_operations, f"unexpected proof operation {operation!r} in process {process_id}")
            normalization_count = int(
                record.get("normalization_count", record.get("batch_size", 0))
            )
            _require(normalization_count == expected_batch_size, f"wrong proof normalization count in {record.get('operation_id')}")
            record["normalization_count"] = normalization_count
            _require(int(record.get("elapsed_ns", -1)) >= 0, f"invalid proof elapsed_ns in {record.get('operation_id')}")
            key = (process_id, record.get("operation_id"), operation)
            grouped[key].append(record)
            records.append(record)
    _require(records, "proof metrics were requested but no records were emitted")

    totals_by_operation = defaultdict(list)
    for (process_id, operation_id, operation), operation_records in grouped.items():
        _require(operation_id, f"missing proof operation_id in process {process_id}")
        by_component = {}
        metadata = None
        for record in operation_records:
            component = record.get("component")
            _require(component not in by_component, f"duplicate {operation_id}/{component}")
            by_component[component] = record
            descriptor = (
                record.get("protocol"), int(record.get("source_layer")),
                int(record.get("target_layer")), int(record.get("dealer_local_id")),
                record.get("receiver_local_id"), int(record.get("batch_size")),
                int(record.get("normalization_count")), record.get("unit"),
            )
            if metadata is None:
                metadata = descriptor
            _require(metadata == descriptor, f"inconsistent proof metadata for {operation_id}")
        required = PROOF_COMPONENTS[operation]
        _require(set(by_component) == set(required) | {"total"}, f"wrong components for {operation_id}: {sorted(by_component)}")
        total = by_component["total"]
        _require(total.get("included_components") == list(required), f"wrong total definition for {operation_id}")
        component_sum = sum(int(by_component[name]["elapsed_ns"]) for name in required)
        _require(int(total["elapsed_ns"]) == component_sum, f"proof total does not equal components for {operation_id}")
        component_success = all(bool(by_component[name].get("success")) for name in required)
        _require(bool(total.get("success")) == component_success, f"inconsistent success flag for {operation_id}")
        _require(bool(total.get("success")), f"unsuccessful proof operation {operation_id}")
        totals_by_operation[operation].append(total)

    missing_operation_types = expected_operations - set(totals_by_operation)
    if not allow_incomplete:
        _require(
            not missing_operation_types,
            "missing proof operation types: "
            f"{sorted(missing_operation_types)}",
        )
    expected_sample_ranges = {}
    for operation, totals in totals_by_operation.items():
        if operation.endswith("generate"):
            minimum = maximum = committee_size * handoffs
        else:
            minimum = committee_size * (committee_size - threshold) * handoffs
            maximum = committee_size * committee_size * handoffs
        expected_sample_ranges[operation] = (minimum, maximum)
        if not allow_incomplete:
            _require(
                minimum <= len(totals) <= maximum,
                f"{operation} total count {len(totals)} is outside "
                f"[{minimum}, {maximum}]",
            )

    paper_critical_path = None
    selected_total_keys = set()
    quorum_configs = QUORUM_PROOF_CONFIGS.get(variant, ())
    quorum_generate_operations = set()
    quorum_verify_operations = set()
    if quorum_configs:
        allowed_quorum_protocols = {
            config["protocol"] for config in quorum_configs
        }
        for document in documents:
            process_id = int(document["process"]["global_process_id"])
            quorums = document.get("proof_quorums")
            _require(
                isinstance(quorums, list),
                f"proof_quorums must be a list in process {process_id}",
            )
            for quorum in quorums:
                _require(
                    quorum.get("protocol") in allowed_quorum_protocols,
                    f"unexpected proof quorum protocol in process {process_id}",
                )

        component_summaries = {}
        for quorum_config in quorum_configs:
            quorum_protocol = quorum_config["protocol"]
            quorum_generate_operations.update(quorum_config["generate"])
            quorum_verify_operations.update(quorum_config["verify"])
            component_summary, component_selected_keys = (
                _analyze_quorum_protocol(
                    documents, totals_by_operation, quorum_config,
                    committee_size, threshold, handoffs, allow_incomplete,
                )
            )
            component_summaries[quorum_protocol] = component_summary
            selected_total_keys.update(component_selected_keys)

        paper_critical_path = _combine_quorum_protocol_summaries(
            variant, component_summaries, expected_batch_size
        )

        for record in records:
            operation = record["operation"]
            if operation in (
                quorum_generate_operations | quorum_verify_operations
            ):
                record["paper_critical_included"] = (
                    record["global_process_id"], record["operation_id"]
                ) in selected_total_keys

    operation_summary = {}
    for operation, totals in sorted(totals_by_operation.items()):
        elapsed = [int(item["elapsed_ns"]) for item in totals]
        component_elapsed = defaultdict(list)
        total_keys = {
            (item["global_process_id"], item["operation_id"])
            for item in totals
        }
        for record in records:
            if record["operation"] == operation and record["component"] != "total":
                if (record["global_process_id"], record["operation_id"]) in total_keys:
                    component_elapsed[record["component"]].append(int(record["elapsed_ns"]))
        normalized_elapsed = [
            int(item["elapsed_ns"]) / int(item["normalization_count"])
            for item in totals
        ]
        batch_sizes = sorted({int(item["batch_size"]) for item in totals})
        operation_summary[operation] = {
            "samples": len(elapsed),
            "successful_samples": sum(bool(item["success"]) for item in totals),
            "expected_samples_min": expected_sample_ranges[operation][0],
            "expected_samples_max": expected_sample_ranges[operation][1],
            "batch_size": batch_sizes[0] if len(batch_sizes) == 1 else batch_sizes,
            "normalization_count": expected_batch_size,
            "mean_batch_elapsed_ns": statistics.fmean(elapsed),
            "median_batch_elapsed_ns": statistics.median(elapsed),
            "min_batch_elapsed_ns": min(elapsed),
            "max_batch_elapsed_ns": max(elapsed),
            "mean_elapsed_ns_per_unit": statistics.fmean(normalized_elapsed),
            "component_mean_elapsed_ns": {
                name: statistics.fmean(values)
                for name, values in sorted(component_elapsed.items())
            },
        }
        if operation in quorum_verify_operations and paper_critical_path:
            operation_summary[operation]["paper_quorum_samples"] = (
                paper_critical_path[
                    "selected_verification_samples_by_operation"
                ][operation]
            )
            operation_summary[operation]["background_samples_excluded"] = (
                paper_critical_path[
                    "background_verification_samples_excluded_by_operation"
                ][operation]
            )
    phase_summary = {}
    for phase, operations in FULL_CRYPTO_PHASES.get(variant, {}).items():
        missing = [
            operation for operation in operations
            if operation not in operation_summary
        ]
        phase_summary[phase] = {
            "included_operations": list(operations),
            "available": not missing,
            "missing_operations": missing,
            "mean_elapsed_ns_per_unit": (
                None if missing else sum(
                    operation_summary[operation]["mean_elapsed_ns_per_unit"]
                    for operation in operations
                )
            ),
        }
    return {
        "enabled": True,
        "complete_case": not allow_incomplete,
        "process_coverage": coverage,
        "scope": "local_commitment_and_proof_cryptographic_operations_only",
        "excluded": [
            "circuit_exec", "interpolation", "mvba", "network_wait",
            "serialization", "encryption",
        ],
        "operations": operation_summary,
        "full_crypto_phases": phase_summary,
        "paper_critical_path": paper_critical_path,
    }, records


def load_documents(input_dir):
    paths = sorted(Path(input_dir).glob("communication-*.json"))
    _require(paths, f"no communication artifacts found in {input_dir}")
    documents = []
    for path in paths:
        try:
            with path.open("r", encoding="utf-8") as stream:
                document = json.load(stream)
        except (OSError, ValueError) as exc:
            raise MetricsValidationError(f"cannot read {path}: {exc}") from exc
        document["_artifact_path"] = str(path)
        documents.append(document)
    return documents


def analyze_documents(documents, allow_incomplete=False):
    _require(documents, "empty communication case")
    reference = documents[0]
    stable_fields = (
        "schema", "implementation", "experiment", "protocol_variant",
        "run_id", "parameters", "selection",
    )
    for field in stable_fields:
        _require(field in reference, f"artifact is missing {field}")
    _require(reference["schema"] == SCHEMA, f"unsupported schema {reference['schema']!r}")

    ids = []
    checkpoint_ids = []
    drained_ids = []
    for document in documents:
        path = document.get("_artifact_path", "<memory>")
        for field in stable_fields:
            _require(document.get(field) == reference[field], f"case mismatch for {field} in {path}")
        _require(document.get("completed") is True, f"incomplete process artifact: {path}")
        _require("process" in document and "communication" in document, f"missing process/communication in {path}")
        process_id = int(document["process"]["global_process_id"])
        ids.append(process_id)
        artifact_state = document.get("artifact_state", "final")
        _require(
            artifact_state in {"final", "protocol-complete-checkpoint"},
            f"unknown artifact_state {artifact_state!r} in {path}",
        )
        if artifact_state == "protocol-complete-checkpoint":
            checkpoint_ids.append(process_id)
        if document.get("transport", {}).get("drained_on_exit") is True:
            drained_ids.append(process_id)

    _require(len(ids) == len(set(ids)), "duplicate global_process_id")
    parameters = reference["parameters"]
    expected_processes = int(parameters["expected_processes"])
    expected_ids = set(range(expected_processes))
    measured_ids = set(ids)
    _require(
        measured_ids <= expected_ids,
        f"out-of-range process IDs: {sorted(measured_ids - expected_ids)}",
    )
    missing_process_ids = sorted(expected_ids - measured_ids)
    case_complete = not missing_process_ids
    if not allow_incomplete:
        _require(
            case_complete,
            f"incomplete case: expected process IDs 0..{expected_processes - 1}, got {sorted(ids)}",
        )
    process_coverage = len(ids) / expected_processes
    communication_complete = (
        case_complete
        and not checkpoint_ids
        and len(drained_ids) == expected_processes
    )

    selection = reference["selection"]
    included_tags = set(selection.get("included_tags", []))
    _require(included_tags, "selection.included_tags must not be empty")
    excluded_prefixes = tuple(selection.get("excluded_tag_prefixes", []))
    layer_ranges = selection.get("tag_layer_ranges", {})
    unit = selection.get("normalization_unit")
    _require(unit in {"sharing", "gate"}, f"unsupported normalization unit {unit!r}")

    included_bytes = 0
    included_messages = 0
    excluded_bytes = 0
    raw_rows = []
    tag_totals = defaultdict(lambda: {"bytes": 0, "messages": 0})
    process_totals = defaultdict(int)

    for document in documents:
        communication = document["communication"]
        by_tag = communication.get("by_tag")
        _require(isinstance(by_tag, dict), "communication.by_tag must be an object")
        observed_bytes = sum(int(value["bytes"]) for value in by_tag.values())
        observed_messages = sum(int(value["messages"]) for value in by_tag.values())
        _require(observed_bytes == int(communication["total_remote_payload_bytes"]), "per-tag bytes do not sum to process total")
        _require(observed_messages == int(communication["total_remote_messages"]), "per-tag messages do not sum to process total")
        process_id = int(document["process"]["global_process_id"])
        layer = int(document["process"]["physical_layer"])
        for tag, values in sorted(by_tag.items()):
            tag_bytes = int(values["bytes"])
            tag_messages = int(values["messages"])
            selected = tag in included_tags
            if selected and tag in layer_ranges:
                lower, upper = layer_ranges[tag]
                selected = int(lower) <= layer <= int(upper)
            known_excluded = tag.startswith(excluded_prefixes) or (
                tag in included_tags and not selected
            )
            _require(selected or known_excluded, f"unknown communication tag {tag!r} in process {process_id}")
            if selected:
                included_bytes += tag_bytes
                included_messages += tag_messages
                tag_totals[tag]["bytes"] += tag_bytes
                tag_totals[tag]["messages"] += tag_messages
                process_totals[process_id] += tag_bytes
            else:
                excluded_bytes += tag_bytes
            raw_rows.append({
                "global_process_id": process_id,
                "physical_layer": layer,
                "tag": tag,
                "bytes": tag_bytes,
                "messages": tag_messages,
                "included": selected,
            })

    for tag in sorted(included_tags):
        if not allow_incomplete:
            _require(tag_totals[tag]["messages"] > 0, f"selected tag {tag!r} has no messages")

    batch_records = []
    for document in documents:
        process_id = int(document["process"]["global_process_id"])
        for batch in document.get("protocol_batches", []):
            record = dict(batch)
            record["global_process_id"] = process_id
            batch_records.append(record)
    _require(batch_records, "no protocol batch metadata")

    operations = {}
    tag_protocols = defaultdict(set)
    roles = defaultdict(lambda: defaultdict(set))
    for batch in batch_records:
        tag = batch["tag"]
        _require(tag in included_tags, f"batch metadata refers to unselected tag {tag!r}")
        operation_id = batch["operation_id"]
        descriptor = (int(batch["batch_size"]), batch["unit"])
        if operation_id in operations:
            _require(operations[operation_id] == descriptor, f"inconsistent batch size/unit for {operation_id}")
        else:
            operations[operation_id] = descriptor
        tag_protocols[tag].add(batch["protocol"])
        roles[(operation_id, tag)][batch["role"]].add(batch["global_process_id"])

    expected_operations = int(parameters["expected_operations"])
    expected_batch_size = int(parameters["expected_batch_size"])
    if not allow_incomplete:
        _require(len(operations) == expected_operations, f"expected {expected_operations} operations, got {len(operations)}")
    for operation_id, (batch_size, batch_unit) in operations.items():
        _require(batch_size == expected_batch_size, f"wrong batch size for {operation_id}: expected {expected_batch_size}, got {batch_size}")
        _require(batch_unit == unit, f"wrong unit for {operation_id}: {batch_unit}")

    committee_size = int(parameters["committee_size"])
    for (operation_id, tag), role_map in roles.items():
        if "participant" in role_map:
            _require(len(role_map) == 1, f"mixed participant/source roles for {operation_id}/{tag}")
            if not allow_incomplete:
                _require(len(role_map["participant"]) == committee_size, f"incomplete participant metadata for {operation_id}/{tag}")
        else:
            _require(set(role_map) <= {"source", "destination"}, f"unknown role metadata for {operation_id}/{tag}")
            if not allow_incomplete:
                _require(set(role_map) == {"source", "destination"}, f"missing source/destination metadata for {operation_id}/{tag}")
                _require(len(role_map["source"]) == committee_size, f"incomplete source metadata for {operation_id}/{tag}")
                _require(len(role_map["destination"]) == committee_size, f"incomplete destination metadata for {operation_id}/{tag}")

    denominator = sum(batch_size for batch_size, _ in operations.values())
    _require(denominator > 0, "normalization denominator is zero")
    component_bytes = defaultdict(int)
    for tag, totals in tag_totals.items():
        protocols = tag_protocols[tag]
        _require(len(protocols) == 1, f"tag {tag!r} maps to multiple components")
        component_bytes[next(iter(protocols))] += totals["bytes"]

    summary = {
        "schema": "protocol-communication-summary-v1",
        "implementation": reference["implementation"],
        "experiment": reference["experiment"],
        "protocol_variant": reference["protocol_variant"],
        "run_id": reference["run_id"],
        "parameters": parameters,
        "case_complete": case_complete,
        "communication_complete": communication_complete,
        "expected_processes": expected_processes,
        "measured_processes": len(ids),
        "measured_process_ids": sorted(ids),
        "missing_process_ids": missing_process_ids,
        "checkpoint_process_ids": sorted(checkpoint_ids),
        "process_coverage": process_coverage,
        "included_tags": sorted(included_tags),
        "system_total_payload_bytes": (
            included_bytes if communication_complete else None
        ),
        "system_total_messages": (
            included_messages if communication_complete else None
        ),
        "observed_payload_bytes": included_bytes,
        "observed_messages": included_messages,
        "excluded_payload_bytes": excluded_bytes,
        "normalization_unit": unit,
        "normalization_count": denominator,
        "bytes_per_{}".format(unit): (
            included_bytes / denominator if communication_complete else None
        ),
        "average_bytes_per_party": (
            included_bytes / expected_processes
            if communication_complete else None
        ),
        "observed_average_bytes_per_process": included_bytes / len(ids),
        "component_bytes": dict(sorted(component_bytes.items())),
        "tag_totals": dict(sorted(tag_totals.items())),
    }
    proof_summary, proof_rows = _analyze_proof_metrics(
        documents,
        reference,
        allow_incomplete=allow_incomplete and not case_complete,
        coverage=process_coverage,
    )
    summary["proof_computation"] = proof_summary
    process_rows = [
        {"global_process_id": process_id, "included_bytes": process_totals[process_id]}
        for process_id in sorted(ids)
    ]
    return summary, raw_rows, process_rows, proof_rows


def write_outputs(output_dir, summary, raw_rows, process_rows, proof_rows):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    with (output_dir / "summary.json").open("w", encoding="utf-8") as stream:
        json.dump(summary, stream, indent=2, sort_keys=True)
        stream.write("\n")
    with (output_dir / "summary.csv").open("w", encoding="utf-8", newline="") as stream:
        fields = [
            "implementation", "experiment", "protocol_variant", "run_id",
            "case_complete", "communication_complete", "expected_processes",
            "measured_processes", "process_coverage",
            "system_total_payload_bytes", "system_total_messages",
            "normalization_unit", "normalization_count",
            "average_bytes_per_party",
            "bytes_per_{}".format(summary["normalization_unit"]),
        ]
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerow(summary)
    with (output_dir / "raw_by_process_tag.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["global_process_id", "physical_layer", "tag", "bytes", "messages", "included"])
        writer.writeheader()
        writer.writerows(raw_rows)
    with (output_dir / "raw_by_process.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["global_process_id", "included_bytes"])
        writer.writeheader()
        writer.writerows(process_rows)
    proof_fields = [
        "global_process_id", "protocol", "operation", "operation_id",
        "component", "source_layer", "target_layer", "dealer_local_id",
        "receiver_local_id", "batch_size", "elapsed_ns", "success",
        "normalization_count", "unit", "included_components",
        "paper_critical_included",
    ]
    with (output_dir / "raw_proof_metrics.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=proof_fields, extrasaction="ignore")
        writer.writeheader()
        for row in proof_rows:
            normalized = dict(row)
            if "included_components" in normalized:
                normalized["included_components"] = ";".join(normalized["included_components"])
            writer.writerow(normalized)
    with (output_dir / "proof_summary.csv").open("w", encoding="utf-8", newline="") as stream:
        fields = [
            "operation", "samples", "successful_samples", "batch_size",
            "normalization_count",
            "mean_batch_elapsed_ns", "median_batch_elapsed_ns",
            "min_batch_elapsed_ns", "max_batch_elapsed_ns",
            "mean_elapsed_ns_per_unit",
        ]
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for operation, values in summary["proof_computation"]["operations"].items():
            writer.writerow({"operation": operation, **values})
    critical = summary["proof_computation"].get("paper_critical_path")
    with (output_dir / "proof_paper_critical_path.csv").open(
        "w", encoding="utf-8", newline=""
    ) as stream:
        fields = [
            "protocol", "definition", "available",
            "verification_dealers_per_receiver",
            "quorum_records", "generation_server_layer_samples",
            "verification_server_layer_samples",
            "mean_generation_batch_elapsed_ns_per_server_layer",
            "mean_quorum_verification_batch_elapsed_ns_per_server_layer",
            "mean_total_batch_elapsed_ns_per_server_layer",
            "mean_total_elapsed_ns_per_unit",
        ]
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        if critical is not None:
            writer.writerow(critical)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_dir", help="directory containing communication-*.json")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument(
        "--allow-incomplete", action="store_true",
        help=(
            "analyze completed process checkpoints even when some process "
            "artifacts are missing; incomplete communication totals are "
            "reported as null"
        ),
    )
    args = parser.parse_args(argv)
    try:
        summary, raw_rows, process_rows, proof_rows = analyze_documents(
            load_documents(args.input_dir),
            allow_incomplete=args.allow_incomplete,
        )
        write_outputs(args.output_dir, summary, raw_rows, process_rows, proof_rows)
    except MetricsValidationError as exc:
        print(f"protocol-overhead analysis failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
