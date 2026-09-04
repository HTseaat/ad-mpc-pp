#!/usr/bin/env python3
"""Fail-closed validation for one distributed AD-MPC adversarial run."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Dict, List, Sequence

WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from unified.extract_adversarial_traces import (
    ScenarioSpec,
    read_scenario,
    validate_scenario,
    write_tsv,
)


def matching_events(
    events: Sequence[Dict[str, object]], name: str
) -> List[Dict[str, object]]:
    return [event for event in events if event.get("event") == name]


def normalized_ids(event: Dict[str, object], field: str) -> List[int] | None:
    values = event.get(field)
    if not isinstance(values, list):
        return None
    try:
        return sorted(int(value) for value in values)
    except (TypeError, ValueError):
        return None


def validate_config_events(
    events: Sequence[Dict[str, object]],
    *,
    scenario: str,
    n: int,
    t: int,
    layers: int,
    computation_epoch: int,
    delay_ms: int | None,
    attack_index: int | None,
) -> List[str]:
    errors: List[str] = []
    configs = matching_events(events, "config")
    expected_count = n * layers
    if len(configs) != expected_count:
        errors.append(f"expected {expected_count} fault config events, got {len(configs)}")
        return errors

    mode = "delay" if scenario == "admpc-delay" else "byzantine"
    selected_ids = list(range(n - t, n))
    identities = []
    for event in configs:
        identity = (event.get("physical_layer_id"), event.get("local_party_id"))
        identities.append(identity)
        expected = {
            "schema": "admpc-fault-v1",
            "protocol": "admpc",
            "mode": mode,
            "target": "adtrans",
            "computation_epoch": computation_epoch,
            "delta_ms": delay_ms,
            "attack_index": attack_index,
            "selected_local_ids": selected_ids,
        }
        for key, value in expected.items():
            if event.get(key) != value:
                errors.append(
                    f"config {identity} has {key}={event.get(key)!r}, expected {value!r}"
                )
                break
        layer, party = identity
        if isinstance(layer, int) and isinstance(party, int):
            expected_global_id = layer * n + party
            if event.get("global_party_id") != expected_global_id:
                errors.append(
                    f"config {identity} has global_party_id={event.get('global_party_id')!r}, "
                    f"expected {expected_global_id}"
                )

    expected_identities = {(layer, party) for layer in range(layers) for party in range(n)}
    if len(identities) != len(set(identities)) or set(identities) != expected_identities:
        errors.append(
            "fault config events do not cover every physical-layer/local-party pair exactly once"
        )
    return errors


def validate_destination_identity(
    events: Sequence[Dict[str, object]], *, n: int, destination_layer: int, name: str
) -> List[str]:
    errors: List[str] = []
    actual = matching_events(events, name)
    expected = {(destination_layer, receiver) for receiver in range(n)}
    identities = [
        (event.get("physical_layer_id"), event.get("local_party_id"))
        for event in actual
    ]
    if len(identities) != n or len(set(identities)) != n or set(identities) != expected:
        errors.append(
            f"{name} does not cover each receiver at destination layer {destination_layer} exactly once"
        )
    return errors


def validate_identical_sets(
    events: Sequence[Dict[str, object]], *, name: str, field: str, expected: List[int]
) -> List[str]:
    errors: List[str] = []
    values = [normalized_ids(event, field) for event in matching_events(events, name)]
    if any(value is None for value in values):
        errors.append(f"{name} contains a malformed {field}")
    elif values and any(value != expected for value in values):
        errors.append(f"{name} {field} values disagree with expected {expected}")
    return errors


def analyze_case(
    *,
    case_dir: Path,
    scenario: str,
    n: int,
    t: int,
    layers: int,
    computation_epoch: int,
    delay_ms: int | None,
    attack_index: int | None,
    output_dir: Path,
) -> Dict[str, object]:
    spec = ScenarioSpec(scenario, "admpc", case_dir / "logs", "distributed")
    layer_rows, event_rows, metadata = read_scenario(spec, n, layers)
    base = validate_scenario(spec, metadata, n, t, layers)
    errors = list(base["errors"])
    events = metadata["events"]

    errors.extend(
        validate_config_events(
            events,
            scenario=scenario,
            n=n,
            t=t,
            layers=layers,
            computation_epoch=computation_epoch,
            delay_ms=delay_ms,
            attack_index=attack_index,
        )
    )

    expected_processes = n * layers
    if metadata["curve_ready_count"] != expected_processes:
        errors.append(
            f"expected {expected_processes} CURVE readiness markers, got "
            f"{metadata['curve_ready_count']}"
        )
    auth_summaries = metadata["curve_auth_summaries"]
    if len(auth_summaries) not in (0, expected_processes):
        errors.append(
            f"expected either zero (AD-MPC logging) or {expected_processes} CURVE "
            "authentication summaries, got "
            f"{len(auth_summaries)}"
        )
    if any(any(value != 0 for value in summary) for summary in auth_summaries):
        errors.append("one or more CURVE authentication anomaly counters are non-zero")
    if metadata["curve_auth_anomalies"]:
        errors.append(
            f"found {len(metadata['curve_auth_anomalies'])} CURVE authentication anomaly warnings"
        )

    destination_layer = computation_epoch + 1
    all_dealers = list(range(n))
    selected = list(range(n - t, n))
    honest = list(range(n - t))
    for name in ("adtrans_acss_complete", "adtrans_common_subset"):
        errors.extend(
            validate_destination_identity(
                events, n=n, destination_layer=destination_layer, name=name
            )
        )

    details: Dict[str, object] = {}
    if scenario == "admpc-delay":
        scheduled = matching_events(events, "delay_scheduled")
        released = matching_events(events, "delay_released")
        expected_sources = {
            (computation_epoch, dealer) for dealer in selected
        }
        for name, values in (("delay_scheduled", scheduled), ("delay_released", released)):
            identities = {
                (event.get("physical_layer_id"), event.get("local_party_id"))
                for event in values
            }
            if identities != expected_sources:
                errors.append(f"{name} does not match the selected C{computation_epoch} dealers")
        actual_delays = [event.get("actual_delay_ms") for event in released]
        if any(
            not isinstance(value, (int, float)) or value < delay_ms
            for value in actual_delays
        ):
            errors.append(f"one or more actual delays are below configured {delay_ms} ms")
        errors.extend(
            validate_identical_sets(
                events,
                name="adtrans_acss_complete",
                field="dealer_local_ids",
                expected=all_dealers,
            )
        )
        errors.extend(
            validate_identical_sets(
                events,
                name="adtrans_common_subset",
                field="dealer_local_ids",
                expected=all_dealers,
            )
        )
        for event in matching_events(events, "adtrans_common_subset"):
            if normalized_ids(event, "corrupted_dealers_in_subset") != selected:
                errors.append(
                    "delay common subset did not consistently record the selected delayed dealer"
                )
                break
        if matching_events(events, "adtrans_verification") or matching_events(
            events, "adtrans_robust_filter"
        ):
            errors.append("delay scenario emitted Byzantine-only ADtrans evidence")
        details["actual_delay_ms"] = actual_delays
    else:
        mutations = matching_events(events, "byzantine_mutation")
        expected_sources = {(computation_epoch, dealer) for dealer in selected}
        mutation_identities = {
            (event.get("physical_layer_id"), event.get("local_party_id"))
            for event in mutations
        }
        if mutation_identities != expected_sources:
            errors.append("ADtrans mutation does not match the selected C3 dealer")
        for event in mutations:
            expected_fields = {
                "component": "adtrans",
                "attack_style": "outgoing_share_fork",
                "outgoing_copy": True,
                "acss_resharing_recomputed": True,
                "commitment_recomputed": True,
                "mask_recomputed": True,
                "consistency_proof_recomputed": True,
            }
            if any(event.get(key) != value for key, value in expected_fields.items()):
                errors.append("ADtrans mutation is missing fork-consistency evidence")
                break

        verifications = matching_events(events, "adtrans_verification")
        verification_ids = {
            (
                event.get("physical_layer_id"),
                event.get("local_party_id"),
                event.get("dealer_local_id"),
            )
            for event in verifications
        }
        expected_verification_ids = {
            (destination_layer, receiver, dealer)
            for receiver in range(n)
            for dealer in selected
        }
        if len(verifications) != len(expected_verification_ids) or verification_ids != expected_verification_ids:
            errors.append("ADtrans verification does not cover every receiver/attacked-dealer pair")
        if any(
            event.get("accepted") is not True
            or event.get("share_binding_valid") is not True
            or event.get("consistency_proof_valid") is not True
            or event.get("legacy_fast_path_overridden") is not True
            for event in verifications
        ):
            errors.append("one or more attacked ADtrans proposals failed local verification evidence")

        robust_events = matching_events(events, "adtrans_robust_filter")
        for event in robust_events:
            if (
                event.get("all_candidates_checked") is not True
                or normalized_ids(event, "candidate_dealers") != all_dealers
                or normalized_ids(event, "corrupted_dealers_detected") != selected
                or normalized_ids(event, "post_decode_mismatch_dealers") != selected
                or normalized_ids(event, "error_dealers") != selected
                or normalized_ids(event, "filtered_dealers") != honest
                or normalized_ids(event, "matching_randomness_dealers") != honest
                or normalized_ids(event, "decoder_error_dealers") != []
            ):
                errors.append("ADtrans robust filter evidence is incomplete or inconsistent")
                break

        errors.extend(
            validate_identical_sets(
                events,
                name="adtrans_acss_complete",
                field="dealer_local_ids",
                expected=all_dealers,
            )
        )
        errors.extend(
            validate_identical_sets(
                events,
                name="adtrans_common_subset",
                field="dealer_local_ids",
                expected=honest,
            )
        )
        for event in matching_events(events, "adtrans_common_subset"):
            if normalized_ids(event, "corrupted_dealers_in_subset") != []:
                errors.append("ADtrans common subset retained an attacked dealer")
                break
        details["filtered_dealers"] = [
            normalized_ids(event, "filtered_dealers") for event in robust_events
        ]

    final_rows = [row for row in layer_rows if row["physical_layer"] == layers - 1]
    final_layer_latency = final_rows[0]["completion_time_sec"] if len(final_rows) == 1 else None
    if final_layer_latency is None:
        errors.append("final physical-layer latency is unavailable")

    for row in layer_rows:
        physical = int(row["physical_layer"])
        row["semantic_stage"] = (
            "input" if physical == 0 else "output" if physical == layers - 1 else f"C{physical}"
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    write_tsv(
        output_dir / "layer-trace.tsv",
        layer_rows,
        (
            "scenario",
            "protocol",
            "physical_layer",
            "semantic_stage",
            "completed_layers",
            "completion_time_sec",
            "min_node_time_sec",
            "mean_node_time_sec",
            "max_node_time_sec",
            "completed_nodes",
        ),
    )
    write_tsv(
        output_dir / "fault-events.tsv",
        sorted(event_rows, key=lambda row: (float(row["relative_time_sec"] or 0), str(row["event"]))),
        (
            "scenario",
            "protocol",
            "event",
            "component",
            "physical_layer",
            "local_party_id",
            "relative_time_sec",
            "details_json",
        ),
    )

    summary: Dict[str, object] = {
        **base,
        "success": not errors,
        "errors": errors,
        "log_layout": "distributed",
        "paper_latency_metric": "max final-physical-layer layer_time",
        "final_layer_latency_sec": final_layer_latency,
        "curve_ready_count": metadata["curve_ready_count"],
        "curve_auth_summary_count": len(auth_summaries),
        "curve_auth_anomaly_count": len(metadata["curve_auth_anomalies"]),
        "curve_auth_evidence": (
            "per-process zero counters"
            if auth_summaries
            else "authenticated readiness barrier plus warning scan"
        ),
        "destination_layer": destination_layer,
        "selected_local_ids": selected,
        "counts": {
            **base["counts"],
            "adtrans_acss_complete": len(matching_events(events, "adtrans_acss_complete")),
            "adtrans_common_subset": len(matching_events(events, "adtrans_common_subset")),
            "adtrans_robust_filter": len(matching_events(events, "adtrans_robust_filter")),
        },
        **details,
    }
    (output_dir / "adversarial-summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case-dir", type=Path, required=True)
    parser.add_argument("--scenario", choices=("admpc-delay", "admpc-byzantine"), required=True)
    parser.add_argument("--n", type=int, default=4)
    parser.add_argument("--t", type=int, default=1)
    parser.add_argument("--layers", type=int, default=8)
    parser.add_argument("--computation-epoch", type=int, default=3)
    parser.add_argument("--delay-ms", type=int)
    parser.add_argument("--attack-index", type=int)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()

    if args.scenario == "admpc-delay":
        if args.delay_ms is None or args.attack_index is not None:
            parser.error("delay requires --delay-ms and forbids --attack-index")
    elif args.attack_index is None or args.delay_ms is not None:
        parser.error("Byzantine requires --attack-index and forbids --delay-ms")

    output_dir = args.output_dir or args.case_dir
    summary = analyze_case(
        case_dir=args.case_dir,
        scenario=args.scenario,
        n=args.n,
        t=args.t,
        layers=args.layers,
        computation_epoch=args.computation_epoch,
        delay_ms=args.delay_ms,
        attack_index=args.attack_index,
        output_dir=output_dir,
    )
    if summary["success"]:
        print(
            f"PASS {args.scenario}: final-layer latency "
            f"{summary['final_layer_latency_sec']:.6f}s"
        )
        return 0
    print(f"FAIL {args.scenario}: " + "; ".join(summary["errors"]))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
