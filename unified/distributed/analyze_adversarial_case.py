#!/usr/bin/env python3
"""Fail-closed validation for one distributed Continuum adversarial run."""

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
    count_events,
    read_scenario,
    validate_scenario,
    write_tsv,
)


def matching_events(events: Sequence[Dict[str, object]], name: str) -> List[Dict[str, object]]:
    return [event for event in events if event.get("event") == name]


def identical_dealer_sets(
    events: Sequence[Dict[str, object]], name: str
) -> tuple[bool, List[List[int]]]:
    values = [event.get("dealers") for event in matching_events(events, name)]
    normalized = [sorted(int(value) for value in dealers) for dealers in values if isinstance(dealers, list)]
    return bool(normalized) and len(normalized) == len(values) and len({tuple(value) for value in normalized}) == 1, normalized


def exclusion_keys(
    events: Sequence[Dict[str, object]], component: str
) -> tuple[set[tuple[object, ...]], set[tuple[object, ...]]]:
    """Return logical identities and payload-sensitive keys for exclusions.

    A protocol task may observe the same rejected ACSS output more than once.
    Those repeats are idempotent evidence, not additional corrupted dealers.
    Different commitment digests for the same receiver/dealer remain distinct
    and therefore fail the expected unique-key count below.
    """
    identities: set[tuple[object, ...]] = set()
    unique: set[tuple[object, ...]] = set()
    for event in matching_events(events, f"{component}_commitment_excluded"):
        identity = (
            event.get("physical_layer_id"),
            event.get("local_party_id"),
            event.get("dealer_local_id"),
        )
        identities.add(identity)
        if component == "aggtrans":
            digest = (event.get("commitment_digest"),)
        else:
            digest = (
                event.get("left_commitment_digest"),
                event.get("right_commitment_digest"),
            )
        unique.add(identity + digest)
    return identities, unique


def validate_config_events(
    events: Sequence[Dict[str, object]],
    *,
    scenario: str,
    n: int,
    t: int,
    layers: int,
    computation_epoch: int,
    batchmul_epoch: int | None,
    delay_ms: int | None,
    attack_index: int | None,
) -> List[str]:
    errors: List[str] = []
    configs = matching_events(events, "config")
    expected_count = n * layers
    if len(configs) != expected_count:
        errors.append(f"expected {expected_count} fault config events, got {len(configs)}")
        return errors

    mode = "delay" if scenario == "continuum-delay" else "byzantine"
    target = "handoff" if mode == "delay" else "aggtrans+batchmul"
    selected_ids = list(range(n - t, n))
    identities = set()
    for event in configs:
        identity = (event.get("physical_layer_id"), event.get("local_party_id"))
        identities.add(identity)
        expected = {
            "schema": "continuum-fault-v1",
            "protocol": "continuum",
            "mode": mode,
            "target": target,
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
        if mode == "byzantine" and event.get("component_epochs") != {
            "aggtrans": computation_epoch,
            "batchmul": batchmul_epoch,
        }:
            errors.append(f"config {identity} has inconsistent component epochs")

    expected_identities = {(layer, party) for layer in range(layers) for party in range(n)}
    if identities != expected_identities:
        errors.append("fault config events do not cover every physical-layer/local-party pair exactly once")
    return errors


def analyze_case(
    *,
    case_dir: Path,
    scenario: str,
    n: int,
    t: int,
    layers: int,
    computation_epoch: int,
    batchmul_epoch: int | None,
    delay_ms: int | None,
    attack_index: int | None,
    output_dir: Path,
) -> Dict[str, object]:
    spec = ScenarioSpec(scenario, "continuum", case_dir / "logs", "distributed")
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
            batchmul_epoch=batchmul_epoch,
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
    if len(auth_summaries) != expected_processes:
        errors.append(
            f"expected {expected_processes} CURVE authentication summaries, got "
            f"{len(auth_summaries)}"
        )
    if any(any(value != 0 for value in summary) for summary in auth_summaries):
        errors.append("one or more CURVE authentication anomaly counters are non-zero")

    reconstruction_lengths = metadata["output_reconstruction_lengths"]
    if len(reconstruction_lengths) != n:
        errors.append(
            f"expected {n} final output reconstruction markers, got "
            f"{len(reconstruction_lengths)}"
        )
    elif min(reconstruction_lengths) <= 0 or len(set(reconstruction_lengths)) != 1:
        errors.append("final output reconstruction lengths are empty or inconsistent")

    dealer_sets: Dict[str, List[List[int]]] = {}
    for component in ("aggtrans", "batchmul"):
        name = f"{component}_common_subset"
        component_events = matching_events(events, name)
        if len(component_events) != n:
            errors.append(f"expected {n} {name} events, got {len(component_events)}")
        identical, values = identical_dealer_sets(events, name)
        dealer_sets[component] = values
        if component_events and not identical:
            errors.append(f"{name} dealer sets disagree across destination parties")

    extra_counts: Dict[str, object] = {}
    if scenario == "continuum-delay":
        releases = matching_events(events, "delay_released")
        actual_delays = [event.get("actual_delay_ms") for event in releases]
        if any(not isinstance(value, (int, float)) or value < delay_ms for value in actual_delays):
            errors.append(f"one or more actual delays are below configured {delay_ms} ms")
        delayed_in_subsets = {
            component: [
                event.get("delayed_dealers_in_subset", [])
                for event in matching_events(events, f"{component}_common_subset")
            ]
            for component in ("aggtrans", "batchmul")
        }
        if any(
            event.get("corrupted_dealers_in_subset") != []
            for component in ("aggtrans", "batchmul")
            for event in matching_events(events, f"{component}_common_subset")
        ):
            errors.append("delay scenario marked a common-subset dealer as corrupted")
        extra_counts.update(
            {
                "actual_delay_ms": actual_delays,
                "delayed_dealers_in_subsets": delayed_in_subsets,
            }
        )
    else:
        expected_attacked_receipts = n * t
        for component in ("aggtrans", "batchmul"):
            verification_name = f"{component}_verification"
            exclusion_name = f"{component}_commitment_excluded"
            verification_events = matching_events(events, verification_name)
            exclusion_events = matching_events(events, exclusion_name)
            identities, unique_exclusions = exclusion_keys(events, component)
            destination_layer = (
                computation_epoch + 1
                if component == "aggtrans"
                else batchmul_epoch + 1
            )
            expected_identities = {
                (destination_layer, receiver, dealer)
                for receiver in range(n)
                for dealer in range(n - t, n)
            }
            if identities != expected_identities:
                errors.append(
                    f"{exclusion_name} does not cover the expected "
                    "destination/receiver/dealer identities"
                )
            if len(unique_exclusions) != expected_attacked_receipts:
                errors.append(
                    f"expected {expected_attacked_receipts} unique {exclusion_name} "
                    f"payloads, got {len(unique_exclusions)}"
                )
            if any(event.get("accepted") is not True for event in verification_events):
                errors.append(f"{verification_name} contains a locally invalid fork")
            if any(
                event.get("corrupted_dealers_in_subset") != []
                for event in matching_events(events, f"{component}_common_subset")
            ):
                errors.append(f"{component} common subset retained a corrupted dealer")
            extra_counts[f"{component}_exclusions"] = len(exclusion_events)
            extra_counts[f"{component}_unique_exclusions"] = len(unique_exclusions)
            extra_counts[f"{component}_duplicate_exclusion_events"] = (
                len(exclusion_events) - len(unique_exclusions)
            )

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
        "output_reconstruction_lengths": reconstruction_lengths,
        "common_subset_dealers": dealer_sets,
        "counts": {**base["counts"], **extra_counts},
    }
    (output_dir / "adversarial-summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case-dir", type=Path, required=True)
    parser.add_argument(
        "--scenario", choices=("continuum-delay", "continuum-byzantine"), required=True
    )
    parser.add_argument("--n", type=int, default=4)
    parser.add_argument("--t", type=int, default=1)
    parser.add_argument("--layers", type=int, default=8)
    parser.add_argument("--computation-epoch", type=int, default=3)
    parser.add_argument("--batchmul-epoch", type=int)
    parser.add_argument("--delay-ms", type=int)
    parser.add_argument("--attack-index", type=int)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()

    if args.scenario == "continuum-delay":
        if args.delay_ms is None or args.batchmul_epoch is not None or args.attack_index is not None:
            parser.error("delay requires --delay-ms and forbids Byzantine-only options")
    else:
        if args.batchmul_epoch is None or args.attack_index is None or args.delay_ms is not None:
            parser.error("Byzantine requires --batchmul-epoch and --attack-index")

    output_dir = args.output_dir or args.case_dir
    summary = analyze_case(
        case_dir=args.case_dir,
        scenario=args.scenario,
        n=args.n,
        t=args.t,
        layers=args.layers,
        computation_epoch=args.computation_epoch,
        batchmul_epoch=args.batchmul_epoch,
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
