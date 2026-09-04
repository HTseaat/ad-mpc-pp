#!/usr/bin/env python3
"""Validate and summarize the Figure 10 fault schedule from archived logs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Dict, Iterable, List, Set, Tuple


EVENT_PREFIX = "FAULT_ACCUM_EVENT "
PROGRESS_PREFIX = "FIGURE10_PROGRESS_EVENT "
EXEC_RE = re.compile(r"my_send_id:\s*(\d+)\s+exec_time:")


def iter_text_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if path.is_file() and path.name != "fault_trace.json":
            yield path


def read_evidence(root: Path) -> Tuple[List[dict], List[dict], Set[int]]:
    events: Dict[Tuple[object, ...], dict] = {}
    progress: Dict[Tuple[object, ...], dict] = {}
    completed_global_ids: Set[int] = set()
    for path in iter_text_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        completed_global_ids.update(int(value) for value in EXEC_RE.findall(text))
        for line in text.splitlines():
            progress_marker = line.find(PROGRESS_PREFIX)
            if progress_marker >= 0:
                raw_progress = line[progress_marker + len(PROGRESS_PREFIX) :].strip()
                try:
                    progress_event = json.loads(raw_progress)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"invalid progress event in {path}: {raw_progress!r}"
                    ) from exc
                progress_key = (
                    progress_event.get("protocol"),
                    progress_event.get("event"),
                    progress_event.get("local_party_id"),
                    progress_event.get("epoch"),
                )
                progress[progress_key] = progress_event
            marker = line.find(EVENT_PREFIX)
            if marker < 0:
                continue
            raw = line[marker + len(EVENT_PREFIX) :].strip()
            try:
                event = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid fault event in {path}: {raw!r}") from exc
            key = (
                event.get("protocol"),
                event.get("event"),
                event.get("local_party_id"),
                event.get("physical_layer_id"),
                event.get("epoch"),
            )
            events[key] = event
    return list(events.values()), list(progress.values()), completed_global_ids


def expected_static_ids(n: int, count: int, epoch: int) -> Set[int]:
    stop = n - (epoch - 1) * count
    return set(range(max(0, stop - count), max(0, stop)))


def validate(
    args: argparse.Namespace,
    events: List[dict],
    completed: Set[int],
    progress: List[dict] = None,
) -> dict:
    progress = [] if progress is None else progress
    silent = [event for event in events if event.get("event") == "silent_entered"]
    errors: List[str] = []
    details: dict = {}

    if args.protocol == "admpc":
        observed: Dict[int, Set[int]] = {}
        for event in silent:
            layer = event.get("physical_layer_id")
            party = event.get("local_party_id")
            if isinstance(layer, int) and isinstance(party, int):
                observed.setdefault(layer, set()).add(party)
        expected_ids = set(range(args.n - args.count, args.n))
        expected_layers = set(range(1, args.d + 1))
        if set(observed) != expected_layers:
            errors.append(
                f"AD-MPC silent layers {sorted(observed)} != {sorted(expected_layers)}"
            )
        for layer in sorted(expected_layers):
            if observed.get(layer, set()) != expected_ids:
                errors.append(
                    f"AD-MPC layer {layer} silent IDs "
                    f"{sorted(observed.get(layer, set()))} != {sorted(expected_ids)}"
                )
        completion_count_by_epoch = {}
        for epoch in range(1, args.d + 1):
            count = sum(
                1
                for party in completed
                if party // args.n == epoch
                and party % args.n not in observed.get(epoch, set())
            )
            completion_count_by_epoch[str(epoch)] = count
            if count < args.n - args.t:
                errors.append(
                    f"AD-MPC epoch {epoch} has {count} completion records; "
                    f"need at least {args.n - args.t}"
                )
        output_layer = args.d + 1
        output_count = sum(1 for party in completed if party // args.n == output_layer)
        if output_count < args.n - args.t:
            errors.append(
                f"AD-MPC output has {output_count} completion records; "
                f"need at least {args.n - args.t}"
            )
        details["silent_ids_by_computation_epoch"] = {
            str(layer): sorted(ids) for layer, ids in sorted(observed.items())
        }
        details["completion_count_by_epoch"] = completion_count_by_epoch
        details["output_completion_count"] = output_count

    elif args.protocol == "continuum":
        observed: Dict[int, Set[int]] = {}
        for event in silent:
            layer = event.get("physical_layer_id")
            party = event.get("local_party_id")
            if isinstance(layer, int) and isinstance(party, int):
                observed.setdefault(layer, set()).add(party)
        expected_ids = set(range(args.n - args.count, args.n))
        expected_layers = set(range(1, args.d + 1))
        if set(observed) != expected_layers:
            errors.append(
                f"Continuum silent layers {sorted(observed)} != {sorted(expected_layers)}"
            )
        for layer in sorted(expected_layers):
            if observed.get(layer, set()) != expected_ids:
                errors.append(
                    f"Continuum layer {layer} silent IDs "
                    f"{sorted(observed.get(layer, set()))} != {sorted(expected_ids)}"
                )
        completion_count_by_epoch = {}
        for layer in sorted(expected_layers):
            count = sum(
                1
                for global_id in completed
                if global_id // args.n == layer
                and global_id % args.n not in observed.get(layer, set())
            )
            completion_count_by_epoch[str(layer)] = count
            if count < args.n - args.t:
                errors.append(
                    f"Continuum epoch {layer} has {count} honest completion records; "
                    f"need at least {args.n - args.t}"
                )
        output_start = (args.d + 1) * args.n
        completed_output = sorted(
            party for party in completed if output_start <= party < output_start + args.n
        )
        if len(completed_output) < args.n - args.t:
            errors.append(
                "Continuum output committee has only "
                f"{len(completed_output)} completion records; need at least {args.n - args.t}"
            )
        details["silent_ids_by_computation_epoch"] = {
            str(layer): sorted(ids) for layer, ids in sorted(observed.items())
        }
        details["completed_output_global_ids"] = completed_output
        details["completion_count_by_epoch"] = completion_count_by_epoch

    else:
        observed: Dict[int, Set[int]] = {}
        for event in silent:
            epoch = event.get("epoch")
            party = event.get("local_party_id")
            if isinstance(epoch, int) and isinstance(party, int):
                observed.setdefault(epoch, set()).add(party)
        threshold_crossing_epoch = args.t // args.count + 1
        expected_epochs = set(range(1, threshold_crossing_epoch + 1))
        if set(observed) != expected_epochs:
            errors.append(
                f"Dumbo-MPC silent epochs {sorted(observed)} != {sorted(expected_epochs)}"
            )
        for epoch in sorted(expected_epochs):
            expected = expected_static_ids(args.n, args.count, epoch)
            if observed.get(epoch, set()) != expected:
                errors.append(
                    f"Dumbo-MPC epoch {epoch} new silent IDs "
                    f"{sorted(observed.get(epoch, set()))} != {sorted(expected)}"
                )
        details["new_silent_ids_by_epoch"] = {
            str(epoch): sorted(ids) for epoch, ids in sorted(observed.items())
        }
        details["expected_threshold_crossing_epoch"] = threshold_crossing_epoch
        details["expected_cumulative_silent_at_crossing"] = (
            threshold_crossing_epoch * args.count
        )
        completed_by_epoch: Dict[int, Set[int]] = {}
        for event in progress:
            if event.get("event") != "epoch_completed":
                continue
            epoch = event.get("epoch")
            party = event.get("local_party_id")
            if isinstance(epoch, int) and isinstance(party, int):
                completed_by_epoch.setdefault(epoch, set()).add(party)
        for epoch in range(1, threshold_crossing_epoch):
            count = len(completed_by_epoch.get(epoch, set()))
            if count < args.n - args.t:
                errors.append(
                    f"Dumbo-MPC epoch {epoch} has {count} completion events; "
                    f"need at least {args.n - args.t}"
                )
        crossing_count = len(completed_by_epoch.get(threshold_crossing_epoch, set()))
        if crossing_count >= args.n - args.t:
            errors.append(
                f"Dumbo-MPC epoch {threshold_crossing_epoch} unexpectedly has "
                f"{crossing_count} completion events"
            )
        details["completion_count_by_epoch"] = {
            str(epoch): len(ids) for epoch, ids in sorted(completed_by_epoch.items())
        }
        details["outcome"] = "right-censored at timeout after expected loss of liveness"

    return {
        "schema": "figure10-fault-trace-summary-v1",
        "protocol": args.protocol,
        "n": args.n,
        "t": args.t,
        "d": args.d,
        "new_silent_per_epoch": args.count,
        "valid": not errors,
        "errors": errors,
        **details,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case-dir", required=True, type=Path)
    parser.add_argument("--protocol", required=True, choices=("admpc", "continuum", "dumbo"))
    parser.add_argument("--n", required=True, type=int)
    parser.add_argument("--t", required=True, type=int)
    parser.add_argument("--d", required=True, type=int)
    parser.add_argument("--count", required=True, type=int)
    args = parser.parse_args()

    events, progress, completed = read_evidence(args.case_dir)
    summary = validate(args, events, completed, progress)
    output = args.case_dir / "fault_trace.json"
    output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Figure 10 fault trace: {'valid' if summary['valid'] else 'INVALID'} ({output})")
    for error in summary["errors"]:
        print(f"  - {error}", file=sys.stderr)
    return 0 if summary["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
