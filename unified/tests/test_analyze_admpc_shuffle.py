import json

import pytest

from unified.analyze_admpc_shuffle import (
    ShuffleAnalysisError,
    analyze_markers,
    load_markers,
    write_outputs,
)


def _timing(exposed=None):
    phases = {}
    names = ["state_receive", "output_reconstruction"]
    if exposed is not None:
        names = [
            "state_receive",
            "bundle_receive",
            "rand_candidates_receive",
            "aprep_receive",
            "rand_sign_normalization",
            "switch_execution",
            "state_transfer",
            "incoming_ack_send",
            "handoff_ack_wait",
        ]
    for index, name in enumerate(names):
        phases[name] = {
            "started_at_seconds": float(index),
            "completed_at_seconds": float(index) + 0.5,
            "duration_seconds": 0.5,
        }
    result = {"schema": "admpc-shuffle-phase-timing-v1", "phases": phases}
    if exposed is not None:
        result["randgen_exposed_seconds"] = exposed
    return result


def _markers():
    markers = []
    n = 2
    layers = 4
    for process_id in range(n * layers):
        layer = process_id // n
        if layer == 0:
            result = {"role": "input", "phase_timing": _timing()}
            elapsed = 1.0
        elif layer == layers - 1:
            result = {
                "role": "output",
                "output_count": 8,
                "permutation_valid": True,
                "input_multiset_digest": "digest",
                "output_multiset_digest": "digest",
                "phase_timing": _timing(),
            }
            elapsed = 10.0 - (process_id % n) * 0.1
        else:
            result = {
                "role": "compute",
                "phase_timing": _timing(float(layer)),
            }
            elapsed = 8.0
        markers.append(
            {
                "schema": "admpc-shuffle-finished-v2",
                "run_id": "fixture",
                "global_id": process_id,
                "layer": layer,
                "local_party": process_id % n,
                "n": n,
                "t": 0,
                "k": 8,
                "mode": "single",
                "switch_layers": 2,
                "physical_layers": layers,
                "elapsed": elapsed,
                "transport_topology": "adjacent",
                "allowed_peer_count": 2 * n - 1 if layer in (0, layers - 1) else 3 * n - 1,
                "result": result,
            }
        )
    return markers


def test_two_segment_breakdown_is_additive(tmp_path):
    summary = analyze_markers(_markers())
    assert summary["latency_seconds"] == {
        "total": 10.0,
        "randgen": 3.0,
        "admpc": 7.0,
    }
    write_outputs(tmp_path, summary)
    document = json.loads((tmp_path / "summary.json").read_text())
    assert document["figure12_stack_order"] == ["admpc", "randgen"]
    assert (tmp_path / "figure12_breakdown.csv").is_file()


def test_missing_process_fails_closed():
    with pytest.raises(ShuffleAnalysisError, match="incomplete run"):
        analyze_markers(_markers()[:-1])


def test_digest_disagreement_fails_closed():
    markers = _markers()
    markers[-1]["result"]["output_multiset_digest"] = "different"
    with pytest.raises(ShuffleAnalysisError, match="digest mismatch|disagree"):
        analyze_markers(markers)


def test_log_error_marker_fails_closed(tmp_path):
    (tmp_path / "node.log").write_text("Traceback (most recent call last):\n")
    with pytest.raises(ShuffleAnalysisError, match="error marker"):
        load_markers(tmp_path)
