import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "summarize_figure9_communication.py"
SPEC = importlib.util.spec_from_file_location("summarize_figure9_communication", SCRIPT)
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


def test_nondefault_batch_size_is_used_for_bgw_normalization():
    result = tool._canonical_hbacss(
        "bgw",
        n=4,
        t=1,
        circuit_depth=3,
        calibration={"measured_protocol_control_and_envelope_bytes": 100},
        topology="static",
        batch_size=20,
    )
    assert result["canonical_bytes_per_gate"] == (
        result["canonical_bytes_per_computation_layer"] / 20
    )
    assert result["canonical_all_computation_layers_bytes"] == (
        3 * result["canonical_bytes_per_computation_layer"]
    )


def test_protocol_selection_constants_are_independent():
    assert tool.PROTOCOLS == (
        "admpc",
        "continuum_batchmul",
        "bgw_aggtrans",
    )
