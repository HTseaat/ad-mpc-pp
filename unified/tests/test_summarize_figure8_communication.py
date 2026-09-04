import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "summarize_figure8_communication.py"
SPEC = importlib.util.spec_from_file_location("summarize_figure8_communication", SCRIPT)
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


def test_n4_canonical_continuum_reference_total():
    aggtrans = tool.canonical_continuum(
        n=4, t=1, circuit_depth=6, control_bytes=47_953,
        variant="aggtrans", old_commitments="retransmit",
    )
    noagg = tool.canonical_continuum(
        n=4, t=1, circuit_depth=6, control_bytes=48_385,
        variant="aggtrans-noagg", old_commitments="retransmit",
    )
    assert aggtrans["canonical_bytes_per_computation_layer"] == 995_985
    assert noagg["canonical_bytes_per_computation_layer"] == 1_449_025
    assert aggtrans["canonical_all_computation_layers_bytes"] == 5_975_910


def test_depth_only_scales_derived_homogeneous_total():
    result = tool.canonical_continuum(
        n=10, t=3, circuit_depth=2, control_bytes=916_389,
        variant="aggtrans", old_commitments="retransmit",
    )
    assert result["canonical_bytes_per_computation_layer"] == 8_745_189
    assert result["canonical_all_computation_layers_bytes"] == 17_490_378
    assert result["canonical_bytes_per_sharing"] == 87_451.89


def test_cached_old_commitment_removes_one_public_vector():
    retransmit = tool.canonical_continuum(
        n=4, t=1, circuit_depth=1, control_bytes=47_953,
        variant="aggtrans", old_commitments="retransmit",
    )
    cached = tool.canonical_continuum(
        n=4, t=1, circuit_depth=1, control_bytes=47_953,
        variant="aggtrans", old_commitments="cached",
    )
    assert (
        cached["canonical_bytes_per_computation_layer"]
        < retransmit["canonical_bytes_per_computation_layer"]
    )


def test_nondefault_batch_size_is_used_for_normalization():
    result = tool.canonical_continuum(
        n=4, t=1, circuit_depth=3, control_bytes=100,
        variant="aggtrans", old_commitments="retransmit", batch_size=20,
    )
    assert result["canonical_bytes_per_sharing"] == (
        result["canonical_bytes_per_computation_layer"] / 20
    )
    assert result["canonical_all_computation_layers_bytes"] == (
        3 * result["canonical_bytes_per_computation_layer"]
    )
