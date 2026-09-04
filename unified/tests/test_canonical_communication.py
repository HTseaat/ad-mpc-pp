import pytest

from unified.canonical_communication import (
    CanonicalCommunicationError,
    PROFILE,
    canonical_admpc_binary_result,
    computation_layer_result,
)


def _summary(components):
    return {
        "parameters": {"cryptographic_payload_encoding": PROFILE},
        "component_bytes": components,
        "system_total_payload_bytes": sum(components.values()),
    }


def test_admpc_uses_only_integrated_figure8_components():
    result = canonical_admpc_binary_result(
        _summary({"randgen": 100, "adtrans": 200}),
        expected_components={"randgen", "adtrans"},
        batch_size=100,
        unit="sharing",
        circuit_depth=6,
    )
    assert result["canonical_bytes_per_computation_layer"] == 300
    assert result["canonical_all_computation_layers_bytes"] == 1800
    assert "batchrand" not in result["components_per_computation_layer"]


def test_admpc_figure9_does_not_accept_a_separate_batchrand_component():
    with pytest.raises(CanonicalCommunicationError, match="component mismatch"):
        canonical_admpc_binary_result(
            _summary({
                "randgen": 1,
                "adprep": 2,
                "exec": 3,
                "adtrans": 4,
                "batchrand": 5,
            }),
            expected_components={"randgen", "adprep", "exec", "adtrans"},
            batch_size=100,
            unit="gate",
            circuit_depth=6,
        )


def test_admpc_requires_current_encoding_metadata():
    summary = _summary({"randgen": 1, "adtrans": 2})
    del summary["parameters"]["cryptographic_payload_encoding"]
    with pytest.raises(CanonicalCommunicationError, match="rerun"):
        canonical_admpc_binary_result(
            summary,
            expected_components={"randgen", "adtrans"},
            batch_size=100,
            unit="sharing",
            circuit_depth=6,
        )


def test_component_sum_is_fail_closed():
    with pytest.raises(CanonicalCommunicationError, match="do not sum"):
        computation_layer_result(
            10,
            batch_size=100,
            unit="gate",
            circuit_depth=6,
            components={"a": 9},
        )
