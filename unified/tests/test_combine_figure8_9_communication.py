import json

import pytest

from unified.combine_figure8_9_communication import CombineError, combine, render_csv


def _summary(figure, circuit, unit, profile="profile-v1"):
    return {
        "experiment": {"figure": figure, "circuit": circuit},
        "canonical_serialization": {"profile": profile},
        "cases": [{
            "n": 4,
            "t": 1,
            "adtrans_alg4_mode": "aggregate",
            "canonical": {
                "protocol": {
                    "canonical_bytes_per_computation_layer": 100,
                    f"canonical_bytes_per_{unit}": 1.0,
                }
            },
        }],
    }


def test_combines_only_canonical_final_values(tmp_path):
    figure8 = tmp_path / "fig8.json"
    figure9 = tmp_path / "fig9.json"
    figure8.write_text(
        json.dumps(_summary(8, "all-linear", "sharing")), encoding="utf-8"
    )
    figure9.write_text(
        json.dumps(_summary(9, "all-multiplication", "gate")),
        encoding="utf-8",
    )
    report = combine(figure8, figure9)
    assert len(report["rows"]) == 2
    assert {row["normalization_unit"] for row in report["rows"]} == {
        "sharing", "gate"
    }
    rendered = render_csv(report)
    assert "canonical_bytes_per_computation_layer" in rendered
    assert "native" not in rendered


def test_rejects_mixed_canonical_profiles(tmp_path):
    figure8 = tmp_path / "fig8.json"
    figure9 = tmp_path / "fig9.json"
    figure8.write_text(
        json.dumps(_summary(8, "all-linear", "sharing", "a")),
        encoding="utf-8",
    )
    figure9.write_text(
        json.dumps(_summary(9, "all-multiplication", "gate", "b")),
        encoding="utf-8",
    )
    with pytest.raises(CombineError, match="profiles differ"):
        combine(figure8, figure9)
