import importlib.util
from pathlib import Path

import pytest

from adkg.shuffle_network import (
    build_butterfly_schedule,
    signed_switch,
    validate_switch_layer,
)


def _load_continuum_schedule_builder():
    source = (
        Path(__file__).resolve().parents[2]
        / "dumbo-mpc"
        / "dumbo-mpc"
        / "AsyRanTriGen"
        / "beaver"
        / "shuffle_network.py"
    )
    spec = importlib.util.spec_from_file_location("continuum_shuffle_network", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.build_butterfly_schedule


def test_schedule_matches_continuum_for_figure12():
    continuum_builder = _load_continuum_schedule_builder()
    assert build_butterfly_schedule(128, "single") == continuum_builder(128, "single")
    schedule = build_butterfly_schedule(128, "iterated")
    assert schedule == continuum_builder(128, "iterated")
    assert len(schedule) == 49
    assert all(len(validate_switch_layer(128, layer)) == 64 for layer in schedule)


def test_signed_switch_semantics():
    assert signed_switch(11, 29, 1) == (29, 11)
    assert signed_switch(11, 29, -1) == (11, 29)


@pytest.mark.parametrize("bad_width", [0, 1, 3, 12])
def test_schedule_rejects_invalid_width(bad_width):
    with pytest.raises(ValueError):
        build_butterfly_schedule(bad_width)


def test_layer_validation_rejects_reused_wire():
    with pytest.raises(ValueError, match="reused"):
        validate_switch_layer(4, [(0, 1), (1, 2)])
