"""Construct an isolated, internally consistent ADtrans Byzantine input view."""

from __future__ import annotations

from typing import Any, List, Sequence, Tuple


def build_adtrans_outgoing_copy(
    *,
    values: Sequence[Any],
    rand_values: Sequence[Any],
    w_list: Sequence[Any],
    attack_index: int,
    delta: Any,
) -> Tuple[List[Any], List[Any], List[Any]]:
    """Copy all outgoing containers and shift exactly one value.

    The normal ACSS dealer path consumes these copies and regenerates the
    sharing, commitments, masks, and consistency proof. No live MPC state is
    modified in place.
    """
    if not values:
        raise ValueError("ADtrans values must be non-empty")
    if attack_index < 0 or attack_index >= len(values):
        raise IndexError("ADtrans attack index is outside the outgoing batch")

    forked_values = list(values)
    forked_rand_values = list(rand_values)
    forked_w_list = list(w_list)
    forked_values[attack_index] = forked_values[attack_index] + delta
    return forked_values, forked_rand_values, forked_w_list
