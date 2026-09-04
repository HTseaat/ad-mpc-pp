"""Pure circuit helpers for the Figure 12 butterfly shuffle network.

This module intentionally has no dependency on the AD-MPC transport or
cryptographic protocols.  The protocol-specific implementation lives in
``admpc_dynamic_shuffle.py``.
"""


def _validate_width(k):
    if isinstance(k, bool) or not isinstance(k, int):
        raise TypeError("shuffle width k must be an integer")
    if k <= 1 or k & (k - 1):
        raise ValueError("shuffle width k must be a power of two greater than one")


def build_butterfly_schedule(k, mode="single"):
    """Return the switch pairs for a single or iterated butterfly network."""
    _validate_width(k)
    if mode not in {"single", "iterated"}:
        raise ValueError("shuffle mode must be 'single' or 'iterated'")

    rounds = k.bit_length() - 1
    base_schedule = []
    for layer in range(rounds):
        stride = 1 << layer
        block = stride << 1
        pairs = []
        for start in range(0, k, block):
            for offset in range(stride):
                pairs.append((start + offset, start + offset + stride))
        base_schedule.append(pairs)

    if mode == "single":
        return base_schedule

    # Copy each layer so callers cannot accidentally mutate another iteration.
    return [list(pairs) for _ in range(rounds) for pairs in base_schedule]


def validate_switch_layer(width, pairs):
    """Validate and return one perfect-matching switch layer as a tuple."""
    _validate_width(width)
    normalized = tuple(tuple(pair) for pair in pairs)
    if len(normalized) != width // 2:
        raise ValueError(
            f"switch layer must contain {width // 2} pairs, got {len(normalized)}"
        )

    seen = set()
    for pair in normalized:
        if len(pair) != 2:
            raise ValueError("each switch pair must contain exactly two wire indices")
        left, right = pair
        if not isinstance(left, int) or not isinstance(right, int):
            raise TypeError("switch wire indices must be integers")
        if left == right or left < 0 or right < 0 or left >= width or right >= width:
            raise ValueError(f"invalid switch pair {pair} for width {width}")
        if left in seen or right in seen:
            raise ValueError(f"wire reused in switch layer: {pair}")
        seen.add(left)
        seen.add(right)

    if len(seen) != width:
        raise ValueError("switch layer does not cover every wire exactly once")
    return normalized


def signed_switch(left, right, selector, inv_two=None):
    """Evaluate the public signed-selector switch used by Figure 12 tests.

    ``selector=1`` swaps the inputs and ``selector=-1`` keeps their order.
    Secret-shared selectors are evaluated by the AD-MPC protocol primitive,
    not by this public helper.
    """
    if selector not in (-1, 1):
        raise ValueError("signed switch selector must be -1 or 1")

    product = selector * (left - right)
    first_numerator = left + right - product
    second_numerator = left + right + product

    if inv_two is not None:
        return first_numerator * inv_two, second_numerator * inv_two
    if isinstance(first_numerator, int) and isinstance(second_numerator, int):
        return first_numerator // 2, second_numerator // 2
    return first_numerator / 2, second_numerator / 2
