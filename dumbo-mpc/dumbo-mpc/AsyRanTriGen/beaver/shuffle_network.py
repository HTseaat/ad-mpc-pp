import math


def build_butterfly_schedule(k, mode="single"):
    """Return switch-pair layers for a power-of-two butterfly network."""
    if k <= 1 or k & (k - 1):
        raise ValueError("shuffle input size k must be a power of two")

    rounds = int(math.log2(k))
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
    if mode == "iterated":
        return [pairs for _ in range(rounds) for pairs in base_schedule]

    raise ValueError(f"unknown shuffle mode: {mode}")
