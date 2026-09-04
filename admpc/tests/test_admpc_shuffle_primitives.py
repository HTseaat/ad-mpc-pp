import asyncio

from adkg.admpc_dynamic_shuffle import (
    ADMPC_Dynamic_Shuffle,
    inputs_per_dealer,
    merge_dealer_input_shares,
    prepare_dealer_inputs,
    randbit_candidate_capacity,
    shuffle_triple_count,
    split_shuffle_triples,
)
from adkg.elliptic_curve import Subgroup
from adkg.field import GF
from adkg.shuffle_network import build_butterfly_schedule


def _local_protocol(t=1):
    protocol = ADMPC_Dynamic_Shuffle.__new__(ADMPC_Dynamic_Shuffle)
    protocol.t = t
    protocol.ZR = GF(Subgroup.BLS12_381)

    async def identity_reconstruction(values, rec_id):
        return list(values)

    protocol.robust_rec_step = identity_reconstruction
    return protocol


def _zero_triples(field, count):
    return [(field(0), field(0), field(0)) for _ in range(count)]


def test_continuum_candidate_capacity_and_triple_split():
    assert [randbit_candidate_capacity(t) for t in (1, 3, 5)] == [68, 68, 72]
    assert [shuffle_triple_count(t) for t in (1, 3, 5)] == [132, 132, 136]
    triples = list(range(136))
    square, switch = split_shuffle_triples(triples, t=5)
    assert square == list(range(72))
    assert switch == list(range(72, 136))


def test_input_padding_and_strict_trim():
    inputs = list(range(1, 9))
    assert inputs_per_dealer(8, 3) == 3
    batches = {
        dealer: prepare_dealer_inputs(inputs, dealer, n=3, zero=0)
        for dealer in range(3)
    }
    assert batches[2] == [7, 8, 0]
    nested = {dealer: [batch] for dealer, batch in batches.items()}
    assert merge_dealer_input_shares(nested, n=3, k=8) == inputs


def test_randbit_normalization_and_switch_layer():
    async def run():
        protocol = _local_protocol(t=1)
        field = protocol.ZR
        candidates = [field(0)] * 4 + [field(value) for value in range(1, 65)]
        square_triples = _zero_triples(field, 68)
        signs = await protocol._normalize_random_signs(
            candidates,
            square_triples,
            square_mult_rec_id=10,
            square_open_rec_id=11,
        )
        assert len(signs) == 64
        assert all(sign * sign == field(1) for sign in signs)
        assert protocol._last_randbit_stats["discarded_zeroes"] == 4

        state = [field(value) for value in range(1, 9)]
        pairs = build_butterfly_schedule(8, "single")[0]
        selectors = [field(1), field(-1), field(1), field(-1)]
        outputs = await protocol._run_switch_layer(
            state,
            pairs,
            selectors,
            _zero_triples(field, 4),
            rec_id=12,
            expected_width=8,
        )
        assert [int(value) for value in outputs] == [2, 1, 3, 4, 6, 5, 7, 8]

    asyncio.run(run())
