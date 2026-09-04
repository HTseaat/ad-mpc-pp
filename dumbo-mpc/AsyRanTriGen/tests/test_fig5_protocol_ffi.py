import copy
from ctypes import CDLL, c_bool, c_char_p, c_int
import json
from pathlib import Path


FR_MODULUS = (
    52435875175126190479447740508185965837690552500527637822603658699938581184513
)


def _encoded(value):
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def _load_library():
    root = Path(__file__).resolve().parents[1]
    library = CDLL(str(root / "kzg_ped_out.so"))
    library.pyNewSRS.argtypes = [c_int]
    library.pyNewSRS.restype = c_char_p
    library.pyCommitWithZeroFull.argtypes = [
        c_char_p,
        c_char_p,
        c_char_p,
        c_int,
    ]
    library.pyCommitWithZeroFull.restype = c_char_p
    library.pyPedersenCommit.argtypes = [c_char_p, c_char_p, c_char_p]
    library.pyPedersenCommit.restype = c_char_p
    library.pyDeriveAggEvalChallenge.argtypes = [c_char_p, c_char_p, c_char_p]
    library.pyDeriveAggEvalChallenge.restype = c_char_p
    library.pyDeriveIPAKZGChallenge.argtypes = [c_char_p, c_char_p, c_char_p]
    library.pyDeriveIPAKZGChallenge.restype = c_char_p
    library.pyAggProveEvalZero.argtypes = [c_char_p, c_char_p]
    library.pyAggProveEvalZero.restype = c_char_p
    library.pyPokPedProve.argtypes = [
        c_char_p,
        c_char_p,
        c_char_p,
        c_char_p,
        c_char_p,
        c_char_p,
    ]
    library.pyPokPedProve.restype = c_char_p
    library.pyPokPedVerify.argtypes = [
        c_char_p,
        c_char_p,
        c_char_p,
        c_char_p,
        c_char_p,
    ]
    library.pyPokPedVerify.restype = c_bool
    library.pyAggPubProEval.argtypes = [
        c_char_p,
        c_char_p,
        c_char_p,
        c_char_p,
        c_char_p,
        c_int,
    ]
    library.pyAggPubProEval.restype = c_char_p
    library.pyAggPubVerEval.argtypes = [
        c_char_p,
        c_char_p,
        c_char_p,
        c_char_p,
        c_char_p,
        c_char_p,
        c_char_p,
        c_int,
    ]
    library.pyAggPubVerEval.restype = c_bool
    library.pyAggPedVerEval.argtypes = [
        c_char_p,
        c_char_p,
        c_char_p,
        c_char_p,
        c_char_p,
        c_char_p,
        c_int,
    ]
    library.pyAggPedVerEval.restype = c_bool
    return library


def _decode_result(raw):
    result = json.loads(raw.decode("utf-8"))
    assert "error" not in result, result.get("error")
    return result


def _fixture(batch_size=3):
    library = _load_library()
    srs = json.loads(library.pyNewSRS(4).decode("utf-8"))
    values = [str(11 + index) for index in range(batch_size)]
    values_aux = [str(31 + index) for index in range(batch_size)]
    committed = _decode_result(
        library.pyCommitWithZeroFull(
            _encoded(srs["Pk"]), _encoded(values), _encoded(values_aux), 1
        )
    )
    commitments = committed["commitmentList"]
    openings = committed["proofAtZero"]
    # The legacy proof producer sometimes emits small Fr values as JSON
    # numbers.  The new stage-3 wire format is intentionally canonical and
    # represents every scalar as a decimal string; stage 4's Python wrapper
    # will perform this same normalization before calling the new API.
    for opening in openings:
        opening["ClaimedValue"] = str(opening["ClaimedValue"])
        opening["ClaimedValueAux"] = str(opening["ClaimedValueAux"])
    pedersen = json.loads(
        library.pyPedersenCommit(
            _encoded(srs["Pk"]), _encoded(values), _encoded(values_aux)
        ).decode("utf-8")
    )
    agg_context = {
        "version": 1,
        "domain": "AggEval",
        "old_point": "1",
        "fresh_point": "0",
        # The old relation is part of the transcript even though this fixture
        # exercises the fresh-zero relation through the FFI.
        "old_commitments": srs["Pk"]["G1_g"][:batch_size],
        "new_commitments": commitments,
    }
    return library, srs, values, values_aux, commitments, openings, pedersen, agg_context


def _derive(library, export, pk, vk, context):
    result = getattr(library, export)(
        _encoded(pk), _encoded(vk), _encoded(context)
    ).decode("utf-8")
    assert not result.startswith("{"), result
    return result


def test_pok_ped_and_agg_pub_eval_round_trip_through_ffi():
    (
        library,
        srs,
        values,
        values_aux,
        commitments,
        openings,
        _,
        context,
    ) = _fixture()
    proof = _decode_result(
        library.pyAggPubProEval(
            _encoded(srs["Pk"]),
            _encoded(srs["Vk"]),
            _encoded(context),
            _encoded(commitments),
            _encoded(openings),
            0,
        )
    )
    assert set(proof) == {"T", "W", "pokPed"}
    # gamma is deliberately absent from both the proof and verifier API.
    assert "gamma" not in proof
    assert library.pyAggPubVerEval(
        _encoded(srs["Pk"]),
        _encoded(srs["Vk"]),
        _encoded(context),
        _encoded(commitments),
        _encoded(proof["T"]),
        _encoded(proof["W"]),
        _encoded(proof["pokPed"]),
        0,
    )

    gamma = int(
        _derive(
            library,
            "pyDeriveAggEvalChallenge",
            srs["Pk"],
            srs["Vk"],
            context,
        )
    )
    combined_value = sum(
        pow(gamma, index, FR_MODULUS) * int(value)
        for index, value in enumerate(values)
    ) % FR_MODULUS
    combined_aux = sum(
        pow(gamma, index, FR_MODULUS) * int(value)
        for index, value in enumerate(values_aux)
    ) % FR_MODULUS
    standalone_pok = _decode_result(
        library.pyPokPedProve(
            _encoded(srs["Pk"]),
            _encoded(srs["Vk"]),
            _encoded(context),
            _encoded(proof["T"]),
            str(combined_value).encode("ascii"),
            str(combined_aux).encode("ascii"),
        )
    )
    assert library.pyPokPedVerify(
        _encoded(srs["Pk"]),
        _encoded(srs["Vk"]),
        _encoded(context),
        _encoded(proof["T"]),
        _encoded(standalone_pok),
    )

    changed_context = copy.deepcopy(context)
    changed_context["old_point"] = "2"
    assert not library.pyAggPubVerEval(
        _encoded(srs["Pk"]),
        _encoded(srs["Vk"]),
        _encoded(changed_context),
        _encoded(commitments),
        _encoded(proof["T"]),
        _encoded(proof["W"]),
        _encoded(proof["pokPed"]),
        0,
    )
    bad_pok = copy.deepcopy(proof["pokPed"])
    bad_pok["z"] = "0" if bad_pok["z"] != "0" else "1"
    assert not library.pyPokPedVerify(
        _encoded(srs["Pk"]),
        _encoded(srs["Vk"]),
        _encoded(context),
        _encoded(proof["T"]),
        _encoded(bad_pok),
    )
    noncanonical_pok = copy.deepcopy(proof["pokPed"])
    noncanonical_pok["z"] = "00"
    assert not library.pyPokPedVerify(
        _encoded(srs["Pk"]),
        _encoded(srs["Vk"]),
        _encoded(context),
        _encoded(proof["T"]),
        _encoded(noncanonical_pok),
    )


def test_agg_ped_ver_eval_round_trip_and_rejects_tampering_through_ffi():
    (
        library,
        srs,
        _,
        _,
        commitments,
        openings,
        pedersen,
        _,
    ) = _fixture()
    context = {
        "version": 1,
        "domain": "IPAKZG",
        "left_point": "0",
        "right_point": "0",
        "output_point": "0",
        "left_commitments": commitments,
        "right_commitments": commitments,
        "output_commitments": commitments,
        "left_pedersen": pedersen,
        "right_pedersen": pedersen,
        "output_pedersen": pedersen,
    }
    gamma = _derive(
        library,
        "pyDeriveIPAKZGChallenge",
        srs["Pk"],
        srs["Vk"],
        context,
    )
    h_only = [{"H": proof["H"]} for proof in openings]
    witness = _decode_result(
        library.pyAggProveEvalZero(_encoded(h_only), gamma.encode("ascii"))
    )["aggH"]
    # pyAggPedVerEval receives neither gamma nor an aggregated T: both are
    # reconstructed by the verifier from the typed context and Pedersen vector.
    assert library.pyAggPedVerEval(
        _encoded(srs["Pk"]),
        _encoded(srs["Vk"]),
        _encoded(context),
        _encoded(commitments),
        _encoded(pedersen),
        _encoded(witness),
        0,
    )

    changed_pedersen = copy.deepcopy(pedersen)
    changed_pedersen[0] = pedersen[1]
    assert not library.pyAggPedVerEval(
        _encoded(srs["Pk"]),
        _encoded(srs["Vk"]),
        _encoded(context),
        _encoded(commitments),
        _encoded(changed_pedersen),
        _encoded(witness),
        0,
    )
    assert not library.pyAggPedVerEval(
        _encoded(srs["Pk"]),
        _encoded(srs["Vk"]),
        _encoded(context),
        _encoded([]),
        _encoded([]),
        _encoded(witness),
        0,
    )


def test_stage_three_ffi_accepts_batch_size_one_and_rejects_bad_lengths():
    (
        library,
        srs,
        _,
        _,
        commitments,
        openings,
        _,
        context,
    ) = _fixture(batch_size=1)
    proof = _decode_result(
        library.pyAggPubProEval(
            _encoded(srs["Pk"]),
            _encoded(srs["Vk"]),
            _encoded(context),
            _encoded(commitments),
            _encoded(openings),
            0,
        )
    )
    assert library.pyAggPubVerEval(
        _encoded(srs["Pk"]),
        _encoded(srs["Vk"]),
        _encoded(context),
        _encoded(commitments),
        _encoded(proof["T"]),
        _encoded(proof["W"]),
        _encoded(proof["pokPed"]),
        0,
    )
    malformed = json.loads(
        library.pyAggPubProEval(
            _encoded(srs["Pk"]),
            _encoded(srs["Vk"]),
            _encoded(context),
            _encoded(commitments),
            _encoded(openings + openings),
            0,
        ).decode("utf-8")
    )
    assert "error" in malformed
