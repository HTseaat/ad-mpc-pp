import copy
from ctypes import CDLL, c_char_p, c_int
import json
from pathlib import Path


def _load_library():
    root = Path(__file__).resolve().parents[1]
    library = CDLL(str(root / "kzg_ped_out.so"))
    library.pyNewSRS.argtypes = [c_int]
    library.pyNewSRS.restype = c_char_p
    library.pyDeriveChallenge.argtypes = [c_char_p]
    library.pyDeriveChallenge.restype = c_char_p
    library.pyDeriveAggEvalChallenge.argtypes = [c_char_p, c_char_p, c_char_p]
    library.pyDeriveAggEvalChallenge.restype = c_char_p
    library.pyDeriveIPAKZGChallenge.argtypes = [c_char_p, c_char_p, c_char_p]
    library.pyDeriveIPAKZGChallenge.restype = c_char_p
    return library


def _encoded(value, **kwargs):
    return json.dumps(value, **kwargs).encode("utf-8")


def _call(library, function_name, pk, vk, context):
    result = getattr(library, function_name)(
        _encoded(pk), _encoded(vk), _encoded(context)
    ).decode("utf-8")
    if result.startswith("{"):
        raise AssertionError(json.loads(result)["error"])
    return result


def test_legacy_challenge_characterization_through_ffi():
    library = _load_library()
    srs = json.loads(library.pyNewSRS(4).decode("utf-8"))
    commitments = srs["Pk"]["G1_g"][:2]
    challenge = library.pyDeriveChallenge(
        _encoded(commitments, separators=(",", ":"))
    ).decode("utf-8")
    assert challenge == (
        "2392097786975479467205329552135548081814733436074882278258736819889816564658"
    )


def test_typed_challenge_exports_are_canonical_and_domain_separated():
    library = _load_library()
    srs = json.loads(library.pyNewSRS(4).decode("utf-8"))
    pk, vk = srs["Pk"], srs["Vk"]
    g, h = pk["G1_g"], pk["G1_h"]

    agg_context = {
        "version": 1,
        "domain": "AggEval",
        # dealer_local_id=0 maps to the actual Shamir point 1.
        "old_point": "1",
        "fresh_point": "0",
        "old_commitments": [g[0], g[1]],
        "new_commitments": [h[0], h[1]],
    }
    agg_challenge = _call(
        library, "pyDeriveAggEvalChallenge", pk, vk, agg_context
    )
    # Key ordering and whitespace are presentation details, not transcript data.
    pretty_context = json.loads(
        json.dumps(agg_context, indent=4, sort_keys=True)
    )
    assert agg_challenge == _call(
        library, "pyDeriveAggEvalChallenge", pk, vk, pretty_context
    )
    changed_agg = copy.deepcopy(agg_context)
    changed_agg["old_point"] = "2"
    assert agg_challenge != _call(
        library, "pyDeriveAggEvalChallenge", pk, vk, changed_agg
    )

    ipa_context = {
        "version": 1,
        "domain": "IPAKZG",
        "left_point": "1",
        "right_point": "1",
        "output_point": "0",
        "left_commitments": [g[0], g[1]],
        "right_commitments": [g[1], g[0]],
        "output_commitments": [h[0], h[1]],
        "left_pedersen": [h[0], h[1]],
        "right_pedersen": [h[1], h[0]],
        "output_pedersen": [g[1], g[0]],
    }
    ipa_challenge = _call(
        library, "pyDeriveIPAKZGChallenge", pk, vk, ipa_context
    )
    assert ipa_challenge != agg_challenge
    changed_ipa = copy.deepcopy(ipa_context)
    changed_ipa["output_pedersen"][0] = g[0]
    assert ipa_challenge != _call(
        library, "pyDeriveIPAKZGChallenge", pk, vk, changed_ipa
    )
