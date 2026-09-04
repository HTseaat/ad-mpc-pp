import copy
from ctypes import CDLL, c_char_p, c_int
import inspect
import json
from pathlib import Path
from pickle import loads
from types import SimpleNamespace

import pytest

from beaver.aggregation_interfaces import (
    AGGTRANS_NOAGG_SCHEMA,
    AGGTRANS_NOAGG_PUBLIC_SCHEMA,
    AGGTRANS_LEGACY_CANONICAL_PROOF_BYTES,
    AGGTRANS_V2_CANONICAL_PROOF_BYTES,
    AGGTRANS_V2_SCHEMA,
    AGGTRANS_V2_PUBLIC_SCHEMA,
    BATCHMUL_PUBLIC_SCHEMA,
    FR_MODULUS,
    AggregationInterfaceError,
    aggregate_ipakzg_witness,
    agg_kzg_mode,
    aggtrans_proof_size_metadata,
    build_batchmul_public_payload,
    build_agg_eval_context,
    build_aggtrans_noagg_payload,
    build_aggtrans_noagg_public_payload,
    build_ipakzg_context,
    build_aggtrans_payload,
    build_aggtrans_public_payload,
    combine_batchmul_payload,
    combine_aggtrans_noagg_payload,
    combine_aggtrans_payload,
    configure_aggregation_ffi,
    derive_ipakzg_challenge,
    normalize_openings,
    parse_batchmul_public_payload,
    parse_aggtrans_noagg_payload,
    parse_aggtrans_noagg_public_payload,
    parse_aggtrans_payload,
    parse_aggtrans_public_payload,
    prove_aggtrans_legacy,
    prove_aggtrans_v2,
    prepare_aggtrans_noagg,
    verify_agg_ped_eval,
    verify_agg_ped_eval_batch,
    verify_aggtrans,
)
from beaver import hbacss as hbacss_module
from beaver.hbacss import ACSS_Foll, ACSS_Pre, Hbacss0, Hbacss1


def _encoded(value):
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


class _CountingLibrary:
    def __init__(self, library):
        self._library = library
        self.pok_verifications = 0
        self.aggpub_batch_verifications = 0
        self.combined_batch_verifications = 0

    def __getattr__(self, name):
        return getattr(self._library, name)

    def pyPokPedVerify(self, *args):
        self.pok_verifications += 1
        return self._library.pyPokPedVerify(*args)

    def pyAggPubVerEvalBatch2(self, *args):
        self.aggpub_batch_verifications += 1
        return self._library.pyAggPubVerEvalBatch2(*args)

    def pyBatchVerifyPubCombined(self, *args):
        self.combined_batch_verifications += 1
        return self._library.pyBatchVerifyPubCombined(*args)


@pytest.fixture(scope="module")
def aggtrans_fixture():
    root = Path(__file__).resolve().parents[1]
    library = CDLL(str(root / "kzg_ped_out.so"))
    configure_aggregation_ffi(library)
    library.pyNewSRS.argtypes = [c_int]
    library.pyNewSRS.restype = c_char_p
    library.pySetN.argtypes = [c_int]
    library.pySetN.restype = None
    library.pyCommit.argtypes = [c_char_p, c_char_p, c_int]
    library.pyCommit.restype = c_char_p
    library.pyCommitWithZeroFull.argtypes = [
        c_char_p, c_char_p, c_char_p, c_int,
    ]
    library.pyCommitWithZeroFull.restype = c_char_p
    library.pyPedersenCommit.argtypes = [c_char_p, c_char_p, c_char_p]
    library.pyPedersenCommit.restype = c_char_p

    n = 4
    threshold = 1
    dealer = 1
    library.pySetN(n)
    srs = json.loads(library.pyNewSRS(threshold).decode("utf-8"))
    pk = _encoded(srs["Pk"])
    vk = _encoded(srs["Vk"])
    old = json.loads(
        library.pyCommit(pk, _encoded(["17", "23", "29"]), threshold).decode(
            "utf-8"
        )
    )
    old_openings = old["batchproofsofallparties"][dealer]
    values = [str(proof["ClaimedValue"]) for proof in old_openings]
    values_aux = [str(proof["ClaimedValueAux"]) for proof in old_openings]
    old_pedersen = json.loads(
        library.pyPedersenCommit(
            pk, _encoded(values), _encoded(values_aux)
        ).decode("utf-8")
    )
    fresh = json.loads(
        library.pyCommitWithZeroFull(
            pk, _encoded(values), _encoded(values_aux), threshold
        ).decode("utf-8")
    )
    fresh_pedersen = json.loads(
        library.pyPedersenCommit(
            pk, _encoded(values), _encoded(values_aux)
        ).decode("utf-8")
    )
    return {
        "library": library,
        "pk": pk,
        "vk": vk,
        "dealer": dealer,
        "old_commitments": old["commitmentList"],
        "old_openings": old_openings,
        "fresh_commitments": fresh["commitmentList"],
        "fresh_openings": fresh["proofAtZero"],
        "old_pedersen": old_pedersen,
        "fresh_pedersen": fresh_pedersen,
        "share_g": fresh["shareG"],
        "share_h": fresh["shareH"],
    }


def _v2_artifacts(fixture):
    return prove_aggtrans_v2(
        library=fixture["library"],
        srs_pk=fixture["pk"],
        srs_vk=fixture["vk"],
        dealer_local_id=fixture["dealer"],
        old_commitments=fixture["old_commitments"],
        fresh_commitments=fixture["fresh_commitments"],
        old_openings=fixture["old_openings"],
        fresh_openings=fixture["fresh_openings"],
    )


def test_feature_flag_modes_are_explicit_and_default_to_v2():
    assert agg_kzg_mode({}) == "v2"
    assert agg_kzg_mode({"AGG_KZG_V2": "1"}) == "v2"
    assert agg_kzg_mode({"AGG_KZG_V2": "0"}) == "legacy"
    assert agg_kzg_mode({"AGG_KZG_V2": "shadow"}) == "shadow"
    with pytest.raises(AggregationInterfaceError, match="AGG_KZG_V2"):
        agg_kzg_mode({"AGG_KZG_V2": "maybe"})


@pytest.mark.parametrize("implementation", [Hbacss0, ACSS_Pre, ACSS_Foll])
def test_all_three_hbacss_implementations_use_common_aggtrans_boundary(
    implementation,
):
    dealer_source = inspect.getsource(implementation._get_dealer_msg)
    receiver_source = inspect.getsource(implementation._handle_dealer_msgs)
    assert "prove_aggtrans_v2(" in dealer_source
    assert "prove_aggtrans_legacy(" in dealer_source
    assert "z = proofandshares[i]" in dealer_source
    assert "_build_hbacss_broadcast_payload(" in dealer_source
    assert "_parse_hbacss_broadcast_payload(" in receiver_source
    assert "combine_aggtrans_payload(" in receiver_source
    assert "verify_aggtrans(" in receiver_source


@pytest.mark.parametrize("implementation", [Hbacss0, ACSS_Pre, ACSS_Foll])
def test_all_three_hbacss_implementations_use_stage7_noagg_boundary(
    implementation,
):
    dealer_source = inspect.getsource(implementation._get_dealer_msg)
    receiver_source = inspect.getsource(implementation._handle_dealer_msgs)
    assert dealer_source.count("prepare_aggtrans_noagg(") == 1
    assert "z = proofandshares[i]" in dealer_source
    assert "_build_hbacss_broadcast_payload(" in dealer_source
    assert "combine_aggtrans_noagg_payload(" in receiver_source
    assert receiver_source.count("_verify_aggtrans_noagg_relations(") == 1
    assert 'operation="noagg_generate"' in dealer_source
    assert '"pedersen_commitment_preparation"' in dealer_source
    assert '"evaluation_proof_verify"' in receiver_source


@pytest.mark.parametrize(
    "implementation", [Hbacss0, ACSS_Pre, ACSS_Foll, Hbacss1]
)
def test_all_batchmul_hbacss_implementations_use_stage6_ipakzg_boundary(
    implementation,
):
    dealer_source = inspect.getsource(implementation._get_dealer_msg)
    receiver_source = inspect.getsource(implementation._handle_dealer_msgs)
    assert dealer_source.count("_generate_ipakzg_aggregate_witnesses(") == 1
    assert receiver_source.count("_verify_ipakzg_aggregate_relations(") == 1


def test_context_maps_local_id_to_field_point_and_normalizes_scalars(
    aggtrans_fixture,
):
    context = build_agg_eval_context(
        aggtrans_fixture["dealer"],
        aggtrans_fixture["old_commitments"],
        aggtrans_fixture["fresh_commitments"],
    )
    assert context["old_point"] == str(aggtrans_fixture["dealer"] + 1)
    assert context["fresh_point"] == "0"
    normalized = normalize_openings([
        {"H": aggtrans_fixture["old_openings"][0]["H"],
         "ClaimedValue": 7 + FR_MODULUS,
         "ClaimedValueAux": "-1"}
    ])
    assert normalized[0]["ClaimedValue"] == "7"
    assert normalized[0]["ClaimedValueAux"] == str(FR_MODULUS - 1)


def test_noagg_combined_payload_and_two_honest_relations(
    aggtrans_fixture, monkeypatch,
):
    fixture = aggtrans_fixture
    combine_calls = []

    def counted_combine(share_g, share_h):
        combine_calls.append((share_g, share_h))
        return fixture["library"].pyPedersenCombine(share_g, share_h)

    artifacts = prepare_aggtrans_noagg(
        library=fixture["library"],
        old_commitments=fixture["old_commitments"],
        fresh_commitments=fixture["fresh_commitments"],
        old_witnesses=[{"H": proof["H"]} for proof in fixture["old_openings"]],
        fresh_witnesses=[
            {"H": proof["H"]} for proof in fixture["fresh_openings"]
        ],
        share_g=fixture["share_g"],
        share_h=fixture["share_h"],
        pedersen_combine=counted_combine,
    )
    assert len(combine_calls) == 1
    payload = build_aggtrans_noagg_payload(
        b"receiver-opening", _encoded(fixture["old_commitments"]), artifacts,
    )
    assert payload["schema"] == AGGTRANS_NOAGG_SCHEMA
    assert set(payload) == {
        "schema", "proof_and_shares", "old_commitments", "W_old", "W_new",
        "Ped",
    }
    assert "pokPed" not in payload
    assert "shareG" not in payload and "shareH" not in payload

    parsed = parse_aggtrans_noagg_payload(payload)
    counting = _CountingLibrary(fixture["library"])
    monkeypatch.setattr(hbacss_module, "lib", counting)
    old_valid, fresh_valid = hbacss_module._verify_aggtrans_noagg_relations(
        mpc_instance=None,
        proof_metric={},
        dealer_local_id=fixture["dealer"],
        srs_vk=fixture["vk"],
        old_commitments=parsed.old_commitments,
        fresh_commitments=_encoded(fixture["fresh_commitments"]),
        old_witnesses=parsed.old_witnesses,
        fresh_witnesses=parsed.fresh_witnesses,
        pedersen=parsed.pedersen,
    )
    assert old_valid and fresh_valid
    assert counting.combined_batch_verifications == 2


def test_noagg_public_bundle_excludes_receiver_opening(aggtrans_fixture):
    fixture = aggtrans_fixture
    artifacts = prepare_aggtrans_noagg(
        library=fixture["library"],
        old_commitments=fixture["old_commitments"],
        fresh_commitments=fixture["fresh_commitments"],
        old_witnesses=[{"H": proof["H"]} for proof in fixture["old_openings"]],
        fresh_witnesses=[
            {"H": proof["H"]} for proof in fixture["fresh_openings"]
        ],
        share_g=fixture["share_g"], share_h=fixture["share_h"],
    )
    public = build_aggtrans_noagg_public_payload(
        _encoded(fixture["old_commitments"]), artifacts,
    )
    assert public["schema"] == AGGTRANS_NOAGG_PUBLIC_SCHEMA
    assert "proof_and_shares" not in public
    parsed_public = parse_aggtrans_noagg_public_payload(public)
    combined = combine_aggtrans_noagg_payload(
        b"receiver-opening", parsed_public,
    )
    assert combined.proof_and_shares == b"receiver-opening"
    assert combined.old_commitments == _encoded(fixture["old_commitments"])


def test_ipakzg_wrapper_builds_full_context_and_verifies_three_relations(
    aggtrans_fixture,
):
    fixture = aggtrans_fixture
    context = build_ipakzg_context(
        fixture["dealer"],
        fixture["old_commitments"], fixture["old_commitments"],
        fixture["fresh_commitments"],
        fixture["old_pedersen"], fixture["old_pedersen"],
        fixture["fresh_pedersen"],
    )
    assert context["left_point"] == str(fixture["dealer"] + 1)
    assert context["right_point"] == str(fixture["dealer"] + 1)
    assert context["output_point"] == "0"
    gamma = derive_ipakzg_challenge(
        fixture["library"], fixture["pk"], fixture["vk"], context,
    )

    old_witness = aggregate_ipakzg_witness(
        library=fixture["library"], context=context, relation="left",
        openings=fixture["old_openings"], gamma=gamma,
    )
    fresh_witness = aggregate_ipakzg_witness(
        library=fixture["library"], context=context, relation="output",
        openings=fixture["fresh_openings"], gamma=gamma,
    )
    for relation, witness in (
        ("left", old_witness), ("right", old_witness),
        ("output", fresh_witness),
    ):
        assert verify_agg_ped_eval(
            library=fixture["library"], srs_pk=fixture["pk"],
            srs_vk=fixture["vk"], context=context,
            relation=relation, witness=witness,
        )

    batch_result = verify_agg_ped_eval_batch(
        library=fixture["library"], srs_pk=fixture["pk"],
        srs_vk=fixture["vk"], context=context,
        left_witness=old_witness, right_witness=old_witness,
        output_witness=fresh_witness,
    )
    assert batch_result.accepted

    # AggPedVerEval must bind even fields belonging to another relation through
    # the common challenge, not merely the selected commitment/Pedersen pair.
    for field in (
        "left_commitments", "right_commitments", "output_commitments",
        "left_pedersen", "right_pedersen", "output_pedersen",
    ):
        changed = copy.deepcopy(context)
        changed[field][0], changed[field][1] = (
            changed[field][1], changed[field][0]
        )
        assert not verify_agg_ped_eval(
            library=fixture["library"], srs_pk=fixture["pk"],
            srs_vk=fixture["vk"], context=changed,
            relation="left", witness=old_witness,
        )
        assert not verify_agg_ped_eval_batch(
            library=fixture["library"], srs_pk=fixture["pk"],
            srs_vk=fixture["vk"], context=changed,
            left_witness=old_witness, right_witness=old_witness,
            output_witness=fresh_witness,
        ).accepted

    for field in ("left_point", "right_point", "output_point"):
        changed = copy.deepcopy(context)
        changed[field] = str(int(changed[field]) + 1)
        assert not verify_agg_ped_eval(
            library=fixture["library"], srs_pk=fixture["pk"],
            srs_vk=fixture["vk"], context=changed,
            relation="left", witness=old_witness,
        )

    with pytest.raises(AggregationInterfaceError, match="equal length"):
        aggregate_ipakzg_witness(
            library=fixture["library"], context=context, relation="left",
            openings=fixture["old_openings"][:-1], gamma=gamma,
        )

    with pytest.raises(AggregationInterfaceError, match="equal length"):
        build_ipakzg_context(
            fixture["dealer"], fixture["old_commitments"][:-1],
            fixture["old_commitments"], fixture["fresh_commitments"],
            fixture["old_pedersen"], fixture["old_pedersen"],
            fixture["fresh_pedersen"],
        )


def test_v2_payload_round_trip_has_no_gamma_and_uses_one_native_verification(
    aggtrans_fixture,
):
    artifacts = _v2_artifacts(aggtrans_fixture)
    payload = build_aggtrans_payload(
        "v2", b"receiver-opening", _encoded(aggtrans_fixture["old_commitments"]),
        v2=artifacts,
    )
    assert payload["schema"] == AGGTRANS_V2_SCHEMA
    assert set(payload) == {
        "schema", "proof_and_shares", "old_commitments", "T",
        "W_old", "W_new", "pok_ped",
    }
    assert all("gamma" not in key.lower() for key in payload)
    sizes = aggtrans_proof_size_metadata("v2", v2=artifacts, legacy=None)
    assert sizes["canonical_proof_bytes"] == AGGTRANS_V2_CANONICAL_PROOF_BYTES
    assert sizes["serialized_proof_bytes"] == sum(
        len(payload[field]) for field in ("T", "W_old", "W_new", "pok_ped")
    )
    parsed = parse_aggtrans_payload("v2", payload)
    counting = _CountingLibrary(aggtrans_fixture["library"])
    result = verify_aggtrans(
        "v2", library=counting,
        srs_pk=aggtrans_fixture["pk"], srs_vk=aggtrans_fixture["vk"],
        dealer_local_id=aggtrans_fixture["dealer"], receiver_local_id=0,
        fresh_commitments=_encoded(aggtrans_fixture["fresh_commitments"]),
        payload=parsed,
    )
    assert result.accepted
    assert counting.aggpub_batch_verifications == 1
    assert counting.pok_verifications == 0


def test_v2_rbc_public_bundle_and_private_avid_opening_are_disjoint(
    aggtrans_fixture,
):
    artifacts = _v2_artifacts(aggtrans_fixture)
    public = build_aggtrans_public_payload(
        "v2", _encoded(aggtrans_fixture["old_commitments"]), v2=artifacts,
    )
    assert public["schema"] == AGGTRANS_V2_PUBLIC_SCHEMA
    assert set(public) == {
        "schema", "old_commitments", "T", "W_old", "W_new", "pok_ped",
    }
    assert "proof_and_shares" not in public
    parsed_public = parse_aggtrans_public_payload("v2", public)
    combined = combine_aggtrans_payload(
        b"receiver-opening", parsed_public,
    )
    assert combined.proof_and_shares == b"receiver-opening"
    assert combined.old_commitments == _encoded(
        aggtrans_fixture["old_commitments"]
    )
    assert combined.v2 == artifacts


@pytest.mark.parametrize("mode", ["v2", "legacy", "shadow"])
def test_aggtrans_public_bundle_round_trips_all_feature_modes(
    aggtrans_fixture, mode,
):
    v2 = _v2_artifacts(aggtrans_fixture)
    legacy = prove_aggtrans_legacy(
        library=aggtrans_fixture["library"],
        fresh_commitments=aggtrans_fixture["fresh_commitments"],
        old_openings=aggtrans_fixture["old_openings"],
        fresh_openings=aggtrans_fixture["fresh_openings"],
        share_g=aggtrans_fixture["share_g"],
        share_h=aggtrans_fixture["share_h"],
    )
    public = build_aggtrans_public_payload(
        mode, _encoded(aggtrans_fixture["old_commitments"]),
        v2=v2, legacy=legacy,
    )
    parsed = parse_aggtrans_public_payload(mode, public)
    combined = combine_aggtrans_payload(b"private-opening", parsed)
    assert combined.proof_and_shares == b"private-opening"
    assert combined.old_commitments == _encoded(
        aggtrans_fixture["old_commitments"]
    )
    assert (combined.v2 is not None) == (mode in {"v2", "shadow"})
    assert (combined.legacy is not None) == (mode in {"legacy", "shadow"})


def test_hbacss_transfer_rbc_envelope_contains_public_bundle_only(
    aggtrans_fixture,
):
    artifacts = _v2_artifacts(aggtrans_fixture)
    instance = SimpleNamespace(
        mode="avss_with_aggtransfer", agg_kzg_mode="v2",
    )
    encoded = hbacss_module._build_hbacss_broadcast_payload(
        instance, b"fresh-commitments", b"ephemeral-key", {
            "serialized_original_commitment": _encoded(
                aggtrans_fixture["old_commitments"]
            ),
            "aggtrans_v2": artifacts,
            "aggtrans_legacy": None,
        },
    )
    envelope = loads(encoded)
    assert len(envelope) == 3
    assert envelope[:2] == (b"fresh-commitments", b"ephemeral-key")
    assert "proof_and_shares" not in envelope[2]
    commitment, ephemeral_key, public = (
        hbacss_module._parse_hbacss_broadcast_payload(instance, encoded)
    )
    assert commitment == b"fresh-commitments"
    assert ephemeral_key == b"ephemeral-key"
    assert public.v2 == artifacts


def _batchmul_public_values():
    return {
        "left_commitments": b"left-commitments",
        "right_commitments": b"right-commitments",
        "left_witness": b"left-witness",
        "right_witness": b"right-witness",
        "output_witness": b"output-witness",
        "left_pedersen": b"left-pedersen",
        "right_pedersen": b"right-pedersen",
        "output_pedersen": b"output-pedersen",
        "factor_proof": "factor-proof-hex",
    }


def test_batchmul_rbc_public_bundle_and_private_avid_opening_are_disjoint():
    values = _batchmul_public_values()
    public = build_batchmul_public_payload(**values)
    assert public["schema"] == BATCHMUL_PUBLIC_SCHEMA
    assert "proof_and_shares" not in public

    parsed = parse_batchmul_public_payload(public)
    combined = combine_batchmul_payload(b"receiver-opening", parsed)
    assert combined.proof_and_shares == b"receiver-opening"
    assert combined.left_commitments == values["left_commitments"]
    assert combined.output_witness == values["output_witness"]
    assert combined.factor_proof == values["factor_proof"]


def test_hbacss_batchmul_rbc_envelope_contains_public_bundle_only():
    values = _batchmul_public_values()
    instance = SimpleNamespace(mode="avss_with_aggbatch_multiplication")
    encoded = hbacss_module._build_hbacss_broadcast_payload(
        instance,
        b"output-commitments",
        b"ephemeral-key",
        {
            "serialized_left_commitment": values["left_commitments"],
            "serialized_right_commitment": values["right_commitments"],
            "ser_aggleftproof": values["left_witness"],
            "ser_aggrightproof": values["right_witness"],
            "ser_aggproofAtZero": values["output_witness"],
            "ser_pedersen_left": values["left_pedersen"],
            "ser_pedersen_right": values["right_pedersen"],
            "ser_pedersen_output": values["output_pedersen"],
            "proof": values["factor_proof"],
        },
    )
    envelope = loads(encoded)
    assert len(envelope) == 3
    assert envelope[:2] == (b"output-commitments", b"ephemeral-key")
    assert "proof_and_shares" not in envelope[2]
    commitments, ephemeral_key, public = (
        hbacss_module._parse_hbacss_broadcast_payload(instance, encoded)
    )
    assert commitments == b"output-commitments"
    assert ephemeral_key == b"ephemeral-key"
    assert public.left_commitments == values["left_commitments"]
    assert public.factor_proof == values["factor_proof"]


@pytest.mark.parametrize("mutation", ["missing", "extra", "schema", "proof-type"])
def test_batchmul_public_bundle_rejects_malformed_schema(mutation):
    public = build_batchmul_public_payload(**_batchmul_public_values())
    if mutation == "missing":
        public.pop("W_output")
    elif mutation == "extra":
        public["unexpected"] = b"field"
    elif mutation == "schema":
        public["schema"] = "batchmul-public-v0"
    else:
        public["factor_proof"] = b"not-text"
    with pytest.raises(AggregationInterfaceError):
        parse_batchmul_public_payload(public)


@pytest.mark.parametrize("field", ["T", "W_old", "W_new", "pok_ped"])
def test_v2_payload_rejects_cryptographic_tampering(aggtrans_fixture, field):
    artifacts = _v2_artifacts(aggtrans_fixture)
    payload = build_aggtrans_payload(
        "v2", b"receiver-opening", _encoded(aggtrans_fixture["old_commitments"]),
        v2=artifacts,
    )
    tampered = copy.deepcopy(payload)
    if field == "pok_ped":
        proof = json.loads(tampered[field].decode("utf-8"))
        proof["z"] = "0" if proof["z"] != "0" else "1"
        tampered[field] = _encoded(proof)
    else:
        # Substitute another valid G1 point so decoding succeeds and the
        # cryptographic relation, rather than JSON parsing, rejects it.
        tampered[field] = _encoded(aggtrans_fixture["old_commitments"][0])
    parsed = parse_aggtrans_payload("v2", tampered)
    result = verify_aggtrans(
        "v2", library=aggtrans_fixture["library"],
        srs_pk=aggtrans_fixture["pk"], srs_vk=aggtrans_fixture["vk"],
        dealer_local_id=aggtrans_fixture["dealer"], receiver_local_id=0,
        fresh_commitments=_encoded(aggtrans_fixture["fresh_commitments"]),
        payload=parsed,
    )
    assert not result.accepted


def test_v2_rejects_commitment_point_and_schema_tampering(aggtrans_fixture):
    artifacts = _v2_artifacts(aggtrans_fixture)
    payload = build_aggtrans_payload(
        "v2", b"receiver-opening", _encoded(aggtrans_fixture["old_commitments"]),
        v2=artifacts,
    )
    changed_old = copy.deepcopy(payload)
    old_commitments = copy.deepcopy(aggtrans_fixture["old_commitments"])
    old_commitments[0] = aggtrans_fixture["fresh_commitments"][0]
    changed_old["old_commitments"] = _encoded(old_commitments)
    result = verify_aggtrans(
        "v2", library=aggtrans_fixture["library"],
        srs_pk=aggtrans_fixture["pk"], srs_vk=aggtrans_fixture["vk"],
        dealer_local_id=aggtrans_fixture["dealer"], receiver_local_id=0,
        fresh_commitments=_encoded(aggtrans_fixture["fresh_commitments"]),
        payload=parse_aggtrans_payload("v2", changed_old),
    )
    assert not result.accepted

    changed_fresh = copy.deepcopy(aggtrans_fixture["fresh_commitments"])
    changed_fresh[0] = aggtrans_fixture["old_commitments"][0]
    result = verify_aggtrans(
        "v2", library=aggtrans_fixture["library"],
        srs_pk=aggtrans_fixture["pk"], srs_vk=aggtrans_fixture["vk"],
        dealer_local_id=aggtrans_fixture["dealer"], receiver_local_id=0,
        fresh_commitments=_encoded(changed_fresh),
        payload=parse_aggtrans_payload("v2", payload),
    )
    assert not result.accepted

    wrong_point = verify_aggtrans(
        "v2", library=aggtrans_fixture["library"],
        srs_pk=aggtrans_fixture["pk"], srs_vk=aggtrans_fixture["vk"],
        dealer_local_id=aggtrans_fixture["dealer"] + 1,
        receiver_local_id=0,
        fresh_commitments=_encoded(aggtrans_fixture["fresh_commitments"]),
        payload=parse_aggtrans_payload("v2", payload),
    )
    assert not wrong_point.accepted

    injected_gamma = copy.deepcopy(payload)
    injected_gamma["gamma"] = b"1"
    with pytest.raises(AggregationInterfaceError, match="schema"):
        parse_aggtrans_payload("v2", injected_gamma)


def test_legacy_rollback_and_shadow_paths_remain_available(aggtrans_fixture):
    v2 = _v2_artifacts(aggtrans_fixture)
    legacy = prove_aggtrans_legacy(
        library=aggtrans_fixture["library"],
        fresh_commitments=aggtrans_fixture["fresh_commitments"],
        old_openings=aggtrans_fixture["old_openings"],
        fresh_openings=aggtrans_fixture["fresh_openings"],
        share_g=aggtrans_fixture["share_g"],
        share_h=aggtrans_fixture["share_h"],
    )
    for mode in ("legacy", "shadow"):
        sizes = aggtrans_proof_size_metadata(mode, v2=v2, legacy=legacy)
        expected = AGGTRANS_LEGACY_CANONICAL_PROOF_BYTES
        if mode == "shadow":
            expected += AGGTRANS_V2_CANONICAL_PROOF_BYTES
        assert sizes["canonical_proof_bytes"] == expected
        encoded_payload = build_aggtrans_payload(
            mode, b"receiver-opening",
            _encoded(aggtrans_fixture["old_commitments"]),
            v2=v2, legacy=legacy,
        )
        parsed = parse_aggtrans_payload(mode, encoded_payload)
        result = verify_aggtrans(
            mode, library=aggtrans_fixture["library"],
            srs_pk=aggtrans_fixture["pk"], srs_vk=aggtrans_fixture["vk"],
            dealer_local_id=aggtrans_fixture["dealer"], receiver_local_id=0,
            fresh_commitments=_encoded(aggtrans_fixture["fresh_commitments"]),
            payload=parsed,
        )
        assert result.accepted
