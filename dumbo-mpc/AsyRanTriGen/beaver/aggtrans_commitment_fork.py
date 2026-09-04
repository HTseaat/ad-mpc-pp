"""Construct a locally valid AggTrans prior-commitment fork.

For one batch position this helper adds the constant polynomial ``delta`` to
the dealer's prior KZG value.  KZG commitments and claimed values shift, while
the evaluation witness is unchanged because the quotient polynomial is
unchanged.  The result therefore passes Algorithm 1 line 204 against the
forked prior commitment, but disagrees with the honest vector at line 207.
"""

from __future__ import annotations

import json
from typing import Any, Dict


FIELD_ORDER = (
    52435875175126190479447740508185965837690552500527637822603658699938581184513
)


def build_aggtrans_commitment_fork(
    *,
    kzg_lib: Any,
    srs_pk: bytes,
    payload: Dict[str, object],
    n: int,
    dealer_local_id: int,
    attack_index: int,
    delta: int,
) -> Dict[str, object]:
    """Return a new payload with one homomorphically shifted prior value."""
    commitments = payload.get("commitment")
    proofs = payload.get("proof")
    if not isinstance(commitments, list) or not isinstance(proofs, list):
        raise ValueError("AggTrans payload must contain commitment/proof lists")
    if len(commitments) != len(proofs) or not commitments:
        raise ValueError("AggTrans commitment/proof lists must be non-empty and equal")
    if not 0 <= dealer_local_id < n:
        raise ValueError("dealer_local_id is outside the committee")
    if not 0 <= attack_index < len(proofs):
        raise ValueError("attack_index is outside the AggTrans batch")

    normalized_delta = int(delta) % FIELD_ORDER
    if normalized_delta == 0:
        raise ValueError("Byzantine delta must be non-zero")

    # Commit directly to the constant pairs (delta, 0).  Their KZG quotient is
    # zero at every evaluation point, so the corresponding witness is the G1
    # identity.  This avoids relying on the library's polynomial sampler for a
    # degree-zero edge case.
    delta_values = ["0"] * len(proofs)
    delta_values[attack_index] = str(normalized_delta)
    delta_aux = ["0"] * len(proofs)
    encoded_delta = kzg_lib.pyPedersenCommit(
        srs_pk,
        json.dumps(delta_values).encode("utf-8"),
        json.dumps(delta_aux).encode("utf-8"),
    )
    delta_commitments = json.loads(encoded_delta.decode("utf-8"))
    if not isinstance(delta_commitments, list) or len(delta_commitments) != len(proofs):
        raise ValueError("constant KZG delta returned an invalid commitment vector")
    identity = {"X": "0", "Y": "0"}
    delta_proofs = [
        {
            "H": identity,
            "ClaimedValue": delta_values[index],
            "ClaimedValueAux": "0",
        }
        for index in range(len(proofs))
    ]
    delta_payload = {
        "commitment": delta_commitments,
        "proof": delta_proofs,
    }

    encoded_fork = kzg_lib.pyCircuitAdd(
        json.dumps(payload).encode("utf-8"),
        json.dumps(delta_payload).encode("utf-8"),
    )
    forked = json.loads(encoded_fork.decode("utf-8"))
    if "error" in forked:
        raise ValueError(f"failed to add constant KZG delta: {forked['error']}")
    if len(forked.get("commitment", [])) != len(commitments):
        raise ValueError("forked AggTrans payload has the wrong batch width")

    # pyCircuitAdd uses big integers for the JSON claims; normalize explicitly
    # to the BLS12-381 scalar field in the negligible wraparound case.
    for proof in forked.get("proof", []):
        proof["ClaimedValue"] = str(int(proof["ClaimedValue"]) % FIELD_ORDER)
        proof["ClaimedValueAux"] = str(
            int(proof["ClaimedValueAux"]) % FIELD_ORDER
        )

    original_proof = proofs[attack_index]
    forked_proof = forked["proof"][attack_index]
    expected_value = (
        int(original_proof["ClaimedValue"]) + normalized_delta
    ) % FIELD_ORDER
    if int(forked_proof["ClaimedValue"]) != expected_value:
        raise ValueError("forked claimed value does not equal share + delta")
    if int(forked_proof["ClaimedValueAux"]) != (
        int(original_proof["ClaimedValueAux"]) % FIELD_ORDER
    ):
        raise ValueError("commitment fork unexpectedly changed auxiliary randomness")
    forked_h = forked_proof["H"]
    original_h = original_proof["H"]
    if (
        int(forked_h["X"]) != int(original_h["X"])
        or int(forked_h["Y"]) != int(original_h["Y"])
    ):
        raise ValueError("constant commitment fork unexpectedly changed KZG witness")
    if forked["commitment"][attack_index] == commitments[attack_index]:
        raise ValueError("commitment fork did not change the attacked commitment")

    return forked
