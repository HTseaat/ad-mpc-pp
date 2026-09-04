"""Construct a locally valid BatchMul input-commitment fork.

For one multiplication gate, a corrupted dealer shifts both input
polynomials by the same non-zero constant.  The input commitments and claimed
values change, while their KZG evaluation witnesses remain valid.  The normal
BatchMul path then recomputes the product, output resharing, and product proof
from this alternate but internally consistent input view.
"""

from __future__ import annotations

from typing import Any, Dict, Tuple

from beaver.aggtrans_commitment_fork import build_aggtrans_commitment_fork


def build_batchmul_input_commitment_fork(
    *,
    kzg_lib: Any,
    srs_pk: bytes,
    left_payload: Dict[str, object],
    right_payload: Dict[str, object],
    n: int,
    dealer_local_id: int,
    attack_index: int,
    delta: int,
) -> Tuple[Dict[str, object], Dict[str, object]]:
    """Return independent left/right input views shifted at one gate."""
    left_proofs = left_payload.get("proof")
    right_proofs = right_payload.get("proof")
    if not isinstance(left_proofs, list) or not isinstance(right_proofs, list):
        raise ValueError("BatchMul inputs must contain proof lists")
    if len(left_proofs) != len(right_proofs) or not left_proofs:
        raise ValueError("BatchMul left/right batches must be non-empty and equal")

    forked_left = build_aggtrans_commitment_fork(
        kzg_lib=kzg_lib,
        srs_pk=srs_pk,
        payload=left_payload,
        n=n,
        dealer_local_id=dealer_local_id,
        attack_index=attack_index,
        delta=delta,
    )
    forked_right = build_aggtrans_commitment_fork(
        kzg_lib=kzg_lib,
        srs_pk=srs_pk,
        payload=right_payload,
        n=n,
        dealer_local_id=dealer_local_id,
        attack_index=attack_index,
        delta=delta,
    )
    return forked_left, forked_right
