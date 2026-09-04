"""Typed Python boundary for the revised aggregate KZG protocols.

This module owns every ctypes declaration, transcript-context constructor and
AggTrans public/private payload schema introduced by protocol stages 4 and 5.  The
three historical HBACSS implementations call these helpers instead of
reimplementing challenge and payload logic independently.
"""

from __future__ import annotations

from ctypes import c_bool, c_char_p, c_int
from dataclasses import dataclass
import json
import logging
import os
from typing import Any, Mapping, Optional, Sequence, Tuple


FR_MODULUS = (
    52435875175126190479447740508185965837690552500527637822603658699938581184513
)
AGGTRANS_V2_SCHEMA = "aggtrans-v2"
AGGTRANS_SHADOW_SCHEMA = "aggtrans-shadow-v1"
AGGTRANS_NOAGG_SCHEMA = "aggtrans-noagg-v1"
AGGTRANS_V2_PUBLIC_SCHEMA = "aggtrans-v2-public-v1"
AGGTRANS_LEGACY_PUBLIC_SCHEMA = "aggtrans-legacy-public-v1"
AGGTRANS_SHADOW_PUBLIC_SCHEMA = "aggtrans-shadow-public-v1"
AGGTRANS_NOAGG_PUBLIC_SCHEMA = "aggtrans-noagg-public-v1"
BATCHMUL_PUBLIC_SCHEMA = "batchmul-public-v1"
AGGTRANS_LEGACY_CANONICAL_PROOF_BYTES = 4 * 48 + 32
AGGTRANS_V2_CANONICAL_PROOF_BYTES = 3 * 48 + 112
_LOG = logging.getLogger(__name__)


class AggregationInterfaceError(ValueError):
    """Raised when an aggregate-proof FFI call or payload is malformed."""


@dataclass(frozen=True)
class AggTransV2Artifacts:
    combined_claim: bytes
    old_witness: bytes
    fresh_witness: bytes
    pok_ped: bytes


@dataclass(frozen=True)
class AggTransLegacyArtifacts:
    old_witness: bytes
    share_g: bytes
    share_h: bytes
    fresh_witness: bytes
    challenge: bytes


@dataclass(frozen=True)
class AggTransReceivedPayload:
    proof_and_shares: bytes
    old_commitments: bytes
    v2: Optional[AggTransV2Artifacts] = None
    legacy: Optional[AggTransLegacyArtifacts] = None


@dataclass(frozen=True)
class AggTransPublicPayload:
    """Common AggTrans transcript delivered consistently by RBC."""

    old_commitments: bytes
    v2: Optional[AggTransV2Artifacts] = None
    legacy: Optional[AggTransLegacyArtifacts] = None


@dataclass(frozen=True)
class AggTransNoAggArtifacts:
    old_witnesses: bytes
    fresh_witnesses: bytes
    pedersen: bytes


@dataclass(frozen=True)
class AggTransNoAggReceivedPayload:
    proof_and_shares: bytes
    old_commitments: bytes
    old_witnesses: bytes
    fresh_witnesses: bytes
    pedersen: bytes


@dataclass(frozen=True)
class AggTransNoAggPublicPayload:
    """Common NoAgg transcript delivered consistently by RBC."""

    old_commitments: bytes
    old_witnesses: bytes
    fresh_witnesses: bytes
    pedersen: bytes


@dataclass(frozen=True)
class BatchMulPublicPayload:
    """Common IPAKZG statement and proof delivered consistently by RBC."""

    left_commitments: bytes
    right_commitments: bytes
    left_witness: bytes
    right_witness: bytes
    output_witness: bytes
    left_pedersen: bytes
    right_pedersen: bytes
    output_pedersen: bytes
    factor_proof: str


@dataclass(frozen=True)
class BatchMulReceivedPayload:
    """RBC public BatchMul bundle combined with one private AVID opening."""

    proof_and_shares: bytes
    left_commitments: bytes
    right_commitments: bytes
    left_witness: bytes
    right_witness: bytes
    output_witness: bytes
    left_pedersen: bytes
    right_pedersen: bytes
    output_pedersen: bytes
    factor_proof: str


@dataclass(frozen=True)
class AggTransVerification:
    pok_ped_valid: bool
    fresh_zero_valid: bool
    old_anchor_valid: bool

    @property
    def accepted(self) -> bool:
        return (
            self.pok_ped_valid
            and self.fresh_zero_valid
            and self.old_anchor_valid
        )


@dataclass(frozen=True)
class IPAKZGAggregateVerification:
    left_valid: bool
    right_valid: bool
    output_valid: bool

    @property
    def accepted(self) -> bool:
        return self.left_valid and self.right_valid and self.output_valid


def configure_aggregation_ffi(library: Any) -> None:
    """Declare the stage-1/2/3 exports used by the Python wrapper."""
    library.pyDeriveChallenge.argtypes = [c_char_p]
    library.pyDeriveChallenge.restype = c_char_p
    library.pyAggProveEvalZero.argtypes = [c_char_p, c_char_p]
    library.pyAggProveEvalZero.restype = c_char_p
    library.pyPubAggVerifyEval.argtypes = [
        c_char_p, c_char_p, c_char_p, c_char_p, c_char_p, c_char_p, c_int,
    ]
    library.pyPubAggVerifyEval.restype = c_bool
    library.pyPubAggVerifyEvalCombined.argtypes = [
        c_char_p, c_char_p, c_char_p, c_char_p, c_char_p, c_int,
    ]
    library.pyPubAggVerifyEvalCombined.restype = c_bool
    library.pyDeriveAggEvalChallenge.argtypes = [c_char_p, c_char_p, c_char_p]
    library.pyDeriveAggEvalChallenge.restype = c_char_p
    library.pyDeriveIPAKZGChallenge.argtypes = [c_char_p, c_char_p, c_char_p]
    library.pyDeriveIPAKZGChallenge.restype = c_char_p
    library.pyPokPedVerify.argtypes = [
        c_char_p, c_char_p, c_char_p, c_char_p, c_char_p,
    ]
    library.pyPokPedVerify.restype = c_bool
    library.pyAggPubProEval.argtypes = [
        c_char_p, c_char_p, c_char_p, c_char_p, c_char_p, c_int,
    ]
    library.pyAggPubProEval.restype = c_char_p
    library.pyAggPubProEvalBatch2.argtypes = [
        c_char_p, c_char_p, c_char_p, c_char_p, c_char_p,
    ]
    library.pyAggPubProEvalBatch2.restype = c_char_p
    library.pyAggPubVerEvalBatch2.argtypes = [
        c_char_p, c_char_p, c_char_p, c_char_p, c_char_p, c_char_p, c_char_p,
    ]
    library.pyAggPubVerEvalBatch2.restype = c_int
    library.pyAggPedVerEval.argtypes = [
        c_char_p, c_char_p, c_char_p, c_char_p, c_char_p, c_char_p, c_int,
    ]
    library.pyAggPedVerEval.restype = c_bool
    library.pyAggPedVerEvalBatch3.argtypes = [
        c_char_p, c_char_p, c_char_p, c_char_p, c_char_p, c_char_p,
    ]
    library.pyAggPedVerEvalBatch3.restype = c_int
    library.pyPedersenCombine.argtypes = [c_char_p, c_char_p]
    library.pyPedersenCombine.restype = c_char_p
    library.pyBatchVerifyPubCombined.argtypes = [
        c_char_p, c_char_p, c_char_p, c_char_p, c_int,
    ]
    library.pyBatchVerifyPubCombined.restype = c_bool


def agg_kzg_mode(environ: Optional[Mapping[str, str]] = None) -> str:
    """Return ``v2`` (default), ``legacy`` or ``shadow``.

    The flag is deliberately independent of ``DISABLE_AGG_PROTO``.  Stage 5
    makes V2 the normal AggTrans path; ``AGG_KZG_V2=0`` is a temporary rollback
    switch, while ``shadow`` sends both artifacts and keeps the legacy result
    authoritative for transition testing.
    """
    env = os.environ if environ is None else environ
    raw = env.get("AGG_KZG_V2", "1").strip().lower()
    if raw in {"1", "true", "yes", "on", "v2"}:
        return "v2"
    if raw in {"0", "false", "no", "off", "legacy"}:
        return "legacy"
    if raw == "shadow":
        return "shadow"
    raise AggregationInterfaceError(
        "AGG_KZG_V2 must be one of 1/v2, 0/legacy, or shadow"
    )


def _json_object(value: Any, label: str) -> Any:
    if isinstance(value, (bytes, bytearray)):
        try:
            return json.loads(bytes(value).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AggregationInterfaceError(f"{label} is not valid JSON") from exc
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError as exc:
            raise AggregationInterfaceError(f"{label} is not valid JSON") from exc
    return value


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def _require_bytes(value: Any, label: str) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise AggregationInterfaceError(f"{label} must be serialized bytes")
    return bytes(value)


def _require_nonempty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise AggregationInterfaceError(f"{label} must be a non-empty string")
    return value


def _normalize_scalar(value: Any, label: str) -> str:
    if isinstance(value, bool):
        raise AggregationInterfaceError(f"{label} must be a field scalar")
    if isinstance(value, int):
        integer = value
    elif isinstance(value, str) and value and value.isdigit():
        integer = int(value, 10)
    else:
        raise AggregationInterfaceError(f"{label} must be a decimal field scalar")
    if not 0 <= integer < FR_MODULUS:
        raise AggregationInterfaceError(f"{label} is outside the scalar field")
    return str(integer)


def _normalize_legacy_field_scalar(value: Any, label: str) -> str:
    """Map an internal legacy integer representation to canonical Fr wire."""
    if isinstance(value, bool):
        raise AggregationInterfaceError(f"{label} must be a field scalar")
    if isinstance(value, int):
        integer = value
    elif (
        isinstance(value, str)
        and value
        and (value.isdigit() or (value[0] == "-" and value[1:].isdigit()))
    ):
        integer = int(value, 10)
    else:
        raise AggregationInterfaceError(f"{label} must be a decimal field scalar")
    return str(integer % FR_MODULUS)


def normalize_openings(openings: Any, label: str = "openings") -> list:
    """Convert legacy integer openings into canonical V2 Fr wire values.

    Legacy linear-gate helpers keep scalar representatives as ordinary signed
    big integers, so repeated additions can leave ``[0, r)`` even though the
    commitment and witness group operations already have Fr semantics.  This
    adapter performs the explicit reduction before the strict V2 FFI boundary.
    """
    decoded = _json_object(openings, label)
    if not isinstance(decoded, list) or not decoded:
        raise AggregationInterfaceError(f"{label} must be a non-empty list")
    normalized = []
    for index, opening in enumerate(decoded):
        if not isinstance(opening, dict):
            raise AggregationInterfaceError(f"{label}[{index}] must be an object")
        if not {"H", "ClaimedValue", "ClaimedValueAux"}.issubset(opening):
            raise AggregationInterfaceError(
                f"{label}[{index}] lacks H/ClaimedValue/ClaimedValueAux"
            )
        normalized.append({
            "H": opening["H"],
            "ClaimedValue": _normalize_legacy_field_scalar(
                opening["ClaimedValue"], f"{label}[{index}].ClaimedValue"
            ),
            "ClaimedValueAux": _normalize_legacy_field_scalar(
                opening["ClaimedValueAux"],
                f"{label}[{index}].ClaimedValueAux",
            ),
        })
    return normalized


def _commitment_vector(value: Any, label: str) -> list:
    decoded = _json_object(value, label)
    if not isinstance(decoded, list) or not decoded:
        raise AggregationInterfaceError(f"{label} must be a non-empty list")
    return decoded


def _witness_vector(value: Any, label: str) -> list:
    decoded = _json_object(value, label)
    if not isinstance(decoded, list) or not decoded:
        raise AggregationInterfaceError(f"{label} must be a non-empty list")
    for index, witness in enumerate(decoded):
        if not isinstance(witness, dict) or set(witness) != {"H"}:
            raise AggregationInterfaceError(
                f"{label}[{index}] must contain exactly the H witness"
            )
    return decoded


def prepare_aggtrans_noagg(
    *,
    library: Any,
    old_commitments: Any,
    fresh_commitments: Any,
    old_witnesses: Any,
    fresh_witnesses: Any,
    share_g: Any,
    share_h: Any,
    pedersen_combine: Optional[Any] = None,
) -> AggTransNoAggArtifacts:
    """Prepare the per-share combined-Ped payload once at the dealer."""
    vectors = {
        "old commitments": _commitment_vector(
            old_commitments, "old commitments"
        ),
        "fresh commitments": _commitment_vector(
            fresh_commitments, "fresh commitments"
        ),
        "old witnesses": _witness_vector(old_witnesses, "old witnesses"),
        "fresh witnesses": _witness_vector(
            fresh_witnesses, "fresh witnesses"
        ),
        "shareG": _commitment_vector(share_g, "shareG"),
        "shareH": _commitment_vector(share_h, "shareH"),
    }
    if len({len(vector) for vector in vectors.values()}) != 1:
        raise AggregationInterfaceError(
            "NoAgg commitments, witnesses, and shares must have equal length"
        )

    combine = (
        library.pyPedersenCombine
        if pedersen_combine is None else pedersen_combine
    )
    raw_pedersen = combine(
        _json_bytes(vectors["shareG"]), _json_bytes(vectors["shareH"])
    )
    if not isinstance(raw_pedersen, (bytes, bytearray)):
        raise AggregationInterfaceError(
            "pyPedersenCombine returned a non-byte result"
        )
    try:
        pedersen = json.loads(bytes(raw_pedersen).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AggregationInterfaceError(
            "pyPedersenCombine returned invalid JSON"
        ) from exc
    if isinstance(pedersen, dict) and "error" in pedersen:
        raise AggregationInterfaceError(
            f"pyPedersenCombine: {pedersen['error']}"
        )
    if not isinstance(pedersen, list) or len(pedersen) != len(
        vectors["shareG"]
    ):
        raise AggregationInterfaceError(
            "pyPedersenCombine returned an invalid commitment vector"
        )
    return AggTransNoAggArtifacts(
        old_witnesses=_json_bytes(vectors["old witnesses"]),
        fresh_witnesses=_json_bytes(vectors["fresh witnesses"]),
        pedersen=_json_bytes(pedersen),
    )


def build_aggtrans_noagg_payload(
    proof_and_shares: bytes,
    old_commitments: bytes,
    artifacts: AggTransNoAggArtifacts,
) -> dict:
    return {
        "schema": AGGTRANS_NOAGG_SCHEMA,
        "proof_and_shares": _require_bytes(
            proof_and_shares, "proof_and_shares"
        ),
        "old_commitments": _require_bytes(
            old_commitments, "old_commitments"
        ),
        "W_old": _require_bytes(artifacts.old_witnesses, "W_old"),
        "W_new": _require_bytes(artifacts.fresh_witnesses, "W_new"),
        "Ped": _require_bytes(artifacts.pedersen, "Ped"),
    }


def parse_aggtrans_noagg_payload(payload: Any) -> AggTransNoAggReceivedPayload:
    expected = {
        "schema", "proof_and_shares", "old_commitments", "W_old", "W_new",
        "Ped",
    }
    if (
        not isinstance(payload, dict)
        or set(payload) != expected
        or payload.get("schema") != AGGTRANS_NOAGG_SCHEMA
    ):
        raise AggregationInterfaceError("invalid AggTrans-NoAgg payload schema")
    return AggTransNoAggReceivedPayload(
        proof_and_shares=_require_bytes(
            payload["proof_and_shares"], "proof_and_shares"
        ),
        old_commitments=_require_bytes(
            payload["old_commitments"], "old_commitments"
        ),
        old_witnesses=_require_bytes(payload["W_old"], "W_old"),
        fresh_witnesses=_require_bytes(payload["W_new"], "W_new"),
        pedersen=_require_bytes(payload["Ped"], "Ped"),
    )


def build_aggtrans_noagg_public_payload(
    old_commitments: bytes,
    artifacts: AggTransNoAggArtifacts,
) -> dict:
    """Build the common NoAgg proof bundle carried by RBC.

    The receiver-specific BACSS opening is intentionally absent and remains
    the only NoAgg value sent through encrypted AVID.
    """
    return {
        "schema": AGGTRANS_NOAGG_PUBLIC_SCHEMA,
        "old_commitments": _require_bytes(
            old_commitments, "old_commitments"
        ),
        "W_old": _require_bytes(artifacts.old_witnesses, "W_old"),
        "W_new": _require_bytes(artifacts.fresh_witnesses, "W_new"),
        "Ped": _require_bytes(artifacts.pedersen, "Ped"),
    }


def parse_aggtrans_noagg_public_payload(
    payload: Any,
) -> AggTransNoAggPublicPayload:
    expected = {"schema", "old_commitments", "W_old", "W_new", "Ped"}
    if (
        not isinstance(payload, dict)
        or set(payload) != expected
        or payload.get("schema") != AGGTRANS_NOAGG_PUBLIC_SCHEMA
    ):
        raise AggregationInterfaceError(
            "invalid AggTrans-NoAgg public payload schema"
        )
    return AggTransNoAggPublicPayload(
        old_commitments=_require_bytes(
            payload["old_commitments"], "old_commitments"
        ),
        old_witnesses=_require_bytes(payload["W_old"], "W_old"),
        fresh_witnesses=_require_bytes(payload["W_new"], "W_new"),
        pedersen=_require_bytes(payload["Ped"], "Ped"),
    )


def combine_aggtrans_noagg_payload(
    proof_and_shares: bytes,
    public: AggTransNoAggPublicPayload,
) -> AggTransNoAggReceivedPayload:
    if not isinstance(public, AggTransNoAggPublicPayload):
        raise AggregationInterfaceError("invalid AggTrans-NoAgg public bundle")
    return AggTransNoAggReceivedPayload(
        proof_and_shares=_require_bytes(
            proof_and_shares, "proof_and_shares"
        ),
        old_commitments=public.old_commitments,
        old_witnesses=public.old_witnesses,
        fresh_witnesses=public.fresh_witnesses,
        pedersen=public.pedersen,
    )


def build_batchmul_public_payload(
    *,
    left_commitments: bytes,
    right_commitments: bytes,
    left_witness: bytes,
    right_witness: bytes,
    output_witness: bytes,
    left_pedersen: bytes,
    right_pedersen: bytes,
    output_pedersen: bytes,
    factor_proof: str,
) -> dict:
    """Build the receiver-independent IPAKZG bundle carried by RBC."""
    return {
        "schema": BATCHMUL_PUBLIC_SCHEMA,
        "C_left": _require_bytes(left_commitments, "C_left"),
        "C_right": _require_bytes(right_commitments, "C_right"),
        "W_left": _require_bytes(left_witness, "W_left"),
        "W_right": _require_bytes(right_witness, "W_right"),
        "W_output": _require_bytes(output_witness, "W_output"),
        "Ped_left": _require_bytes(left_pedersen, "Ped_left"),
        "Ped_right": _require_bytes(right_pedersen, "Ped_right"),
        "Ped_output": _require_bytes(output_pedersen, "Ped_output"),
        "factor_proof": _require_nonempty_string(factor_proof, "factor_proof"),
    }


def parse_batchmul_public_payload(payload: Any) -> BatchMulPublicPayload:
    expected = {
        "schema", "C_left", "C_right", "W_left", "W_right", "W_output",
        "Ped_left", "Ped_right", "Ped_output", "factor_proof",
    }
    if (
        not isinstance(payload, dict)
        or set(payload) != expected
        or payload.get("schema") != BATCHMUL_PUBLIC_SCHEMA
    ):
        raise AggregationInterfaceError("invalid BatchMul public payload schema")
    return BatchMulPublicPayload(
        left_commitments=_require_bytes(payload["C_left"], "C_left"),
        right_commitments=_require_bytes(payload["C_right"], "C_right"),
        left_witness=_require_bytes(payload["W_left"], "W_left"),
        right_witness=_require_bytes(payload["W_right"], "W_right"),
        output_witness=_require_bytes(payload["W_output"], "W_output"),
        left_pedersen=_require_bytes(payload["Ped_left"], "Ped_left"),
        right_pedersen=_require_bytes(payload["Ped_right"], "Ped_right"),
        output_pedersen=_require_bytes(payload["Ped_output"], "Ped_output"),
        factor_proof=_require_nonempty_string(
            payload["factor_proof"], "factor_proof"
        ),
    )


def combine_batchmul_payload(
    proof_and_shares: bytes,
    public: BatchMulPublicPayload,
) -> BatchMulReceivedPayload:
    if not isinstance(public, BatchMulPublicPayload):
        raise AggregationInterfaceError("invalid BatchMul public bundle")
    return BatchMulReceivedPayload(
        proof_and_shares=_require_bytes(proof_and_shares, "proof_and_shares"),
        left_commitments=public.left_commitments,
        right_commitments=public.right_commitments,
        left_witness=public.left_witness,
        right_witness=public.right_witness,
        output_witness=public.output_witness,
        left_pedersen=public.left_pedersen,
        right_pedersen=public.right_pedersen,
        output_pedersen=public.output_pedersen,
        factor_proof=public.factor_proof,
    )


def verify_aggtrans_noagg_relation(
    *,
    library: Any,
    srs_vk: bytes,
    commitments: bytes,
    witnesses: bytes,
    pedersen: bytes,
    evaluation_index: int,
) -> bool:
    """Verify every proof in one NoAgg combined-Ped relation individually."""
    if not isinstance(evaluation_index, int) or evaluation_index < -1:
        raise AggregationInterfaceError("invalid NoAgg evaluation index")
    return bool(library.pyBatchVerifyPubCombined(
        _require_bytes(srs_vk, "SRS Vk"),
        _require_bytes(commitments, "commitments"),
        _require_bytes(witnesses, "witnesses"),
        _require_bytes(pedersen, "Pedersen commitments"),
        evaluation_index,
    ))


def build_agg_eval_context(
    dealer_local_id: int,
    old_commitments: Any,
    fresh_commitments: Any,
) -> dict:
    if not isinstance(dealer_local_id, int) or dealer_local_id < 0:
        raise AggregationInterfaceError("dealer_local_id must be non-negative")
    old_vector = _commitment_vector(old_commitments, "old commitments")
    fresh_vector = _commitment_vector(fresh_commitments, "fresh commitments")
    if len(old_vector) != len(fresh_vector):
        raise AggregationInterfaceError(
            "old and fresh commitment vectors must have equal length"
        )
    return {
        "version": 1,
        "domain": "AggEval",
        "old_point": str(dealer_local_id + 1),
        "fresh_point": "0",
        "old_commitments": old_vector,
        "new_commitments": fresh_vector,
    }


def build_ipakzg_context(
    dealer_local_id: int,
    left_commitments: Any,
    right_commitments: Any,
    output_commitments: Any,
    left_pedersen: Any,
    right_pedersen: Any,
    output_pedersen: Any,
) -> dict:
    """Build the stage-6-ready IPAKZG transcript without switching callers."""
    if not isinstance(dealer_local_id, int) or dealer_local_id < 0:
        raise AggregationInterfaceError("dealer_local_id must be non-negative")
    vectors = {
        "left_commitments": _commitment_vector(
            left_commitments, "left commitments"
        ),
        "right_commitments": _commitment_vector(
            right_commitments, "right commitments"
        ),
        "output_commitments": _commitment_vector(
            output_commitments, "output commitments"
        ),
        "left_pedersen": _commitment_vector(left_pedersen, "left Pedersen"),
        "right_pedersen": _commitment_vector(right_pedersen, "right Pedersen"),
        "output_pedersen": _commitment_vector(output_pedersen, "output Pedersen"),
    }
    if len({len(vector) for vector in vectors.values()}) != 1:
        raise AggregationInterfaceError(
            "all IPAKZG commitment and Pedersen vectors must have equal length"
        )
    dealer_point = str(dealer_local_id + 1)
    return {
        "version": 1,
        "domain": "IPAKZG",
        "left_point": dealer_point,
        "right_point": dealer_point,
        "output_point": "0",
        **vectors,
    }


def _decode_ffi_json(raw: Any, label: str) -> dict:
    if not isinstance(raw, (bytes, bytearray)):
        raise AggregationInterfaceError(f"{label} returned a non-byte result")
    try:
        decoded = json.loads(bytes(raw).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AggregationInterfaceError(f"{label} returned invalid JSON") from exc
    if not isinstance(decoded, dict):
        raise AggregationInterfaceError(f"{label} returned a non-object result")
    if "error" in decoded:
        raise AggregationInterfaceError(f"{label}: {decoded['error']}")
    return decoded


def derive_agg_eval_challenge(
    library: Any, srs_pk: bytes, srs_vk: bytes, context: dict,
) -> bytes:
    raw = library.pyDeriveAggEvalChallenge(
        _require_bytes(srs_pk, "SRS Pk"),
        _require_bytes(srs_vk, "SRS Vk"),
        _json_bytes(context),
    )
    if not isinstance(raw, (bytes, bytearray)):
        raise AggregationInterfaceError("challenge export returned non-bytes")
    text = bytes(raw).decode("utf-8")
    if text.startswith("{"):
        error = _decode_ffi_json(raw, "pyDeriveAggEvalChallenge")
        raise AggregationInterfaceError(str(error))
    canonical = _normalize_scalar(text, "AggEval challenge")
    return canonical.encode("ascii")


def derive_ipakzg_challenge(
    library: Any, srs_pk: bytes, srs_vk: bytes, context: dict,
) -> bytes:
    raw = library.pyDeriveIPAKZGChallenge(
        _require_bytes(srs_pk, "SRS Pk"),
        _require_bytes(srs_vk, "SRS Vk"),
        _json_bytes(context),
    )
    if not isinstance(raw, (bytes, bytearray)):
        raise AggregationInterfaceError("IPAKZG challenge export returned non-bytes")
    text = bytes(raw).decode("utf-8")
    if text.startswith("{"):
        error = _decode_ffi_json(raw, "pyDeriveIPAKZGChallenge")
        raise AggregationInterfaceError(str(error))
    canonical = _normalize_scalar(text, "IPAKZG challenge")
    return canonical.encode("ascii")


def verify_agg_ped_eval(
    *,
    library: Any,
    srs_pk: bytes,
    srs_vk: bytes,
    context: dict,
    relation: str,
    witness: Any,
) -> bool:
    """Verify one left/right/output AggPedVerEval relation from typed ctx."""
    relation_fields = {
        "left": ("left_commitments", "left_pedersen", "left_point"),
        "right": ("right_commitments", "right_pedersen", "right_point"),
        "output": ("output_commitments", "output_pedersen", "output_point"),
    }
    try:
        commitment_field, pedersen_field, point_field = relation_fields[relation]
        commitments = context[commitment_field]
        pedersen = context[pedersen_field]
        point = int(_normalize_scalar(context[point_field], point_field), 10)
    except (KeyError, TypeError) as exc:
        raise AggregationInterfaceError(
            f"invalid IPAKZG context or relation {relation!r}"
        ) from exc
    return bool(library.pyAggPedVerEval(
        _require_bytes(srs_pk, "SRS Pk"),
        _require_bytes(srs_vk, "SRS Vk"),
        _json_bytes(context),
        _json_bytes(commitments),
        _json_bytes(pedersen),
        _json_bytes(_json_object(witness, f"{relation} witness")),
        point,
    ))


def verify_agg_ped_eval_batch(
    *,
    library: Any,
    srs_pk: bytes,
    srs_vk: bytes,
    context: dict,
    left_witness: Any,
    right_witness: Any,
    output_witness: Any,
) -> IPAKZGAggregateVerification:
    """Verify all three AggPedVerEval relations with one parsed IPAKZG ctx."""
    result_mask = int(library.pyAggPedVerEvalBatch3(
        _require_bytes(srs_pk, "SRS Pk"),
        _require_bytes(srs_vk, "SRS Vk"),
        _json_bytes(context),
        _json_bytes(_json_object(left_witness, "left witness")),
        _json_bytes(_json_object(right_witness, "right witness")),
        _json_bytes(_json_object(output_witness, "output witness")),
    ))
    return IPAKZGAggregateVerification(
        left_valid=bool(result_mask & 1),
        right_valid=bool(result_mask & 2),
        output_valid=bool(result_mask & 4),
    )


def _aggregate_witnesses(library: Any, openings: Sequence[dict], gamma: bytes) -> bytes:
    h_only = [{"H": opening["H"]} for opening in openings]
    result = _decode_ffi_json(
        library.pyAggProveEvalZero(_json_bytes(h_only), gamma),
        "pyAggProveEvalZero",
    )
    if set(result) != {"aggH"}:
        raise AggregationInterfaceError("aggregated witness has unexpected fields")
    return _json_bytes(result["aggH"])


def aggregate_ipakzg_witness(
    *,
    library: Any,
    context: dict,
    relation: str,
    openings: Any,
    gamma: bytes,
) -> bytes:
    """Aggregate one IPAKZG witness vector against its typed context.

    The prover uses the same relation selector as :func:`verify_agg_ped_eval`.
    Besides keeping the three duplicated HBACSS implementations aligned, this
    check prevents a witness vector of a different length from being silently
    aggregated under the context challenge.
    """
    commitment_fields = {
        "left": "left_commitments",
        "right": "right_commitments",
        "output": "output_commitments",
    }
    try:
        commitment_field = commitment_fields[relation]
        expected_length = len(context[commitment_field])
    except (KeyError, TypeError) as exc:
        raise AggregationInterfaceError(
            f"invalid IPAKZG context or relation {relation!r}"
        ) from exc
    normalized = normalize_openings(openings, f"{relation} openings")
    if len(normalized) != expected_length:
        raise AggregationInterfaceError(
            f"{relation} commitments and openings must have equal length"
        )
    return _aggregate_witnesses(
        library, normalized, _require_bytes(gamma, "IPAKZG challenge")
    )


def prove_aggtrans_v2(
    *,
    library: Any,
    srs_pk: bytes,
    srs_vk: bytes,
    dealer_local_id: int,
    old_commitments: Any,
    fresh_commitments: Any,
    old_openings: Any,
    fresh_openings: Any,
) -> AggTransV2Artifacts:
    context = build_agg_eval_context(
        dealer_local_id, old_commitments, fresh_commitments,
    )
    old_normalized = normalize_openings(old_openings, "old openings")
    fresh_normalized = normalize_openings(fresh_openings, "fresh openings")
    batch_size = len(context["old_commitments"])
    if len(old_normalized) != batch_size or len(fresh_normalized) != batch_size:
        raise AggregationInterfaceError(
            "commitments and old/fresh openings must have equal length"
        )
    proof = _decode_ffi_json(
        library.pyAggPubProEvalBatch2(
            _require_bytes(srs_pk, "SRS Pk"),
            _require_bytes(srs_vk, "SRS Vk"),
            _json_bytes(context),
            _json_bytes(old_normalized),
            _json_bytes(fresh_normalized),
        ),
        "pyAggPubProEvalBatch2",
    )
    if set(proof) != {"T", "W_old", "W_new", "pokPed"}:
        raise AggregationInterfaceError("AggPub proof has unexpected fields")
    return AggTransV2Artifacts(
        combined_claim=_json_bytes(proof["T"]),
        old_witness=_json_bytes(proof["W_old"]),
        fresh_witness=_json_bytes(proof["W_new"]),
        pok_ped=_json_bytes(proof["pokPed"]),
    )


def prove_aggtrans_legacy(
    *,
    library: Any,
    fresh_commitments: Any,
    old_openings: Any,
    fresh_openings: Any,
    share_g: Any,
    share_h: Any,
) -> AggTransLegacyArtifacts:
    commitments = _commitment_vector(fresh_commitments, "fresh commitments")
    old_normalized = normalize_openings(old_openings, "old openings")
    fresh_normalized = normalize_openings(fresh_openings, "fresh openings")
    share_g_vector = _commitment_vector(share_g, "shareG")
    share_h_vector = _commitment_vector(share_h, "shareH")
    lengths = {
        len(commitments), len(old_normalized), len(fresh_normalized),
        len(share_g_vector), len(share_h_vector),
    }
    if len(lengths) != 1:
        raise AggregationInterfaceError("legacy AggTrans vectors must have equal length")
    challenge = library.pyDeriveChallenge(_json_bytes(commitments))
    if not isinstance(challenge, (bytes, bytearray)):
        raise AggregationInterfaceError("legacy challenge returned non-bytes")
    challenge = bytes(challenge)
    share_g_openings = [
        {"H": point, "ClaimedValue": "0", "ClaimedValueAux": "0"}
        for point in share_g_vector
    ]
    share_h_openings = [
        {"H": point, "ClaimedValue": "0", "ClaimedValueAux": "0"}
        for point in share_h_vector
    ]
    return AggTransLegacyArtifacts(
        old_witness=_aggregate_witnesses(library, old_normalized, challenge),
        share_g=_aggregate_witnesses(library, share_g_openings, challenge),
        share_h=_aggregate_witnesses(library, share_h_openings, challenge),
        fresh_witness=_aggregate_witnesses(library, fresh_normalized, challenge),
        challenge=challenge,
    )


def build_aggtrans_payload(
    mode: str,
    proof_and_shares: bytes,
    old_commitments: bytes,
    *,
    v2: Optional[AggTransV2Artifacts] = None,
    legacy: Optional[AggTransLegacyArtifacts] = None,
) -> Any:
    proof_and_shares = _require_bytes(proof_and_shares, "proof_and_shares")
    old_commitments = _require_bytes(old_commitments, "old_commitments")
    if mode == "legacy":
        if legacy is None:
            raise AggregationInterfaceError("legacy AggTrans artifacts are missing")
        return (
            proof_and_shares, old_commitments, legacy.old_witness,
            legacy.share_g, legacy.share_h, legacy.fresh_witness,
            legacy.challenge,
        )
    if v2 is None:
        raise AggregationInterfaceError("V2 AggTrans artifacts are missing")
    v2_payload = {
        "schema": AGGTRANS_V2_SCHEMA,
        "proof_and_shares": proof_and_shares,
        "old_commitments": old_commitments,
        "T": v2.combined_claim,
        "W_old": v2.old_witness,
        "W_new": v2.fresh_witness,
        "pok_ped": v2.pok_ped,
    }
    if mode == "v2":
        return v2_payload
    if mode == "shadow":
        if legacy is None:
            raise AggregationInterfaceError("shadow legacy artifacts are missing")
        return {
            "schema": AGGTRANS_SHADOW_SCHEMA,
            "v2": v2_payload,
            "legacy": build_aggtrans_payload(
                "legacy", proof_and_shares, old_commitments, legacy=legacy,
            ),
        }
    raise AggregationInterfaceError(f"unsupported AggTrans mode {mode!r}")


def _parse_v2_payload(payload: Any) -> AggTransReceivedPayload:
    if not isinstance(payload, dict):
        raise AggregationInterfaceError("AggTrans V2 payload must be an object")
    expected = {
        "schema", "proof_and_shares", "old_commitments", "T",
        "W_old", "W_new", "pok_ped",
    }
    if set(payload) != expected or payload.get("schema") != AGGTRANS_V2_SCHEMA:
        raise AggregationInterfaceError("invalid AggTrans V2 payload schema")
    return AggTransReceivedPayload(
        proof_and_shares=_require_bytes(
            payload["proof_and_shares"], "proof_and_shares"
        ),
        old_commitments=_require_bytes(
            payload["old_commitments"], "old_commitments"
        ),
        v2=AggTransV2Artifacts(
            combined_claim=_require_bytes(payload["T"], "T"),
            old_witness=_require_bytes(payload["W_old"], "W_old"),
            fresh_witness=_require_bytes(payload["W_new"], "W_new"),
            pok_ped=_require_bytes(payload["pok_ped"], "pok_ped"),
        ),
    )


def _parse_legacy_payload(payload: Any) -> AggTransReceivedPayload:
    if not isinstance(payload, tuple) or len(payload) != 7:
        raise AggregationInterfaceError("invalid legacy AggTrans payload")
    values = tuple(_require_bytes(value, f"legacy[{index}]") for index, value in enumerate(payload))
    return AggTransReceivedPayload(
        proof_and_shares=values[0],
        old_commitments=values[1],
        legacy=AggTransLegacyArtifacts(
            old_witness=values[2], share_g=values[3], share_h=values[4],
            fresh_witness=values[5], challenge=values[6],
        ),
    )


def parse_aggtrans_payload(mode: str, payload: Any) -> AggTransReceivedPayload:
    if mode == "v2":
        return _parse_v2_payload(payload)
    if mode == "legacy":
        return _parse_legacy_payload(payload)
    if mode == "shadow":
        if not isinstance(payload, dict) or set(payload) != {"schema", "v2", "legacy"}:
            raise AggregationInterfaceError("invalid AggTrans shadow payload")
        if payload.get("schema") != AGGTRANS_SHADOW_SCHEMA:
            raise AggregationInterfaceError("invalid AggTrans shadow schema")
        parsed_v2 = _parse_v2_payload(payload["v2"])
        parsed_legacy = _parse_legacy_payload(payload["legacy"])
        if (
            parsed_v2.proof_and_shares != parsed_legacy.proof_and_shares
            or parsed_v2.old_commitments != parsed_legacy.old_commitments
        ):
            raise AggregationInterfaceError(
                "shadow V2/legacy base payloads do not match"
            )
        return AggTransReceivedPayload(
            proof_and_shares=parsed_v2.proof_and_shares,
            old_commitments=parsed_v2.old_commitments,
            v2=parsed_v2.v2,
            legacy=parsed_legacy.legacy,
        )
    raise AggregationInterfaceError(f"unsupported AggTrans mode {mode!r}")


def build_aggtrans_public_payload(
    mode: str,
    old_commitments: bytes,
    *,
    v2: Optional[AggTransV2Artifacts] = None,
    legacy: Optional[AggTransLegacyArtifacts] = None,
) -> dict:
    """Build the common AggTrans proof transcript carried by RBC.

    Per-recipient ``proof_and_shares`` is deliberately not accepted by this
    API, which prevents the public transcript from drifting across AVID
    indices under a Byzantine dealer.
    """
    old_commitments = _require_bytes(old_commitments, "old_commitments")
    if mode == "v2":
        if v2 is None:
            raise AggregationInterfaceError("V2 AggTrans artifacts are missing")
        return {
            "schema": AGGTRANS_V2_PUBLIC_SCHEMA,
            "old_commitments": old_commitments,
            "T": _require_bytes(v2.combined_claim, "T"),
            "W_old": _require_bytes(v2.old_witness, "W_old"),
            "W_new": _require_bytes(v2.fresh_witness, "W_new"),
            "pok_ped": _require_bytes(v2.pok_ped, "pok_ped"),
        }
    if mode == "legacy":
        if legacy is None:
            raise AggregationInterfaceError(
                "legacy AggTrans artifacts are missing"
            )
        return {
            "schema": AGGTRANS_LEGACY_PUBLIC_SCHEMA,
            "old_commitments": old_commitments,
            "W_old": _require_bytes(legacy.old_witness, "W_old"),
            "shareG": _require_bytes(legacy.share_g, "shareG"),
            "shareH": _require_bytes(legacy.share_h, "shareH"),
            "W_new": _require_bytes(legacy.fresh_witness, "W_new"),
            "challenge": _require_bytes(legacy.challenge, "challenge"),
        }
    if mode == "shadow":
        if v2 is None or legacy is None:
            raise AggregationInterfaceError(
                "shadow AggTrans artifacts are missing"
            )
        return {
            "schema": AGGTRANS_SHADOW_PUBLIC_SCHEMA,
            "v2": build_aggtrans_public_payload(
                "v2", old_commitments, v2=v2
            ),
            "legacy": build_aggtrans_public_payload(
                "legacy", old_commitments, legacy=legacy
            ),
        }
    raise AggregationInterfaceError(f"unsupported AggTrans mode {mode!r}")


def _parse_v2_public_payload(payload: Any) -> AggTransPublicPayload:
    expected = {
        "schema", "old_commitments", "T", "W_old", "W_new", "pok_ped",
    }
    if (
        not isinstance(payload, dict)
        or set(payload) != expected
        or payload.get("schema") != AGGTRANS_V2_PUBLIC_SCHEMA
    ):
        raise AggregationInterfaceError(
            "invalid AggTrans V2 public payload schema"
        )
    return AggTransPublicPayload(
        old_commitments=_require_bytes(
            payload["old_commitments"], "old_commitments"
        ),
        v2=AggTransV2Artifacts(
            combined_claim=_require_bytes(payload["T"], "T"),
            old_witness=_require_bytes(payload["W_old"], "W_old"),
            fresh_witness=_require_bytes(payload["W_new"], "W_new"),
            pok_ped=_require_bytes(payload["pok_ped"], "pok_ped"),
        ),
    )


def _parse_legacy_public_payload(payload: Any) -> AggTransPublicPayload:
    expected = {
        "schema", "old_commitments", "W_old", "shareG", "shareH",
        "W_new", "challenge",
    }
    if (
        not isinstance(payload, dict)
        or set(payload) != expected
        or payload.get("schema") != AGGTRANS_LEGACY_PUBLIC_SCHEMA
    ):
        raise AggregationInterfaceError(
            "invalid legacy AggTrans public payload schema"
        )
    return AggTransPublicPayload(
        old_commitments=_require_bytes(
            payload["old_commitments"], "old_commitments"
        ),
        legacy=AggTransLegacyArtifacts(
            old_witness=_require_bytes(payload["W_old"], "W_old"),
            share_g=_require_bytes(payload["shareG"], "shareG"),
            share_h=_require_bytes(payload["shareH"], "shareH"),
            fresh_witness=_require_bytes(payload["W_new"], "W_new"),
            challenge=_require_bytes(payload["challenge"], "challenge"),
        ),
    )


def parse_aggtrans_public_payload(
    mode: str, payload: Any,
) -> AggTransPublicPayload:
    if mode == "v2":
        return _parse_v2_public_payload(payload)
    if mode == "legacy":
        return _parse_legacy_public_payload(payload)
    if mode == "shadow":
        if (
            not isinstance(payload, dict)
            or set(payload) != {"schema", "v2", "legacy"}
            or payload.get("schema") != AGGTRANS_SHADOW_PUBLIC_SCHEMA
        ):
            raise AggregationInterfaceError(
                "invalid AggTrans shadow public payload schema"
            )
        parsed_v2 = _parse_v2_public_payload(payload["v2"])
        parsed_legacy = _parse_legacy_public_payload(payload["legacy"])
        if parsed_v2.old_commitments != parsed_legacy.old_commitments:
            raise AggregationInterfaceError(
                "shadow V2/legacy public commitments do not match"
            )
        return AggTransPublicPayload(
            old_commitments=parsed_v2.old_commitments,
            v2=parsed_v2.v2,
            legacy=parsed_legacy.legacy,
        )
    raise AggregationInterfaceError(f"unsupported AggTrans mode {mode!r}")


def combine_aggtrans_payload(
    proof_and_shares: bytes,
    public: AggTransPublicPayload,
) -> AggTransReceivedPayload:
    if not isinstance(public, AggTransPublicPayload):
        raise AggregationInterfaceError("invalid AggTrans public bundle")
    return AggTransReceivedPayload(
        proof_and_shares=_require_bytes(
            proof_and_shares, "proof_and_shares"
        ),
        old_commitments=public.old_commitments,
        v2=public.v2,
        legacy=public.legacy,
    )


def aggtrans_proof_size_metadata(
    mode: str,
    *,
    v2: Optional[AggTransV2Artifacts],
    legacy: Optional[AggTransLegacyArtifacts],
) -> dict:
    """Return canonical and current JSON-wire sizes for proof-only fields."""
    canonical_bytes = 0
    serialized_bytes = 0
    if mode in {"v2", "shadow"}:
        if v2 is None:
            raise AggregationInterfaceError("V2 proof size requires V2 artifacts")
        canonical_bytes += AGGTRANS_V2_CANONICAL_PROOF_BYTES
        serialized_bytes += sum((
            len(v2.combined_claim), len(v2.old_witness),
            len(v2.fresh_witness), len(v2.pok_ped),
        ))
    if mode in {"legacy", "shadow"}:
        if legacy is None:
            raise AggregationInterfaceError(
                "legacy proof size requires legacy artifacts"
            )
        canonical_bytes += AGGTRANS_LEGACY_CANONICAL_PROOF_BYTES
        serialized_bytes += sum((
            len(legacy.old_witness), len(legacy.share_g),
            len(legacy.share_h), len(legacy.fresh_witness),
            len(legacy.challenge),
        ))
    if mode not in {"v2", "legacy", "shadow"}:
        raise AggregationInterfaceError(f"unsupported AggTrans mode {mode!r}")
    return {
        "canonical_proof_bytes": canonical_bytes,
        "serialized_proof_bytes": serialized_bytes,
    }


def verify_aggtrans_v2(
    *,
    library: Any,
    srs_pk: bytes,
    srs_vk: bytes,
    dealer_local_id: int,
    fresh_commitments: bytes,
    payload: AggTransReceivedPayload,
) -> AggTransVerification:
    if payload.v2 is None:
        raise AggregationInterfaceError("V2 verification artifacts are missing")
    context = build_agg_eval_context(
        dealer_local_id, payload.old_commitments, fresh_commitments,
    )
    result_mask = int(library.pyAggPubVerEvalBatch2(
        _require_bytes(srs_pk, "SRS Pk"),
        _require_bytes(srs_vk, "SRS Vk"),
        _json_bytes(context),
        payload.v2.combined_claim,
        payload.v2.old_witness,
        payload.v2.fresh_witness,
        payload.v2.pok_ped,
    ))
    return AggTransVerification(
        pok_ped_valid=bool(result_mask & 1),
        fresh_zero_valid=bool(result_mask & 2),
        old_anchor_valid=bool(result_mask & 4),
    )


def verify_aggtrans_legacy(
    *, library: Any, srs_vk: bytes, dealer_local_id: int,
    fresh_commitments: bytes, payload: AggTransReceivedPayload,
) -> AggTransVerification:
    if payload.legacy is None:
        raise AggregationInterfaceError("legacy verification artifacts are missing")
    legacy = payload.legacy
    fresh_valid = bool(library.pyPubAggVerifyEval(
        srs_vk, fresh_commitments, legacy.share_g, legacy.share_h,
        legacy.fresh_witness, legacy.challenge, 0,
    ))
    old_valid = bool(library.pyPubAggVerifyEval(
        srs_vk, payload.old_commitments, legacy.share_g, legacy.share_h,
        legacy.old_witness, legacy.challenge, dealer_local_id + 1,
    ))
    return AggTransVerification(True, fresh_valid, old_valid)


def select_aggtrans_verification(
    mode: str,
    *,
    v2: Optional[AggTransVerification],
    legacy: Optional[AggTransVerification],
    dealer_local_id: int,
    receiver_local_id: int,
) -> AggTransVerification:
    if mode == "v2":
        if v2 is None:
            raise AggregationInterfaceError("missing V2 verification result")
        return v2
    if mode == "legacy":
        if legacy is None:
            raise AggregationInterfaceError("missing legacy verification result")
        return legacy
    if mode == "shadow":
        if v2 is None or legacy is None:
            raise AggregationInterfaceError("shadow verification results are incomplete")
        if v2 != legacy:
            _LOG.warning(
                "AggTrans shadow mismatch: dealer_id=%s receiver_id=%s "
                "fields=pok_ped_valid,fresh_zero_valid,old_anchor_valid "
                "legacy=%s/%s/%s v2=%s/%s/%s",
                dealer_local_id, receiver_local_id,
                legacy.pok_ped_valid, legacy.fresh_zero_valid,
                legacy.old_anchor_valid, v2.pok_ped_valid,
                v2.fresh_zero_valid, v2.old_anchor_valid,
            )
        return legacy
    raise AggregationInterfaceError(f"unsupported AggTrans mode {mode!r}")


def verify_aggtrans(
    mode: str,
    *,
    library: Any,
    srs_pk: bytes,
    srs_vk: bytes,
    dealer_local_id: int,
    receiver_local_id: int,
    fresh_commitments: bytes,
    payload: AggTransReceivedPayload,
) -> AggTransVerification:
    """Run the selected verifier; shadow mode compares both without secrets."""
    v2_result = None
    legacy_result = None
    if mode in {"v2", "shadow"}:
        v2_result = verify_aggtrans_v2(
            library=library, srs_pk=srs_pk, srs_vk=srs_vk,
            dealer_local_id=dealer_local_id,
            fresh_commitments=fresh_commitments, payload=payload,
        )
    if mode in {"legacy", "shadow"}:
        legacy_result = verify_aggtrans_legacy(
            library=library, srs_vk=srs_vk,
            dealer_local_id=dealer_local_id,
            fresh_commitments=fresh_commitments, payload=payload,
        )
    return select_aggtrans_verification(
        mode, v2=v2_result, legacy=legacy_result,
        dealer_local_id=dealer_local_id,
        receiver_local_id=receiver_local_id,
    )
