"""Fail-closed wrapper around the repository's existing Boldyreva TBLS."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import time
from typing import Any, Dict, Mapping, Sequence, Tuple

from beaver.broadcast.crypto.boldyreva import deserialize1, serialize

from .model import (
    CandidateCommittee,
    CandidateRegistry,
    ElectionContext,
    ElectionModelError,
    SelectionResult,
    canonical_json_bytes,
    derive_coin_seed,
    select_candidate,
)


CERTIFICATE_VERSION = 1


class ElectionCryptoError(ValueError):
    """Raised for invalid keys, shares, signatures, or certificates."""


@dataclass(frozen=True)
class CryptoBreakdown:
    share_verify_ms_total: float = 0.0
    combine_ms: float = 0.0
    combined_verify_ms: float = 0.0
    selection_ms: float = 0.0

    def to_dict(self) -> Dict[str, float]:
        return {
            "share_verify_ms_total": self.share_verify_ms_total,
            "combine_ms": self.combine_ms,
            "combined_verify_ms": self.combined_verify_ms,
            "selection_ms": self.selection_ms,
        }


@dataclass(frozen=True)
class ElectionCertificate:
    run_id: str
    source_committee_id: str
    target_epoch: int
    registry_id: str
    registry_digest: str
    signer_ids: Tuple[int, ...]
    threshold_signature_b64: str
    signature_digest: str
    selection_counter: int
    candidate_index: int
    committee_id: str
    certificate_version: int = CERTIFICATE_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return {
            "candidate_index": self.candidate_index,
            "certificate_version": self.certificate_version,
            "committee_id": self.committee_id,
            "registry_digest": self.registry_digest,
            "registry_id": self.registry_id,
            "run_id": self.run_id,
            "selection_counter": self.selection_counter,
            "signer_ids": list(self.signer_ids),
            "signature_digest": self.signature_digest,
            "source_committee_id": self.source_committee_id,
            "target_epoch": self.target_epoch,
            "threshold_signature_b64": self.threshold_signature_b64,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ElectionCertificate":
        expected = {
            "candidate_index",
            "certificate_version",
            "committee_id",
            "registry_digest",
            "registry_id",
            "run_id",
            "selection_counter",
            "signer_ids",
            "signature_digest",
            "source_committee_id",
            "target_epoch",
            "threshold_signature_b64",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ElectionCryptoError("certificate fields do not match schema")
        raw_signer_ids = value["signer_ids"]
        if not isinstance(raw_signer_ids, Sequence) or isinstance(
            raw_signer_ids, (str, bytes)
        ):
            raise ElectionCryptoError("certificate signer IDs must be a sequence")
        fields = dict(value)
        fields["signer_ids"] = tuple(raw_signer_ids)
        try:
            certificate = cls(**fields)
        except TypeError as exc:
            raise ElectionCryptoError("certificate values do not match schema") from exc
        _validate_certificate_shape(certificate)
        return certificate


@dataclass(frozen=True)
class ResolvedElection:
    context: ElectionContext
    selection: SelectionResult
    committee: CandidateCommittee
    signature_digest: str


def _validate_certificate_shape(certificate: ElectionCertificate) -> None:
    if (
        type(certificate.certificate_version) is not int
        or certificate.certificate_version != CERTIFICATE_VERSION
    ):
        raise ElectionCryptoError("unsupported certificate version")
    try:
        ElectionContext(
            run_id=certificate.run_id,
            source_committee_id=certificate.source_committee_id,
            target_epoch=certificate.target_epoch,
            registry_id=certificate.registry_id,
            registry_digest=certificate.registry_digest,
        )
    except ElectionModelError as exc:
        raise ElectionCryptoError("certificate election context is invalid") from exc
    if (
        not isinstance(certificate.committee_id, str)
        or not certificate.committee_id
        or certificate.committee_id.strip() != certificate.committee_id
    ):
        raise ElectionCryptoError("certificate committee ID is invalid")
    if (
        type(certificate.selection_counter) is not int
        or certificate.selection_counter < 0
        or type(certificate.candidate_index) is not int
        or certificate.candidate_index < 0
    ):
        raise ElectionCryptoError("certificate selection fields are invalid")
    if (
        not isinstance(certificate.signer_ids, tuple)
        or any(type(signer_id) is not int for signer_id in certificate.signer_ids)
        or len(set(certificate.signer_ids)) != len(certificate.signer_ids)
    ):
        raise ElectionCryptoError("certificate signer IDs are invalid")
    if (
        not isinstance(certificate.signature_digest, str)
        or len(certificate.signature_digest) != 64
        or any(character not in "0123456789abcdef" for character in certificate.signature_digest)
    ):
        raise ElectionCryptoError("certificate signature digest is invalid")
    if (
        not isinstance(certificate.threshold_signature_b64, str)
        or not certificate.threshold_signature_b64
    ):
        raise ElectionCryptoError("certificate threshold signature is invalid")


def validate_public_key(public_key: Any, *, n: int, t: int) -> None:
    if type(n) is not int or type(t) is not int or n < 1 or t < 0:
        raise ElectionCryptoError("invalid n/t parameters")
    if n < 3 * t + 1:
        raise ElectionCryptoError("n must satisfy n >= 3*t+1")
    if getattr(public_key, "l", None) != n:
        raise ElectionCryptoError("TBLS public key party count mismatch")
    if getattr(public_key, "k", None) != t + 1:
        raise ElectionCryptoError("TBLS public key threshold must equal t+1")


def validate_private_share(private_key: Any, *, public_key: Any, sender_id: int) -> None:
    if type(sender_id) is not int or not 0 <= sender_id < public_key.l:
        raise ElectionCryptoError("sender ID is outside the TBLS key range")
    for attribute in ("l", "k", "VK", "VKs"):
        if getattr(private_key, attribute, None) != getattr(public_key, attribute, None):
            raise ElectionCryptoError("TBLS private share does not match public key")
    if getattr(private_key, "i", None) != sender_id:
        raise ElectionCryptoError("TBLS private share index does not match sender")


def sign_share(
    private_key: Any,
    public_key: Any,
    sender_id: int,
    context: ElectionContext,
) -> Tuple[bytes, float]:
    validate_private_share(private_key, public_key=public_key, sender_id=sender_id)
    started = time.perf_counter()
    try:
        point = private_key.sign(public_key.hash_message(context.canonical_bytes()))
        encoded = serialize(point)
    except Exception as exc:
        raise ElectionCryptoError("failed to generate TBLS signature share") from exc
    return encoded, (time.perf_counter() - started) * 1000.0


def verify_share(
    public_key: Any,
    sender_id: int,
    context: ElectionContext,
    share_bytes: bytes,
) -> Tuple[bool, float]:
    started = time.perf_counter()
    try:
        if type(sender_id) is not int or not 0 <= sender_id < public_key.l:
            return False, (time.perf_counter() - started) * 1000.0
        if not isinstance(share_bytes, bytes) or not share_bytes:
            return False, (time.perf_counter() - started) * 1000.0
        point = deserialize1(share_bytes)
        message_hash = public_key.hash_message(context.canonical_bytes())
        public_key.verify_share(point, sender_id, message_hash)
        return True, (time.perf_counter() - started) * 1000.0
    except Exception:
        return False, (time.perf_counter() - started) * 1000.0


def verify_combined_signature(
    public_key: Any, context: ElectionContext, signature_bytes: bytes
) -> Tuple[bool, float]:
    started = time.perf_counter()
    try:
        if not isinstance(signature_bytes, bytes) or not signature_bytes:
            return False, (time.perf_counter() - started) * 1000.0
        signature = deserialize1(signature_bytes)
        message_hash = public_key.hash_message(context.canonical_bytes())
        public_key.verify_signature(signature, message_hash)
        return True, (time.perf_counter() - started) * 1000.0
    except Exception:
        return False, (time.perf_counter() - started) * 1000.0


def combine_verified_shares(
    public_key: Any,
    context: ElectionContext,
    shares: Mapping[int, bytes],
) -> Tuple[bytes, Tuple[int, ...], CryptoBreakdown]:
    if not isinstance(shares, Mapping):
        raise ElectionCryptoError("signature shares must be a sender mapping")
    if len(shares) < public_key.k:
        raise ElectionCryptoError("fewer than t+1 signature shares")
    verify_ms = 0.0
    decoded: Dict[int, Any] = {}
    for sender_id in sorted(shares):
        valid, elapsed = verify_share(
            public_key, sender_id, context, shares[sender_id]
        )
        verify_ms += elapsed
        if not valid:
            raise ElectionCryptoError(f"invalid signature share from sender {sender_id}")
        decoded[sender_id] = deserialize1(shares[sender_id])
    selected_ids = tuple(sorted(decoded)[: public_key.k])
    selected = {sender_id: decoded[sender_id] for sender_id in selected_ids}
    started = time.perf_counter()
    try:
        signature = public_key.combine_shares(selected)
        signature_bytes = serialize(signature)
    except Exception as exc:
        raise ElectionCryptoError("failed to combine TBLS signature shares") from exc
    combine_ms = (time.perf_counter() - started) * 1000.0
    valid, combined_verify_ms = verify_combined_signature(
        public_key, context, signature_bytes
    )
    if not valid:
        raise ElectionCryptoError("combined TBLS signature failed verification")
    return signature_bytes, selected_ids, CryptoBreakdown(
        share_verify_ms_total=verify_ms,
        combine_ms=combine_ms,
        combined_verify_ms=combined_verify_ms,
    )


def build_certificate(
    *,
    public_key: Any,
    registry: CandidateRegistry,
    context: ElectionContext,
    shares: Mapping[int, bytes],
) -> Tuple[ElectionCertificate, Tuple[int, ...], CryptoBreakdown]:
    context.validate_registry(registry)
    signature, used_share_ids, breakdown = combine_verified_shares(
        public_key, context, shares
    )
    started = time.perf_counter()
    selection = select_candidate(derive_coin_seed(signature), registry)
    selection_ms = (time.perf_counter() - started) * 1000.0
    certificate = ElectionCertificate(
        run_id=context.run_id,
        source_committee_id=context.source_committee_id,
        target_epoch=context.target_epoch,
        registry_id=context.registry_id,
        registry_digest=context.registry_digest,
        signer_ids=used_share_ids,
        threshold_signature_b64=base64.b64encode(signature).decode("ascii"),
        signature_digest=hashlib.sha256(signature).hexdigest(),
        selection_counter=selection.selection_counter,
        candidate_index=selection.candidate_index,
        committee_id=selection.committee_id,
    )
    return certificate, used_share_ids, CryptoBreakdown(
        share_verify_ms_total=breakdown.share_verify_ms_total,
        combine_ms=breakdown.combine_ms,
        combined_verify_ms=breakdown.combined_verify_ms,
        selection_ms=selection_ms,
    )


def verify_certificate(
    *,
    public_key: Any,
    registry: CandidateRegistry,
    certificate: ElectionCertificate,
) -> Tuple[ResolvedElection, CryptoBreakdown]:
    _validate_certificate_shape(certificate)
    if (
        len(certificate.signer_ids) != public_key.k
        or len(set(certificate.signer_ids)) != public_key.k
        or any(
            type(signer_id) is not int or not 0 <= signer_id < public_key.l
            for signer_id in certificate.signer_ids
        )
    ):
        raise ElectionCryptoError("certificate signer IDs are invalid")
    try:
        context = ElectionContext(
            run_id=certificate.run_id,
            source_committee_id=certificate.source_committee_id,
            target_epoch=certificate.target_epoch,
            registry_id=certificate.registry_id,
            registry_digest=certificate.registry_digest,
        )
        context.validate_registry(registry)
    except ElectionModelError as exc:
        raise ElectionCryptoError("certificate election context is invalid") from exc
    try:
        signature = base64.b64decode(
            certificate.threshold_signature_b64.encode("ascii"), validate=True
        )
    except Exception as exc:
        raise ElectionCryptoError("certificate signature is not canonical base64") from exc
    if hashlib.sha256(signature).hexdigest() != certificate.signature_digest:
        raise ElectionCryptoError("certificate signature digest mismatch")
    valid, verify_ms = verify_combined_signature(public_key, context, signature)
    if not valid:
        raise ElectionCryptoError("certificate threshold signature is invalid")
    started = time.perf_counter()
    selection = select_candidate(derive_coin_seed(signature), registry)
    selection_ms = (time.perf_counter() - started) * 1000.0
    if selection.selection_counter != certificate.selection_counter:
        raise ElectionCryptoError("certificate selection counter mismatch")
    if selection.candidate_index != certificate.candidate_index:
        raise ElectionCryptoError("certificate candidate index mismatch")
    if selection.committee_id != certificate.committee_id:
        raise ElectionCryptoError("certificate committee ID mismatch")
    return ResolvedElection(
        context=context,
        selection=selection,
        committee=registry.candidate(selection.candidate_index),
        signature_digest=certificate.signature_digest,
    ), CryptoBreakdown(combined_verify_ms=verify_ms, selection_ms=selection_ms)
