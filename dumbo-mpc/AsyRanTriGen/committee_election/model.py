"""Canonical candidate-registry and deterministic-selection model.

This module is intentionally free of Charm, asyncio, IPC, and MPC imports so
its byte-level test vectors can be checked in any ordinary Python process.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any, Dict, Mapping, Sequence, Tuple


REGISTRY_VERSION = 1
MESSAGE_VERSION = 1
MESSAGE_DOMAIN = "continuum-committee-election-v1"
COIN_DOMAIN = b"continuum-election-seed-v1\x00"
SELECTION_DOMAIN = b"continuum-election-select-v1\x00"
PERMUTATION_DOMAIN = b"continuum-election-permutation-v1\x00"
_HEX_256 = re.compile(r"^[0-9a-f]{64}$")


class ElectionModelError(ValueError):
    """Raised when canonical election input is invalid."""


def _require_plain_int(name: str, value: Any, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ElectionModelError(f"{name} must be an integer >= {minimum}")
    return value


def _require_text(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ElectionModelError(f"{name} must be a non-empty trimmed string")
    if "\x00" in value:
        raise ElectionModelError(f"{name} must not contain NUL")
    return value


def _require_digest(name: str, value: Any) -> str:
    if not isinstance(value, str) or _HEX_256.fullmatch(value) is None:
        raise ElectionModelError(f"{name} must be a lowercase SHA-256 hex digest")
    return value


def canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    """Return the single canonical JSON encoding used by the election."""

    try:
        text = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ElectionModelError("value is not canonically JSON encodable") from exc
    return text.encode("utf-8")


@dataclass(frozen=True)
class CommitteeMember:
    global_party_id: int
    endpoint_id: str
    authenticated_identity_digest: str
    protocol_public_key_digest: str

    def __post_init__(self) -> None:
        _require_plain_int("global_party_id", self.global_party_id)
        _require_text("endpoint_id", self.endpoint_id)
        _require_digest(
            "authenticated_identity_digest", self.authenticated_identity_digest
        )
        _require_digest(
            "protocol_public_key_digest", self.protocol_public_key_digest
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "authenticated_identity_digest": self.authenticated_identity_digest,
            "endpoint_id": self.endpoint_id,
            "global_party_id": self.global_party_id,
            "protocol_public_key_digest": self.protocol_public_key_digest,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CommitteeMember":
        expected = {
            "global_party_id",
            "endpoint_id",
            "authenticated_identity_digest",
            "protocol_public_key_digest",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ElectionModelError("committee member fields do not match schema")
        return cls(**dict(value))


@dataclass(frozen=True)
class CandidateCommittee:
    committee_id: str
    members: Tuple[CommitteeMember, ...]

    def __post_init__(self) -> None:
        _require_text("committee_id", self.committee_id)
        members = tuple(sorted(tuple(self.members), key=lambda item: item.global_party_id))
        if not members:
            raise ElectionModelError("candidate committee must not be empty")
        ids = [member.global_party_id for member in members]
        endpoints = [member.endpoint_id for member in members]
        if len(set(ids)) != len(ids):
            raise ElectionModelError("candidate committee has duplicate party IDs")
        if len(set(endpoints)) != len(endpoints):
            raise ElectionModelError("candidate committee has duplicate endpoints")
        object.__setattr__(self, "members", members)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "committee_id": self.committee_id,
            "members": [member.to_dict() for member in self.members],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CandidateCommittee":
        if not isinstance(value, Mapping) or set(value) != {"committee_id", "members"}:
            raise ElectionModelError("candidate committee fields do not match schema")
        raw_members = value["members"]
        if not isinstance(raw_members, Sequence) or isinstance(raw_members, (str, bytes)):
            raise ElectionModelError("candidate members must be a sequence")
        return cls(
            committee_id=value["committee_id"],
            members=tuple(CommitteeMember.from_dict(item) for item in raw_members),
        )


@dataclass(frozen=True)
class CandidateRegistry:
    registry_id: str
    committee_size: int
    candidates: Tuple[CandidateCommittee, ...]
    registry_version: int = REGISTRY_VERSION

    def __post_init__(self) -> None:
        _require_text("registry_id", self.registry_id)
        _require_plain_int("committee_size", self.committee_size, minimum=1)
        if type(self.registry_version) is not int or self.registry_version != REGISTRY_VERSION:
            raise ElectionModelError("unsupported candidate registry version")
        candidates = tuple(sorted(tuple(self.candidates), key=lambda item: item.committee_id))
        if not candidates:
            raise ElectionModelError("candidate registry must not be empty")
        ids = [candidate.committee_id for candidate in candidates]
        if len(set(ids)) != len(ids):
            raise ElectionModelError("candidate registry has duplicate committee IDs")
        for candidate in candidates:
            if len(candidate.members) != self.committee_size:
                raise ElectionModelError(
                    f"candidate {candidate.committee_id} does not have committee_size members"
                )
        object.__setattr__(self, "candidates", candidates)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "committee_size": self.committee_size,
            "registry_id": self.registry_id,
            "registry_version": self.registry_version,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    def digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def candidate(self, index: int) -> CandidateCommittee:
        _require_plain_int("candidate index", index)
        try:
            return self.candidates[index]
        except IndexError as exc:
            raise ElectionModelError("candidate index is out of range") from exc

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CandidateRegistry":
        expected = {"registry_version", "registry_id", "committee_size", "candidates"}
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ElectionModelError("candidate registry fields do not match schema")
        raw_candidates = value["candidates"]
        if not isinstance(raw_candidates, Sequence) or isinstance(
            raw_candidates, (str, bytes)
        ):
            raise ElectionModelError("candidates must be a sequence")
        return cls(
            registry_version=value["registry_version"],
            registry_id=value["registry_id"],
            committee_size=value["committee_size"],
            candidates=tuple(
                CandidateCommittee.from_dict(item) for item in raw_candidates
            ),
        )

    @classmethod
    def from_json_bytes(cls, payload: bytes) -> "CandidateRegistry":
        if not isinstance(payload, bytes):
            raise ElectionModelError("registry payload must be bytes")
        try:
            decoded = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ElectionModelError("registry payload is not valid UTF-8 JSON") from exc
        return cls.from_dict(decoded)


@dataclass(frozen=True)
class ElectionContext:
    run_id: str
    source_committee_id: str
    target_epoch: int
    registry_id: str
    registry_digest: str
    message_version: int = MESSAGE_VERSION
    protocol_domain: str = MESSAGE_DOMAIN

    def __post_init__(self) -> None:
        _require_text("run_id", self.run_id)
        _require_text("source_committee_id", self.source_committee_id)
        _require_plain_int("target_epoch", self.target_epoch, minimum=2)
        _require_text("registry_id", self.registry_id)
        _require_digest("registry_digest", self.registry_digest)
        if type(self.message_version) is not int or self.message_version != MESSAGE_VERSION:
            raise ElectionModelError("unsupported election message version")
        if self.protocol_domain != MESSAGE_DOMAIN:
            raise ElectionModelError("unsupported election protocol domain")

    @classmethod
    def for_registry(
        cls,
        *,
        run_id: str,
        source_committee_id: str,
        target_epoch: int,
        registry: CandidateRegistry,
    ) -> "ElectionContext":
        return cls(
            run_id=run_id,
            source_committee_id=source_committee_id,
            target_epoch=target_epoch,
            registry_id=registry.registry_id,
            registry_digest=registry.digest(),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "message_version": self.message_version,
            "protocol_domain": self.protocol_domain,
            "registry_digest": self.registry_digest,
            "registry_id": self.registry_id,
            "run_id": self.run_id,
            "source_committee_id": self.source_committee_id,
            "target_epoch": self.target_epoch,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    def validate_registry(self, registry: CandidateRegistry) -> None:
        if self.registry_id != registry.registry_id:
            raise ElectionModelError("election context registry ID mismatch")
        if self.registry_digest != registry.digest():
            raise ElectionModelError("election context registry digest mismatch")


@dataclass(frozen=True)
class SelectionResult:
    candidate_index: int
    committee_id: str
    selection_counter: int


def derive_coin_seed(signature_bytes: bytes) -> bytes:
    if not isinstance(signature_bytes, bytes) or not signature_bytes:
        raise ElectionModelError("threshold signature serialization must be non-empty bytes")
    return hashlib.sha256(COIN_DOMAIN + signature_bytes).digest()


def _sample_index(seed: bytes, upper_bound: int) -> Tuple[int, int]:
    if not isinstance(seed, bytes) or len(seed) != 32:
        raise ElectionModelError("election seed must contain exactly 32 bytes")
    _require_plain_int("upper_bound", upper_bound, minimum=1)
    if upper_bound > (1 << 32):
        raise ElectionModelError("candidate universe is unreasonably large")
    limit = ((1 << 256) // upper_bound) * upper_bound
    for counter in range(1 << 32):
        digest = hashlib.sha256(
            SELECTION_DOMAIN + seed + counter.to_bytes(8, "big")
        ).digest()
        value = int.from_bytes(digest, "big")
        if value < limit:
            return value % upper_bound, counter
    raise ElectionModelError("rejection sampler exhausted its counter space")


def select_candidate(seed: bytes, registry: CandidateRegistry) -> SelectionResult:
    index, counter = _sample_index(seed, len(registry.candidates))
    return SelectionResult(index, registry.candidate(index).committee_id, counter)


def deterministic_permutation(seed: bytes, candidate_count: int) -> Tuple[int, ...]:
    """Return a deterministic fallback ordering for registered candidates.

    Selection of one committee uses rejection sampling above.  This optional
    ordering is available for a later fallback policy and is not consumed by
    Stages 1--3.
    """

    if not isinstance(seed, bytes) or len(seed) != 32:
        raise ElectionModelError("election seed must contain exactly 32 bytes")
    _require_plain_int("candidate_count", candidate_count, minimum=1)
    if candidate_count > (1 << 32):
        raise ElectionModelError("candidate universe is unreasonably large")
    scored = []
    for index in range(candidate_count):
        score = hashlib.sha256(
            PERMUTATION_DOMAIN + seed + index.to_bytes(8, "big")
        ).digest()
        scored.append((score, index))
    return tuple(index for _, index in sorted(scored))
