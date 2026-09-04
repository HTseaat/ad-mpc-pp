"""Canonical, public-only serialization of the generated Continuum SRS."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Tuple

from ..config import SetupParams


FORMAT_NAME = "continuum-kzg-srs-v1"
DIGEST_DOMAIN = b"Continuum/KZG-SRS/v1\x00"
CURVE_NAME = "BLS12-381"
_FIELDS = {
    "format",
    "curve",
    "n",
    "t",
    "requested_powers",
    "effective_powers",
    "run_id",
    "g1_g",
    "g1_h",
    "g2",
    "alpha_g2",
    "digest",
}


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _decode_point(value: Any, expected_size: int, label: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a base64 string")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"{label} is not valid base64") from exc
    if len(decoded) != expected_size:
        raise ValueError(
            f"{label} must encode {expected_size} bytes, got {len(decoded)}"
        )
    return decoded


@dataclass(frozen=True)
class ContinuumSRS:
    n: int
    t: int
    requested_powers: int
    effective_powers: int
    run_id: str
    g1_g: Tuple[bytes, ...]
    g1_h: Tuple[bytes, ...]
    g2: bytes
    alpha_g2: bytes
    digest: str
    curve: str = CURVE_NAME
    format: str = FORMAT_NAME

    def payload_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "curve": self.curve,
            "n": self.n,
            "t": self.t,
            "requested_powers": self.requested_powers,
            "effective_powers": self.effective_powers,
            "run_id": self.run_id,
            "g1_g": [_b64(point) for point in self.g1_g],
            "g1_h": [_b64(point) for point in self.g1_h],
            "g2": _b64(self.g2),
            "alpha_g2": _b64(self.alpha_g2),
        }

    def expected_digest(self) -> str:
        return hashlib.sha256(
            DIGEST_DOMAIN + _canonical_json(self.payload_dict())
        ).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        value = self.payload_dict()
        value["digest"] = self.digest
        return value

    def to_json_bytes(self) -> bytes:
        return _canonical_json(self.to_dict()) + b"\n"

    @property
    def encoded_size_bytes(self) -> int:
        return len(self.to_json_bytes())

    def validate(self) -> None:
        params = SetupParams.create(
            self.n,
            self.t,
            self.requested_powers,
            run_id=self.run_id,
        )
        if self.format != FORMAT_NAME or self.curve != CURVE_NAME:
            raise ValueError("unsupported SRS format or curve")
        if params.effective_powers != self.effective_powers:
            raise ValueError("effective_powers is not canonical")
        if len(self.g1_g) != self.requested_powers:
            raise ValueError("g1_g length does not match requested_powers")
        if len(self.g1_h) != self.requested_powers:
            raise ValueError("g1_h length does not match requested_powers")
        if any(len(point) != 48 for point in self.g1_g + self.g1_h):
            raise ValueError("every compressed G1 point must be 48 bytes")
        if len(self.g2) != 96 or len(self.alpha_g2) != 96:
            raise ValueError("every compressed G2 point must be 96 bytes")
        if self.digest != self.expected_digest():
            raise ValueError("SRS digest mismatch")


def _point_bytes(point: Any) -> bytes:
    return bytes(point.__getstate__())


def build_srs(result: Any, *, already_verified: bool = False) -> ContinuumSRS:
    """Build the public artifact, truncating chains to requested powers."""

    if not already_verified:
        from ..protocol.verification import verify_result

        report = verify_result(result)
        if not report.ok:
            raise ValueError(f"refusing to serialize invalid setup result: {report}")
    if not result.parties:
        raise ValueError("setup result has no party outputs")

    first = result.parties[0]
    count = result.params.requested_powers
    record_without_digest = ContinuumSRS(
        n=result.params.n,
        t=result.params.t,
        requested_powers=count,
        effective_powers=result.params.effective_powers,
        run_id=result.params.run_id,
        g1_g=tuple(_point_bytes(point) for point in first.g_chain[:count]),
        g1_h=tuple(_point_bytes(point) for point in first.h_chain[:count]),
        g2=_point_bytes(result.g2),
        alpha_g2=_point_bytes(first.alpha_g2),
        digest="",
    )
    record = ContinuumSRS(
        **{
            **record_without_digest.__dict__,
            "digest": record_without_digest.expected_digest(),
        }
    )
    record.validate()
    return record


def parse_srs(value: Mapping[str, Any]) -> ContinuumSRS:
    if not isinstance(value, Mapping) or set(value) != _FIELDS:
        raise ValueError("SRS JSON has missing or unknown fields")
    for name in ("n", "t", "requested_powers", "effective_powers"):
        if type(value[name]) is not int:
            raise ValueError(f"{name} must be an integer")
    if not isinstance(value["run_id"], str) or not value["run_id"]:
        raise ValueError("run_id must be a non-empty string")
    if not isinstance(value["g1_g"], list) or not isinstance(value["g1_h"], list):
        raise ValueError("g1 chains must be arrays")
    if not isinstance(value["digest"], str) or len(value["digest"]) != 64:
        raise ValueError("digest must be a SHA-256 hex string")

    record = ContinuumSRS(
        n=value["n"],
        t=value["t"],
        requested_powers=value["requested_powers"],
        effective_powers=value["effective_powers"],
        run_id=value["run_id"],
        g1_g=tuple(
            _decode_point(point, 48, f"g1_g[{index}]")
            for index, point in enumerate(value["g1_g"])
        ),
        g1_h=tuple(
            _decode_point(point, 48, f"g1_h[{index}]")
            for index, point in enumerate(value["g1_h"])
        ),
        g2=_decode_point(value["g2"], 96, "g2"),
        alpha_g2=_decode_point(value["alpha_g2"], 96, "alpha_g2"),
        digest=value["digest"],
        curve=value["curve"],
        format=value["format"],
    )
    record.validate()
    return record


def load_srs(path: Path | str) -> ContinuumSRS:
    source = Path(path)
    try:
        value = json.loads(source.read_text(encoding="ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load SRS file {source}: {exc}") from exc
    return parse_srs(value)


def write_srs(record: ContinuumSRS, path: Path | str) -> Path:
    record.validate()
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=str(destination.parent)
    )
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(record.to_json_bytes())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, destination)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise
    return destination
